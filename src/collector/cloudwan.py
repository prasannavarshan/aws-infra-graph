"""CloudWAN (Network Manager) collector — Core Networks, Segments, Attachments."""

from __future__ import annotations

import json

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BOTO_CONFIG, BaseCollector, get_session_for_account
from src.collector.cloudwan_policy import process_policy
from src.config import settings
from src.graph.model import (
    NodeLabel,
    RelationshipType,
    ResourceEdge,
    ResourceNode,
)

logger = structlog.get_logger()


def _parse_tags(tag_list: list[dict] | None) -> dict[str, str]:
    """Convert AWS tag list to a flat dict."""
    if not tag_list:
        return {}
    return {t["Key"]: t["Value"] for t in tag_list}


def _tag_name(tags: dict[str, str], fallback: str = "") -> str:
    """Extract the Name tag, falling back to given default."""
    return tags.get("Name", fallback)


class CloudWANCollector(BaseCollector):
    """Collects CloudWAN Core Networks, Segments, and Attachments.

    CloudWAN / Network Manager APIs are global (us-west-2 endpoint),
    so this collector only runs once regardless of configured regions.

    CloudWAN APIs are global — list_core_networks works from any
    account, but get_core_network / get_core_network_policy require
    the owner account. The collector assumes into the owner account
    via STS when needed.
    """

    run_once: bool = True

    def collect(
        self,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Override base collect — CloudWAN is a global service."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            nm = self.client("networkmanager", "us-west-2")
            self._collect_core_networks(nm, nodes, edges)
            self._collect_attachments(nm, nodes, edges)
        except ClientError as e:
            logger.error(
                "cloudwan_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

        return nodes, edges

    def collect_in_region(
        self, region: str,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Not used — collect() is overridden for global API."""
        return [], []

    def _collect_core_networks(
        self,
        nm,  # noqa: ANN001
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect Core Networks and their segments."""
        paginator = nm.get_paginator("list_core_networks")
        for page in paginator.paginate():
            for cn_summary in page.get(
                "CoreNetworks", [],
            ):
                cn_id = cn_summary["CoreNetworkId"]
                owner = cn_summary.get("OwnerAccountId", "")
                try:
                    detail = nm.get_core_network(
                        CoreNetworkId=cn_id,
                    )["CoreNetwork"]
                    self._process_core_network(
                        detail, nm, nodes, edges,
                    )
                except ClientError as e:
                    code = e.response["Error"]["Code"]
                    if code == "ResourceNotFoundException" and owner:
                        self._collect_core_network_via_owner(
                            cn_id, owner, nodes, edges,
                        )
                    else:
                        logger.warning(
                            "core_network_detail_failed",
                            core_network_id=cn_id,
                            error=code,
                        )

    def _collect_core_network_via_owner(
        self,
        cn_id: str,
        owner_account: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Assume into the owner account to get core network details."""
        try:
            session = get_session_for_account(owner_account)
            owner_nm = session.client(
                "networkmanager", "us-west-2",
                config=BOTO_CONFIG,
                verify=settings.aws.ssl_verify,
            )
            detail = owner_nm.get_core_network(
                CoreNetworkId=cn_id,
            )["CoreNetwork"]
            self._process_core_network(
                detail, owner_nm, nodes, edges,
            )
            # list_attachments requires the owner account session —
            # calling it from the crawl account returns empty results.
            self._collect_attachments(
                owner_nm, nodes, edges,
                core_network_id=cn_id,
                cn_owner_id=owner_account,
            )
            logger.info(
                "core_network_collected_via_owner",
                core_network_id=cn_id,
                owner_account=owner_account,
            )
        except ClientError as e:
            logger.warning(
                "core_network_owner_failed",
                core_network_id=cn_id,
                owner_account=owner_account,
                error=e.response["Error"]["Code"],
            )

    def _process_core_network(
        self,
        cn: dict,
        nm,  # noqa: ANN001
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single Core Network and its segments."""
        cn_id = cn["CoreNetworkId"]
        arn = cn.get(
            "CoreNetworkArn",
            f"arn:aws:networkmanager::{self.account_id}"
            f":core-network/{cn_id}",
        )
        tags = _parse_tags(cn.get("Tags"))

        segments = cn.get("Segments", [])
        edge_locations = cn.get("Edges", [])

        nodes.append(ResourceNode(
            arn=arn,
            name=_tag_name(tags, cn_id),
            label=NodeLabel.CLOUDWAN_CORE_NETWORK,
            account_id=self.account_id,
            region="global",
            tags=tags,
            properties={
                "core_network_id": cn_id,
                "state": cn.get("State", ""),
                "global_network_id": cn.get(
                    "GlobalNetworkId", "",
                ),
                "segment_count": len(segments),
                "edge_location_count": len(
                    edge_locations,
                ),
                "edge_locations": [
                    e.get("EdgeLocation", "")
                    for e in edge_locations
                ],
            },
        ))

        for seg in segments:
            self._process_segment(
                seg, cn_id, arn, nodes, edges,
            )

        # Fetch policy and delegate to cloudwan_policy module
        policy_edges = self._fetch_and_process_policy(
            nm, cn_id, arn, nodes,
        )
        if policy_edges is not None:
            edges.extend(policy_edges)
        else:
            self._fallback_shared_segments(
                segments, cn_id, edges,
            )

    def _process_segment(
        self,
        seg: dict,
        cn_id: str,
        cn_arn: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single CloudWAN segment."""
        seg_name = seg.get("Name", "unknown")
        seg_arn = (
            f"arn:aws:networkmanager::{self.account_id}"
            f":core-network/{cn_id}/segment/{seg_name}"
        )

        shared_segments = seg.get("SharedSegments", [])

        nodes.append(ResourceNode(
            arn=seg_arn,
            name=seg_name,
            label=NodeLabel.CLOUDWAN_SEGMENT,
            account_id=self.account_id,
            region="global",
            properties={
                "core_network_id": cn_id,
                "edge_locations": seg.get(
                    "EdgeLocations", [],
                ),
                "shared_segments": shared_segments,
                "isolate_attachments": seg.get(
                    "IsolateAttachments", False,
                ),
                "require_attachment_acceptance": seg.get(
                    "RequireAttachmentAcceptance", False,
                ),
            },
        ))

        edges.append(ResourceEdge(
            source_arn=cn_arn,
            target_arn=seg_arn,
            relationship=RelationshipType.HAS_SEGMENT,
        ))

    def _fetch_and_process_policy(
        self,
        nm,  # noqa: ANN001
        cn_id: str,
        cn_arn: str,
        nodes: list[ResourceNode],
    ) -> list[ResourceEdge] | None:
        """Fetch core network policy and extract edges.

        Returns list of edges on success, None on failure
        (caller should fall back to SharedSegments).
        """
        try:
            resp = nm.get_core_network_policy(
                CoreNetworkId=cn_id,
            )
            doc_str = resp["CoreNetworkPolicy"]["PolicyDocument"]
            doc = (
                json.loads(doc_str)
                if isinstance(doc_str, str) else doc_str
            )
            return process_policy(
                doc, cn_id, cn_arn,
                self.account_id, nodes,
            )
        except ClientError as e:
            logger.warning(
                "core_network_policy_fetch_failed",
                core_network_id=cn_id,
                error=e.response["Error"]["Code"],
            )
            return None
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(
                "core_network_policy_parse_failed",
                core_network_id=cn_id,
                error=str(e),
            )
            return None

    def _fallback_shared_segments(
        self,
        segments: list[dict],
        cn_id: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Create CONNECTS_TO edges from SharedSegments (fallback)."""
        for seg in segments:
            seg_name = seg.get("Name", "unknown")
            seg_arn = (
                f"arn:aws:networkmanager::"
                f"{self.account_id}"
                f":core-network/{cn_id}"
                f"/segment/{seg_name}"
            )
            for shared in seg.get("SharedSegments", []):
                shared_arn = (
                    f"arn:aws:networkmanager::"
                    f"{self.account_id}"
                    f":core-network/{cn_id}"
                    f"/segment/{shared}"
                )
                edges.append(ResourceEdge(
                    source_arn=seg_arn,
                    target_arn=shared_arn,
                    relationship=(
                        RelationshipType.CONNECTS_TO
                    ),
                    properties={
                        "type": "shared_segment",
                    },
                ))

    def _collect_attachments(
        self,
        nm,  # noqa: ANN001
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
        core_network_id: str = "",
        cn_owner_id: str = "",
    ) -> None:
        """Collect CloudWAN attachments (VPC, TGW, etc.).

        When core_network_id is provided, scopes the query to that
        core network — required when nm is an owner-account session
        since list_attachments only returns results for accessible
        core networks.
        """
        paginator = nm.get_paginator("list_attachments")
        params: dict = {}
        if core_network_id:
            params["CoreNetworkId"] = core_network_id
        for page in paginator.paginate(**params):
            for att in page.get("Attachments", []):
                self._process_attachment(
                    att, nodes, edges, cn_owner_id=cn_owner_id,
                )

    def _process_attachment(
        self,
        att: dict,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
        cn_owner_id: str = "",
    ) -> None:
        """Process a single CloudWAN attachment."""
        att_id = att["AttachmentId"]
        cn_id = att.get("CoreNetworkId", "")
        resource_arn = att.get("ResourceArn", "")
        att_type = att.get("AttachmentType", "")
        segment = att.get("SegmentName", "")
        owner_id = att.get(
            "OwnerAccountId", self.account_id,
        )
        # cn_owner_id is the core network owner (may differ from
        # attachment owner); used for core-network / segment ARNs.
        # Fall back to self.account_id when called from the direct
        # (non-owner-assume) path so existing ARN format is preserved.
        cn_account = cn_owner_id or self.account_id
        edge_location = att.get("EdgeLocation", "")
        tags = _parse_tags(att.get("Tags"))

        arn = (
            f"arn:aws:networkmanager::{owner_id}"
            f":attachment/{att_id}"
        )

        nodes.append(ResourceNode(
            arn=arn,
            name=_tag_name(tags, att_id),
            label=NodeLabel.CLOUDWAN_ATTACHMENT,
            account_id=owner_id,
            region=edge_location or "global",
            tags=tags,
            properties={
                "attachment_id": att_id,
                "attachment_type": att_type,
                "core_network_id": cn_id,
                "resource_arn": resource_arn,
                "segment_name": segment,
                "edge_location": edge_location,
                "state": att.get("State", ""),
                "owner_account_id": owner_id,
            },
        ))

        if cn_id:
            cn_arn = (
                f"arn:aws:networkmanager::"
                f"{cn_account}"
                f":core-network/{cn_id}"
            )
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=cn_arn,
                relationship=RelationshipType.ATTACHED_TO,
                properties={
                    "attachment_type": att_type,
                    "segment": segment,
                },
            ))

        if cn_id and segment:
            seg_arn = (
                f"arn:aws:networkmanager::"
                f"{cn_account}"
                f":core-network/{cn_id}"
                f"/segment/{segment}"
            )
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=seg_arn,
                relationship=RelationshipType.PART_OF,
                properties={
                    "attachment_type": att_type,
                },
            ))

        if resource_arn:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=resource_arn,
                relationship=RelationshipType.ATTACHED_TO,
                properties={
                    "attachment_type": att_type,
                    "direction": "resource",
                },
            ))
