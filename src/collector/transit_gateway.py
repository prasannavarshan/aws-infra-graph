"""Transit Gateway collector — TGWs, attachments, and route tables."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
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


def _summarize_tgw_routes(routes: list[dict]) -> str:
    """Summarize TGW routes into a compact string.

    Format: '10.0.0.0/8 -> tgw-attach-xxx; 10.150.0.0/16 -> tgw-attach-yyy'
    Skips blackhole routes.
    """
    parts = []
    for route in routes:
        dest = route.get("DestinationCidrBlock", "")
        if not dest:
            continue
        attachments = route.get("TransitGatewayAttachments", [])
        if attachments:
            target = attachments[0].get(
                "TransitGatewayAttachmentId", "blackhole",
            )
        else:
            target = "blackhole"
        parts.append(f"{dest} -> {target}")
    return "; ".join(parts) if parts else "none"


class TransitGatewayCollector(BaseCollector):
    """Collects Transit Gateways, attachments, and route tables."""

    def collect_in_region(
        self, region: str,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect TGW resources in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            ec2 = self.client("ec2", region)
            self._collect_tgws(ec2, region, nodes, edges)
            self._collect_attachments(ec2, region, nodes, edges)
            self._collect_route_tables(ec2, region, nodes, edges)
        except ClientError as e:
            logger.error(
                "tgw_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _collect_tgws(
        self,
        ec2,  # noqa: ANN001
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect Transit Gateways."""
        paginator = ec2.get_paginator(
            "describe_transit_gateways",
        )
        for page in paginator.paginate():
            for tgw in page.get("TransitGateways", []):
                self._process_tgw(tgw, region, nodes, edges)

    def _process_tgw(
        self,
        tgw: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single Transit Gateway."""
        tgw_id = tgw["TransitGatewayId"]
        arn = tgw.get(
            "TransitGatewayArn",
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":transit-gateway/{tgw_id}",
        )
        tags = _parse_tags(tgw.get("Tags"))

        nodes.append(ResourceNode(
            arn=arn,
            name=_tag_name(tags, tgw_id),
            label=NodeLabel.TRANSIT_GATEWAY,
            account_id=tgw.get(
                "OwnerId", self.account_id,
            ),
            region=region,
            tags=tags,
            properties={
                "tgw_id": tgw_id,
                "state": tgw.get("State", ""),
                "owner_id": tgw.get(
                    "OwnerId", self.account_id,
                ),
                "amazon_side_asn": tgw.get(
                    "Options", {},
                ).get("AmazonSideAsn", 0),
                "auto_accept_shared": tgw.get(
                    "Options", {},
                ).get(
                    "AutoAcceptSharedAttachments", "",
                ),
                "default_route_table_association": tgw.get(
                    "Options", {},
                ).get(
                    "DefaultRouteTableAssociation", "",
                ),
                "default_route_table_propagation": tgw.get(
                    "Options", {},
                ).get(
                    "DefaultRouteTablePropagation", "",
                ),
            },
        ))

        # BELONGS_TO edge to owner account
        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=(
                f"arn:aws:organizations::"
                f"{tgw.get('OwnerId', self.account_id)}"
                f":account/{tgw.get('OwnerId', self.account_id)}"
            ),
            relationship=RelationshipType.BELONGS_TO,
        ))

    def _collect_attachments(
        self,
        ec2,  # noqa: ANN001
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect TGW attachments (VPC, peering, connect)."""
        paginator = ec2.get_paginator(
            "describe_transit_gateway_attachments",
        )
        for page in paginator.paginate():
            for att in page.get(
                "TransitGatewayAttachments", [],
            ):
                self._process_attachment(
                    att, region, nodes, edges,
                )

    def _process_attachment(
        self,
        att: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single TGW attachment."""
        att_id = att["TransitGatewayAttachmentId"]
        tgw_id = att.get("TransitGatewayId", "")
        tgw_owner = att.get(
            "TransitGatewayOwnerId", self.account_id,
        )
        resource_id = att.get("ResourceId", "")
        resource_type = att.get("ResourceType", "")
        resource_owner = att.get(
            "ResourceOwnerId", self.account_id,
        )
        tags = _parse_tags(att.get("Tags"))

        arn = (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":transit-gateway-attachment/{att_id}"
        )

        nodes.append(ResourceNode(
            arn=arn,
            name=_tag_name(tags, att_id),
            label=NodeLabel.TGW_ATTACHMENT,
            account_id=resource_owner,
            region=region,
            tags=tags,
            properties={
                "attachment_id": att_id,
                "tgw_id": tgw_id,
                "tgw_owner_id": tgw_owner,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "resource_owner_id": resource_owner,
                "state": att.get("State", ""),
                "association_state": att.get(
                    "Association", {},
                ).get("State", ""),
                "association_route_table_id": att.get(
                    "Association", {},
                ).get(
                    "TransitGatewayRouteTableId", "",
                ),
            },
        ))

        # ATTACHED_TO edge → TGW (use TGW owner account)
        if tgw_id:
            tgw_arn = (
                f"arn:aws:ec2:{region}:{tgw_owner}"
                f":transit-gateway/{tgw_id}"
            )
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=tgw_arn,
                relationship=RelationshipType.ATTACHED_TO,
                properties={
                    "resource_type": resource_type,
                },
            ))

        # ATTACHED_TO edge → VPC (use resource owner account)
        if resource_type == "vpc" and resource_id:
            vpc_arn = (
                f"arn:aws:ec2:{region}:{resource_owner}"
                f":vpc/{resource_id}"
            )
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=vpc_arn,
                relationship=RelationshipType.ATTACHED_TO,
                properties={
                    "resource_type": "vpc",
                },
            ))

        # PEERS_WITH for peering attachments
        if resource_type == "peering" and resource_id:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:ec2:{region}:{tgw_owner}"
                    f":transit-gateway/{resource_id}"
                ),
                relationship=RelationshipType.PEERS_WITH,
            ))

    def _collect_route_tables(
        self,
        ec2,  # noqa: ANN001
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect TGW route tables."""
        paginator = ec2.get_paginator(
            "describe_transit_gateway_route_tables",
        )
        for page in paginator.paginate():
            for rt in page.get(
                "TransitGatewayRouteTables", [],
            ):
                self._process_route_table(
                    ec2, rt, region, nodes, edges,
                )

    def _process_route_table(
        self,
        ec2,  # noqa: ANN001
        rt: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single TGW route table."""
        rt_id = rt["TransitGatewayRouteTableId"]
        tgw_id = rt.get("TransitGatewayId", "")
        tags = _parse_tags(rt.get("Tags"))

        arn = (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":transit-gateway-route-table/{rt_id}"
        )

        # Fetch active routes for this TGW route table
        try:
            routes_resp = ec2.search_transit_gateway_routes(
                TransitGatewayRouteTableId=rt_id,
                Filters=[
                    {"Name": "state", "Values": ["active"]},
                ],
            )
            tgw_routes = routes_resp.get("Routes", [])
        except ClientError as e:
            logger.warning(
                "tgw_route_search_failed",
                route_table_id=rt_id,
                error_code=e.response["Error"]["Code"],
            )
            tgw_routes = []

        nodes.append(ResourceNode(
            arn=arn,
            name=_tag_name(tags, rt_id),
            label=NodeLabel.TGW_ROUTE_TABLE,
            account_id=self.account_id,
            region=region,
            tags=tags,
            properties={
                "route_table_id": rt_id,
                "tgw_id": tgw_id,
                "state": rt.get("State", ""),
                "default_association": rt.get(
                    "DefaultAssociationRouteTable", False,
                ),
                "default_propagation": rt.get(
                    "DefaultPropagationRouteTable", False,
                ),
                "routes": _summarize_tgw_routes(tgw_routes),
            },
        ))

        # PART_OF edge → TGW
        if tgw_id:
            tgw_arn = (
                f"arn:aws:ec2:{region}:{self.account_id}"
                f":transit-gateway/{tgw_id}"
            )
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=tgw_arn,
                relationship=RelationshipType.PART_OF,
            ))
