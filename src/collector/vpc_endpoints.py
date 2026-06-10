"""VPC Endpoints collector — Interface and Gateway endpoints."""

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


def _tag_name(tags: dict[str, str]) -> str:
    """Extract the Name tag, falling back to empty string."""
    return tags.get("Name", "")


class VPCEndpointsCollector(BaseCollector):
    """Collects VPC Endpoints (Interface and Gateway)."""

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect VPC endpoints in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            ec2 = self.client("ec2", region)
            paginator = ec2.get_paginator(
                "describe_vpc_endpoints",
            )
            for page in paginator.paginate():
                for ep in page.get("VpcEndpoints", []):
                    self._process_endpoint(
                        ep, region, nodes, edges,
                    )
        except ClientError as e:
            logger.error(
                "vpc_endpoints_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _endpoint_arn(
        self, region: str, endpoint_id: str,
    ) -> str:
        return (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":vpc-endpoint/{endpoint_id}"
        )

    def _vpc_arn(self, region: str, vpc_id: str) -> str:
        return (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":vpc/{vpc_id}"
        )

    def _process_endpoint(
        self,
        ep: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single VPC endpoint."""
        endpoint_id = ep["VpcEndpointId"]
        arn = self._endpoint_arn(region, endpoint_id)
        tags = _parse_tags(ep.get("Tags"))
        service_name = ep.get("ServiceName", "")
        vpc_id = ep.get("VpcId", "")

        nodes.append(ResourceNode(
            arn=arn,
            name=_tag_name(tags) or endpoint_id,
            label=NodeLabel.VPC_ENDPOINT,
            account_id=self.account_id,
            region=region,
            tags=tags,
            properties={
                "endpoint_id": endpoint_id,
                "service_name": service_name,
                "endpoint_type": ep.get(
                    "VpcEndpointType", "",
                ),
                "state": ep.get("State", ""),
                "vpc_id": vpc_id,
                "policy_document": ep.get(
                    "PolicyDocument", "",
                ),
                "private_dns_enabled": ep.get(
                    "PrivateDnsEnabled", False,
                ),
                "route_table_ids": ep.get(
                    "RouteTableIds", [],
                ),
                "subnet_ids": ep.get("SubnetIds", []),
                "network_interface_ids": ep.get(
                    "NetworkInterfaceIds", [],
                ),
            },
        ))

        # PART_OF edge to VPC
        if vpc_id:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=self._vpc_arn(region, vpc_id),
                relationship=RelationshipType.PART_OF,
            ))

        # CONNECTS_TO edge encoding the service
        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=(
                f"arn:aws:ec2:{region}:{self.account_id}"
                f":vpc-endpoint-service/{service_name}"
            ),
            relationship=RelationshipType.CONNECTS_TO,
            properties={"service_name": service_name},
        ))

        # HAS_SG edges for interface endpoints
        for sg_id in ep.get("Groups", []):
            group_id = sg_id.get("GroupId", "")
            if group_id:
                edges.append(ResourceEdge(
                    source_arn=arn,
                    target_arn=(
                        f"arn:aws:ec2:{region}"
                        f":{self.account_id}"
                        f":security-group/{group_id}"
                    ),
                    relationship=RelationshipType.HAS_SG,
                ))
