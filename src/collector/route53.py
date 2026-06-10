"""Route53 collector — Hosted Zones and DNS Records."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class Route53Collector(BaseCollector):
    """Collects Route53 Hosted Zones and Records.

    Route53 is global — overrides collect() to avoid region iteration.
    """

    def collect(self) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect all hosted zones and their records."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("route53", "us-east-1")
            self._collect_zones(client, nodes, edges)
        except ClientError as e:
            logger.error(
                "route53_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

        logger.info(
            "route53_collected",
            account_id=self.account_id,
            nodes=len(nodes),
        )
        return nodes, edges

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Not used — Route53 is a global service."""
        return [], []

    def _collect_zones(
        self,
        client,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect hosted zones and their records."""
        try:
            paginator = client.get_paginator("list_hosted_zones")
            for page in paginator.paginate():
                for zone in page["HostedZones"]:
                    self._process_zone(client, zone, nodes, edges)
        except ClientError as e:
            logger.error(
                "route53_zones_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

    def _vpc_arn(self, region: str, vpc_id: str) -> str:
        return (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":vpc/{vpc_id}"
        )

    def _process_zone(
        self,
        client,
        zone: dict,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single hosted zone and its records."""
        zone_id = zone["Id"].split("/")[-1]
        zone_arn = (
            f"arn:aws:route53:::hostedzone/{zone_id}"
        )
        is_private = zone.get("Config", {}).get(
            "PrivateZone", False
        )

        vpc_associations: list[str] = []
        if is_private:
            vpc_associations = self._get_vpc_associations(
                client, zone_id, zone_arn, edges,
            )

        nodes.append(ResourceNode(
            arn=zone_arn,
            name=zone.get("Name", ""),
            label=NodeLabel.ROUTE53_ZONE,
            account_id=self.account_id,
            region="global",
            properties={
                "zone_id": zone_id,
                "is_private": is_private,
                "record_count": zone.get(
                    "ResourceRecordSetCount", 0
                ),
                "vpc_associations": vpc_associations,
            },
        ))

        self._collect_records(
            client, zone_id, zone_arn, nodes, edges,
        )

    def _get_vpc_associations(
        self,
        client,
        zone_id: str,
        zone_arn: str,
        edges: list[ResourceEdge],
    ) -> list[str]:
        """Fetch VPC associations for a private hosted zone.

        Returns:
            List of 'vpc_id (region)' strings for the zone
            properties.
        """
        vpc_list: list[str] = []
        try:
            resp = client.get_hosted_zone(Id=zone_id)
            vpcs = resp.get("VPCs", [])
            for vpc in vpcs:
                vpc_id = vpc.get("VPCId", "")
                vpc_region = vpc.get("VPCRegion", "")
                if not vpc_id:
                    continue
                vpc_list.append(f"{vpc_id} ({vpc_region})")
                edges.append(ResourceEdge(
                    source_arn=zone_arn,
                    target_arn=self._vpc_arn(
                        vpc_region, vpc_id,
                    ),
                    relationship=(
                        RelationshipType.ASSOCIATED_WITH
                    ),
                    properties={
                        "vpc_id": vpc_id,
                        "vpc_region": vpc_region,
                    },
                ))
        except ClientError as e:
            logger.warning(
                "route53_vpc_association_failed",
                zone_id=zone_id,
                error_code=e.response["Error"]["Code"],
            )
        return vpc_list

    def _collect_records(
        self,
        client,
        zone_id: str,
        zone_arn: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect DNS records in a hosted zone."""
        try:
            paginator = client.get_paginator(
                "list_resource_record_sets"
            )
            for page in paginator.paginate(HostedZoneId=zone_id):
                for record in page["ResourceRecordSets"]:
                    self._process_record(
                        record, zone_id, zone_arn, nodes, edges
                    )
        except ClientError as e:
            logger.warning(
                "route53_records_failed",
                zone_id=zone_id,
                error_code=e.response["Error"]["Code"],
            )

    def _process_record(
        self,
        record: dict,
        zone_id: str,
        zone_arn: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single DNS record."""
        record_name = record.get("Name", "")
        record_type = record.get("Type", "")
        record_arn = (
            f"arn:aws:route53:::hostedzone/{zone_id}"
            f"/record/{record_name}/{record_type}"
        )

        values = [
            rr.get("Value", "")
            for rr in record.get("ResourceRecords", [])
        ]
        alias = record.get("AliasTarget", {})

        nodes.append(ResourceNode(
            arn=record_arn,
            name=record_name,
            label=NodeLabel.ROUTE53_RECORD,
            account_id=self.account_id,
            region="global",
            properties={
                "record_type": record_type,
                "ttl": record.get("TTL", 0),
                "values": values,
                "alias_target": alias.get("DNSName", ""),
                "alias_zone_id": alias.get("HostedZoneId", ""),
            },
        ))

        # Record PART_OF Zone
        edges.append(ResourceEdge(
            source_arn=record_arn,
            target_arn=zone_arn,
            relationship=RelationshipType.PART_OF,
        ))
