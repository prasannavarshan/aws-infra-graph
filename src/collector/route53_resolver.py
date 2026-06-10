"""Route53 Resolver collector — endpoints, rules, and VPC associations."""

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


class Route53ResolverCollector(BaseCollector):
    """Collects Route53 Resolver endpoints and forwarding rules.

    Captures:
    - Resolver endpoints (inbound/outbound) with IPs
    - Forwarding rules with target IPs
    - Rule-to-VPC associations
    - Endpoint-to-VPC and endpoint-to-SG edges
    """

    def collect_in_region(
        self, region: str,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect resolver resources in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("route53resolver", region)
            self._collect_endpoints(
                client, region, nodes, edges,
            )
            self._collect_rules(
                client, region, nodes, edges,
            )
        except ClientError as e:
            logger.error(
                "route53_resolver_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _collect_endpoints(
        self,
        client,  # noqa: ANN001
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect resolver endpoints (inbound/outbound)."""
        paginator = client.get_paginator(
            "list_resolver_endpoints",
        )
        for page in paginator.paginate():
            for ep in page.get("ResolverEndpoints", []):
                self._process_endpoint(
                    client, ep, region, nodes, edges,
                )

    def _process_endpoint(
        self,
        client,  # noqa: ANN001
        ep: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single resolver endpoint."""
        ep_id = ep["Id"]
        arn = ep["Arn"]
        vpc_id = ep.get("HostVPCId", "")
        direction = ep.get("Direction", "")
        tags = self._get_tags(client, arn)

        # Get IP addresses for the endpoint
        ip_addresses = self._get_endpoint_ips(
            client, ep_id,
        )

        nodes.append(ResourceNode(
            arn=arn,
            name=ep.get("Name") or _tag_name(tags) or ep_id,
            label=NodeLabel.RESOLVER_ENDPOINT,
            account_id=self.account_id,
            region=region,
            tags=tags,
            properties={
                "endpoint_id": ep_id,
                "direction": direction,
                "status": ep.get("Status", ""),
                "vpc_id": vpc_id,
                "ip_address_count": ep.get(
                    "IpAddressCount", 0,
                ),
                "ip_addresses": ip_addresses,
                "security_group_ids": ep.get(
                    "SecurityGroupIds", [],
                ),
            },
        ))

        # PART_OF -> VPC
        if vpc_id:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=self._vpc_arn(region, vpc_id),
                relationship=RelationshipType.PART_OF,
            ))

        # HAS_SG -> SecurityGroup
        for sg_id in ep.get("SecurityGroupIds", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=self._sg_arn(region, sg_id),
                relationship=RelationshipType.HAS_SG,
            ))

    def _get_endpoint_ips(
        self,
        client,  # noqa: ANN001
        endpoint_id: str,
    ) -> list[str]:
        """Get IP addresses assigned to a resolver endpoint."""
        ips: list[str] = []
        try:
            paginator = client.get_paginator(
                "list_resolver_endpoint_ip_addresses",
            )
            for page in paginator.paginate(
                ResolverEndpointId=endpoint_id,
            ):
                for ip_info in page.get("IpAddresses", []):
                    ip = ip_info.get("Ip", "")
                    if ip:
                        ips.append(ip)
        except ClientError as e:
            logger.warning(
                "resolver_endpoint_ips_failed",
                endpoint_id=endpoint_id,
                error_code=e.response["Error"]["Code"],
            )
        return ips

    def _collect_rules(
        self,
        client,  # noqa: ANN001
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect resolver forwarding rules."""
        paginator = client.get_paginator(
            "list_resolver_rules",
        )
        for page in paginator.paginate():
            for rule in page.get("ResolverRules", []):
                self._process_rule(
                    client, rule, region, nodes, edges,
                )

    def _process_rule(
        self,
        client,  # noqa: ANN001
        rule: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single resolver rule."""
        rule_id = rule["Id"]
        arn = rule["Arn"]
        tags = self._get_tags(client, arn)

        # Target IPs for FORWARD rules
        target_ips = [
            t.get("Ip", "")
            for t in rule.get("TargetIps", [])
            if t.get("Ip")
        ]
        target_ports = [
            t.get("Port", 53)
            for t in rule.get("TargetIps", [])
        ]

        nodes.append(ResourceNode(
            arn=arn,
            name=rule.get("Name") or _tag_name(tags) or rule_id,
            label=NodeLabel.RESOLVER_RULE,
            account_id=self.account_id,
            region=region,
            tags=tags,
            properties={
                "rule_id": rule_id,
                "rule_type": rule.get("RuleType", ""),
                "domain_name": rule.get("DomainName", ""),
                "status": rule.get("Status", ""),
                "target_ips": target_ips,
                "target_ports": target_ports,
                "resolver_endpoint_id": rule.get(
                    "ResolverEndpointId", "",
                ),
                "owner_id": rule.get("OwnerId", ""),
                "share_status": rule.get(
                    "ShareStatus", "",
                ),
            },
        ))

        # Link rule -> endpoint (if FORWARD type)
        ep_id = rule.get("ResolverEndpointId", "")
        if ep_id:
            ep_arn = (
                f"arn:aws:route53resolver:{region}"
                f":{self.account_id}"
                f":resolver-endpoint/{ep_id}"
            )
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=ep_arn,
                relationship=RelationshipType.ROUTES_TO,
            ))

        # Collect VPC associations for this rule
        self._collect_rule_associations(
            client, rule_id, arn, region, edges,
        )

    def _collect_rule_associations(
        self,
        client,  # noqa: ANN001
        rule_id: str,
        rule_arn: str,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Collect VPC associations for a resolver rule."""
        try:
            paginator = client.get_paginator(
                "list_resolver_rule_associations",
            )
            for page in paginator.paginate(
                Filters=[{
                    "Name": "ResolverRuleId",
                    "Values": [rule_id],
                }],
            ):
                for assoc in page.get(
                    "ResolverRuleAssociations", [],
                ):
                    vpc_id = assoc.get("VPCId", "")
                    status = assoc.get("Status", "")
                    if vpc_id and status == "COMPLETE":
                        edges.append(ResourceEdge(
                            source_arn=rule_arn,
                            target_arn=self._vpc_arn(
                                region, vpc_id,
                            ),
                            relationship=(
                                RelationshipType
                                .ASSOCIATED_WITH
                            ),
                            properties={
                                "vpc_id": vpc_id,
                                "status": status,
                            },
                        ))
        except ClientError as e:
            logger.warning(
                "resolver_rule_associations_failed",
                rule_id=rule_id,
                error_code=e.response["Error"]["Code"],
            )

    def _get_tags(
        self,
        client,  # noqa: ANN001
        arn: str,
    ) -> dict[str, str]:
        """Get tags for a resolver resource."""
        try:
            resp = client.list_tags_for_resource(
                ResourceArn=arn,
            )
            return _parse_tags(resp.get("Tags"))
        except ClientError:
            return {}

    def _vpc_arn(self, region: str, vpc_id: str) -> str:
        return (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":vpc/{vpc_id}"
        )

    def _sg_arn(self, region: str, sg_id: str) -> str:
        return (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":security-group/{sg_id}"
        )
