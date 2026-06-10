"""ELB collector — Application and Network Load Balancers with Target Groups."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class ELBCollector(BaseCollector):
    """Collects ALBs, NLBs, and their Target Groups."""

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect load balancers and target groups in a region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        client = self.client("elbv2", region)
        self._collect_load_balancers(client, region, nodes, edges)
        self._collect_target_groups(client, region, nodes, edges)

        return nodes, edges

    def _collect_load_balancers(
        self,
        client,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect ALBs and NLBs."""
        try:
            paginator = client.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    self._process_lb(lb, region, nodes, edges)
        except ClientError as e:
            logger.error(
                "elb_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _process_lb(
        self,
        lb: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single load balancer."""
        arn = lb["LoadBalancerArn"]
        nodes.append(ResourceNode(
            arn=arn,
            name=lb.get("LoadBalancerName", ""),
            label=NodeLabel.LOAD_BALANCER,
            account_id=self.account_id,
            region=region,
            properties={
                "dns_name": lb.get("DNSName", ""),
                "scheme": lb.get("Scheme", ""),
                "lb_type": lb.get("Type", ""),
                "state": lb.get("State", {}).get("Code", ""),
                "vpc_id": lb.get("VpcId", ""),
            },
        ))

        # LB PART_OF VPC
        vpc_id = lb.get("VpcId")
        if vpc_id:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:ec2:{region}:{self.account_id}"
                    f":vpc/{vpc_id}"
                ),
                relationship=RelationshipType.PART_OF,
            ))

        # LB HAS_SG for each security group
        for sg_id in lb.get("SecurityGroups", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:ec2:{region}:{self.account_id}"
                    f":security-group/{sg_id}"
                ),
                relationship=RelationshipType.HAS_SG,
            ))

        # LB RUNS_IN each AZ subnet
        for az in lb.get("AvailabilityZones", []):
            subnet_id = az.get("SubnetId")
            if subnet_id:
                edges.append(ResourceEdge(
                    source_arn=arn,
                    target_arn=(
                        f"arn:aws:ec2:{region}:{self.account_id}"
                        f":subnet/{subnet_id}"
                    ),
                    relationship=RelationshipType.RUNS_IN,
                ))

    def _collect_target_groups(
        self,
        client,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect Target Groups and link to LBs."""
        try:
            paginator = client.get_paginator("describe_target_groups")
            for page in paginator.paginate():
                for tg in page["TargetGroups"]:
                    self._process_target_group(
                        client, tg, region, nodes, edges
                    )
        except ClientError as e:
            logger.error(
                "target_group_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _process_target_group(
        self,
        client,
        tg: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single target group with LB and target edges."""
        tg_arn = tg["TargetGroupArn"]
        nodes.append(ResourceNode(
            arn=tg_arn,
            name=tg.get("TargetGroupName", ""),
            label=NodeLabel.TARGET_GROUP,
            account_id=self.account_id,
            region=region,
            properties={
                "protocol": tg.get("Protocol", ""),
                "port": tg.get("Port", 0),
                "target_type": tg.get("TargetType", ""),
                "vpc_id": tg.get("VpcId", ""),
                "health_check_protocol": tg.get(
                    "HealthCheckProtocol", ""
                ),
                "health_check_path": tg.get("HealthCheckPath", ""),
            },
        ))

        # TARGETS edges from each associated LB
        for lb_arn in tg.get("LoadBalancerArns", []):
            edges.append(ResourceEdge(
                source_arn=lb_arn,
                target_arn=tg_arn,
                relationship=RelationshipType.TARGETS,
            ))

        # ROUTES_TO edges to registered targets (instances/IPs)
        self._collect_tg_targets(client, tg_arn, region, edges)

    def _collect_tg_targets(
        self,
        client,
        tg_arn: str,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Collect targets registered in a target group."""
        try:
            resp = client.describe_target_health(TargetGroupArn=tg_arn)
            for desc in resp.get("TargetHealthDescriptions", []):
                target_id = desc.get("Target", {}).get("Id", "")
                if target_id.startswith("i-"):
                    edges.append(ResourceEdge(
                        source_arn=tg_arn,
                        target_arn=(
                            f"arn:aws:ec2:{region}:{self.account_id}"
                            f":instance/{target_id}"
                        ),
                        relationship=RelationshipType.ROUTES_TO,
                    ))
        except ClientError as e:
            logger.warning(
                "tg_targets_failed",
                tg_arn=tg_arn,
                error_code=e.response["Error"]["Code"],
            )
