"""Lambda collector — Lambda functions with role and VPC relationships."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class LambdaCollector(BaseCollector):
    """Collects Lambda functions."""

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect Lambda functions in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("lambda", region)
            paginator = client.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    self._process_function(fn, region, nodes, edges)
        except ClientError as e:
            logger.error(
                "lambda_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _process_function(
        self,
        fn: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single Lambda function into nodes and edges."""
        arn = fn["FunctionArn"]

        nodes.append(ResourceNode(
            arn=arn,
            name=fn["FunctionName"],
            label=NodeLabel.LAMBDA_FUNCTION,
            account_id=self.account_id,
            region=region,
            properties={
                "runtime": fn.get("Runtime", ""),
                "handler": fn.get("Handler", ""),
                "memory_size": fn.get("MemorySize", 128),
                "timeout": fn.get("Timeout", 3),
                "code_size": fn.get("CodeSize", 0),
                "last_modified": fn.get("LastModified", ""),
                "package_type": fn.get("PackageType", "Zip"),
                "architectures": fn.get("Architectures", ["x86_64"]),
            },
        ))

        # HAS_ROLE edge
        role_arn = fn.get("Role")
        if role_arn:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=role_arn,
                relationship=RelationshipType.HAS_ROLE,
            ))

        # VPC security groups
        vpc_config = fn.get("VpcConfig", {})
        for sg_id in vpc_config.get("SecurityGroupIds", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:ec2:{region}:{self.account_id}"
                    f":security-group/{sg_id}"
                ),
                relationship=RelationshipType.HAS_SG,
            ))

        # VPC subnets
        for subnet_id in vpc_config.get("SubnetIds", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:ec2:{region}:{self.account_id}"
                    f":subnet/{subnet_id}"
                ),
                relationship=RelationshipType.RUNS_IN,
            ))
