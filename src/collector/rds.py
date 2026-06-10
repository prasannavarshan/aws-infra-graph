"""RDS collector — RDS instances with subnet and security group relationships."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class RDSCollector(BaseCollector):
    """Collects RDS database instances."""

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect RDS instances in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            rds = self.client("rds", region)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    self._process_instance(db, region, nodes, edges)
        except ClientError as e:
            logger.error(
                "rds_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _process_instance(
        self,
        db: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single RDS instance into nodes and edges."""
        arn = db["DBInstanceArn"]
        name = db.get("DBInstanceIdentifier", "")

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.RDS_INSTANCE,
            account_id=self.account_id,
            region=region,
            properties={
                "db_instance_id": name,
                "engine": db.get("Engine", ""),
                "engine_version": db.get("EngineVersion", ""),
                "instance_class": db.get("DBInstanceClass", ""),
                "multi_az": db.get("MultiAZ", False),
                "storage_type": db.get("StorageType", ""),
                "allocated_storage": db.get("AllocatedStorage", 0),
                "endpoint": db.get("Endpoint", {}).get("Address", ""),
                "port": db.get("Endpoint", {}).get("Port", 0),
                "publicly_accessible": db.get(
                    "PubliclyAccessible", False
                ),
                "storage_encrypted": db.get("StorageEncrypted", False),
            },
        ))

        self._add_sg_edges(db, arn, region, edges)
        self._add_subnet_edges(db, arn, region, edges)

    def _add_sg_edges(
        self,
        db: dict,
        arn: str,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Create HAS_SG edges for VPC security groups."""
        for sg in db.get("VpcSecurityGroups", []):
            sg_id = sg.get("VpcSecurityGroupId")
            if sg_id:
                edges.append(ResourceEdge(
                    source_arn=arn,
                    target_arn=(
                        f"arn:aws:ec2:{region}:{self.account_id}"
                        f":security-group/{sg_id}"
                    ),
                    relationship=RelationshipType.HAS_SG,
                ))

    def _add_subnet_edges(
        self,
        db: dict,
        arn: str,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Create RUNS_IN edges for DB subnet group subnets."""
        subnet_group = db.get("DBSubnetGroup", {})
        for subnet in subnet_group.get("Subnets", []):
            subnet_id = subnet.get("SubnetIdentifier")
            if subnet_id:
                edges.append(ResourceEdge(
                    source_arn=arn,
                    target_arn=(
                        f"arn:aws:ec2:{region}:{self.account_id}"
                        f":subnet/{subnet_id}"
                    ),
                    relationship=RelationshipType.RUNS_IN,
                ))
