"""ECS collector — Clusters and Services."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class ECSCollector(BaseCollector):
    """Collects ECS Clusters and Services."""

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect ECS clusters and services in a region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("ecs", region)
            cluster_arns = self._list_cluster_arns(client)
            if cluster_arns:
                self._describe_clusters(
                    client, cluster_arns, region, nodes, edges
                )
                for cluster_arn in cluster_arns:
                    self._collect_services(
                        client, cluster_arn, region, nodes, edges
                    )
        except ClientError as e:
            logger.error(
                "ecs_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _list_cluster_arns(self, client) -> list[str]:
        """List all ECS cluster ARNs."""
        arns: list[str] = []
        paginator = client.get_paginator("list_clusters")
        for page in paginator.paginate():
            arns.extend(page.get("clusterArns", []))
        return arns

    def _describe_clusters(
        self,
        client,
        cluster_arns: list[str],
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Describe clusters and create nodes."""
        # describe_clusters accepts max 100 ARNs
        for i in range(0, len(cluster_arns), 100):
            batch = cluster_arns[i : i + 100]
            resp = client.describe_clusters(clusters=batch)
            for cluster in resp.get("clusters", []):
                arn = cluster["clusterArn"]
                nodes.append(ResourceNode(
                    arn=arn,
                    name=cluster.get("clusterName", ""),
                    label=NodeLabel.ECS_CLUSTER,
                    account_id=self.account_id,
                    region=region,
                    properties={
                        "status": cluster.get("status", ""),
                        "running_tasks": cluster.get(
                            "runningTasksCount", 0
                        ),
                        "active_services": cluster.get(
                            "activeServicesCount", 0
                        ),
                        "capacity_providers": cluster.get(
                            "capacityProviders", []
                        ),
                    },
                ))
                edges.append(ResourceEdge(
                    source_arn=arn,
                    target_arn=(
                        f"arn:aws:organizations"
                        f"::{self.account_id}:account"
                    ),
                    relationship=RelationshipType.BELONGS_TO,
                ))

    def _collect_services(
        self,
        client,
        cluster_arn: str,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect services in a cluster."""
        try:
            service_arns: list[str] = []
            paginator = client.get_paginator("list_services")
            for page in paginator.paginate(cluster=cluster_arn):
                service_arns.extend(page.get("serviceArns", []))

            if not service_arns:
                return

            # describe_services accepts max 10 ARNs
            for i in range(0, len(service_arns), 10):
                batch = service_arns[i : i + 10]
                resp = client.describe_services(
                    cluster=cluster_arn, services=batch
                )
                for svc in resp.get("services", []):
                    self._process_service(
                        svc, cluster_arn, region, nodes, edges
                    )
        except ClientError as e:
            logger.warning(
                "ecs_services_failed",
                cluster_arn=cluster_arn,
                error_code=e.response["Error"]["Code"],
            )

    def _process_service(
        self,
        svc: dict,
        cluster_arn: str,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single ECS service."""
        arn = svc["serviceArn"]
        nodes.append(ResourceNode(
            arn=arn,
            name=svc.get("serviceName", ""),
            label=NodeLabel.ECS_SERVICE,
            account_id=self.account_id,
            region=region,
            properties={
                "status": svc.get("status", ""),
                "desired_count": svc.get("desiredCount", 0),
                "running_count": svc.get("runningCount", 0),
                "launch_type": svc.get("launchType", ""),
                "task_definition": svc.get("taskDefinition", ""),
            },
        ))

        # Service PART_OF Cluster
        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=cluster_arn,
            relationship=RelationshipType.PART_OF,
        ))

        # Service HAS_ROLE via task role
        role_arn = svc.get("roleArn")
        if role_arn:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=role_arn,
                relationship=RelationshipType.HAS_ROLE,
            ))

        # Network config — subnets and SGs
        net = svc.get("networkConfiguration", {}).get(
            "awsvpcConfiguration", {}
        )
        for subnet_id in net.get("subnets", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:ec2:{region}:{self.account_id}"
                    f":subnet/{subnet_id}"
                ),
                relationship=RelationshipType.RUNS_IN,
            ))
        for sg_id in net.get("securityGroups", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:ec2:{region}:{self.account_id}"
                    f":security-group/{sg_id}"
                ),
                relationship=RelationshipType.HAS_SG,
            ))

        # Load balancer associations
        for lb in svc.get("loadBalancers", []):
            tg_arn = lb.get("targetGroupArn")
            if tg_arn:
                edges.append(ResourceEdge(
                    source_arn=tg_arn,
                    target_arn=arn,
                    relationship=RelationshipType.ROUTES_TO,
                ))
