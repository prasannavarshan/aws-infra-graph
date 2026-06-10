"""EKS collector — Clusters and Node Groups."""

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


class EKSCollector(BaseCollector):
    """Collects EKS Clusters and Node Groups."""

    def collect_in_region(
        self, region: str,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect EKS clusters and node groups in a region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("eks", region)
            cluster_names = self._list_clusters(client)
            for name in cluster_names:
                self._collect_cluster(
                    client, name, region, nodes, edges,
                )
        except ClientError as e:
            logger.error(
                "eks_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    # --- Helpers ---

    def _account_arn(self) -> str:
        return f"arn:aws:organizations::{self.account_id}:account"

    def _subnet_arn(self, region: str, subnet_id: str) -> str:
        return (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":subnet/{subnet_id}"
        )

    def _sg_arn(self, region: str, sg_id: str) -> str:
        return (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":security-group/{sg_id}"
        )

    # --- Collection methods ---

    def _list_clusters(self, client) -> list[str]:
        """List all EKS cluster names using pagination."""
        names: list[str] = []
        paginator = client.get_paginator("list_clusters")
        for page in paginator.paginate():
            names.extend(page.get("clusters", []))
        return names

    def _collect_cluster(
        self,
        client,
        cluster_name: str,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Describe a cluster and collect its node groups."""
        try:
            resp = client.describe_cluster(name=cluster_name)
            cluster = resp.get("cluster", {})

            self._process_cluster(
                cluster, region, nodes, edges,
            )
            self._collect_nodegroups(
                client,
                cluster_name,
                cluster["arn"],
                region,
                nodes,
                edges,
            )
        except ClientError as e:
            logger.warning(
                "eks_cluster_describe_failed",
                cluster_name=cluster_name,
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _process_cluster(
        self,
        cluster: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single EKS cluster into node and edges."""
        arn = cluster["arn"]
        vpc_config = cluster.get("resourcesVpcConfig", {})
        k8s_net = cluster.get(
            "kubernetesNetworkConfig", {},
        )

        nodes.append(ResourceNode(
            arn=arn,
            name=cluster.get("name", ""),
            label=NodeLabel.EKS_CLUSTER,
            account_id=self.account_id,
            region=region,
            tags=cluster.get("tags", {}),
            properties={
                "version": cluster.get("version", ""),
                "status": cluster.get("status", ""),
                "endpoint": cluster.get("endpoint", ""),
                "platform_version": cluster.get(
                    "platformVersion", "",
                ),
                "service_cidr": k8s_net.get(
                    "serviceIpv4Cidr", "",
                ),
                "endpoint_public_access": vpc_config.get(
                    "endpointPublicAccess", False,
                ),
                "endpoint_private_access": vpc_config.get(
                    "endpointPrivateAccess", False,
                ),
            },
        ))

        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=self._account_arn(),
            relationship=RelationshipType.BELONGS_TO,
        ))

        role_arn = cluster.get("roleArn")
        if role_arn:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=role_arn,
                relationship=RelationshipType.HAS_ROLE,
            ))

        for subnet_id in vpc_config.get("subnetIds", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=self._subnet_arn(region, subnet_id),
                relationship=RelationshipType.RUNS_IN,
            ))

        for sg_id in vpc_config.get("securityGroupIds", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=self._sg_arn(region, sg_id),
                relationship=RelationshipType.HAS_SG,
            ))

        cluster_sg = vpc_config.get("clusterSecurityGroupId")
        if cluster_sg:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=self._sg_arn(region, cluster_sg),
                relationship=RelationshipType.HAS_SG,
            ))

    def _collect_nodegroups(
        self,
        client,
        cluster_name: str,
        cluster_arn: str,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """List and describe node groups for a cluster."""
        try:
            ng_names: list[str] = []
            paginator = client.get_paginator(
                "list_nodegroups",
            )
            for page in paginator.paginate(
                clusterName=cluster_name,
            ):
                ng_names.extend(
                    page.get("nodegroups", []),
                )

            for ng_name in ng_names:
                resp = client.describe_nodegroup(
                    clusterName=cluster_name,
                    nodegroupName=ng_name,
                )
                ng = resp.get("nodegroup", {})
                self._process_nodegroup(
                    ng, cluster_arn, region, nodes, edges,
                )
        except ClientError as e:
            logger.warning(
                "eks_nodegroups_failed",
                cluster_name=cluster_name,
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _process_nodegroup(
        self,
        ng: dict,
        cluster_arn: str,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single EKS node group."""
        arn = ng["nodegroupArn"]
        scaling = ng.get("scalingConfig", {})

        nodes.append(ResourceNode(
            arn=arn,
            name=ng.get("nodegroupName", ""),
            label=NodeLabel.EKS_NODEGROUP,
            account_id=self.account_id,
            region=region,
            tags=ng.get("tags", {}),
            properties={
                "status": ng.get("status", ""),
                "instance_types": ng.get(
                    "instanceTypes", [],
                ),
                "ami_type": ng.get("amiType", ""),
                "capacity_type": ng.get(
                    "capacityType", "",
                ),
                "disk_size": ng.get("diskSize", 0),
                "min_size": scaling.get("minSize", 0),
                "max_size": scaling.get("maxSize", 0),
                "desired_size": scaling.get(
                    "desiredSize", 0,
                ),
            },
        ))

        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=cluster_arn,
            relationship=RelationshipType.PART_OF,
        ))

        role_arn = ng.get("nodeRole")
        if role_arn:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=role_arn,
                relationship=RelationshipType.HAS_ROLE,
            ))

        for subnet_id in ng.get("subnets", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=self._subnet_arn(
                    region, subnet_id,
                ),
                relationship=RelationshipType.RUNS_IN,
            ))
