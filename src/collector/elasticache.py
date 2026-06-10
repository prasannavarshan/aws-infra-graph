"""ElastiCache collector — clusters and replication groups with VPC relationships."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class ElastiCacheCollector(BaseCollector):
    """Collects ElastiCache clusters and replication groups."""

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect ElastiCache resources in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            ec = self.client("elasticache", region)
            subnet_map = self._build_subnet_map(ec)
            self._collect_replication_groups(ec, region, nodes)
            self._collect_clusters(ec, region, nodes, edges, subnet_map)
        except ClientError as e:
            logger.error(
                "elasticache_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )
            return nodes, edges

        self._collect_serverless_caches(
            ec, region, nodes, edges,
        )

        return nodes, edges

    def _build_subnet_map(
        self, ec: object
    ) -> dict[str, list[str]]:
        """Build a mapping of subnet group name to subnet IDs.

        Args:
            ec: ElastiCache boto3 client.

        Returns:
            Dict mapping cache subnet group name to list of subnet IDs.
        """
        subnet_map: dict[str, list[str]] = {}
        try:
            paginator = ec.get_paginator(  # type: ignore[union-attr]
                "describe_cache_subnet_groups"
            )
            for page in paginator.paginate():
                for group in page["CacheSubnetGroups"]:
                    name = group["CacheSubnetGroupName"]
                    subnet_ids = [
                        s["SubnetIdentifier"]
                        for s in group.get("Subnets", [])
                    ]
                    subnet_map[name] = subnet_ids
        except ClientError as e:
            logger.warning(
                "elasticache_subnet_groups_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )
        return subnet_map

    def _collect_replication_groups(
        self,
        ec: object,
        region: str,
        nodes: list[ResourceNode],
    ) -> None:
        """Collect ElastiCache replication groups."""
        paginator = ec.get_paginator(  # type: ignore[union-attr]
            "describe_replication_groups"
        )
        for page in paginator.paginate():
            for rg in page["ReplicationGroups"]:
                self._process_replication_group(rg, region, nodes)

    def _process_replication_group(
        self,
        rg: dict,
        region: str,
        nodes: list[ResourceNode],
    ) -> None:
        """Process a single replication group into a node."""
        arn = rg.get("ARN", "")
        name = rg.get("ReplicationGroupId", "")

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.ELASTICACHE_REPLICATION_GROUP,
            account_id=self.account_id,
            region=region,
            properties={
                "engine": "redis",
                "description": rg.get("Description", ""),
                "status": rg.get("Status", ""),
                "cluster_enabled": rg.get(
                    "ClusterEnabled", False
                ),
                "multi_az": rg.get(
                    "MultiAZ", "disabled"
                ),
                "automatic_failover": rg.get(
                    "AutomaticFailover", "disabled"
                ),
                "num_node_groups": len(
                    rg.get("NodeGroups", [])
                ),
                "snapshot_retention_limit": rg.get(
                    "SnapshotRetentionLimit", 0
                ),
                "at_rest_encryption": rg.get(
                    "AtRestEncryptionEnabled", False
                ),
                "transit_encryption": rg.get(
                    "TransitEncryptionEnabled", False
                ),
            },
        ))

    def _collect_clusters(
        self,
        ec: object,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
        subnet_map: dict[str, list[str]],
    ) -> None:
        """Collect ElastiCache cache clusters."""
        paginator = ec.get_paginator(  # type: ignore[union-attr]
            "describe_cache_clusters"
        )
        for page in paginator.paginate(ShowCacheNodeInfo=True):
            for cluster in page["CacheClusters"]:
                self._process_cluster(
                    cluster, region, nodes, edges, subnet_map
                )

    def _process_cluster(
        self,
        cluster: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
        subnet_map: dict[str, list[str]],
    ) -> None:
        """Process a single cache cluster into nodes and edges."""
        arn = cluster.get("ARN", "")
        name = cluster.get("CacheClusterId", "")

        endpoint = cluster.get("ConfigurationEndpoint") or {}
        if not endpoint:
            # Single-node clusters use CacheNodes[0].Endpoint
            cache_nodes = cluster.get("CacheNodes", [])
            if cache_nodes:
                endpoint = cache_nodes[0].get("Endpoint", {})

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.ELASTICACHE_CLUSTER,
            account_id=self.account_id,
            region=region,
            properties={
                "engine": cluster.get("Engine", ""),
                "engine_version": cluster.get(
                    "EngineVersion", ""
                ),
                "cache_node_type": cluster.get(
                    "CacheNodeType", ""
                ),
                "num_cache_nodes": cluster.get(
                    "NumCacheNodes", 0
                ),
                "status": cluster.get(
                    "CacheClusterStatus", ""
                ),
                "endpoint": endpoint.get("Address", ""),
                "port": endpoint.get("Port", 0),
                "preferred_az": cluster.get(
                    "PreferredAvailabilityZone", ""
                ),
                "snapshot_retention_limit": cluster.get(
                    "SnapshotRetentionLimit", 0
                ),
                "at_rest_encryption": cluster.get(
                    "AtRestEncryptionEnabled", False
                ),
                "transit_encryption": cluster.get(
                    "TransitEncryptionEnabled", False
                ),
            },
        ))

        self._add_sg_edges(cluster, arn, region, edges)
        self._add_subnet_edges(
            cluster, arn, region, edges, subnet_map
        )
        self._add_replication_group_edge(
            cluster, arn, region, edges
        )

    def _add_sg_edges(
        self,
        cluster: dict,
        arn: str,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Create HAS_SG edges for security groups."""
        for sg in cluster.get("SecurityGroups", []):
            sg_id = sg.get("SecurityGroupId")
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
        cluster: dict,
        arn: str,
        region: str,
        edges: list[ResourceEdge],
        subnet_map: dict[str, list[str]],
    ) -> None:
        """Create RUNS_IN edges for cache subnet group subnets."""
        subnet_group_name = cluster.get(
            "CacheSubnetGroupName", ""
        )
        subnet_ids = subnet_map.get(subnet_group_name, [])
        for subnet_id in subnet_ids:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:ec2:{region}:{self.account_id}"
                    f":subnet/{subnet_id}"
                ),
                relationship=RelationshipType.RUNS_IN,
            ))

    def _add_replication_group_edge(
        self,
        cluster: dict,
        arn: str,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Create PART_OF edge to replication group if present."""
        rg_id = cluster.get("ReplicationGroupId")
        if rg_id:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:elasticache:{region}"
                    f":{self.account_id}"
                    f":replicationgroup:{rg_id}"
                ),
                relationship=RelationshipType.PART_OF,
            ))

    # --- Serverless caches ---

    _SKIP_STATUSES = {"CREATE-FAILED", "DELETING"}

    def _collect_serverless_caches(
        self,
        ec: object,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect ElastiCache serverless caches."""
        try:
            paginator = ec.get_paginator(  # type: ignore[union-attr]
                "describe_serverless_caches",
            )
            for page in paginator.paginate():
                for cache in page.get(
                    "ServerlessCaches", [],
                ):
                    status = cache.get("Status", "")
                    if status in self._SKIP_STATUSES:
                        continue
                    self._process_serverless_cache(
                        cache, region, nodes, edges,
                    )
        except ClientError as e:
            logger.warning(
                "elasticache_serverless_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "elasticache_serverless_unsupported",
                error=str(e),
                account_id=self.account_id,
                region=region,
            )

    def _process_serverless_cache(
        self,
        cache: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single serverless cache."""
        arn = cache.get("ARN", "")
        name = cache.get("ServerlessCacheName", "")

        endpoint = cache.get("Endpoint", {})
        reader = cache.get("ReaderEndpoint", {})
        limits = cache.get("CacheUsageLimits", {})
        storage = limits.get("DataStorage", {})
        ecpu = limits.get("ECPUPerSecond", {})

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.ELASTICACHE_SERVERLESS_CACHE,
            account_id=self.account_id,
            region=region,
            properties={
                "engine": cache.get("Engine", ""),
                "full_engine_version": cache.get(
                    "FullEngineVersion", "",
                ),
                "major_engine_version": cache.get(
                    "MajorEngineVersion", "",
                ),
                "status": cache.get("Status", ""),
                "description": cache.get(
                    "Description", "",
                ),
                "endpoint": endpoint.get("Address", ""),
                "port": endpoint.get("Port", 0),
                "reader_endpoint": reader.get(
                    "Address", "",
                ),
                "max_data_storage_gb": storage.get(
                    "Maximum", 0,
                ),
                "max_ecpu_per_second": ecpu.get(
                    "Maximum", 0,
                ),
                "kms_key_id": cache.get("KmsKeyId", ""),
                "snapshot_retention_limit": cache.get(
                    "SnapshotRetentionLimit", 0,
                ),
                "daily_snapshot_time": cache.get(
                    "DailySnapshotTime", "",
                ),
                "user_group_id": cache.get(
                    "UserGroupId", "",
                ),
            },
        ))

        for sg_id in cache.get("SecurityGroupIds", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:ec2:{region}"
                    f":{self.account_id}"
                    f":security-group/{sg_id}"
                ),
                relationship=RelationshipType.HAS_SG,
            ))

        for subnet_id in cache.get("SubnetIds", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:ec2:{region}"
                    f":{self.account_id}"
                    f":subnet/{subnet_id}"
                ),
                relationship=RelationshipType.RUNS_IN,
            ))
