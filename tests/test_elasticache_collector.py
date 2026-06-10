"""Tests for the ElastiCache collector."""

from __future__ import annotations

from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from src.collector.elasticache import ElastiCacheCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.fixture()
def elasticache_env():
    """Set up moto-mocked ElastiCache with replication group and cluster."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        ec = session.client("elasticache", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        subnet1 = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.1.0/24",
            AvailabilityZone="us-east-1a",
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.2.0/24",
            AvailabilityZone="us-east-1b",
        )

        sg = ec2.create_security_group(
            GroupName="cache-sg",
            Description="Cache SG",
            VpcId=vpc_id,
        )

        ec.create_cache_subnet_group(
            CacheSubnetGroupName="test-subnet-group",
            CacheSubnetGroupDescription="Test",
            SubnetIds=[
                subnet1["Subnet"]["SubnetId"],
                subnet2["Subnet"]["SubnetId"],
            ],
        )

        # Create replication group (moto creates the node)
        ec.create_replication_group(
            ReplicationGroupId="test-repl-group",
            ReplicationGroupDescription="Test replication group",
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheClusters=1,
            CacheSubnetGroupName="test-subnet-group",
            SecurityGroupIds=[sg["GroupId"]],
        )

        # Create standalone cluster (moto supports this)
        ec.create_cache_cluster(
            CacheClusterId="test-standalone",
            Engine="redis",
            CacheNodeType="cache.t3.micro",
            NumCacheNodes=1,
            CacheSubnetGroupName="test-subnet-group",
            SecurityGroupIds=[sg["GroupId"]],
        )

        yield {
            "session": session,
            "sg_id": sg["GroupId"],
            "subnet1_id": subnet1["Subnet"]["SubnetId"],
            "subnet2_id": subnet2["Subnet"]["SubnetId"],
        }


class TestElastiCacheCollectorHappyPath:
    """Happy path tests for ElastiCache collector."""

    def test_collects_replication_group(self, elasticache_env):
        collector = ElastiCacheCollector(
            session=elasticache_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        rg_nodes = [
            n for n in nodes
            if n.label == NodeLabel.ELASTICACHE_REPLICATION_GROUP
        ]
        assert len(rg_nodes) == 1
        assert rg_nodes[0].name == "test-repl-group"
        assert rg_nodes[0].properties["engine"] == "redis"

    def test_collects_cache_cluster(self, elasticache_env):
        collector = ElastiCacheCollector(
            session=elasticache_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        cluster_nodes = [
            n for n in nodes
            if n.label == NodeLabel.ELASTICACHE_CLUSTER
        ]
        assert len(cluster_nodes) >= 1
        names = [n.name for n in cluster_nodes]
        assert "test-standalone" in names

    def test_cluster_runs_in_subnet(self, elasticache_env):
        """Subnet edges via CacheSubnetGroupName lookup."""
        collector = ElastiCacheCollector(
            session=elasticache_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        runs_in = [
            e for e in edges
            if e.relationship == RelationshipType.RUNS_IN
        ]
        assert len(runs_in) >= 1
        subnet1 = elasticache_env["subnet1_id"]
        subnet2 = elasticache_env["subnet2_id"]
        target_arns = [e.target_arn for e in runs_in]
        assert any(subnet1 in a for a in target_arns)
        assert any(subnet2 in a for a in target_arns)

    def test_standalone_memcached_cluster(self):
        """Standalone Memcached cluster with correct properties."""
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            ec2 = session.client("ec2", region_name=REGION)
            ec = session.client("elasticache", region_name=REGION)

            vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
            vpc_id = vpc["Vpc"]["VpcId"]
            subnet = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock="10.0.1.0/24",
                AvailabilityZone="us-east-1a",
            )
            ec.create_cache_subnet_group(
                CacheSubnetGroupName="mc-sg",
                CacheSubnetGroupDescription="MC",
                SubnetIds=[subnet["Subnet"]["SubnetId"]],
            )
            ec.create_cache_cluster(
                CacheClusterId="test-memcached",
                Engine="memcached",
                CacheNodeType="cache.t3.micro",
                NumCacheNodes=1,
                CacheSubnetGroupName="mc-sg",
            )

            collector = ElastiCacheCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()

            cluster_nodes = [
                n for n in nodes
                if n.label == NodeLabel.ELASTICACHE_CLUSTER
            ]
            assert len(cluster_nodes) == 1
            assert cluster_nodes[0].name == "test-memcached"
            assert (
                cluster_nodes[0].properties["engine"] == "memcached"
            )

            # No PART_OF for standalone
            part_of = [
                e for e in edges
                if e.relationship == RelationshipType.PART_OF
            ]
            assert len(part_of) == 0


class TestElastiCacheEdgeCreation:
    """Test edge creation using mocked API responses.

    Moto doesn't populate SecurityGroups or ReplicationGroupId
    on cache clusters, so we test those code paths with mocks.
    """

    def _make_collector(self) -> ElastiCacheCollector:
        """Create a collector with a mock session."""
        session = MagicMock()
        return ElastiCacheCollector(
            session=session,
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )

    def test_has_sg_edge(self):
        """HAS_SG edge from cluster to security group."""
        collector = self._make_collector()
        edges: list = []
        cluster = {
            "SecurityGroups": [
                {"SecurityGroupId": "sg-abc123", "Status": "active"},
            ],
        }
        collector._add_sg_edges(
            cluster, "arn:aws:elasticache:us-east-1:123:cluster:c1",
            REGION, edges,
        )
        assert len(edges) == 1
        assert edges[0].relationship == RelationshipType.HAS_SG
        assert "sg-abc123" in edges[0].target_arn

    def test_part_of_replication_group_edge(self):
        """PART_OF edge from cluster to replication group."""
        collector = self._make_collector()
        edges: list = []
        cluster = {"ReplicationGroupId": "my-rg"}
        collector._add_replication_group_edge(
            cluster, "arn:aws:elasticache:us-east-1:123:cluster:c1",
            REGION, edges,
        )
        assert len(edges) == 1
        assert edges[0].relationship == RelationshipType.PART_OF
        assert "my-rg" in edges[0].target_arn

    def test_no_part_of_when_no_replication_group(self):
        """No PART_OF edge when ReplicationGroupId is absent."""
        collector = self._make_collector()
        edges: list = []
        cluster = {}
        collector._add_replication_group_edge(
            cluster, "arn:aws:elasticache:us-east-1:123:cluster:c1",
            REGION, edges,
        )
        assert len(edges) == 0

    def test_subnet_edges_from_map(self):
        """RUNS_IN edges from subnet map lookup."""
        collector = self._make_collector()
        edges: list = []
        cluster = {"CacheSubnetGroupName": "my-group"}
        subnet_map = {"my-group": ["subnet-aaa", "subnet-bbb"]}
        collector._add_subnet_edges(
            cluster, "arn:aws:elasticache:us-east-1:123:cluster:c1",
            REGION, edges, subnet_map,
        )
        assert len(edges) == 2
        assert all(
            e.relationship == RelationshipType.RUNS_IN
            for e in edges
        )


class TestElastiCacheCollectorEdgeCases:
    """Edge case tests."""

    def test_empty_region_returns_nothing(self):
        with mock_aws():
            session = boto3.Session(region_name="eu-west-1")
            collector = ElastiCacheCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["eu-west-1"],
            )
            nodes, edges = collector.collect()
            ec_nodes = [
                n for n in nodes
                if n.label in (
                    NodeLabel.ELASTICACHE_CLUSTER,
                    NodeLabel.ELASTICACHE_REPLICATION_GROUP,
                )
            ]
            assert len(ec_nodes) == 0


class TestElastiCacheCollectorErrors:
    """Error handling tests."""

    def test_handles_api_error_gracefully(self):
        """Collector returns empty lists on ClientError."""
        session = MagicMock()
        mock_client = MagicMock()
        session.client.return_value = mock_client

        mock_client.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "No"}},
            "DescribeCacheSubnetGroups",
        )

        collector = ElastiCacheCollector(
            session=session,
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()
        assert isinstance(nodes, list)
        assert isinstance(edges, list)
        assert len(nodes) == 0

    def test_handles_empty_region(self):
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = ElastiCacheCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
            assert isinstance(edges, list)


# --- Serverless cache tests (MagicMock-based) ---


def _make_serverless_cache(
    name: str = "my-serverless",
    engine: str = "redis",
    status: str = "AVAILABLE",
    sg_ids: list[str] | None = None,
    subnet_ids: list[str] | None = None,
) -> dict:
    """Build a mock serverless cache response dict."""
    return {
        "ServerlessCacheName": name,
        "ARN": (
            f"arn:aws:elasticache:{REGION}:{ACCOUNT_ID}"
            f":serverlesscache:{name}"
        ),
        "Engine": engine,
        "FullEngineVersion": "7.1",
        "MajorEngineVersion": "7",
        "Status": status,
        "Description": "test serverless cache",
        "Endpoint": {
            "Address": f"{name}.serverless.cache.amazonaws.com",
            "Port": 6379,
        },
        "ReaderEndpoint": {
            "Address": f"{name}-ro.serverless.cache.amazonaws.com",
            "Port": 6379,
        },
        "CacheUsageLimits": {
            "DataStorage": {"Maximum": 100, "Unit": "GB"},
            "ECPUPerSecond": {"Maximum": 15000},
        },
        "SecurityGroupIds": sg_ids or ["sg-serverless1"],
        "SubnetIds": subnet_ids or [
            "subnet-sless1", "subnet-sless2",
        ],
        "KmsKeyId": "arn:aws:kms:us-west-2:123:key/abc",
        "SnapshotRetentionLimit": 7,
        "DailySnapshotTime": "05:00",
    }


def _make_serverless_collector(
    caches: list[dict],
) -> ElastiCacheCollector:
    """Build a collector with mocked serverless API."""
    session = MagicMock()
    mock_client = MagicMock()
    session.client.return_value = mock_client

    # Subnet groups paginator (for traditional clusters)
    sg_paginator = MagicMock()
    sg_paginator.paginate.return_value = [
        {"CacheSubnetGroups": []},
    ]
    # Replication groups paginator
    rg_paginator = MagicMock()
    rg_paginator.paginate.return_value = [
        {"ReplicationGroups": []},
    ]
    # Clusters paginator
    cc_paginator = MagicMock()
    cc_paginator.paginate.return_value = [
        {"CacheClusters": []},
    ]
    # Serverless paginator
    sl_paginator = MagicMock()
    sl_paginator.paginate.return_value = [
        {"ServerlessCaches": caches},
    ]

    def pick_paginator(api_name: str) -> MagicMock:
        return {
            "describe_cache_subnet_groups": sg_paginator,
            "describe_replication_groups": rg_paginator,
            "describe_cache_clusters": cc_paginator,
            "describe_serverless_caches": sl_paginator,
        }[api_name]

    mock_client.get_paginator.side_effect = pick_paginator

    return ElastiCacheCollector(
        session=session,
        account_id=ACCOUNT_ID,
        regions=[REGION],
    )


class TestServerlessCacheCollection:
    """Tests for serverless ElastiCache collection."""

    def test_collects_serverless_cache_node(self):
        """Serverless cache creates node with correct label."""
        cache = _make_serverless_cache()
        collector = _make_serverless_collector([cache])
        nodes, edges = collector.collect()

        sl_nodes = [
            n for n in nodes
            if n.label.value == "ElastiCacheServerlessCache"
        ]
        assert len(sl_nodes) == 1
        node = sl_nodes[0]
        assert node.name == "my-serverless"
        assert node.properties["engine"] == "redis"
        assert node.properties["max_data_storage_gb"] == 100
        assert node.properties["max_ecpu_per_second"] == 15000
        assert node.properties["endpoint"] == (
            "my-serverless.serverless.cache.amazonaws.com"
        )

    def test_serverless_has_sg_edges(self):
        """HAS_SG edges created from SecurityGroupIds."""
        cache = _make_serverless_cache(
            sg_ids=["sg-aaa", "sg-bbb"],
        )
        collector = _make_serverless_collector([cache])
        _, edges = collector.collect()

        sg_edges = [
            e for e in edges
            if e.relationship.value == "HAS_SG"
            and "security-group" in e.target_arn
        ]
        assert len(sg_edges) == 2
        targets = {e.target_arn for e in sg_edges}
        assert any("sg-aaa" in t for t in targets)
        assert any("sg-bbb" in t for t in targets)

    def test_serverless_runs_in_subnet_edges(self):
        """RUNS_IN edges created from SubnetIds."""
        cache = _make_serverless_cache(
            subnet_ids=["subnet-a", "subnet-b"],
        )
        collector = _make_serverless_collector([cache])
        _, edges = collector.collect()

        subnet_edges = [
            e for e in edges
            if e.relationship.value == "RUNS_IN"
            and "subnet" in e.target_arn
        ]
        assert len(subnet_edges) == 2

    def test_serverless_no_caches_no_crash(self):
        """Empty serverless response handled gracefully."""
        collector = _make_serverless_collector([])
        nodes, edges = collector.collect()
        sl_nodes = [
            n for n in nodes
            if n.label.value == "ElastiCacheServerlessCache"
        ]
        assert len(sl_nodes) == 0

    def test_serverless_skips_failed_status(self):
        """CREATE-FAILED caches are skipped."""
        cache = _make_serverless_cache(
            status="CREATE-FAILED",
        )
        collector = _make_serverless_collector([cache])
        nodes, _ = collector.collect()
        sl_nodes = [
            n for n in nodes
            if n.label.value == "ElastiCacheServerlessCache"
        ]
        assert len(sl_nodes) == 0

    def test_serverless_api_error_graceful(self):
        """ClientError on serverless API doesn't crash collector."""
        session = MagicMock()
        mock_client = MagicMock()
        session.client.return_value = mock_client

        call_count = 0

        def paginator_side_effect(api_name: str):
            nonlocal call_count
            if api_name == "describe_serverless_caches":
                raise ClientError(
                    {
                        "Error": {
                            "Code": "AccessDenied",
                            "Message": "No",
                        },
                    },
                    "DescribeServerlessCaches",
                )
            p = MagicMock()
            if api_name == "describe_cache_subnet_groups":
                p.paginate.return_value = [
                    {"CacheSubnetGroups": []},
                ]
            elif api_name == "describe_replication_groups":
                p.paginate.return_value = [
                    {"ReplicationGroups": []},
                ]
            elif api_name == "describe_cache_clusters":
                p.paginate.return_value = [
                    {"CacheClusters": []},
                ]
            return p

        mock_client.get_paginator.side_effect = (
            paginator_side_effect
        )

        collector = ElastiCacheCollector(
            session=session,
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()
        assert isinstance(nodes, list)
        assert isinstance(edges, list)
