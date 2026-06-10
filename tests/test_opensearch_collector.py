"""Tests for the OpenSearch collector."""

from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from src.collector.opensearch import OpenSearchCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def _make_collector(
    session: MagicMock | None = None,
) -> OpenSearchCollector:
    """Create a collector with a mock session."""
    session = session or MagicMock()
    return OpenSearchCollector(
        session=session,
        account_id=ACCOUNT_ID,
        regions=[REGION],
    )


def _mock_domain(
    name: str = "test-domain",
    vpc: bool = True,
    sg_ids: list[str] | None = None,
    subnet_ids: list[str] | None = None,
) -> dict:
    """Build a mock OpenSearch domain status dict."""
    domain = {
        "ARN": f"arn:aws:es:{REGION}:{ACCOUNT_ID}:domain/{name}",
        "DomainName": name,
        "DomainId": f"{ACCOUNT_ID}/{name}",
        "EngineVersion": "OpenSearch_2.7",
        "ClusterConfig": {
            "InstanceType": "r6g.large.search",
            "InstanceCount": 2,
            "DedicatedMasterEnabled": True,
            "ZoneAwarenessEnabled": True,
        },
        "EncryptionAtRestOptions": {"Enabled": True},
        "NodeToNodeEncryptionOptions": {"Enabled": True},
        "AdvancedSecurityOptions": {"Enabled": True},
        "AccessPolicies": '{"Version":"2012-10-17"}',
    }
    if vpc:
        domain["VPCOptions"] = {
            "VPCId": "vpc-abc123",
            "SecurityGroupIds": ["sg-aaa"] if sg_ids is None else sg_ids,
            "SubnetIds": ["subnet-111"] if subnet_ids is None else subnet_ids,
        }
        domain["Endpoints"] = {"vpc": "vpc-test.es.amazonaws.com"}
    else:
        domain["Endpoint"] = "search-test.es.amazonaws.com"
    return domain


def _setup_mock_client(
    domains: list[dict],
) -> MagicMock:
    """Set up a mock OpenSearch client that returns given domains."""
    client = MagicMock()
    names = [d["DomainName"] for d in domains]
    client.list_domain_names.return_value = {
        "DomainNames": [{"DomainName": n} for n in names],
    }
    client.describe_domains.return_value = {
        "DomainStatusList": domains,
    }
    return client


class TestOpenSearchHappyPath:
    """Happy path tests for OpenSearch collector."""

    def test_domain_node_created(self):
        """Domain node created with correct label and properties."""
        domain = _mock_domain()
        client = _setup_mock_client([domain])
        session = MagicMock()
        session.client.return_value = client

        collector = _make_collector(session)
        nodes, _ = collector.collect()

        os_nodes = [
            n for n in nodes
            if n.label == NodeLabel.OPENSEARCH_DOMAIN
        ]
        assert len(os_nodes) == 1
        node = os_nodes[0]
        assert node.name == "test-domain"
        assert node.properties["engine_version"] == "OpenSearch_2.7"
        assert node.properties["instance_type"] == "r6g.large.search"
        assert node.properties["instance_count"] == 2
        assert node.properties["dedicated_master"] is True
        assert node.properties["zone_awareness"] is True
        assert node.properties["encryption_at_rest"] is True
        assert node.properties["node_to_node_encryption"] is True
        assert node.properties["fine_grained_access"] is True
        assert node.properties["vpc_id"] == "vpc-abc123"
        assert "vpc-test" in node.properties["endpoint"]

    def test_has_sg_edges(self):
        """VPC domain creates HAS_SG edges."""
        domain = _mock_domain(
            sg_ids=["sg-aaa", "sg-bbb"],
        )
        client = _setup_mock_client([domain])
        session = MagicMock()
        session.client.return_value = client

        collector = _make_collector(session)
        _, edges = collector.collect()

        sg_edges = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_SG
        ]
        assert len(sg_edges) == 2
        sg_arns = {e.target_arn for e in sg_edges}
        assert any("sg-aaa" in a for a in sg_arns)
        assert any("sg-bbb" in a for a in sg_arns)

    def test_runs_in_subnet_edges(self):
        """VPC domain creates RUNS_IN edges."""
        domain = _mock_domain(
            subnet_ids=["subnet-111", "subnet-222"],
        )
        client = _setup_mock_client([domain])
        session = MagicMock()
        session.client.return_value = client

        collector = _make_collector(session)
        _, edges = collector.collect()

        runs_in = [
            e for e in edges
            if e.relationship == RelationshipType.RUNS_IN
        ]
        assert len(runs_in) == 2
        arns = {e.target_arn for e in runs_in}
        assert any("subnet-111" in a for a in arns)
        assert any("subnet-222" in a for a in arns)

    def test_belongs_to_account_edge(self):
        """Domain BELONGS_TO account edge created."""
        domain = _mock_domain()
        client = _setup_mock_client([domain])
        session = MagicMock()
        session.client.return_value = client

        collector = _make_collector(session)
        _, edges = collector.collect()

        belongs = [
            e for e in edges
            if e.relationship == RelationshipType.BELONGS_TO
        ]
        assert len(belongs) == 1
        assert ACCOUNT_ID in belongs[0].target_arn

    def test_multiple_domains(self):
        """Multiple domains in one region all collected."""
        domains = [
            _mock_domain(name="domain-a"),
            _mock_domain(name="domain-b"),
            _mock_domain(name="domain-c"),
        ]
        client = _setup_mock_client(domains)
        session = MagicMock()
        session.client.return_value = client

        collector = _make_collector(session)
        nodes, _ = collector.collect()

        os_nodes = [
            n for n in nodes
            if n.label == NodeLabel.OPENSEARCH_DOMAIN
        ]
        assert len(os_nodes) == 3
        names = {n.name for n in os_nodes}
        assert names == {"domain-a", "domain-b", "domain-c"}


class TestOpenSearchEdgeCases:
    """Edge case tests."""

    def test_public_domain_no_vpc_edges(self):
        """Public domain (no VPC) creates node but no SG/subnet edges."""
        domain = _mock_domain(vpc=False)
        client = _setup_mock_client([domain])
        session = MagicMock()
        session.client.return_value = client

        collector = _make_collector(session)
        nodes, edges = collector.collect()

        os_nodes = [
            n for n in nodes
            if n.label == NodeLabel.OPENSEARCH_DOMAIN
        ]
        assert len(os_nodes) == 1
        assert os_nodes[0].properties["vpc_id"] == ""
        assert "search-test" in os_nodes[0].properties["endpoint"]

        sg_edges = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_SG
        ]
        runs_in = [
            e for e in edges
            if e.relationship == RelationshipType.RUNS_IN
        ]
        assert len(sg_edges) == 0
        assert len(runs_in) == 0

    def test_empty_region_no_domains(self):
        """Empty region returns no nodes or edges."""
        client = MagicMock()
        client.list_domain_names.return_value = {
            "DomainNames": [],
        }
        session = MagicMock()
        session.client.return_value = client

        collector = _make_collector(session)
        nodes, edges = collector.collect()

        os_nodes = [
            n for n in nodes
            if n.label == NodeLabel.OPENSEARCH_DOMAIN
        ]
        assert len(os_nodes) == 0

    def test_domain_with_empty_sg_list(self):
        """Domain with empty SecurityGroupIds list creates no SG edges."""
        domain = _mock_domain(sg_ids=[])
        client = _setup_mock_client([domain])
        session = MagicMock()
        session.client.return_value = client

        collector = _make_collector(session)
        _, edges = collector.collect()

        sg_edges = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_SG
        ]
        assert len(sg_edges) == 0


class TestOpenSearchErrors:
    """Error handling tests."""

    def test_list_domain_names_error(self):
        """list_domain_names ClientError → empty result, logged."""
        client = MagicMock()
        client.list_domain_names.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "No"}},
            "ListDomainNames",
        )
        session = MagicMock()
        session.client.return_value = client

        collector = _make_collector(session)
        nodes, edges = collector.collect()

        assert len(nodes) == 0
        assert len(edges) == 0

    def test_describe_domains_error(self):
        """describe_domains ClientError → empty result, logged."""
        client = MagicMock()
        client.list_domain_names.return_value = {
            "DomainNames": [{"DomainName": "test-domain"}],
        }
        client.describe_domains.side_effect = ClientError(
            {"Error": {"Code": "ValidationException", "Message": "Bad"}},
            "DescribeDomains",
        )
        session = MagicMock()
        session.client.return_value = client

        collector = _make_collector(session)
        nodes, edges = collector.collect()

        assert len(nodes) == 0
        assert len(edges) == 0

    def test_collect_in_region_client_error(self):
        """Top-level ClientError in collect_in_region → empty result."""
        session = MagicMock()
        session.client.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "No"}},
            "CreateClient",
        )

        collector = _make_collector(session)
        nodes, edges = collector.collect()

        assert len(nodes) == 0
        assert len(edges) == 0


class TestOpenSearchBatching:
    """Test domain name batching for describe_domains."""

    def test_batches_over_five_domains(self):
        """More than 5 domains are split into batches of 5."""
        names = [f"domain-{i}" for i in range(7)]
        domains = [_mock_domain(name=n) for n in names]

        client = MagicMock()
        client.list_domain_names.return_value = {
            "DomainNames": [{"DomainName": n} for n in names],
        }
        # Return appropriate domains per batch
        client.describe_domains.side_effect = [
            {"DomainStatusList": domains[:5]},
            {"DomainStatusList": domains[5:]},
        ]
        session = MagicMock()
        session.client.return_value = client

        collector = _make_collector(session)
        nodes, _ = collector.collect()

        os_nodes = [
            n for n in nodes
            if n.label == NodeLabel.OPENSEARCH_DOMAIN
        ]
        assert len(os_nodes) == 7
        assert client.describe_domains.call_count == 2

        # Verify batch sizes
        call_args = client.describe_domains.call_args_list
        assert len(call_args[0][1]["DomainNames"]) == 5
        assert len(call_args[1][1]["DomainNames"]) == 2
