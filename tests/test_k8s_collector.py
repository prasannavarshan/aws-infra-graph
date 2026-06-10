"""Tests for K8s collector orchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.collector.k8s.collector import K8sCollector
from src.graph.model import NodeLabel

CLUSTER_NAME = "test-cluster"
REGION = "us-east-1"
ACCOUNT_ID = "123456789012"
CLUSTER_ARN = (
    f"arn:aws:eks:{REGION}:{ACCOUNT_ID}"
    f":cluster/{CLUSTER_NAME}"
)


@pytest.fixture()
def cluster_infos():
    return [{
        "arn": CLUSTER_ARN,
        "name": CLUSTER_NAME,
        "region": REGION,
    }]


@pytest.fixture()
def mock_session():
    return MagicMock()


class TestK8sCollectorHappyPath:
    """Happy path tests for K8sCollector."""

    @patch(
        "src.collector.k8s.collector.get_cluster_connection",
    )
    @patch("src.collector.k8s.collector.collect_namespaces")
    @patch("src.collector.k8s.collector.collect_nodes")
    @patch("src.collector.k8s.collector.collect_workloads")
    @patch(
        "src.collector.k8s.collector.collect_service_accounts",
    )
    @patch("src.collector.k8s.collector.collect_ingresses")
    @patch("src.collector.k8s.collector.collect_services")
    def test_collects_all_resource_types(
        self,
        mock_services,
        mock_ingresses,
        mock_sas,
        mock_workloads,
        mock_nodes,
        mock_ns,
        mock_conn,
        mock_session,
        cluster_infos,
    ):
        from src.collector.k8s.auth import ClusterConnection

        mock_conn.return_value = ClusterConnection(
            endpoint="https://test.eks.amazonaws.com",
            ca_data="",
            token="k8s-aws-v1.test",
            cluster_arn=CLUSTER_ARN,
            cluster_name=CLUSTER_NAME,
            account_id=ACCOUNT_ID,
            region=REGION,
        )

        # Each collector returns minimal data
        mock_ns.return_value = ([], [])
        mock_nodes.return_value = ([], [])
        mock_workloads.return_value = ([], [], {})
        mock_sas.return_value = ([], [])
        mock_ingresses.return_value = ([], [])
        mock_services.return_value = ([], [])

        collector = K8sCollector(
            mock_session, ACCOUNT_ID, cluster_infos,
        )
        nodes, edges = collector.collect()

        mock_ns.assert_called_once()
        mock_nodes.assert_called_once()
        mock_workloads.assert_called_once()
        mock_sas.assert_called_once()
        mock_ingresses.assert_called_once()
        mock_services.assert_called_once()


class TestK8sCollectorEdgeCases:
    """Edge case tests for K8sCollector."""

    def test_empty_cluster_list(self, mock_session):
        collector = K8sCollector(mock_session, ACCOUNT_ID, [])
        nodes, edges = collector.collect()
        assert nodes == []
        assert edges == []

    @patch(
        "src.collector.k8s.collector.get_cluster_connection",
    )
    def test_connection_failure_skips_cluster(
        self, mock_conn, mock_session, cluster_infos,
    ):
        mock_conn.return_value = None

        collector = K8sCollector(
            mock_session, ACCOUNT_ID, cluster_infos,
        )
        nodes, edges = collector.collect()

        assert nodes == []
        assert edges == []


class TestK8sCollectorErrors:
    """Error handling tests for K8sCollector."""

    @patch(
        "src.collector.k8s.collector.get_cluster_connection",
    )
    @patch("src.collector.k8s.collector.collect_namespaces")
    @patch("src.collector.k8s.collector.collect_nodes")
    @patch("src.collector.k8s.collector.collect_workloads")
    @patch(
        "src.collector.k8s.collector.collect_service_accounts",
    )
    @patch("src.collector.k8s.collector.collect_ingresses")
    @patch("src.collector.k8s.collector.collect_services")
    def test_one_resource_failure_doesnt_block_others(
        self,
        mock_services,
        mock_ingresses,
        mock_sas,
        mock_workloads,
        mock_nodes,
        mock_ns,
        mock_conn,
        mock_session,
        cluster_infos,
    ):
        from src.collector.k8s.auth import ClusterConnection
        from src.graph.model import ResourceNode

        mock_conn.return_value = ClusterConnection(
            endpoint="https://test.eks.amazonaws.com",
            ca_data="",
            token="k8s-aws-v1.test",
            cluster_arn=CLUSTER_ARN,
            cluster_name=CLUSTER_NAME,
            account_id=ACCOUNT_ID,
            region=REGION,
        )

        # Namespaces succeeds, nodes raises, rest empty
        ns_node = ResourceNode(
            arn=f"arn:k8s:{CLUSTER_ARN}:namespace/-/default",
            name="default",
            label=NodeLabel.K8S_NAMESPACE,
            account_id=ACCOUNT_ID,
            region=REGION,
        )
        mock_ns.return_value = ([ns_node], [])
        mock_nodes.side_effect = RuntimeError("API error")
        mock_workloads.return_value = ([], [], {})
        mock_sas.return_value = ([], [])
        mock_ingresses.return_value = ([], [])
        mock_services.return_value = ([], [])

        collector = K8sCollector(
            mock_session, ACCOUNT_ID, cluster_infos,
        )
        nodes, edges = collector.collect()

        # Should still have the namespace node
        assert len(nodes) == 1
        assert nodes[0].name == "default"

    @patch(
        "src.collector.k8s.collector.get_cluster_connection",
    )
    def test_cluster_exception_caught(
        self, mock_conn, mock_session,
    ):
        """Exception during connection should not propagate."""
        mock_conn.side_effect = RuntimeError("STS failed")

        collector = K8sCollector(
            mock_session,
            ACCOUNT_ID,
            [{
                "arn": CLUSTER_ARN,
                "name": CLUSTER_NAME,
                "region": REGION,
            }],
        )
        nodes, edges = collector.collect()

        assert nodes == []
        assert edges == []
