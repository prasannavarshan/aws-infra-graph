"""Tests for K8s resource collection functions."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from src.collector.k8s.auth import ClusterConnection
from src.collector.k8s.resources import (
    _ec2_arn_from_provider_id,
    _k8s_arn,
    collect_ingresses,
    collect_namespaces,
    collect_nodes,
    collect_service_accounts,
    collect_services,
    collect_workloads,
)
from src.graph.model import NodeLabel, RelationshipType

CLUSTER_NAME = "test-cluster"
REGION = "us-east-1"
ACCOUNT_ID = "123456789012"
CLUSTER_ARN = (
    f"arn:aws:eks:{REGION}:{ACCOUNT_ID}"
    f":cluster/{CLUSTER_NAME}"
)


@pytest.fixture()
def conn():
    """Create a test ClusterConnection."""
    return ClusterConnection(
        endpoint="https://test.eks.amazonaws.com",
        ca_data="",
        token="k8s-aws-v1.test",
        cluster_arn=CLUSTER_ARN,
        cluster_name=CLUSTER_NAME,
        account_id=ACCOUNT_ID,
        region=REGION,
    )


# --- Helper function tests ---


class TestK8sArn:
    """Tests for synthetic ARN construction."""

    def test_namespace_arn(self):
        arn = _k8s_arn(CLUSTER_ARN, "namespace", "-", "kube-system")
        assert arn == (
            f"arn:k8s:{CLUSTER_ARN}:namespace/-/kube-system"
        )

    def test_deployment_arn(self):
        arn = _k8s_arn(
            CLUSTER_ARN, "deployment", "default", "nginx",
        )
        assert "deployment/default/nginx" in arn


class TestEc2ArnFromProviderId:
    """Tests for providerID parsing."""

    def test_happy_path(self):
        arn = _ec2_arn_from_provider_id(
            "aws:///us-east-1a/i-0abc123def456",
            ACCOUNT_ID,
            REGION,
        )
        assert arn == (
            f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}"
            f":instance/i-0abc123def456"
        )

    def test_malformed_provider_id_returns_none(self):
        arn = _ec2_arn_from_provider_id(
            "gce://project/zone/instance", ACCOUNT_ID, REGION,
        )
        assert arn is None

    def test_empty_provider_id_returns_none(self):
        arn = _ec2_arn_from_provider_id(
            "", ACCOUNT_ID, REGION,
        )
        assert arn is None


# --- Namespace collection ---


class TestCollectNamespaces:
    """Tests for collect_namespaces."""

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_happy_path(self, mock_get, conn):
        mock_get.return_value = {
            "items": [
                {
                    "metadata": {
                        "name": "default",
                        "labels": {},
                    },
                    "status": {"phase": "Active"},
                },
                {
                    "metadata": {
                        "name": "kube-system",
                        "labels": {
                            "kubernetes.io/metadata.name":
                                "kube-system",
                        },
                    },
                    "status": {"phase": "Active"},
                },
            ],
        }

        nodes, edges = collect_namespaces(conn)

        assert len(nodes) == 2
        assert len(edges) == 2
        assert nodes[0].label == NodeLabel.K8S_NAMESPACE
        assert nodes[0].name == "default"
        assert edges[0].relationship == RelationshipType.PART_OF
        assert edges[0].target_arn == CLUSTER_ARN

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_api_returns_none(self, mock_get, conn):
        mock_get.return_value = None
        nodes, edges = collect_namespaces(conn)
        assert nodes == []
        assert edges == []

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_empty_items(self, mock_get, conn):
        mock_get.return_value = {"items": []}
        nodes, edges = collect_namespaces(conn)
        assert nodes == []
        assert edges == []


# --- Node collection ---


class TestCollectNodes:
    """Tests for collect_nodes."""

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_happy_path_with_ec2_link(self, mock_get, conn):
        mock_get.return_value = {
            "items": [{
                "metadata": {
                    "name": "ip-10-0-1-5.ec2.internal",
                    "labels": {
                        "node.kubernetes.io/instance-type":
                            "m5.xlarge",
                    },
                },
                "spec": {
                    "providerID":
                        "aws:///us-east-1a/i-0abc123def",
                },
                "status": {
                    "nodeInfo": {
                        "kubeletVersion": "v1.28.0",
                        "osImage": "Amazon Linux 2",
                    },
                    "addresses": [
                        {
                            "type": "InternalIP",
                            "address": "10.0.1.5",
                        },
                        {
                            "type": "Hostname",
                            "address":
                                "ip-10-0-1-5.ec2.internal",
                        },
                    ],
                },
            }],
        }

        nodes, edges = collect_nodes(conn)

        assert len(nodes) == 1
        assert nodes[0].label == NodeLabel.K8S_NODE

        # Should have PART_OF and HOSTS_ON edges
        rel_types = {e.relationship for e in edges}
        assert RelationshipType.PART_OF in rel_types
        assert RelationshipType.HOSTS_ON in rel_types

        hosts_on = [
            e for e in edges
            if e.relationship == RelationshipType.HOSTS_ON
        ]
        assert "i-0abc123def" in hosts_on[0].target_arn

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_no_provider_id_no_hosts_on(self, mock_get, conn):
        """Node without providerID should not create HOSTS_ON."""
        mock_get.return_value = {
            "items": [{
                "metadata": {"name": "test-node", "labels": {}},
                "spec": {},
                "status": {
                    "nodeInfo": {},
                    "addresses": [],
                },
            }],
        }

        nodes, edges = collect_nodes(conn)

        assert len(nodes) == 1
        hosts_on = [
            e for e in edges
            if e.relationship == RelationshipType.HOSTS_ON
        ]
        assert len(hosts_on) == 0


# --- Workload collection ---


class TestCollectWorkloads:
    """Tests for collect_workloads."""

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_happy_path(self, mock_get, conn):
        # Mock returns data for deployments, empty for others
        def side_effect(c, path):
            if "deployments" in path:
                return {
                    "items": [{
                        "metadata": {
                            "name": "nginx",
                            "namespace": "default",
                            "labels": {"app": "nginx"},
                        },
                        "spec": {
                            "replicas": 3,
                            "selector": {
                                "matchLabels": {
                                    "app": "nginx",
                                },
                            },
                        },
                        "status": {"readyReplicas": 3},
                    }],
                }
            return {"items": []}

        mock_get.side_effect = side_effect

        nodes, edges, selectors = collect_workloads(conn)

        assert len(nodes) == 1
        assert nodes[0].label == NodeLabel.K8S_DEPLOYMENT
        assert nodes[0].properties["kind"] == "deployment"
        assert len(selectors) == 1

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_all_apis_fail(self, mock_get, conn):
        mock_get.return_value = None
        nodes, edges, selectors = collect_workloads(conn)
        assert nodes == []
        assert selectors == {}


# --- Service collection ---


class TestCollectServices:
    """Tests for collect_services."""

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_selects_matching_deployment(self, mock_get, conn):
        mock_get.return_value = {
            "items": [{
                "metadata": {
                    "name": "nginx-svc",
                    "namespace": "default",
                    "labels": {},
                },
                "spec": {
                    "type": "ClusterIP",
                    "selector": {"app": "nginx"},
                    "ports": [{"port": 80, "protocol": "TCP"}],
                },
                "status": {},
            }],
        }

        dep_arn = _k8s_arn(
            CLUSTER_ARN, "deployment", "default", "nginx",
        )
        selectors = {dep_arn: {"app": "nginx"}}

        nodes, edges = collect_services(conn, selectors)

        assert len(nodes) == 1
        assert nodes[0].label == NodeLabel.K8S_SERVICE
        select_edges = [
            e for e in edges
            if e.relationship == RelationshipType.SELECTS
        ]
        assert len(select_edges) == 1

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_lb_type_stores_hostname(self, mock_get, conn):
        mock_get.return_value = {
            "items": [{
                "metadata": {
                    "name": "my-lb-svc",
                    "namespace": "default",
                    "labels": {},
                },
                "spec": {
                    "type": "LoadBalancer",
                    "selector": {},
                    "ports": [{"port": 443, "protocol": "TCP"}],
                },
                "status": {
                    "loadBalancer": {
                        "ingress": [{
                            "hostname":
                                "abc.elb.amazonaws.com",
                        }],
                    },
                },
            }],
        }

        nodes, edges = collect_services(conn, {})

        assert nodes[0].properties["external_hostname"] == (
            "abc.elb.amazonaws.com"
        )


# --- Service account collection ---


class TestCollectServiceAccounts:
    """Tests for collect_service_accounts."""

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_irsa_creates_assumes_irsa_edge(
        self, mock_get, conn,
    ):
        role_arn = (
            "arn:aws:iam::123456789012:role/my-irsa-role"
        )
        mock_get.return_value = {
            "items": [{
                "metadata": {
                    "name": "my-sa",
                    "namespace": "app-ns",
                    "labels": {},
                    "annotations": {
                        "eks.amazonaws.com/role-arn": role_arn,
                    },
                },
            }],
        }

        nodes, edges = collect_service_accounts(conn)

        assert len(nodes) == 1
        assert nodes[0].label == NodeLabel.K8S_SERVICE_ACCOUNT
        irsa_edges = [
            e for e in edges
            if e.relationship == RelationshipType.ASSUMES_IRSA
        ]
        assert len(irsa_edges) == 1
        assert irsa_edges[0].target_arn == role_arn

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_no_irsa_no_assumes_edge(self, mock_get, conn):
        mock_get.return_value = {
            "items": [{
                "metadata": {
                    "name": "default",
                    "namespace": "default",
                    "labels": {},
                },
            }],
        }

        nodes, edges = collect_service_accounts(conn)

        irsa_edges = [
            e for e in edges
            if e.relationship == RelationshipType.ASSUMES_IRSA
        ]
        assert len(irsa_edges) == 0


# --- Ingress collection ---


class TestCollectIngresses:
    """Tests for collect_ingresses."""

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_happy_path(self, mock_get, conn):
        mock_get.return_value = {
            "items": [{
                "metadata": {
                    "name": "my-ingress",
                    "namespace": "default",
                    "labels": {},
                },
                "spec": {
                    "ingressClassName": "alb",
                    "rules": [{
                        "host": "app.example.com",
                        "http": {
                            "paths": [{
                                "path": "/",
                                "backend": {
                                    "service": {
                                        "name": "app-svc",
                                        "port": {
                                            "number": 80,
                                        },
                                    },
                                },
                            }],
                        },
                    }],
                },
                "status": {
                    "loadBalancer": {
                        "ingress": [{
                            "hostname":
                                "xyz.elb.amazonaws.com",
                        }],
                    },
                },
            }],
        }

        nodes, edges = collect_ingresses(conn)

        assert len(nodes) == 1
        assert nodes[0].label == NodeLabel.K8S_INGRESS
        assert nodes[0].properties["external_hostname"] == (
            "xyz.elb.amazonaws.com"
        )

    @patch("src.collector.k8s.resources.k8s_api_get")
    def test_404_returns_empty(self, mock_get, conn):
        """Networking API not available should return empty."""
        mock_get.return_value = None
        nodes, edges = collect_ingresses(conn)
        assert nodes == []
        assert edges == []
