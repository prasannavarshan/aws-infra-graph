"""Tests for the ECS collector."""

import boto3
import pytest
from moto import mock_aws

from src.collector.ecs import ECSCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.fixture()
def ecs_env():
    """Set up moto-mocked ECS with a cluster and service."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        ecs = session.client("ecs", region_name=REGION)

        cluster = ecs.create_cluster(clusterName="test-cluster")
        cluster_arn = cluster["cluster"]["clusterArn"]

        # Register a task definition for the service
        ecs.register_task_definition(
            family="test-task",
            containerDefinitions=[{
                "name": "web",
                "image": "nginx:latest",
                "memory": 256,
            }],
        )

        ecs.create_service(
            cluster="test-cluster",
            serviceName="test-service",
            taskDefinition="test-task",
            desiredCount=2,
        )

        yield {
            "session": session,
            "cluster_arn": cluster_arn,
        }


class TestECSCollectorHappyPath:
    """Happy path tests for ECS collector."""

    def test_collects_cluster(self, ecs_env):
        collector = ECSCollector(
            session=ecs_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()

        clusters = [
            n for n in nodes if n.label == NodeLabel.ECS_CLUSTER
        ]
        assert len(clusters) == 1
        assert clusters[0].name == "test-cluster"

    def test_collects_service(self, ecs_env):
        collector = ECSCollector(
            session=ecs_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        services = [
            n for n in nodes if n.label == NodeLabel.ECS_SERVICE
        ]
        assert len(services) == 1
        assert services[0].name == "test-service"

    def test_service_part_of_cluster(self, ecs_env):
        collector = ECSCollector(
            session=ecs_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        part_of = [
            e for e in edges
            if e.relationship == RelationshipType.PART_OF
        ]
        assert len(part_of) >= 1

    def test_cluster_belongs_to_account(self, ecs_env):
        collector = ECSCollector(
            session=ecs_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        belongs = [
            e for e in edges
            if e.relationship == RelationshipType.BELONGS_TO
        ]
        assert len(belongs) >= 1


class TestECSCollectorEdgeCases:
    """Edge case tests."""

    def test_empty_region(self):
        with mock_aws():
            session = boto3.Session(region_name="eu-west-1")
            collector = ECSCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["eu-west-1"],
            )
            nodes, _ = collector.collect()
            clusters = [
                n for n in nodes
                if n.label == NodeLabel.ECS_CLUSTER
            ]
            assert len(clusters) == 0


class TestECSCollectorErrors:
    """Error handling tests."""

    def test_handles_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = ECSCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
