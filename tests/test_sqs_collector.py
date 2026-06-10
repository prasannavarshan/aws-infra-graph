"""Tests for the SQS collector."""

import boto3
import pytest
from moto import mock_aws

from src.collector.sqs import SQSCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.fixture()
def sqs_env():
    """Set up moto-mocked SQS with queues."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        client = session.client("sqs", region_name=REGION)

        client.create_queue(QueueName="test-queue")
        client.create_queue(
            QueueName="test-queue-dlq",
        )

        yield {"session": session}


class TestSQSHappyPath:
    def test_collects_queues(self, sqs_env):
        collector = SQSCollector(
            session=sqs_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()

        queues = [
            n for n in nodes if n.label == NodeLabel.SQS_QUEUE
        ]
        assert len(queues) == 2

    def test_queue_properties(self, sqs_env):
        collector = SQSCollector(
            session=sqs_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()
        q = next(
            (n for n in nodes if n.name == "test-queue"), None
        )
        assert q is not None
        assert q.properties["visibility_timeout"] == 30

    def test_belongs_to_edge(self, sqs_env):
        collector = SQSCollector(
            session=sqs_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()
        belongs = [
            e for e in edges
            if e.relationship == RelationshipType.BELONGS_TO
        ]
        assert len(belongs) == 2


class TestSQSEdgeCases:
    def test_empty_region(self):
        with mock_aws():
            session = boto3.Session(region_name="eu-west-1")
            collector = SQSCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["eu-west-1"],
            )
            nodes, _ = collector.collect()
            assert len(nodes) == 0


class TestSQSErrors:
    def test_handles_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = SQSCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
