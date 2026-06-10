"""Tests for the SNS collector."""

import boto3
import pytest
from moto import mock_aws

from src.collector.sns import SNSCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.fixture()
def sns_env():
    """Set up moto-mocked SNS with a topic."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        client = session.client("sns", region_name=REGION)

        topic = client.create_topic(Name="test-topic")
        topic_arn = topic["TopicArn"]

        yield {
            "session": session,
            "topic_arn": topic_arn,
        }


class TestSNSHappyPath:
    def test_collects_topic(self, sns_env):
        collector = SNSCollector(
            session=sns_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()

        topics = [
            n for n in nodes if n.label == NodeLabel.SNS_TOPIC
        ]
        assert len(topics) == 1
        assert topics[0].name == "test-topic"

    def test_topic_properties(self, sns_env):
        collector = SNSCollector(
            session=sns_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()
        topic = nodes[0]
        assert topic.arn == sns_env["topic_arn"]

    def test_belongs_to_edge(self, sns_env):
        collector = SNSCollector(
            session=sns_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()
        belongs = [
            e for e in edges
            if e.relationship == RelationshipType.BELONGS_TO
        ]
        assert len(belongs) == 1


class TestSNSEdgeCases:
    def test_empty_region(self):
        with mock_aws():
            session = boto3.Session(region_name="eu-west-1")
            collector = SNSCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["eu-west-1"],
            )
            nodes, _ = collector.collect()
            assert len(nodes) == 0


class TestSNSErrors:
    def test_handles_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = SNSCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
