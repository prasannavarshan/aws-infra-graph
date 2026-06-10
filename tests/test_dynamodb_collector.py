"""Tests for the DynamoDB collector."""

import boto3
import pytest
from moto import mock_aws

from src.collector.dynamodb import DynamoDBCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.fixture()
def dynamodb_env():
    """Set up moto-mocked DynamoDB with a table."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        client = session.client("dynamodb", region_name=REGION)

        client.create_table(
            TableName="test-table",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        yield {"session": session}


class TestDynamoDBHappyPath:
    def test_collects_table(self, dynamodb_env):
        collector = DynamoDBCollector(
            session=dynamodb_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()

        tables = [
            n for n in nodes if n.label == NodeLabel.DYNAMODB_TABLE
        ]
        assert len(tables) == 1
        assert tables[0].name == "test-table"

    def test_table_properties(self, dynamodb_env):
        collector = DynamoDBCollector(
            session=dynamodb_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()
        table = nodes[0]
        assert table.properties["table_status"] == "ACTIVE"

    def test_belongs_to_edge(self, dynamodb_env):
        collector = DynamoDBCollector(
            session=dynamodb_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()
        belongs = [
            e for e in edges
            if e.relationship == RelationshipType.BELONGS_TO
        ]
        assert len(belongs) == 1


class TestDynamoDBEdgeCases:
    def test_empty_region(self):
        with mock_aws():
            session = boto3.Session(region_name="eu-west-1")
            collector = DynamoDBCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["eu-west-1"],
            )
            nodes, _ = collector.collect()
            assert len(nodes) == 0


class TestDynamoDBErrors:
    def test_handles_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = DynamoDBCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
