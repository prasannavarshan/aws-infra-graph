"""Tests for the API Gateway collector."""

import boto3
import pytest
from moto import mock_aws

from src.collector.apigateway import APIGatewayCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.fixture()
def apigw_env():
    """Set up moto-mocked API Gateway with a REST API."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        client = session.client("apigateway", region_name=REGION)

        api = client.create_rest_api(
            name="test-api",
            description="Test REST API",
            endpointConfiguration={"types": ["REGIONAL"]},
        )

        yield {
            "session": session,
            "api_id": api["id"],
        }


class TestAPIGatewayHappyPath:
    def test_collects_rest_api(self, apigw_env):
        collector = APIGatewayCollector(
            session=apigw_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()

        apis = [
            n for n in nodes if n.label == NodeLabel.API_GATEWAY
        ]
        assert len(apis) == 1
        assert apis[0].name == "test-api"

    def test_api_properties(self, apigw_env):
        collector = APIGatewayCollector(
            session=apigw_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()
        api = nodes[0]
        assert api.properties["api_type"] == "REST"
        assert api.properties["api_id"] == apigw_env["api_id"]

    def test_belongs_to_edge(self, apigw_env):
        collector = APIGatewayCollector(
            session=apigw_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()
        belongs = [
            e for e in edges
            if e.relationship == RelationshipType.BELONGS_TO
        ]
        assert len(belongs) >= 1


class TestAPIGatewayEdgeCases:
    def test_empty_region(self):
        with mock_aws():
            session = boto3.Session(region_name="eu-west-1")
            collector = APIGatewayCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["eu-west-1"],
            )
            nodes, _ = collector.collect()
            apis = [
                n for n in nodes
                if n.label == NodeLabel.API_GATEWAY
            ]
            assert len(apis) == 0


class TestAPIGatewayErrors:
    def test_handles_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = APIGatewayCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
