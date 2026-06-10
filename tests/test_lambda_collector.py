"""Tests for the Lambda collector."""

import json
import zipfile
from io import BytesIO

import boto3
import pytest
from moto import mock_aws

from src.collector.lambda_fn import LambdaCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


def _make_zip() -> bytes:
    """Create a minimal ZIP for Lambda deployment."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lambda_function.py", "def handler(e, c): pass")
    return buf.getvalue()


@pytest.fixture()
def lambda_env():
    """Set up moto-mocked Lambda with a function."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam", region_name=REGION)
        lam = session.client("lambda", region_name=REGION)

        # Create execution role
        trust = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        })
        role = iam.create_role(
            RoleName="lambda-exec",
            AssumeRolePolicyDocument=trust,
        )
        role_arn = role["Role"]["Arn"]

        lam.create_function(
            FunctionName="test-function",
            Runtime="python3.12",
            Role=role_arn,
            Handler="lambda_function.handler",
            Code={"ZipFile": _make_zip()},
            MemorySize=256,
            Timeout=30,
        )

        yield {
            "session": session,
            "role_arn": role_arn,
        }


class TestLambdaCollectorHappyPath:
    """Happy path tests for Lambda collector."""

    def test_collects_lambda_function(self, lambda_env):
        collector = LambdaCollector(
            session=lambda_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()

        fn_nodes = [
            n for n in nodes if n.label == NodeLabel.LAMBDA_FUNCTION
        ]
        assert len(fn_nodes) == 1
        assert fn_nodes[0].name == "test-function"

    def test_lambda_properties(self, lambda_env):
        collector = LambdaCollector(
            session=lambda_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        fn = next(
            (n for n in nodes if n.name == "test-function"), None
        )
        assert fn is not None
        assert fn.properties["runtime"] == "python3.12"
        assert fn.properties["memory_size"] == 256
        assert fn.properties["timeout"] == 30

    def test_lambda_has_role_edge(self, lambda_env):
        collector = LambdaCollector(
            session=lambda_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        has_role = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_ROLE
        ]
        assert len(has_role) == 1
        assert has_role[0].target_arn == lambda_env["role_arn"]


class TestLambdaCollectorEdgeCases:
    """Edge case tests."""

    def test_empty_region_returns_nothing(self):
        with mock_aws():
            session = boto3.Session(region_name="eu-west-1")
            collector = LambdaCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["eu-west-1"],
            )
            nodes, _ = collector.collect()
            fn_nodes = [
                n for n in nodes
                if n.label == NodeLabel.LAMBDA_FUNCTION
            ]
            assert len(fn_nodes) == 0


class TestLambdaCollectorErrors:
    """Error handling tests."""

    def test_handles_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = LambdaCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
