"""Tests for the IAM collector."""

import json

import boto3
import pytest
from moto import mock_aws

from src.collector.iam import IAMCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"


@pytest.fixture()
def iam_env():
    """Set up moto-mocked IAM with roles, policies, and users."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        iam = session.client("iam", region_name="us-east-1")

        trust_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        })

        iam.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=trust_policy,
            Path="/",
        )

        policy = iam.create_policy(
            PolicyName="test-policy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }],
            }),
        )
        policy_arn = policy["Policy"]["Arn"]

        iam.attach_role_policy(
            RoleName="test-role", PolicyArn=policy_arn
        )

        iam.create_user(UserName="test-user")
        iam.attach_user_policy(
            UserName="test-user", PolicyArn=policy_arn
        )

        yield {
            "session": session,
            "policy_arn": policy_arn,
        }


class TestIAMCollectorHappyPath:
    """Happy path tests for IAM collector."""

    def test_collects_roles_and_policies(self, iam_env):
        collector = IAMCollector(
            session=iam_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        nodes, edges = collector.collect()

        roles = [n for n in nodes if n.label == NodeLabel.IAM_ROLE]
        policies = [n for n in nodes if n.label == NodeLabel.IAM_POLICY]
        users = [n for n in nodes if n.label == NodeLabel.IAM_USER]

        assert len(roles) >= 1
        assert len(policies) >= 1
        assert len(users) >= 1

    def test_role_has_policy_edge(self, iam_env):
        collector = IAMCollector(
            session=iam_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        _, edges = collector.collect()

        has_policy = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_POLICY
        ]
        assert len(has_policy) >= 2  # role + user each have the policy

    def test_role_node_properties(self, iam_env):
        collector = IAMCollector(
            session=iam_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        nodes, _ = collector.collect()

        test_role = next(
            (n for n in nodes if n.name == "test-role"), None
        )
        assert test_role is not None
        assert test_role.region == "global"
        assert "ec2.amazonaws.com" in test_role.properties["assume_role_policy"]


class TestIAMCollectorEdgeCases:
    """Edge case tests for IAM collector."""

    def test_collect_in_region_returns_empty(self, iam_env):
        collector = IAMCollector(
            session=iam_env["session"],
            account_id=ACCOUNT_ID,
        )
        nodes, edges = collector.collect_in_region("us-east-1")
        assert nodes == []
        assert edges == []

    def test_no_duplicate_across_regions(self, iam_env):
        """IAM is global — should not duplicate across regions."""
        collector = IAMCollector(
            session=iam_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1", "eu-west-1"],
        )
        nodes, _ = collector.collect()
        arns = [n.arn for n in nodes]
        assert len(arns) == len(set(arns))


class TestIAMCollectorErrors:
    """Error handling tests."""

    def test_handles_no_permissions_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name="us-east-1")
            collector = IAMCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["us-east-1"],
            )
            # Should not crash on empty account
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
            assert isinstance(edges, list)
