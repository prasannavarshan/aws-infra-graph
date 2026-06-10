"""Tests for the Organizations collector."""

from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

from src.collector.organizations import OrganizationsCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"


@pytest.fixture()
def org_env():
    """Set up a moto-mocked AWS Organization with member accounts."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        org_client = session.client("organizations", region_name="us-east-1")

        org_client.create_organization(FeatureSet="ALL")

        account1 = org_client.create_account(
            Email="dev@example.com", AccountName="dev-account"
        )
        account1_id = account1["CreateAccountStatus"]["AccountId"]

        account2 = org_client.create_account(
            Email="staging@example.com", AccountName="staging-account"
        )
        account2_id = account2["CreateAccountStatus"]["AccountId"]

        with patch(
            "src.collector.organizations.get_org_session",
            return_value=session,
        ):
            yield {
                "session": session,
                "account1_id": account1_id,
                "account2_id": account2_id,
            }


class TestOrganizationsCollectorHappyPath:
    """Happy path: discover accounts in the organization."""

    def test_collects_all_accounts(self, org_env):
        collector = OrganizationsCollector(
            session=org_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        nodes, edges = collector.collect()

        account_nodes = [
            n for n in nodes if n.label == NodeLabel.ACCOUNT
        ]
        # Management account + 2 created accounts
        assert len(account_nodes) >= 3

    def test_account_node_has_correct_properties(self, org_env):
        collector = OrganizationsCollector(
            session=org_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        nodes, _ = collector.collect()

        dev = next(
            (n for n in nodes if n.properties.get("account_name") == "dev-account"),
            None,
        )
        assert dev is not None
        assert dev.label == NodeLabel.ACCOUNT
        assert dev.region == "global"
        assert dev.properties["email"] == "dev@example.com"

    def test_creates_member_of_edges(self, org_env):
        collector = OrganizationsCollector(
            session=org_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        _, edges = collector.collect()

        member_edges = [
            e for e in edges
            if e.relationship == RelationshipType.MEMBER_OF
        ]
        # Each account should have a MEMBER_OF edge to its parent
        assert len(member_edges) >= 3

    def test_does_not_iterate_regions(self, org_env):
        """Organizations collector should make a single call, not per-region."""
        collector = OrganizationsCollector(
            session=org_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1", "eu-west-1", "ap-southeast-1"],
        )
        nodes, _ = collector.collect()

        # Should still only find accounts once (not duplicated per region)
        account_nodes = [
            n for n in nodes if n.label == NodeLabel.ACCOUNT
        ]
        arns = [n.arn for n in account_nodes]
        assert len(arns) == len(set(arns)), "Duplicate accounts found"


class TestOrganizationsCollectorEdgeCases:
    """Edge cases for the Organizations collector."""

    def test_collect_in_region_returns_empty(self, org_env):
        """collect_in_region should return empty — global service."""
        collector = OrganizationsCollector(
            session=org_env["session"],
            account_id=ACCOUNT_ID,
        )
        nodes, edges = collector.collect_in_region("us-east-1")
        assert nodes == []
        assert edges == []


class TestOrganizationsCollectorErrors:
    """Error handling for the Organizations collector."""

    def test_non_org_account_handles_gracefully(self):
        """An account not in an Organization should not crash."""
        with mock_aws():
            session = boto3.Session(region_name="us-east-1")
            # Don't create an organization — the API call should fail
            collector = OrganizationsCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["us-east-1"],
            )
            with patch(
                "src.collector.organizations.get_org_session",
                return_value=session,
            ):
                nodes, edges = collector.collect()
            assert nodes == []
            assert edges == []
