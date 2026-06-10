"""Tests for get_resource_security_groups MCP tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.tools.guided_resolve import ResolvedResource
from src.tools.resource_sgs import (
    _format_resource_sgs_output,
    _format_rules,
    _format_sg_details,
    get_resource_security_groups,
)

# --- Helpers ---


def _make_sg(
    group_id: str = "sg-abc123",
    name: str = "test-sg",
    vpc_id: str = "vpc-111",
    account_id: str = "111111111111",
    ingress: str = "tcp:443 from 0.0.0.0/0",
    egress: str = "all:all to 0.0.0.0/0",
) -> dict:
    return {
        "group_id": group_id,
        "name": name,
        "vpc_id": vpc_id,
        "account_id": account_id,
        "ingress": ingress,
        "egress": egress,
    }


def _make_resource(
    arn: str = "arn:aws:eks:us-west-2:111:cluster/my-cluster",
    name: str = "my-cluster",
    label: str = "EKSCluster",
    account_id: str = "111111111111",
    region: str = "us-west-2",
) -> ResolvedResource:
    return ResolvedResource(
        arn=arn, name=name, label=label,
        account_id=account_id, region=region,
    )


def _make_ctx(neo4j: AsyncMock) -> MagicMock:
    ctx = MagicMock()
    app = MagicMock()
    app.neo4j = neo4j
    ctx.request_context.lifespan_context = app
    return ctx


def _mock_neo4j_for_tool(
    resource_rows: list[dict] | None = None,
    sg_rows: list[dict] | None = None,
    account_rows: list[dict] | None = None,
) -> AsyncMock:
    """Build a mock neo4j with side_effect chain.

    Query order in the tool:
    1. load_account_names
    2. load_vpc_names
    3. load_sg_names
    4. (optional) _resolve_account
    5. _resolve_resource (strategy 1)
    6. _get_resource_sgs
    """
    neo4j = AsyncMock()
    side_effects: list = [
        # load_account_names
        [{"id": "111111111111", "name": "test-acct"}],
        # load_vpc_names
        [{"id": "vpc-111", "name": "test-vpc", "owner_id": "111111111111"}],
        # load_sg_names
        [],
    ]
    if account_rows is not None:
        side_effects.append(account_rows)
    if resource_rows is not None:
        side_effects.append(resource_rows)
    if sg_rows is not None:
        side_effects.append(sg_rows)
    neo4j.query = AsyncMock(side_effect=side_effects)
    return neo4j


# --- TestFormatRules ---


class TestFormatRules:
    """Tests for _format_rules."""

    def test_multiple_rules_on_separate_lines(self):
        rules = "tcp:443 from 0.0.0.0/0; all:all from sg:sg-xxx"
        lines = _format_rules(rules, "from")
        assert len(lines) == 2
        assert "tcp:443 from 0.0.0.0/0" in lines[0]
        assert "all:all from sg:sg-xxx" in lines[1]

    def test_empty_rules_shows_none(self):
        assert _format_rules("", "from") == ["(none)"]
        assert _format_rules("  ", "from") == ["(none)"]

    def test_single_rule(self):
        lines = _format_rules("tcp:443 from 0.0.0.0/0", "from")
        assert len(lines) == 1

    def test_with_sg_names_enriches(self):
        """SG references are enriched with names."""
        rules = "tcp:443 from sg:sg-abc123"
        sg_names = {"sg-abc123": "my-sg"}
        lines = _format_rules(rules, "from", sg_names)
        assert any("my-sg" in line for line in lines)

    def test_without_sg_names_no_crash(self):
        """No sg_names param still works (backward compat)."""
        rules = "tcp:443 from sg:sg-abc123"
        lines = _format_rules(rules, "from")
        assert len(lines) == 1
        assert "sg:sg-abc123" in lines[0]


# --- TestFormatSgDetails ---


class TestFormatSgDetails:
    """Tests for _format_sg_details."""

    def test_sg_with_rules(self):
        sg = _make_sg(
            ingress="tcp:443 from 0.0.0.0/0; tcp:80 from 10.0.0.0/8",
            egress="all:all to 0.0.0.0/0",
        )
        lines = _format_sg_details(
            sg, 1,
            {"111111111111": "test-acct"},
            {"vpc-111": {"name": "test-vpc", "owner_id": "111111111111"}},
        )
        text = "\n".join(lines)
        assert "sg-abc123" in text
        assert "test-sg" in text
        assert "Ingress:" in text
        assert "tcp:443 from 0.0.0.0/0" in text
        assert "tcp:80 from 10.0.0.0/8" in text
        assert "Egress:" in text
        assert "all:all to 0.0.0.0/0" in text

    def test_empty_ingress_shows_none(self):
        sg = _make_sg(ingress="", egress="all:all to 0.0.0.0/0")
        lines = _format_sg_details(sg, 1, {}, {})
        text = "\n".join(lines)
        assert "(none)" in text

    def test_vpc_enrichment(self):
        sg = _make_sg()
        lines = _format_sg_details(
            sg, 1,
            {"111111111111": "test-acct"},
            {"vpc-111": {"name": "my-vpc", "owner_id": "111111111111"}},
        )
        text = "\n".join(lines)
        assert "my-vpc" in text


# --- TestFormatResourceSgsOutput ---


class TestFormatResourceSgsOutput:
    """Tests for _format_resource_sgs_output."""

    def test_full_output(self):
        resource = _make_resource()
        sgs = [_make_sg(), _make_sg(group_id="sg-def456", name="sg-2")]
        output = _format_resource_sgs_output(
            resource, sgs, "worker node SGs",
            {"111111111111": "test-acct"},
            {"vpc-111": {"name": "test-vpc", "owner_id": "111111111111"}},
        )
        assert "Security Groups for EKSCluster my-cluster" in output
        assert "Resource: my-cluster" in output
        assert "Type: EKSCluster" in output
        assert "worker node SGs" in output
        assert "Found 2 security group(s)" in output
        assert "sg-abc123" in output
        assert "sg-def456" in output

    def test_account_enrichment(self):
        resource = _make_resource()
        output = _format_resource_sgs_output(
            resource, [_make_sg()], "SGs",
            {"111111111111": "my-account"},
            {},
        )
        assert "111111111111 (my-account)" in output


# --- TestGetResourceSecurityGroups (orchestrator) ---


class TestGetResourceSecurityGroups:
    """Tests for the MCP tool orchestrator."""

    @pytest.mark.asyncio
    async def test_happy_path_two_sgs(self):
        """Resource with 2 SGs returns formatted output."""
        resource_row = {
            "arn": "arn:aws:lambda:us-east-1:111:function:my-fn",
            "name": "my-fn",
            "label": "LambdaFunction",
            "account_id": "111111111111",
            "region": "us-east-1",
        }
        sg1 = _make_sg(
            group_id="sg-111", name="sg-one",
            ingress="tcp:443 from 0.0.0.0/0",
        )
        sg2 = _make_sg(
            group_id="sg-222", name="sg-two",
            ingress="tcp:80 from 10.0.0.0/8",
        )
        neo4j = _mock_neo4j_for_tool(
            resource_rows=[resource_row],
            sg_rows=[sg1, sg2],
        )
        ctx = _make_ctx(neo4j)

        result = await get_resource_security_groups(
            ctx, resource_name="lambda my-fn",
        )

        assert "Security Groups for LambdaFunction my-fn" in result
        assert "sg-111" in result
        assert "sg-222" in result
        assert "Found 2 security group(s)" in result

    @pytest.mark.asyncio
    async def test_eks_worker_traversal(self):
        """EKS cluster returns worker node SGs."""
        resource_row = {
            "arn": "arn:aws:eks:us-west-2:111:cluster/my-eks",
            "name": "my-eks",
            "label": "EKSCluster",
            "account_id": "111111111111",
            "region": "us-west-2",
        }
        worker_sg = _make_sg(
            group_id="sg-worker",
            name="eks-worker-sg",
        )
        neo4j = _mock_neo4j_for_tool(
            resource_rows=[resource_row],
            sg_rows=[worker_sg],
        )
        ctx = _make_ctx(neo4j)

        result = await get_resource_security_groups(
            ctx, resource_name="eks my-eks",
        )

        assert "worker node SGs" in result
        assert "sg-worker" in result

    @pytest.mark.asyncio
    async def test_eks_fallback_control_plane(self):
        """EKS with no workers falls back to control-plane SGs."""
        resource_row = {
            "arn": "arn:aws:eks:us-west-2:111:cluster/my-eks",
            "name": "my-eks",
            "label": "EKSCluster",
            "account_id": "111111111111",
            "region": "us-west-2",
        }
        ctrl_sg = _make_sg(
            group_id="sg-ctrl",
            name="eks-cluster-sg",
        )
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(side_effect=[
            # load_account_names
            [{"id": "111111111111", "name": "test-acct"}],
            # load_vpc_names
            [{"id": "vpc-111", "name": "test-vpc", "owner_id": "111111111111"}],
            # load_sg_names
            [],
            # _resolve_resource strategy 1
            [resource_row],
            # _get_eks_sgs: worker query returns empty
            [],
            # _get_eks_sgs: control-plane fallback
            [ctrl_sg],
        ])
        ctx = _make_ctx(neo4j)

        result = await get_resource_security_groups(
            ctx, resource_name="eks my-eks",
        )

        assert "control-plane SGs" in result
        assert "sg-ctrl" in result

    @pytest.mark.asyncio
    async def test_resource_disambiguation(self):
        """Multiple matches returns candidate list."""
        rows = [
            {
                "arn": "arn:aws:lambda:us-east-1:111:function:fn-a",
                "name": "fn-a",
                "label": "LambdaFunction",
                "account_id": "111111111111",
                "region": "us-east-1",
            },
            {
                "arn": "arn:aws:lambda:us-east-1:222:function:fn-b",
                "name": "fn-b",
                "label": "LambdaFunction",
                "account_id": "222222222222",
                "region": "us-east-1",
            },
        ]
        neo4j = _mock_neo4j_for_tool(resource_rows=rows)
        ctx = _make_ctx(neo4j)

        result = await get_resource_security_groups(
            ctx, resource_name="fn",
        )

        assert "Multiple resources match" in result
        assert "fn-a" in result
        assert "fn-b" in result

    @pytest.mark.asyncio
    async def test_account_disambiguation(self):
        """Multiple account matches returns account list."""
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(side_effect=[
            # load_account_names
            [{"id": "111111111111", "name": "test-acct"}],
            # load_vpc_names
            [],
            # load_sg_names
            [],
            # _resolve_account: multiple matches
            [
                {"id": "111111111111", "name": "beta-one"},
                {"id": "222222222222", "name": "beta-two"},
            ],
        ])
        ctx = _make_ctx(neo4j)

        result = await get_resource_security_groups(
            ctx, resource_name="my-fn", account_id="beta",
        )

        assert "Multiple accounts match" in result
        assert "beta-one" in result
        assert "beta-two" in result

    @pytest.mark.asyncio
    async def test_resource_not_found(self):
        """No matching resource returns error."""
        neo4j = _mock_neo4j_for_tool(resource_rows=[])
        # Need additional side effects for strategy 2 and 3
        neo4j.query = AsyncMock(side_effect=[
            # load_account_names
            [{"id": "111111111111", "name": "test-acct"}],
            # load_vpc_names
            [],
            # load_sg_names
            [],
            # _resolve_resource strategy 1: empty
            [],
            # _resolve_resource strategy 3 (any-token ranked): empty
            [],
        ])
        ctx = _make_ctx(neo4j)

        result = await get_resource_security_groups(
            ctx, resource_name="nonexistent-thing",
        )

        assert "No resource found" in result

    @pytest.mark.asyncio
    async def test_no_sgs_found(self):
        """Resource with no SGs returns helpful message."""
        resource_row = {
            "arn": "arn:aws:s3:::my-bucket",
            "name": "my-bucket",
            "label": "S3Bucket",
            "account_id": "111111111111",
            "region": "us-east-1",
        }
        neo4j = _mock_neo4j_for_tool(
            resource_rows=[resource_row],
            sg_rows=[],
        )
        ctx = _make_ctx(neo4j)

        result = await get_resource_security_groups(
            ctx, resource_name="my-bucket",
        )

        assert "No security groups found" in result
        assert "VPC-attached" in result

    @pytest.mark.asyncio
    async def test_resource_type_narrows_search(self):
        """Passing resource_type prepends to hint."""
        resource_row = {
            "arn": "arn:aws:lambda:us-east-1:111:function:my-fn",
            "name": "my-fn",
            "label": "LambdaFunction",
            "account_id": "111111111111",
            "region": "us-east-1",
        }
        sg = _make_sg()
        neo4j = _mock_neo4j_for_tool(
            resource_rows=[resource_row],
            sg_rows=[sg],
        )
        ctx = _make_ctx(neo4j)

        result = await get_resource_security_groups(
            ctx,
            resource_name="my-fn",
            resource_type="lambda",
        )

        assert "LambdaFunction" in result
        # Verify the query was called (resource_type prepended)
        calls = neo4j.query.call_args_list
        # Strategy 1 query should have LambdaFunction label
        found_lambda = any(
            "LambdaFunction" in str(c) for c in calls
        )
        assert found_lambda

    @pytest.mark.asyncio
    async def test_account_not_found(self):
        """Account with no matches returns error."""
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(side_effect=[
            # load_account_names
            [],
            # load_vpc_names
            [],
            # load_sg_names
            [],
            # _resolve_account: no matches
            [],
        ])
        ctx = _make_ctx(neo4j)

        result = await get_resource_security_groups(
            ctx,
            resource_name="my-fn",
            account_id="nonexistent",
        )

        assert "No account found" in result

    @pytest.mark.asyncio
    async def test_enriched_account_vpc_names(self):
        """Output includes enriched account and VPC names."""
        resource_row = {
            "arn": "arn:aws:ec2:us-west-2:111:instance/i-123",
            "name": "my-instance",
            "label": "EC2Instance",
            "account_id": "111111111111",
            "region": "us-west-2",
        }
        sg = _make_sg(
            vpc_id="vpc-111",
            account_id="111111111111",
        )
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(side_effect=[
            # load_account_names
            [{"id": "111111111111", "name": "my-account"}],
            # load_vpc_names
            [{"id": "vpc-111", "name": "my-vpc", "owner_id": "111111111111"}],
            # load_sg_names
            [],
            # _resolve_resource strategy 1
            [resource_row],
            # _get_resource_sgs
            [sg],
        ])
        ctx = _make_ctx(neo4j)

        result = await get_resource_security_groups(
            ctx, resource_name="ec2 my-instance",
        )

        assert "my-account" in result
        assert "my-vpc" in result
