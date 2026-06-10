"""Tests for SCP analysis MCP tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.tools.scp import (
    _format_effective_scps,
    get_effective_scps,
)


def _make_ctx(query_results: list[list[dict]]):
    """Create a mock MCP context with neo4j query results."""
    ctx = MagicMock()
    neo4j = AsyncMock()
    neo4j.query = AsyncMock(side_effect=query_results)
    app = MagicMock()
    app.neo4j = neo4j
    ctx.request_context.lifespan_context = app
    return ctx


class TestGetEffectiveSCPs:
    """Tests for get_effective_scps tool."""

    @pytest.mark.asyncio
    async def test_no_params_returns_error(self):
        ctx = _make_ctx([])
        result = await get_effective_scps(ctx)
        assert "Provide either" in result

    @pytest.mark.asyncio
    async def test_account_not_found(self):
        ctx = _make_ctx([[]])  # empty account result
        result = await get_effective_scps(
            ctx, account_id="999999999999",
        )
        assert "No account found" in result

    @pytest.mark.asyncio
    async def test_account_with_direct_and_inherited(self):
        acct_result = [{
            "acct_name": "prod-account",
            "acct_arn": "arn:aws:organizations::123:account/a1",
            "ou_name": "Production",
            "ou_arn": "arn:aws:organizations::123:ou/r-root/ou-prod",
        }]
        direct_scps = [{
            "name": "FullAWSAccess",
            "arn": "arn:scp1",
            "aws_managed": True,
            "summary": "Allow: *",
            "description": "",
        }]
        inherited_scps = [{
            "ou_name": "Production",
            "ou_arn": "arn:ou",
            "depth": 0,
            "name": "DenyS3Delete",
            "arn": "arn:scp2",
            "aws_managed": False,
            "summary": "Deny: s3:DeleteBucket",
            "description": "",
        }, {
            "ou_name": "Root",
            "ou_arn": "arn:root",
            "depth": 1,
            "name": "Level1SCP",
            "arn": "arn:scp3",
            "aws_managed": False,
            "summary": "Deny: iam:CreateUser",
            "description": "",
        }]

        ctx = _make_ctx([acct_result, direct_scps, inherited_scps])
        result = await get_effective_scps(
            ctx, account_id="123456789012",
        )
        assert "prod-account" in result
        assert "FullAWSAccess" in result
        assert "DenyS3Delete" in result
        assert "Level1SCP" in result
        assert "Production" in result
        assert "Root" in result
        assert "Total: 3" in result

    @pytest.mark.asyncio
    async def test_ou_not_found(self):
        ctx = _make_ctx([[]])  # empty OU result
        result = await get_effective_scps(
            ctx, ou_name="NonExistent",
        )
        assert "No OU found" in result

    @pytest.mark.asyncio
    async def test_ou_disambiguation(self):
        ctx = _make_ctx([
            [{"name": "Prod", "arn": "a1"}, {"name": "ProdAlt", "arn": "a2"}],
        ])
        result = await get_effective_scps(
            ctx, ou_name="Prod",
        )
        assert "Multiple OUs" in result

    @pytest.mark.asyncio
    async def test_ou_with_scps(self):
        ou_result = [{"name": "Prod-OU", "arn": "arn:ou-prod"}]
        direct = [{
            "name": "Level2SCP",
            "arn": "arn:scp",
            "aws_managed": False,
            "summary": "Deny: ec2:*",
            "description": "",
        }]
        inherited = [{
            "ou_name": "Root",
            "ou_arn": "arn:root",
            "depth": 1,
            "name": "FullAWSAccess",
            "arn": "arn:scp2",
            "aws_managed": True,
            "summary": "Allow: *",
            "description": "",
        }]
        ctx = _make_ctx([ou_result, direct, inherited])
        result = await get_effective_scps(
            ctx, ou_name="SLG-Prod",
        )
        assert "SLG-Prod" in result
        assert "Level2SCP" in result
        assert "FullAWSAccess" in result
        assert "Total: 2" in result


class TestFormatting:
    """Tests for output formatting."""

    def test_no_scps(self):
        result = _format_effective_scps("Test", [], [])
        assert "No SCPs found" in result

    def test_aws_managed_flag(self):
        scps = [{
            "name": "FullAWSAccess",
            "arn": "arn:x",
            "aws_managed": True,
            "summary": "Allow: *",
            "description": "",
        }]
        result = _format_effective_scps("Test", scps, [])
        assert "[AWS managed]" in result
