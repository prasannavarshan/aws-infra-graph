"""Tests for shared VPC resource discovery in find_resources."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.main import find_resources


def _make_ctx(
    side_effects: list[list[dict]] | None = None,
) -> MagicMock:
    """Create a fake MCP Context with mocked Neo4j.

    Args:
        side_effects: List of return values for successive
            neo4j.query() calls. If None, returns empty lists.
    """
    neo4j = AsyncMock()
    if side_effects is not None:
        neo4j.query = AsyncMock(side_effect=side_effects)
    else:
        neo4j.query = AsyncMock(return_value=[])

    app_ctx = MagicMock()
    app_ctx.neo4j = neo4j

    ctx = MagicMock()
    ctx.request_context.lifespan_context = app_ctx
    return ctx


class TestSharedVpcFindResources:
    """Tests for include_shared_vpc parameter."""

    @pytest.mark.asyncio
    async def test_shared_vpc_returns_owner_nats(self):
        """Happy path: include_shared_vpc=True returns NATs
        from shared VPC owner account."""
        nat_node = {
            "name": "nat-owner",
            "arn": "arn:aws:ec2:us-east-1:732:natgw/nat-1",
            "account_id": "732313447068",
            "region": "us-east-1",
            "public_ip": "52.1.2.3",
        }
        ctx = _make_ctx(side_effects=[
            [{"total": 1}],  # count query
            [{"n": nat_node}],  # data query
            [],  # load_account_names (after results)
        ])

        result = await find_resources(
            ctx,
            resource_type="NATGateway",
            account_id="222222222222",
            include_shared_vpc=True,
        )

        assert "nat-owner" in result
        assert "732313447068" in result
        # Verify UNION query was used (SHARED_WITH in query)
        calls = ctx.request_context.lifespan_context.neo4j.query
        count_call_query = calls.call_args_list[0][0][0]
        assert "SHARED_WITH" in count_call_query

    @pytest.mark.asyncio
    async def test_default_no_shared_vpc(self):
        """Default: include_shared_vpc=False does NOT use
        UNION query."""
        ctx = _make_ctx(side_effects=[
            [{"total": 0}],  # count
            [],  # data (empty — no load_account_names call)
        ])

        result = await find_resources(
            ctx,
            resource_type="NATGateway",
            account_id="222222222222",
            include_shared_vpc=False,
        )

        assert "No NATGateway resources found" in result
        calls = ctx.request_context.lifespan_context.neo4j.query
        count_call_query = calls.call_args_list[0][0][0]
        assert "SHARED_WITH" not in count_call_query

    @pytest.mark.asyncio
    async def test_shared_vpc_no_account_id_falls_back(self):
        """Edge case: include_shared_vpc=True with no account_id
        uses normal query (UNION needs account_id)."""
        ctx = _make_ctx(side_effects=[
            [{"total": 0}],
            [],
        ])

        result = await find_resources(
            ctx,
            resource_type="NATGateway",
            include_shared_vpc=True,
        )

        assert "No NATGateway resources found" in result
        calls = ctx.request_context.lifespan_context.neo4j.query
        count_call_query = calls.call_args_list[0][0][0]
        assert "SHARED_WITH" not in count_call_query

    @pytest.mark.asyncio
    async def test_shared_vpc_non_networking_type(self):
        """Edge case: include_shared_vpc=True with non-VPC-networking
        type (EC2Instance) uses normal query, no UNION."""
        ctx = _make_ctx(side_effects=[
            [{"total": 0}],
            [],
        ])

        result = await find_resources(
            ctx,
            resource_type="EC2Instance",
            account_id="222222222222",
            include_shared_vpc=True,
        )

        assert "No EC2Instance resources found" in result
        calls = ctx.request_context.lifespan_context.neo4j.query
        count_call_query = calls.call_args_list[0][0][0]
        assert "SHARED_WITH" not in count_call_query

    @pytest.mark.asyncio
    async def test_shared_vpc_igw_uses_union(self):
        """InternetGateway is a VPC networking type and should
        use the UNION query."""
        ctx = _make_ctx(side_effects=[
            [{"total": 0}],
            [],
        ])

        await find_resources(
            ctx,
            resource_type="InternetGateway",
            account_id="123456789012",
            include_shared_vpc=True,
        )

        calls = ctx.request_context.lifespan_context.neo4j.query
        count_call_query = calls.call_args_list[0][0][0]
        assert "SHARED_WITH" in count_call_query

    @pytest.mark.asyncio
    async def test_shared_vpc_route_table_uses_union(self):
        """RouteTable is a VPC networking type and should
        use the UNION query."""
        ctx = _make_ctx(side_effects=[
            [{"total": 0}],
            [],
        ])

        await find_resources(
            ctx,
            resource_type="RouteTable",
            account_id="123456789012",
            include_shared_vpc=True,
        )

        calls = ctx.request_context.lifespan_context.neo4j.query
        count_call_query = calls.call_args_list[0][0][0]
        assert "SHARED_WITH" in count_call_query
        assert "PART_OF" in count_call_query
