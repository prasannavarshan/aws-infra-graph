"""Integration tests for MCP tools — mocked Neo4j responses."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.main import (
    find_resources,
    get_account_summary,
    get_dependencies,
    get_network_path,
    get_resource,
)


def _make_ctx(query_results: list[dict]) -> MagicMock:
    """Create a fake MCP Context with mocked Neo4j."""
    neo4j = AsyncMock()
    neo4j.query = AsyncMock(return_value=query_results)

    app_ctx = MagicMock()
    app_ctx.neo4j = neo4j

    ctx = MagicMock()
    ctx.request_context.lifespan_context = app_ctx
    return ctx


class TestFindResources:
    @pytest.mark.asyncio
    async def test_returns_formatted_results(self):
        data = [
            {"n": {
                "name": "web-server",
                "arn": "arn:aws:ec2:us-east-1:123:instance/i-1",
                "account_id": "123",
                "region": "us-east-1",
            }},
        ]
        ctx = _make_ctx(data)
        # count query, data query, load_account_names
        ctx.request_context.lifespan_context.neo4j.query = (
            AsyncMock(side_effect=[
                [{"total": 1}], data,
                [],  # load_account_names
            ])
        )
        result = await find_resources(ctx, "EC2Instance")

        assert "web-server" in result
        assert "1 EC2Instance" in result

    @pytest.mark.asyncio
    async def test_no_results_message(self):
        ctx = _make_ctx([])
        result = await find_resources(ctx, "EC2Instance")
        assert "No EC2Instance" in result


class TestGetResource:
    @pytest.mark.asyncio
    async def test_returns_details(self):
        node_results = [
            {
                "n": {
                    "name": "vpc-main",
                    "arn": "arn:aws:ec2:us-east-1:123:vpc/vpc-1",
                    "account_id": "123",
                    "region": "us-east-1",
                    "cidr_block": "10.0.0.0/16",
                },
                "labels": ["VPC"],
            }
        ]
        rel_results = [
            {
                "rel_type": "PART_OF",
                "related_arn": "arn:sub",
                "related_name": "subnet-1",
                "related_labels": ["Subnet"],
                "direction": "incoming",
            }
        ]

        neo4j = AsyncMock()
        neo4j.query = AsyncMock(
            side_effect=[
                node_results,
                [],  # load_account_names
                rel_results,
            ]
        )
        app_ctx = MagicMock()
        app_ctx.neo4j = neo4j
        ctx = MagicMock()
        ctx.request_context.lifespan_context = app_ctx

        result = await get_resource(
            ctx, "arn:aws:ec2:us-east-1:123:vpc/vpc-1"
        )
        assert "vpc-main" in result
        assert "VPC" in result
        assert "PART_OF" in result

    @pytest.mark.asyncio
    async def test_not_found(self):
        ctx = _make_ctx([])
        result = await get_resource(ctx, "arn:nonexistent")
        assert "No resource found" in result


class TestGetDependencies:
    @pytest.mark.asyncio
    async def test_returns_dependency_chain(self):
        ctx = _make_ctx([
            {
                "chain": [
                    {"name": "i-1", "arn": "a", "labels": ["EC2Instance"]},
                    {"name": "sub-1", "arn": "b", "labels": ["Subnet"]},
                ],
                "rel_types": ["RUNS_IN"],
            }
        ])
        result = await get_dependencies(ctx, "arn:test")
        assert "RUNS_IN" in result
        assert "i-1" in result

    @pytest.mark.asyncio
    async def test_no_dependencies(self):
        ctx = _make_ctx([])
        result = await get_dependencies(ctx, "arn:test")
        assert "No dependencies" in result

    @pytest.mark.asyncio
    async def test_depth_capped_at_5(self):
        ctx = _make_ctx([])
        result = await get_dependencies(ctx, "arn:test", depth=100)
        assert "No dependencies" in result


class TestGetNetworkPath:
    @pytest.mark.asyncio
    async def test_returns_path(self):
        ctx = _make_ctx([
            {
                "nodes": [
                    {"name": "src", "arn": "a", "labels": ["EC2Instance"]},
                    {"name": "dst", "arn": "b", "labels": ["EC2Instance"]},
                ],
                "relationships": ["RUNS_IN"],
            }
        ])
        result = await get_network_path(ctx, "arn:a", "arn:b")
        assert "Network path" in result
        assert "src" in result

    @pytest.mark.asyncio
    async def test_no_path(self):
        ctx = _make_ctx([])
        result = await get_network_path(ctx, "arn:a", "arn:b")
        assert "No path found" in result


class TestGetAccountSummary:
    @pytest.mark.asyncio
    async def test_returns_summary(self):
        summary_data = [
            {"label": "EC2Instance", "count": 10},
            {"label": "VPC", "count": 3},
        ]
        ctx = _make_ctx([])
        ctx.request_context.lifespan_context.neo4j.query = (
            AsyncMock(side_effect=[
                summary_data,  # summary query runs first
                [],  # load_account_names (called after results)
            ])
        )
        result = await get_account_summary(ctx, "123")
        assert "Account 123" in result
        assert "13 total" in result
        assert "EC2Instance: 10" in result

    @pytest.mark.asyncio
    async def test_no_resources(self):
        ctx = _make_ctx([])
        result = await get_account_summary(ctx)
        assert "No resources" in result
