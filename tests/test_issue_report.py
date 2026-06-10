"""Tests for the issue reporting MCP tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.tools.issue_report import close_issue, list_issues, report_issue


def _make_ctx(query_results: list | None = None) -> MagicMock:
    """Create a mock MCP Context with a Neo4j client."""
    neo4j = AsyncMock()
    neo4j.query = AsyncMock(return_value=query_results or [])

    app_ctx = MagicMock()
    app_ctx.neo4j = neo4j

    ctx = MagicMock()
    ctx.request_context.lifespan_context = app_ctx
    return ctx


def _make_ctx_fn(query_fn) -> MagicMock:
    """Create a mock MCP Context with a custom query function."""
    neo4j = AsyncMock()
    neo4j.query = AsyncMock(side_effect=query_fn)

    app_ctx = MagicMock()
    app_ctx.neo4j = neo4j

    ctx = MagicMock()
    ctx.request_context.lifespan_context = app_ctx
    return ctx


class TestReportIssue:
    """Tests for the report_issue tool."""

    @pytest.mark.asyncio
    async def test_report_issue_creates_node(self):
        """Happy path: creates ToolIssue node with correct fields."""
        ctx = _make_ctx([{"id": "issue-20260325-120000"}])
        result = await report_issue(
            ctx,
            tool_name="find_resources",
            description="Returned zero results for EC2 in us-west-2",
            severity="high",
            query_context="account=sling-prod, type=EC2Instance",
        )
        assert "issue-" in result
        assert "find_resources" in result
        assert "high" in result

        neo4j = ctx.request_context.lifespan_context.neo4j
        neo4j.query.assert_called_once()
        params = neo4j.query.call_args[0][1]
        assert params["tool_name"] == "find_resources"
        assert params["description"] == "Returned zero results for EC2 in us-west-2"
        assert params["severity"] == "high"
        assert params["query_context"] == "account=sling-prod, type=EC2Instance"

    @pytest.mark.asyncio
    async def test_report_issue_default_severity(self):
        """Edge case: omitting severity defaults to medium."""
        ctx = _make_ctx([{"id": "issue-20260325-120001"}])
        result = await report_issue(
            ctx,
            tool_name="trace_dns",
            description="DNS trace timed out unexpectedly",
        )
        assert "medium" in result
        params = ctx.request_context.lifespan_context.neo4j.query.call_args[0][1]
        assert params["severity"] == "medium"

    @pytest.mark.asyncio
    async def test_report_issue_empty_tool_name(self):
        """Error case: empty tool_name returns error."""
        ctx = _make_ctx()
        result = await report_issue(ctx, tool_name="", description="something broke")
        assert "Error" in result
        assert "tool_name" in result
        ctx.request_context.lifespan_context.neo4j.query.assert_not_called()

    @pytest.mark.asyncio
    async def test_report_issue_empty_description(self):
        """Error case: empty description returns error."""
        ctx = _make_ctx()
        result = await report_issue(ctx, tool_name="find_resources", description="")
        assert "Error" in result
        assert "description" in result
        ctx.request_context.lifespan_context.neo4j.query.assert_not_called()

    @pytest.mark.asyncio
    async def test_report_issue_invalid_severity(self):
        """Error case: invalid severity returns error with valid options."""
        ctx = _make_ctx()
        result = await report_issue(
            ctx, tool_name="find_resources",
            description="bad", severity="critical",
        )
        assert "Error" in result
        assert "invalid severity" in result
        assert "high" in result
        ctx.request_context.lifespan_context.neo4j.query.assert_not_called()


class TestListIssues:
    """Tests for the list_issues tool."""

    @pytest.mark.asyncio
    async def test_list_open_issues(self):
        """Happy path: returns formatted list of open issues."""
        async def _query(cypher: str, params=None):
            return [
                {
                    "id": "issue-20260325-120000",
                    "tool_name": "find_resources",
                    "description": "Missing EC2 instances in us-west-2",
                    "severity": "high",
                    "status": "open",
                    "query_context": "account=sling-prod",
                    "created_at": "2026-03-25T12:00:00Z",
                },
            ]

        ctx = _make_ctx_fn(_query)
        result = await list_issues(ctx, status="open")
        assert "issue-20260325-120000" in result
        assert "find_resources" in result
        assert "HIGH" in result
        assert "Missing EC2 instances" in result
        assert "account=sling-prod" in result

    @pytest.mark.asyncio
    async def test_list_issues_filter_by_tool(self):
        """Edge case: tool_name filter is passed as query param."""
        ctx = _make_ctx([])
        result = await list_issues(ctx, status="open", tool_name="trace_dns")
        assert "No open issues found" in result
        params = ctx.request_context.lifespan_context.neo4j.query.call_args[0][1]
        assert params.get("tool_name") == "trace_dns"

    @pytest.mark.asyncio
    async def test_list_issues_no_results(self):
        """Edge case: empty result returns friendly message."""
        ctx = _make_ctx([])
        result = await list_issues(ctx, status="open")
        assert "No open issues found" in result

    @pytest.mark.asyncio
    async def test_list_issues_invalid_status(self):
        """Error case: invalid status returns error with valid options."""
        ctx = _make_ctx()
        result = await list_issues(ctx, status="pending")
        assert "Error" in result
        assert "invalid status" in result
        ctx.request_context.lifespan_context.neo4j.query.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_issues_all_status(self):
        """Edge case: status=all returns issues regardless of status."""
        async def _query(cypher: str, params=None):
            return [
                {
                    "id": "issue-20260325-120000",
                    "tool_name": "find_resources",
                    "description": "test",
                    "severity": "low",
                    "status": "closed",
                    "query_context": "",
                    "created_at": "2026-03-25T12:00:00Z",
                },
            ]

        ctx = _make_ctx_fn(_query)
        result = await list_issues(ctx, status="all")
        assert "Issues (1)" in result
        assert "status: all" in result


class TestCloseIssue:
    """Tests for the close_issue tool."""

    @pytest.mark.asyncio
    async def test_close_issue_success(self):
        """Happy path: open issue gets closed."""
        async def _query(cypher: str, params=None):
            return [{"id": "issue-20260325-120000"}]

        ctx = _make_ctx_fn(_query)
        result = await close_issue(ctx, issue_id="issue-20260325-120000")
        assert "closed" in result
        assert "issue-20260325-120000" in result

        neo4j = ctx.request_context.lifespan_context.neo4j
        params = neo4j.query.call_args[0][1]
        assert params["issue_id"] == "issue-20260325-120000"
        assert params["closed_at"] is not None

    @pytest.mark.asyncio
    async def test_close_issue_not_found(self):
        """Edge case: non-existent or already-closed issue returns message."""
        ctx = _make_ctx([])
        result = await close_issue(ctx, issue_id="issue-nonexistent")
        assert "No open issue found" in result

    @pytest.mark.asyncio
    async def test_close_issue_empty_id(self):
        """Error case: empty issue_id returns error."""
        ctx = _make_ctx()
        result = await close_issue(ctx, issue_id="")
        assert "Error" in result
        assert "issue_id" in result
        ctx.request_context.lifespan_context.neo4j.query.assert_not_called()
