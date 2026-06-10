"""Tests for the org knowledge feedback MCP tools."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.tools.feedback import (
    get_org_knowledge,
    review_org_knowledge,
    save_org_knowledge,
)


def _make_ctx(query_results: list | None = None) -> MagicMock:
    """Create a mock MCP Context with a Neo4j client.

    Args:
        query_results: Default list to return from neo4j.query().
    """
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


class TestSaveFeedback:
    """Tests for the save_org_knowledge tool."""

    @pytest.mark.asyncio
    async def test_save_feedback_creates_pending(self):
        """Happy path: saves feedback with pending status."""
        ctx = _make_ctx([{"id": "fb-20260222-001"}])
        result = await save_org_knowledge(
            ctx,
            content="payments = Payments Service team",
            category="acronym",
        )
        assert "Org knowledge saved as pending" in result
        assert "acronym" in result

        neo4j = ctx.request_context.lifespan_context.neo4j
        neo4j.query.assert_called_once()
        call_args = neo4j.query.call_args
        params = call_args[0][1]
        assert params["content"] == "payments = Payments Service team"
        assert params["category"] == "acronym"
        assert "pending" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_save_feedback_default_category(self):
        """Edge case: omitting category defaults to general."""
        ctx = _make_ctx([{"id": "fb-20260222-002"}])
        result = await save_org_knowledge(
            ctx,
            content="Some general knowledge",
        )
        assert "Org knowledge saved as pending" in result
        assert "general" in result

        params = (
            ctx.request_context.lifespan_context
            .neo4j.query.call_args[0][1]
        )
        assert params["category"] == "general"

    @pytest.mark.asyncio
    async def test_save_feedback_empty_content_error(self):
        """Error case: empty content returns error."""
        ctx = _make_ctx()
        result = await save_org_knowledge(ctx, content="")
        assert "Error" in result
        assert "empty" in result

        neo4j = ctx.request_context.lifespan_context.neo4j
        neo4j.query.assert_not_called()

    @pytest.mark.asyncio
    async def test_save_feedback_invalid_category(self):
        """Error case: invalid category returns error."""
        ctx = _make_ctx()
        result = await save_org_knowledge(
            ctx, content="test", category="bogus",
        )
        assert "Error" in result
        assert "invalid category" in result
        neo4j = ctx.request_context.lifespan_context.neo4j
        neo4j.query.assert_not_called()


class TestReviewList:
    """Tests for review_org_knowledge with action=list."""

    @pytest.mark.asyncio
    async def test_review_list_pending(self):
        """Happy path: returns formatted list of pending entries."""
        async def _query(cypher: str, params=None):
            return [
                {
                    "id": "fb-20260222-001",
                    "content": "payments = Payments Service",
                    "category": "acronym",
                    "created_at": "2026-02-22T00:45:00Z",
                },
            ]

        ctx = _make_ctx_fn(_query)
        result = await review_org_knowledge(ctx, action="list")
        assert "Pending feedback (1)" in result
        assert "fb-20260222-001" in result
        assert "payments = Payments Service" in result
        assert "acronym" in result

    @pytest.mark.asyncio
    async def test_review_list_empty(self):
        """Edge case: no pending entries returns friendly message."""
        ctx = _make_ctx([])
        result = await review_org_knowledge(ctx, action="list")
        assert "No pending feedback" in result


class TestReviewApprove:
    """Tests for review_org_knowledge with action=approve."""

    @pytest.mark.asyncio
    async def test_review_approve_updates_neo4j(self):
        """Happy path: status set to approved, reviewed_at set."""
        async def _query(cypher: str, params=None):
            if "SET" in cypher:
                return [
                    {
                        "id": "fb-20260222-001",
                        "content": "payments = Payments Service",
                        "category": "acronym",
                    },
                ]
            return []

        ctx = _make_ctx_fn(_query)
        with patch(
            "src.tools.feedback._append_to_org_knowledge",
        ):
            result = await review_org_knowledge(
                ctx, action="approve", ids="fb-20260222-001",
            )

        assert "Approved 1 entry(s)" in result
        assert "fb-20260222-001" in result
        assert "ORG_KNOWLEDGE.md" in result

        neo4j = ctx.request_context.lifespan_context.neo4j
        call_args = neo4j.query.call_args
        cypher = call_args[0][0]
        params = call_args[0][1]
        assert "approved" in cypher
        assert params["reviewed_at"] is not None

    @pytest.mark.asyncio
    async def test_review_approve_writes_to_file(self, tmp_path):
        """Happy path: content appended under correct category."""
        async def _query(cypher: str, params=None):
            if "SET" in cypher:
                return [
                    {
                        "id": "fb-001",
                        "content": "payments = Payments Service",
                        "category": "acronym",
                    },
                ]
            return []

        # Create a temporary ORG_KNOWLEDGE.md
        tmp_file = tmp_path / "ORG_KNOWLEDGE.md"
        tmp_file.write_text(
            "# Org Knowledge\n\n"
            "## Acronyms\n\n"
            "## Services\n\n"
            "## General\n",
            encoding="utf-8",
        )

        ctx = _make_ctx_fn(_query)
        with patch(
            "src.tools.feedback.ORG_KNOWLEDGE_PATH",
            tmp_file,
        ):
            await review_org_knowledge(
                ctx, action="approve", ids="fb-001",
            )

        text = tmp_file.read_text(encoding="utf-8")
        # Entry should appear between Acronyms and Services
        acronym_idx = text.index("## Acronyms")
        services_idx = text.index("## Services")
        entry_idx = text.index("- payments = Payments Service")
        assert acronym_idx < entry_idx < services_idx

    @pytest.mark.asyncio
    async def test_review_approve_missing_ids(self):
        """Error case: approve without ids returns error."""
        ctx = _make_ctx()
        result = await review_org_knowledge(
            ctx, action="approve", ids="",
        )
        assert "Error" in result
        assert "ids required" in result


class TestReviewReject:
    """Tests for review_org_knowledge with action=reject."""

    @pytest.mark.asyncio
    async def test_review_reject_no_file_write(self):
        """Happy path: status set to rejected, no file write."""
        async def _query(cypher: str, params=None):
            if "SET" in cypher:
                return [{"id": "fb-20260222-001"}]
            return []

        ctx = _make_ctx_fn(_query)
        with patch(
            "src.tools.feedback._append_to_org_knowledge",
        ) as mock_append:
            result = await review_org_knowledge(
                ctx, action="reject", ids="fb-20260222-001",
            )
            mock_append.assert_not_called()

        assert "Rejected 1 entry(s)" in result
        assert "fb-20260222-001" in result

    @pytest.mark.asyncio
    async def test_review_reject_not_found(self):
        """Edge case: reject non-existent ID returns message."""
        ctx = _make_ctx([])
        result = await review_org_knowledge(
            ctx, action="reject", ids="fb-nonexistent",
        )
        assert "No pending feedback found" in result


class TestReviewInvalidAction:
    """Tests for review_org_knowledge with unknown action."""

    @pytest.mark.asyncio
    async def test_review_invalid_action(self):
        """Error case: unknown action returns error."""
        ctx = _make_ctx()
        result = await review_org_knowledge(
            ctx, action="delete",
        )
        assert "Error" in result
        assert "unknown action" in result
        assert "list, approve, reject" in result


class TestGetOrgKnowledge:
    """Tests for the get_org_knowledge tool."""

    @pytest.mark.asyncio
    async def test_returns_file_contents(self, tmp_path):
        """Happy path: returns full file contents."""
        tmp_file = tmp_path / "ORG_KNOWLEDGE.md"
        tmp_file.write_text(
            "# Org Knowledge\n\n"
            "## Acronyms\n\n"
            "- payments = Payments Service\n\n"
            "## General\n",
            encoding="utf-8",
        )
        ctx = _make_ctx()
        with patch(
            "src.tools.feedback.ORG_KNOWLEDGE_PATH", tmp_file,
        ):
            result = await get_org_knowledge(ctx)
        assert "payments = Payments Service" in result
        assert "## Acronyms" in result

    @pytest.mark.asyncio
    async def test_file_not_found(self, tmp_path):
        """Edge case: file doesn't exist returns message."""
        missing = tmp_path / "MISSING.md"
        ctx = _make_ctx()
        with patch(
            "src.tools.feedback.ORG_KNOWLEDGE_PATH", missing,
        ):
            result = await get_org_knowledge(ctx)
        assert "No org knowledge file found" in result

    @pytest.mark.asyncio
    async def test_empty_file(self, tmp_path):
        """Edge case: empty file returns message."""
        tmp_file = tmp_path / "ORG_KNOWLEDGE.md"
        tmp_file.write_text("", encoding="utf-8")
        ctx = _make_ctx()
        with patch(
            "src.tools.feedback.ORG_KNOWLEDGE_PATH", tmp_file,
        ):
            result = await get_org_knowledge(ctx)
        assert "empty" in result
