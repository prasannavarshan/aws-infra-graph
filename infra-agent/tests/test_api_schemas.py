"""Tests for infra_agent.api.schemas."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from infra_agent.api.schemas import (
    ChatRequest,
    ChatResponse,
    ErrorResponse,
    SessionHistoryResponse,
)
from infra_agent.models import Message, MessageRole, ToolCallSummary


class TestChatRequest:
    """Verify ChatRequest validation."""

    def test_valid_request(self) -> None:
        req = ChatRequest(message="What VPCs exist?")
        assert req.session_id is None

    def test_with_session_id(self) -> None:
        req = ChatRequest(message="hello", session_id="sess-1")
        assert req.session_id == "sess-1"

    def test_empty_message_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ChatRequest(message="")


class TestChatResponse:
    """Verify ChatResponse construction."""

    def test_round_trip(self) -> None:
        tc = ToolCallSummary(
            tool_name="t",
            arguments={},
            result_summary="ok",
            duration_ms=5,
            success=True,
        )
        resp = ChatResponse(
            response="Here are your VPCs",
            session_id="s1",
            tool_calls=[tc],
        )
        data = resp.model_dump()
        assert data["session_id"] == "s1"
        assert len(data["tool_calls"]) == 1


class TestSessionHistoryResponse:
    """Verify SessionHistoryResponse construction."""

    def test_with_messages(self) -> None:
        now = datetime.now(UTC)
        msg = Message(role=MessageRole.USER, content="hi")
        resp = SessionHistoryResponse(
            session_id="s1",
            user="bob",
            messages=[msg],
            created_at=now,
        )
        assert len(resp.messages) == 1
        assert resp.user == "bob"


class TestErrorResponse:
    """Verify ErrorResponse construction."""

    def test_minimal(self) -> None:
        err = ErrorResponse(error="not found")
        assert err.detail is None

    def test_with_detail(self) -> None:
        err = ErrorResponse(error="bad request", detail="missing field")
        assert err.detail == "missing field"
