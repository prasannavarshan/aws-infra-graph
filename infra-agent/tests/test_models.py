"""Tests for infra_agent.models."""

from datetime import UTC, datetime

from infra_agent.models import (
    HealthStatus,
    Message,
    MessageRole,
    Session,
    ToolCallSummary,
)


class TestMessageRole:
    """Verify MessageRole enum values."""

    def test_values(self) -> None:
        assert MessageRole.USER == "user"
        assert MessageRole.AGENT == "agent"


class TestToolCallSummary:
    """Verify ToolCallSummary construction and serialization."""

    def test_round_trip(self) -> None:
        tc = ToolCallSummary(
            tool_name="list_vpcs",
            arguments={"region": "us-east-1"},
            result_summary="Found 3 VPCs",
            duration_ms=120,
            success=True,
        )
        data = tc.model_dump()
        assert data["tool_name"] == "list_vpcs"
        assert data["success"] is True
        assert ToolCallSummary.model_validate(data) == tc


class TestMessage:
    """Verify Message defaults and construction."""

    def test_defaults(self) -> None:
        msg = Message(role=MessageRole.USER, content="hello")
        assert msg.tool_calls == []
        assert isinstance(msg.timestamp, datetime)
        assert msg.timestamp.tzinfo is not None

    def test_with_tool_calls(self) -> None:
        tc = ToolCallSummary(
            tool_name="t",
            arguments={},
            result_summary="ok",
            duration_ms=10,
            success=True,
        )
        msg = Message(
            role=MessageRole.AGENT,
            content="done",
            tool_calls=[tc],
        )
        assert len(msg.tool_calls) == 1


class TestSession:
    """Verify Session construction."""

    def test_minimal(self) -> None:
        now = datetime.now(UTC)
        s = Session(
            session_id="abc-123",
            user=None,
            created_at=now,
            last_active=now,
        )
        assert s.messages == []
        assert s.user is None

    def test_with_user(self) -> None:
        now = datetime.now(UTC)
        s = Session(
            session_id="abc-123",
            user="alice@example.com",
            created_at=now,
            last_active=now,
        )
        assert s.user == "alice@example.com"


class TestHealthStatus:
    """Verify HealthStatus construction."""

    def test_healthy(self) -> None:
        h = HealthStatus(
            status="ok", mcp_server=True, litellm_reachable=True
        )
        assert h.status == "ok"

    def test_degraded(self) -> None:
        h = HealthStatus(
            status="degraded", mcp_server=False, litellm_reachable=True
        )
        assert h.mcp_server is False
