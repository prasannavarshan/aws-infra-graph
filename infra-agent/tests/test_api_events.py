"""Tests for infra_agent.api.events."""

from infra_agent.api.events import DoneEvent, TextChunkEvent, ToolCallEvent
from infra_agent.models import ToolCallSummary


class TestTextChunkEvent:
    """Verify TextChunkEvent defaults and serialization."""

    def test_type_literal(self) -> None:
        e = TextChunkEvent(chunk="hello")
        assert e.type == "text"

    def test_serialization(self) -> None:
        e = TextChunkEvent(chunk="world")
        data = e.model_dump()
        assert data == {"type": "text", "chunk": "world"}


class TestToolCallEvent:
    """Verify ToolCallEvent defaults and serialization."""

    def test_type_literal(self) -> None:
        e = ToolCallEvent(tool_name="list_vpcs", arguments={"r": "us-east-1"})
        assert e.type == "tool_call"

    def test_serialization(self) -> None:
        e = ToolCallEvent(tool_name="t", arguments={})
        data = e.model_dump()
        assert data["type"] == "tool_call"
        assert data["tool_name"] == "t"


class TestDoneEvent:
    """Verify DoneEvent defaults and serialization."""

    def test_type_literal(self) -> None:
        e = DoneEvent(response="done", session_id="s1", tool_calls=[])
        assert e.type == "done"

    def test_with_tool_calls(self) -> None:
        tc = ToolCallSummary(
            tool_name="t",
            arguments={},
            result_summary="ok",
            duration_ms=10,
            success=True,
        )
        e = DoneEvent(
            response="finished",
            session_id="s1",
            tool_calls=[tc],
        )
        data = e.model_dump()
        assert len(data["tool_calls"]) == 1
        assert data["type"] == "done"
