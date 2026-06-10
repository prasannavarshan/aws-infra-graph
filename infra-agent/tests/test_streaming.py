"""Tests for infra_agent.api.streaming — SSE event generation."""

import json
from unittest.mock import AsyncMock

from pydantic import SecretStr

from infra_agent.agent import InfraAgent
from infra_agent.api.streaming import stream_chat_response
from infra_agent.config import Settings
from infra_agent.models import ToolCallSummary, TokenUsage


def _make_agent() -> InfraAgent:
    settings = Settings(
        LITELLM_API_KEY=SecretStr("sk-test"),
        MCP_SERVER_URL="http://localhost:8000/mcp",
    )
    return InfraAgent(settings)


class TestStreamChatResponse:
    """stream_chat_response yields correct SSE event sequence."""

    async def test_yields_text_then_done_for_simple_response(self) -> None:
        agent = _make_agent()
        agent.chat = AsyncMock(return_value=("Hello world", [], TokenUsage()))

        events = []
        async for event in stream_chat_response(agent, "Hi", [], "sess-1"):
            events.append(event)

        assert len(events) == 2

        # First event: text
        assert events[0]["event"] == "text"
        text_data = json.loads(events[0]["data"])
        assert text_data["chunk"] == "Hello world"

        # Last event: done
        assert events[1]["event"] == "done"
        done_data = json.loads(events[1]["data"])
        assert done_data["response"] == "Hello world"
        assert done_data["session_id"] == "sess-1"
        assert done_data["tool_calls"] == []

    async def test_yields_tool_call_events_between_text_and_done(self) -> None:
        agent = _make_agent()
        tool = ToolCallSummary(
            tool_name="list_ec2",
            arguments={"region": "us-east-1"},
            result_summary="Found 3 instances",
            duration_ms=100,
            success=True,
        )
        agent.chat = AsyncMock(return_value=("Got 3 instances", [tool], TokenUsage()))

        events = []
        async for event in stream_chat_response(agent, "List EC2", [], "sess-2"):
            events.append(event)

        assert len(events) == 3
        assert events[0]["event"] == "text"
        assert events[1]["event"] == "tool_call"
        assert events[2]["event"] == "done"

        tc_data = json.loads(events[1]["data"])
        assert tc_data["tool_name"] == "list_ec2"
        assert tc_data["arguments"] == {"region": "us-east-1"}

    async def test_done_event_includes_all_tool_calls(self) -> None:
        agent = _make_agent()
        tools = [
            ToolCallSummary(
                tool_name="list_ec2",
                arguments={},
                result_summary="ok",
                duration_ms=50,
                success=True,
            ),
            ToolCallSummary(
                tool_name="list_vpcs",
                arguments={},
                result_summary="ok",
                duration_ms=30,
                success=True,
            ),
        ]
        agent.chat = AsyncMock(return_value=("Results", tools, TokenUsage()))

        events = []
        async for event in stream_chat_response(agent, "Query", [], "sess-3"):
            events.append(event)

        # text + 2 tool_calls + done = 4
        assert len(events) == 4

        done_data = json.loads(events[-1]["data"])
        assert len(done_data["tool_calls"]) == 2
        names = [tc["tool_name"] for tc in done_data["tool_calls"]]
        assert names == ["list_ec2", "list_vpcs"]
