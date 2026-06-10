"""Tests for infra_agent.agent — InfraAgent core."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from infra_agent.agent import (
    InfraAgent,
    _is_connection_error,
    _is_rate_limit,
    _to_pydantic_messages,
)
from infra_agent.config import Settings
from infra_agent.models import Message, MessageRole


def _make_settings(**overrides) -> Settings:
    """Create a Settings instance with test defaults."""
    defaults = {
        "LITELLM_API_KEY": SecretStr("sk-test-key"),
        "MCP_SERVER_URL": "http://localhost:8000/mcp",
        "LITELLM_MODEL": "gpt-4o",
        "SYSTEM_PROMPT_PATH": "/nonexistent/prompt.md",
    }
    defaults.update(overrides)
    return Settings(**defaults)


class TestInfraAgentInit:
    """Verify InfraAgent construction."""

    def test_creates_agent_with_settings(self) -> None:
        settings = _make_settings()
        agent = InfraAgent(settings)

        assert agent._connected is False
        assert agent._agent is not None
        assert agent._mcp_server is not None


class TestConnect:
    """Verify MCP server connection with retry logic."""

    async def test_connect_success_first_attempt(self) -> None:
        settings = _make_settings()
        agent = InfraAgent(settings)
        agent._mcp_server.__aenter__ = AsyncMock()

        await agent.connect()

        assert agent._connected is True
        agent._mcp_server.__aenter__.assert_awaited_once()

    async def test_connect_retries_on_failure(self) -> None:
        settings = _make_settings()
        agent = InfraAgent(settings)

        call_count = 0

        async def flaky_enter():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise OSError("Connection refused")
            return agent._mcp_server

        agent._mcp_server.__aenter__ = flaky_enter

        with patch("infra_agent.agent.asyncio.sleep", new_callable=AsyncMock):
            await agent.connect()

        assert agent._connected is True
        assert call_count == 3

    async def test_connect_raises_after_max_attempts(self) -> None:
        settings = _make_settings()
        agent = InfraAgent(settings)
        agent._mcp_server.__aenter__ = AsyncMock(
            side_effect=OSError("Connection refused")
        )

        with (
            patch("infra_agent.agent.asyncio.sleep", new_callable=AsyncMock),
            pytest.raises(ConnectionError, match="Failed to connect"),
        ):
            await agent.connect()

        assert agent._connected is False


class TestDisconnect:
    """Verify clean MCP server disconnection."""

    async def test_disconnect_when_connected(self) -> None:
        settings = _make_settings()
        agent = InfraAgent(settings)
        agent._connected = True
        agent._mcp_server.__aexit__ = AsyncMock()

        await agent.disconnect()

        assert agent._connected is False
        agent._mcp_server.__aexit__.assert_awaited_once()

    async def test_disconnect_noop_when_not_connected(self) -> None:
        settings = _make_settings()
        agent = InfraAgent(settings)
        agent._mcp_server.__aexit__ = AsyncMock()

        await agent.disconnect()

        assert agent._connected is False
        agent._mcp_server.__aexit__.assert_not_awaited()


class TestChat:
    """Verify chat method returns response and tool summaries."""

    async def test_chat_returns_response_text(self) -> None:
        settings = _make_settings()
        agent = InfraAgent(settings)

        mock_result = MagicMock()
        mock_result.output = "There are 3 EC2 instances."
        mock_result.all_messages.return_value = []

        agent._agent.run = AsyncMock(return_value=mock_result)

        text, summaries, _usage = await agent.chat("How many EC2 instances?", [])

        assert text == "There are 3 EC2 instances."
        assert summaries == []

    async def test_chat_handles_connection_error(self) -> None:
        settings = _make_settings()
        agent = InfraAgent(settings)
        agent._agent.run = AsyncMock(
            side_effect=OSError("Connection refused")
        )

        text, summaries, _usage = await agent.chat("test", [])

        assert "temporarily unavailable" in text
        assert summaries == []

    async def test_chat_handles_generic_error(self) -> None:
        settings = _make_settings()
        agent = InfraAgent(settings)
        agent._agent.run = AsyncMock(
            side_effect=ValueError("Unexpected error")
        )

        text, summaries, _usage = await agent.chat("test", [])

        assert "went wrong" in text
        assert summaries == []

    async def test_chat_retries_on_rate_limit(self) -> None:
        settings = _make_settings()
        agent = InfraAgent(settings)

        mock_result = MagicMock()
        mock_result.output = "Retried successfully."
        mock_result.all_messages.return_value = []

        agent._agent.run = AsyncMock(
            side_effect=[Exception("Rate limit exceeded (429)"), mock_result]
        )

        with patch("infra_agent.agent.asyncio.sleep", new_callable=AsyncMock):
            text, summaries, _usage = await agent.chat("test", [])

        assert text == "Retried successfully."


class TestMessageConversion:
    """Verify domain Message → pydantic-ai ModelMessage conversion."""

    def test_converts_user_message(self) -> None:
        msgs = [Message(role=MessageRole.USER, content="Hello")]
        result = _to_pydantic_messages(msgs)

        assert len(result) == 1
        assert result[0].parts[0].content == "Hello"

    def test_converts_agent_message(self) -> None:
        msgs = [Message(role=MessageRole.AGENT, content="Hi there")]
        result = _to_pydantic_messages(msgs)

        assert len(result) == 1
        assert result[0].parts[0].content == "Hi there"

    def test_empty_history(self) -> None:
        result = _to_pydantic_messages([])
        assert result == []


class TestErrorClassifiers:
    """Verify rate-limit and connection error detection helpers."""

    def test_rate_limit_detection(self) -> None:
        assert _is_rate_limit(Exception("Rate limit exceeded")) is True
        assert _is_rate_limit(Exception("Error 429: too many requests")) is True
        assert _is_rate_limit(Exception("Something else")) is False

    def test_connection_error_detection(self) -> None:
        assert _is_connection_error(Exception("Connection refused")) is True
        assert _is_connection_error(Exception("connect error")) is True
        assert _is_connection_error(Exception("Host unreachable")) is True
        assert _is_connection_error(Exception("Bad request")) is False
