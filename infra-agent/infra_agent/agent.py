"""PydanticAI agent core — wraps the LLM + MCP integration."""

import asyncio
import logging
import os
import time

from pydantic_ai import Agent
from pydantic_ai.mcp import MCPServerStreamableHTTP
from pydantic_ai.models.openai import OpenAIChatModel
from pydantic_ai.providers.litellm import LiteLLMProvider

from infra_agent.config import Settings
from infra_agent.models import Message, MessageRole, ToolCallSummary, TokenUsage
from infra_agent.prompt import load_system_prompt

logger = logging.getLogger(__name__)

_MAX_CONNECT_ATTEMPTS = 5
_RATE_LIMIT_DELAY_S = 2.0


class InfraAgent:
    """High-level wrapper around a PydanticAI agent connected to an MCP server.

    Args:
        settings: Application configuration.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._system_prompt = load_system_prompt(settings.SYSTEM_PROMPT_PATH)

        mcp_headers = {}
        if settings.MCP_AUTH_TOKEN:
            mcp_headers["Authorization"] = f"Bearer {settings.MCP_AUTH_TOKEN}"

        self._mcp_server = MCPServerStreamableHTTP(
            url=settings.MCP_SERVER_URL,
            headers=mcp_headers if mcp_headers else None,
        )

        # Configure LLM provider
        provider_kwargs: dict = {
            "api_key": settings.LITELLM_API_KEY.get_secret_value(),
        }
        if settings.LITELLM_BASE_URL:
            provider_kwargs["api_base"] = settings.LITELLM_BASE_URL

        model = OpenAIChatModel(
            settings.LITELLM_MODEL,
            provider=LiteLLMProvider(**provider_kwargs),
        )

        self._agent = Agent(
            model=model,
            system_prompt=self._system_prompt,
            toolsets=[self._mcp_server],
        )
        self._connected = False

    async def connect(self) -> None:
        """Connect to the MCP server with exponential backoff retry.

        Raises:
            ConnectionError: If all connection attempts fail.
        """
        delay = 1.0
        last_err: BaseException | None = None

        for attempt in range(1, _MAX_CONNECT_ATTEMPTS + 1):
            try:
                await self._mcp_server.__aenter__()
                self._connected = True
                logger.info("Connected to MCP server on attempt %d", attempt)
                return
            except Exception as exc:
                last_err = exc
                logger.warning(
                    "MCP connection attempt %d/%d failed: %s",
                    attempt,
                    _MAX_CONNECT_ATTEMPTS,
                    exc,
                )
                if attempt < _MAX_CONNECT_ATTEMPTS:
                    await asyncio.sleep(delay)
                    delay *= 2

        raise ConnectionError(
            f"Failed to connect to MCP server after {_MAX_CONNECT_ATTEMPTS} attempts: {last_err}"
        )

    async def disconnect(self) -> None:
        """Cleanly disconnect from the MCP server."""
        if self._connected:
            try:
                await self._mcp_server.__aexit__(None, None, None)
            except Exception as exc:
                logger.warning("Error disconnecting from MCP server: %s", exc)
            finally:
                self._connected = False
                logger.info("Disconnected from MCP server")

    async def chat(
        self,
        message: str,
        history: list[Message],
    ) -> tuple[str, list[ToolCallSummary], TokenUsage]:
        """Run the agent with a user message and conversation history.

        Args:
            message: The user's current message.
            history: Previous messages in the conversation.

        Returns:
            A tuple of (response_text, tool_call_summaries, token_usage).
        """
        pydantic_history = _to_pydantic_messages(history)

        try:
            result = await self._run_with_retry(message, pydantic_history)
        except ConnectionError as exc:
            logger.error("MCP connection error during chat: %s", exc)
            return (
                "The infrastructure data source is temporarily unavailable. "
                "Please try again in a moment.",
                [],
                TokenUsage(),
            )
        except Exception as exc:
            logger.error(
                "Agent run failed: [%s] %s", type(exc).__name__, exc
            )
            return (
                f"Something went wrong: {type(exc).__name__}: {exc}",
                [],
                TokenUsage(),
            )

        tool_summaries = _extract_tool_summaries(result)
        usage = _extract_token_usage(result)

        return (result.output, tool_summaries, usage)

    async def _run_with_retry(
        self,
        message: str,
        pydantic_history: list,
    ):
        """Execute agent.run with a single retry on rate-limit errors.

        Args:
            message: User prompt text.
            pydantic_history: Converted message history.

        Returns:
            The AgentRunResult from pydantic-ai.

        Raises:
            ConnectionError: When MCP server is unreachable.
            Exception: On non-retryable LLM errors.
        """
        try:
            return await self._agent.run(
                message,
                message_history=pydantic_history or None,
            )
        except Exception as exc:
            logger.warning(
                "Agent.run raised [%s]: %s", type(exc).__name__, exc
            )
            if _is_rate_limit(exc):
                logger.warning("Rate-limited, retrying after %.1fs", _RATE_LIMIT_DELAY_S)
                await asyncio.sleep(_RATE_LIMIT_DELAY_S)
                return await self._agent.run(
                    message,
                    message_history=pydantic_history or None,
                )
            if _is_connection_error(exc):
                raise ConnectionError(str(exc)) from exc
            raise


def _to_pydantic_messages(history: list[Message]) -> list:
    """Convert domain Message objects to pydantic-ai ModelMessage format.

    Args:
        history: List of domain Message objects.

    Returns:
        List suitable for pydantic-ai message_history parameter.
    """
    from pydantic_ai.messages import (
        ModelRequest,
        ModelResponse,
        TextPart,
        UserPromptPart,
    )

    messages = []
    for msg in history:
        if msg.role == MessageRole.USER:
            messages.append(
                ModelRequest(parts=[UserPromptPart(content=msg.content)])
            )
        elif msg.role == MessageRole.AGENT:
            messages.append(
                ModelResponse(parts=[TextPart(content=msg.content)])
            )
    return messages


def _extract_tool_summaries(result) -> list[ToolCallSummary]:
    """Extract tool call summaries from an AgentRunResult.

    Args:
        result: The AgentRunResult from pydantic-ai.

    Returns:
        List of ToolCallSummary objects.
    """
    from pydantic_ai.messages import ToolCallPart, ToolReturnPart

    summaries: list[ToolCallSummary] = []
    tool_call_starts: dict[str, float] = {}

    for msg in result.all_messages():
        if hasattr(msg, "parts"):
            for part in msg.parts:
                if isinstance(part, ToolCallPart):
                    tool_call_starts[part.tool_call_id] = time.monotonic()
                elif isinstance(part, ToolReturnPart):
                    start = tool_call_starts.pop(part.tool_call_id, None)
                    duration_ms = (
                        int((time.monotonic() - start) * 1000) if start else 0
                    )
                    content = str(part.content)
                    summaries.append(
                        ToolCallSummary(
                            tool_name=part.tool_name,
                            arguments={},
                            result_summary=content[:200],
                            duration_ms=duration_ms,
                            success=True,
                        )
                    )
    return summaries


def _is_rate_limit(exc: Exception) -> bool:
    """Check if an exception indicates a rate-limit error."""
    msg = str(exc).lower()
    return "rate" in msg and "limit" in msg or "429" in msg


def _extract_token_usage(result) -> TokenUsage:
    """Extract token usage from an AgentRunResult.

    Args:
        result: The AgentRunResult from pydantic-ai.

    Returns:
        TokenUsage with input/output/total token counts.
    """
    try:
        usage = result.usage()
        return TokenUsage(
            input_tokens=usage.request_tokens or 0,
            output_tokens=usage.response_tokens or 0,
            total_tokens=(usage.request_tokens or 0) + (usage.response_tokens or 0),
        )
    except Exception:
        return TokenUsage()


def _is_connection_error(exc: Exception) -> bool:
    """Check if an exception indicates a connection failure to MCP server."""
    msg = str(exc).lower()
    # Only match clear MCP/network failures, not LLM API retries
    return any(
        term in msg
        for term in ("connection refused", "unreachable", "connect error")
    ) or isinstance(exc, (OSError, ConnectionRefusedError))
