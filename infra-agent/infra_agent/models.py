"""Core domain models for the infra-agent."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class MessageRole(StrEnum):
    """Role of a message participant."""

    USER = "user"
    AGENT = "agent"


class ToolCallSummary(BaseModel):
    """Summary of a single MCP tool invocation.

    Attributes:
        tool_name: Name of the tool that was called.
        arguments: Arguments passed to the tool.
        result_summary: Short summary of the tool result.
        duration_ms: Execution time in milliseconds.
        success: Whether the tool call succeeded.
    """

    tool_name: str
    arguments: dict
    result_summary: str
    duration_ms: int
    success: bool


class Message(BaseModel):
    """A single message in a conversation session.

    Attributes:
        role: Who sent the message (user or agent).
        content: Text content of the message.
        tool_calls: Tool calls made during this message (agent only).
        timestamp: When the message was created.
    """

    role: MessageRole
    content: str
    tool_calls: list[ToolCallSummary] = []
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC)
    )


class Session(BaseModel):
    """A conversation session between a user and the agent.

    Attributes:
        session_id: Unique identifier for the session.
        user: Authenticated user identity, if available.
        messages: Ordered list of messages in the session.
        created_at: When the session was created.
        last_active: When the session was last used.
    """

    session_id: str
    user: str | None
    messages: list[Message] = []
    created_at: datetime
    last_active: datetime


class HealthStatus(BaseModel):
    """Health check response for the /health endpoint.

    Attributes:
        status: Overall status string (e.g. "ok", "degraded").
        mcp_server: Whether the MCP server is reachable.
        litellm_reachable: Whether the LiteLLM API is reachable.
    """

    status: str
    mcp_server: bool
    litellm_reachable: bool


class TokenUsage(BaseModel):
    """Token usage statistics for a single agent response.

    Attributes:
        input_tokens: Tokens in the prompt/context.
        output_tokens: Tokens in the response.
        total_tokens: Sum of input and output tokens.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
