"""API request and response schemas for the infra-agent REST endpoints."""

from datetime import datetime

from pydantic import BaseModel, Field

from infra_agent.models import Message, ToolCallSummary, TokenUsage


class ChatRequest(BaseModel):
    """Incoming chat request from a client.

    Attributes:
        message: The user's message text (must not be empty).
        session_id: Optional session ID to continue a conversation.
    """

    message: str = Field(min_length=1)
    session_id: str | None = None


class ChatResponse(BaseModel):
    """Response returned after a chat completion.

    Attributes:
        response: The agent's reply text.
        session_id: Session ID for this conversation.
        tool_calls: Tool calls made while generating the response.
        usage: Token usage statistics for this response.
    """

    response: str
    session_id: str
    tool_calls: list[ToolCallSummary]
    usage: TokenUsage | None = None


class SessionHistoryResponse(BaseModel):
    """Full conversation history for a session.

    Attributes:
        session_id: Session identifier.
        user: Authenticated user identity, if available.
        messages: Ordered list of messages in the session.
        created_at: When the session was created.
    """

    session_id: str
    user: str | None
    messages: list[Message]
    created_at: datetime


class ErrorResponse(BaseModel):
    """Standard error response body.

    Attributes:
        error: Short error description.
        detail: Optional additional detail.
    """

    error: str
    detail: str | None = None
