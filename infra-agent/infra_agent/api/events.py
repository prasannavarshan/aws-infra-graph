"""Server-Sent Events (SSE) payload models for streaming responses."""

from typing import Literal

from pydantic import BaseModel

from infra_agent.models import ToolCallSummary


class TextChunkEvent(BaseModel):
    """A streamed text chunk from the agent.

    Attributes:
        type: Event discriminator, always "text".
        chunk: The text fragment.
    """

    type: Literal["text"] = "text"
    chunk: str


class ToolCallEvent(BaseModel):
    """Notification that the agent is invoking a tool.

    Attributes:
        type: Event discriminator, always "tool_call".
        tool_name: Name of the tool being called.
        arguments: Arguments passed to the tool.
    """

    type: Literal["tool_call"] = "tool_call"
    tool_name: str
    arguments: dict


class DoneEvent(BaseModel):
    """Final event signalling the stream is complete.

    Attributes:
        type: Event discriminator, always "done".
        response: The full assembled response text.
        session_id: Session ID for this conversation.
        tool_calls: All tool calls made during the response.
    """

    type: Literal["done"] = "done"
    response: str
    session_id: str
    tool_calls: list[ToolCallSummary]
