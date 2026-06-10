"""SSE stream handler — converts agent responses into Server-Sent Event payloads."""

import logging
from collections.abc import AsyncIterator

from infra_agent.agent import InfraAgent
from infra_agent.api.events import DoneEvent, TextChunkEvent, ToolCallEvent
from infra_agent.models import Message

logger = logging.getLogger(__name__)


async def stream_chat_response(
    agent: InfraAgent,
    message: str,
    history: list[Message],
    session_id: str,
) -> AsyncIterator[dict]:
    """Run the agent and yield SSE event dicts for the response.

    Executes agent.chat() and emits the result as a sequence of SSE events:
    1. A ``text`` event with the full response text.
    2. A ``tool_call`` event for each tool invocation.
    3. A ``done`` event with the complete response and metadata.

    Args:
        agent: The InfraAgent instance.
        message: The user's message text.
        history: Previous messages in the conversation.
        session_id: Session identifier for this conversation.

    Yields:
        Dicts with ``event`` and ``data`` keys suitable for EventSourceResponse.
    """
    response_text, tool_calls, _usage = await agent.chat(message, history)

    # 1. Emit text chunk
    text_event = TextChunkEvent(chunk=response_text)
    yield {"event": text_event.type, "data": text_event.model_dump_json()}

    # 2. Emit tool call events
    for tc in tool_calls:
        tool_event = ToolCallEvent(tool_name=tc.tool_name, arguments=tc.arguments)
        yield {"event": tool_event.type, "data": tool_event.model_dump_json()}

    # 3. Emit done event
    done_event = DoneEvent(
        response=response_text,
        session_id=session_id,
        tool_calls=tool_calls,
    )
    yield {"event": done_event.type, "data": done_event.model_dump_json()}
