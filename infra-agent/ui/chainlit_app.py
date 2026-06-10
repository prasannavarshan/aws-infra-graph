"""Chainlit chat interface for the infra-agent.

Runs the PydanticAI agent directly in-process with streaming,
so text appears word-by-word and tool calls show in real-time.

Run with: chainlit run ui/chainlit_app.py
"""

import sys
from pathlib import Path

# Ensure infra_agent package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import chainlit as cl

from infra_agent.agent import InfraAgent
from infra_agent.config import Settings
from infra_agent.logging_config import setup_logging
from infra_agent.models import Message, MessageRole, TokenUsage


_agent: InfraAgent | None = None


@cl.on_chat_start
async def on_start():
    """Initialize agent on first chat and show welcome message."""
    global _agent

    if _agent is None:
        settings = Settings()
        setup_logging(settings.LOG_LEVEL)
        _agent = InfraAgent(settings)
        await _agent.connect()

    cl.user_session.set("history", [])
    await cl.Message(
        content=(
            "👋 Hi! I'm your **AWS infrastructure assistant**. "
            "I'm connected to a live knowledge graph of your org's AWS resources.\n\n"
            "Try asking things like:\n"
            "- *What accounts are in the org?*\n"
            "- *Can EKS in prod reach RDS in staging on port 5432?*\n"
            "- *Show me open security groups*\n"
            "- *Trace the route from 10.10.1.5 to 10.20.1.5*"
        ),
    ).send()


@cl.on_message
async def on_message(message: cl.Message):
    """Handle user message with streaming agent response."""
    global _agent

    if _agent is None:
        await cl.Message(content="❌ Agent not initialized. Refresh the page.").send()
        return

    history: list[Message] = cl.user_session.get("history", [])

    # Convert history to pydantic-ai format
    from infra_agent.agent import _to_pydantic_messages
    pydantic_history = _to_pydantic_messages(history)

    # Create the response message for streaming
    response_msg = cl.Message(content="")
    await response_msg.send()

    try:
        async with _agent._agent.run_stream(
            message.content,
            message_history=pydantic_history or None,
        ) as stream:
            # Stream text tokens as they arrive
            async for chunk in stream.stream_text(delta=True):
                await response_msg.stream_token(chunk)

        # Get the final result after streaming completes
        output = await stream.get_output()

        # Extract tool call summaries
        from infra_agent.agent import _extract_tool_summaries, _extract_token_usage
        tool_summaries = _extract_tool_summaries(stream)
        usage = _extract_token_usage(stream)

        # Display tool calls as steps
        for tc in tool_summaries:
            status = "✅" if tc.success else "❌"
            async with cl.Step(
                name=f"{status} {tc.tool_name}",
                type="tool",
            ) as step:
                step.input = tc.arguments
                step.output = tc.result_summary
                if tc.duration_ms:
                    step.output += f"\n\n⏱ {tc.duration_ms}ms"

        # Append token usage footer
        if usage.total_tokens > 0:
            await response_msg.stream_token(
                f"\n\n---\n"
                f"📊 *Tokens — in: {usage.input_tokens:,} · "
                f"out: {usage.output_tokens:,} · "
                f"total: {usage.total_tokens:,}*"
            )

        # Finalize the streamed message
        await response_msg.update()

        # Save to history
        history.append(Message(role=MessageRole.USER, content=message.content))
        history.append(Message(
            role=MessageRole.AGENT,
            content=output,
            tool_calls=tool_summaries,
        ))
        cl.user_session.set("history", history)

    except Exception as exc:
        response_msg.content = f"❌ {type(exc).__name__}: {exc}"
        await response_msg.update()
