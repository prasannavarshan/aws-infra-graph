"""API router with chat, session, and health endpoints."""

import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sse_starlette.sse import EventSourceResponse

from infra_agent.agent import InfraAgent
from infra_agent.api.auth import get_current_user
from infra_agent.api.schemas import (
    ChatRequest,
    ChatResponse,
    SessionHistoryResponse,
)
from infra_agent.api.streaming import stream_chat_response
from infra_agent.config import Settings
from infra_agent.models import HealthStatus, Message, MessageRole, ToolCallSummary
from infra_agent.sessions.manager import SessionManager

logger = logging.getLogger(__name__)


def create_router(
    agent: InfraAgent,
    session_manager: SessionManager,
    settings: Settings,
) -> APIRouter:
    """Factory that builds the API router with injected dependencies.

    Args:
        agent: The InfraAgent instance for chat processing.
        session_manager: Session lifecycle manager.
        settings: Application settings.

    Returns:
        A configured FastAPI APIRouter.
    """
    router = APIRouter()

    @router.post("/chat", response_model=ChatResponse)
    async def chat(
        body: ChatRequest,
        user: str = Depends(get_current_user),
    ) -> ChatResponse:
        """Process a chat message and return the agent's response.

        Creates a new session if no session_id is provided, or continues
        an existing conversation.

        Args:
            body: The chat request with message and optional session_id.
            user: Authenticated user identity from auth middleware.

        Returns:
            ChatResponse with the agent reply, session ID, and tool calls.
        """
        if body.session_id:
            session = session_manager.get_session(body.session_id)
            if session is None:
                session = session_manager.create_session(user=user)
        else:
            session = session_manager.create_session(user=user)

        response_text, tool_calls, usage = await agent.chat(
            body.message, session.messages
        )

        user_msg = Message(role=MessageRole.USER, content=body.message)
        agent_msg = Message(
            role=MessageRole.AGENT,
            content=response_text,
            tool_calls=tool_calls,
        )
        session_manager.add_turn(session.session_id, user_msg, agent_msg)

        return ChatResponse(
            response=response_text,
            session_id=session.session_id,
            tool_calls=tool_calls,
            usage=usage,
        )

    @router.post("/chat/stream")
    async def chat_stream(
        body: ChatRequest,
        user: str = Depends(get_current_user),
    ) -> EventSourceResponse:
        """Stream a chat response as Server-Sent Events.

        Creates or loads a session, streams the agent response, then
        persists the turn after streaming completes.

        Args:
            body: The chat request with message and optional session_id.
            user: Authenticated user identity from auth middleware.

        Returns:
            EventSourceResponse streaming text, tool_call, and done events.
        """
        if body.session_id:
            session = session_manager.get_session(body.session_id)
            if session is None:
                session = session_manager.create_session(user=user)
        else:
            session = session_manager.create_session(user=user)

        async def _event_generator():
            response_text = ""
            tool_calls = []

            async for event in stream_chat_response(
                agent, body.message, session.messages, session.session_id
            ):
                if event.get("event") == "done":
                    import json

                    done_data = json.loads(event["data"])
                    response_text = done_data["response"]
                    tool_calls = done_data["tool_calls"]
                yield event

            # Save turn after streaming completes
            user_msg = Message(role=MessageRole.USER, content=body.message)
            agent_msg = Message(
                role=MessageRole.AGENT,
                content=response_text,
                tool_calls=[
                    ToolCallSummary(**tc) if isinstance(tc, dict) else tc
                    for tc in tool_calls
                ],
            )
            session_manager.add_turn(session.session_id, user_msg, agent_msg)

        return EventSourceResponse(_event_generator())

    @router.get(
        "/sessions/{session_id}/history",
        response_model=SessionHistoryResponse,
    )
    async def get_session_history(
        session_id: str,
        user: str = Depends(get_current_user),
    ) -> SessionHistoryResponse:
        """Return the full conversation history for a session.

        Args:
            session_id: The session identifier.
            user: Authenticated user identity from auth middleware.

        Returns:
            SessionHistoryResponse with messages and metadata.

        Raises:
            HTTPException: 404 if session not found.
        """
        session = session_manager.get_session(session_id)
        if session is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session not found: {session_id}",
            )
        return SessionHistoryResponse(
            session_id=session.session_id,
            user=session.user,
            messages=session.messages,
            created_at=session.created_at,
        )

    @router.delete("/sessions/{session_id}", status_code=status.HTTP_200_OK)
    async def delete_session(
        session_id: str,
        user: str = Depends(get_current_user),
    ) -> dict[str, str]:
        """Delete a session by ID.

        Args:
            session_id: The session to remove.
            user: Authenticated user identity from auth middleware.

        Returns:
            Confirmation message.

        Raises:
            HTTPException: 404 if session not found.
        """
        deleted = session_manager.delete_session(session_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session not found: {session_id}",
            )
        return {"detail": f"Session {session_id} deleted"}

    @router.get("/health", response_model=HealthStatus)
    async def health() -> HealthStatus:
        """Return health status of the agent and its dependencies.

        Checks MCP server connectivity and LiteLLM reachability.
        No authentication required.

        Returns:
            HealthStatus with component statuses.
        """
        mcp_ok = agent._connected

        litellm_ok = False
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{settings.MCP_SERVER_URL.rstrip('/')}/health"
                )
                litellm_ok = resp.status_code < 500
        except httpx.HTTPError:
            pass

        overall = "ok" if (mcp_ok and litellm_ok) else "degraded"
        return HealthStatus(
            status=overall,
            mcp_server=mcp_ok,
            litellm_reachable=litellm_ok,
        )

    return router
