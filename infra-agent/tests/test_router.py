"""Tests for infra_agent.api.router — all API endpoints."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from infra_agent.agent import InfraAgent
from infra_agent.api.auth import get_current_user
from infra_agent.api.router import create_router
from infra_agent.config import Settings
from infra_agent.models import ToolCallSummary, TokenUsage
from infra_agent.sessions.manager import SessionManager
from infra_agent.sessions.store import InMemorySessionStore


def _make_settings() -> Settings:
    return Settings(
        LITELLM_API_KEY=SecretStr("sk-test"),
        MCP_SERVER_URL="http://localhost:8000/mcp",
    )


def _build_app() -> tuple[FastAPI, InfraAgent, SessionManager]:
    """Create a test FastAPI app with mock agent and real session store."""
    settings = _make_settings()
    agent = InfraAgent(settings)
    store = InMemorySessionStore()
    session_manager = SessionManager(store)

    # Mock the agent.chat method
    agent.chat = AsyncMock(return_value=("Test response", [], TokenUsage()))

    router = create_router(agent, session_manager, settings)
    app = FastAPI()
    app.state.settings = settings
    app.include_router(router)

    # Override auth to always return "testuser"
    async def _mock_user() -> str:
        return "testuser"

    app.dependency_overrides[get_current_user] = _mock_user

    return app, agent, session_manager


@pytest.fixture
def app_bundle():
    """Fixture providing (app, agent, session_manager)."""
    return _build_app()


@pytest.fixture
def app(app_bundle):
    return app_bundle[0]


@pytest.fixture
def mock_agent(app_bundle):
    return app_bundle[1]


@pytest.fixture
def session_manager(app_bundle):
    return app_bundle[2]


class TestPostChat:
    """POST /chat endpoint tests."""

    async def test_creates_session_and_returns_response(
        self, app, mock_agent
    ) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/chat", json={"message": "How many EC2 instances?"}
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["response"] == "Test response"
        assert data["session_id"]  # non-empty
        assert data["tool_calls"] == []

    async def test_continues_existing_session(
        self, app, mock_agent, session_manager
    ) -> None:
        session = session_manager.create_session(user="testuser")
        sid = session.session_id

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/chat",
                json={"message": "Follow up", "session_id": sid},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == sid

    async def test_creates_new_session_if_id_not_found(
        self, app, mock_agent
    ) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/chat",
                json={
                    "message": "Hello",
                    "session_id": "nonexistent-id",
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] != "nonexistent-id"

    async def test_returns_tool_calls(self, app, mock_agent) -> None:
        tool = ToolCallSummary(
            tool_name="list_ec2",
            arguments={"region": "us-east-1"},
            result_summary="Found 3 instances",
            duration_ms=120,
            success=True,
        )
        mock_agent.chat = AsyncMock(return_value=("Got it", [tool], TokenUsage()))

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/chat", json={"message": "List EC2"}
            )

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["tool_calls"]) == 1
        assert data["tool_calls"][0]["tool_name"] == "list_ec2"


class TestPostChatStream:
    """POST /chat/stream endpoint tests."""

    async def test_streams_sse_events(self, app, mock_agent) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/chat/stream", json={"message": "How many VPCs?"}
            )

        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")

    async def test_stream_creates_session(
        self, app, mock_agent, session_manager
    ) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/chat/stream", json={"message": "Hello"}
            )

        assert resp.status_code == 200
        # The response body should contain a done event with a session_id
        body = resp.text
        assert '"done"' in body

    async def test_stream_continues_existing_session(
        self, app, mock_agent, session_manager
    ) -> None:
        session = session_manager.create_session(user="testuser")
        sid = session.session_id

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/chat/stream",
                json={"message": "Follow up", "session_id": sid},
            )

        assert resp.status_code == 200
        assert sid in resp.text


class TestGetSessionHistory:
    """GET /sessions/{session_id}/history endpoint tests."""

    async def test_returns_history(self, app, session_manager) -> None:
        session = session_manager.create_session(user="testuser")

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get(
                f"/sessions/{session.session_id}/history"
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["session_id"] == session.session_id
        assert data["user"] == "testuser"
        assert data["messages"] == []

    async def test_404_for_unknown_session(self, app) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/sessions/unknown-id/history")

        assert resp.status_code == 404


class TestDeleteSession:
    """DELETE /sessions/{session_id} endpoint tests."""

    async def test_deletes_session(self, app, session_manager) -> None:
        session = session_manager.create_session(user="testuser")

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.delete(
                f"/sessions/{session.session_id}"
            )

        assert resp.status_code == 200
        assert session_manager.get_session(session.session_id) is None

    async def test_404_for_unknown_session(self, app) -> None:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.delete("/sessions/unknown-id")

        assert resp.status_code == 404


class TestHealthEndpoint:
    """GET /health endpoint tests."""

    async def test_returns_health_status(self, app, mock_agent) -> None:
        mock_agent._connected = True

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            with patch(
                "infra_agent.api.router.httpx.AsyncClient"
            ) as mock_httpx:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_ctx = AsyncMock()
                mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
                mock_ctx.__aexit__ = AsyncMock(return_value=False)
                mock_ctx.get = AsyncMock(return_value=mock_resp)
                mock_httpx.return_value = mock_ctx

                resp = await client.get("/health")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["mcp_server"] is True
        assert data["litellm_reachable"] is True

    async def test_degraded_when_disconnected(self, app, mock_agent) -> None:
        mock_agent._connected = False

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            with patch(
                "infra_agent.api.router.httpx.AsyncClient"
            ) as mock_httpx:
                mock_ctx = AsyncMock()
                mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
                mock_ctx.__aexit__ = AsyncMock(return_value=False)
                mock_ctx.get = AsyncMock(
                    side_effect=httpx.ConnectError("refused")
                )
                mock_httpx.return_value = mock_ctx

                resp = await client.get("/health")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["mcp_server"] is False

    async def test_health_no_auth_required(self) -> None:
        """Health endpoint should work without auth dependency override."""
        settings = _make_settings()
        agent = InfraAgent(settings)
        agent._connected = True
        agent.chat = AsyncMock(return_value=("", [], TokenUsage()))
        store = InMemorySessionStore()
        sm = SessionManager(store)

        router = create_router(agent, sm, settings)
        app = FastAPI()
        app.state.settings = settings
        app.include_router(router)
        # Deliberately NOT overriding get_current_user

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            with patch(
                "infra_agent.api.router.httpx.AsyncClient"
            ) as mock_httpx:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_ctx = AsyncMock()
                mock_ctx.__aenter__ = AsyncMock(return_value=mock_ctx)
                mock_ctx.__aexit__ = AsyncMock(return_value=False)
                mock_ctx.get = AsyncMock(return_value=mock_resp)
                mock_httpx.return_value = mock_ctx

                resp = await client.get("/health")

        # Should succeed even without auth override (OIDC not configured → anonymous)
        assert resp.status_code == 200
