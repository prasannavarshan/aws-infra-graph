"""Tests for bearer token authentication middleware."""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from src.auth import BearerAuthMiddleware, generate_token


def _make_app(token: str) -> Starlette:
    """Create a test Starlette app with auth middleware."""

    async def hello(request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", hello)])
    app.add_middleware(BearerAuthMiddleware, token=token)
    return app


class TestBearerAuth:
    """Tests for BearerAuthMiddleware."""

    def test_valid_token_allowed(self):
        """Request with correct token returns 200."""
        app = _make_app("secret-token")
        client = TestClient(app)
        resp = client.get(
            "/", headers={"Authorization": "Bearer secret-token"},
        )
        assert resp.status_code == 200
        assert resp.text == "ok"

    def test_missing_header_rejected(self):
        """Request without Authorization header returns 401."""
        app = _make_app("secret-token")
        client = TestClient(app)
        resp = client.get("/")
        assert resp.status_code == 401
        assert "Missing" in resp.json()["error"]

    def test_wrong_token_rejected(self):
        """Request with wrong token returns 401."""
        app = _make_app("secret-token")
        client = TestClient(app)
        resp = client.get(
            "/", headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 401
        assert "Invalid" in resp.json()["error"]

    def test_non_bearer_scheme_rejected(self):
        """Request with Basic auth returns 401."""
        app = _make_app("secret-token")
        client = TestClient(app)
        resp = client.get(
            "/", headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.status_code == 401

    def test_empty_bearer_rejected(self):
        """Request with 'Bearer ' but no token returns 401."""
        app = _make_app("secret-token")
        client = TestClient(app)
        resp = client.get(
            "/", headers={"Authorization": "Bearer "},
        )
        assert resp.status_code == 401


class TestGenerateToken:
    """Tests for generate_token."""

    def test_generates_string(self):
        """Token is a non-empty string."""
        token = generate_token()
        assert isinstance(token, str)
        assert len(token) > 20

    def test_unique_each_call(self):
        """Each call generates a different token."""
        t1 = generate_token()
        t2 = generate_token()
        assert t1 != t2
