"""Tests for infra_agent.api.auth — OIDC/SSO auth middleware."""

from unittest.mock import patch

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from infra_agent.api.auth import (
    _extract_user_identity,
    _jwks_cache,
    get_current_user,
)
from infra_agent.config import Settings


def _make_settings(**overrides) -> Settings:
    """Create a Settings instance with test defaults."""
    defaults = {
        "LITELLM_API_KEY": SecretStr("sk-test"),
        "MCP_SERVER_URL": "http://localhost:8000/mcp",
    }
    defaults.update(overrides)
    return Settings(**defaults)


def _make_app(settings: Settings | None = None) -> FastAPI:
    """Create a minimal FastAPI app with a protected test endpoint."""
    from fastapi import Depends

    app = FastAPI()
    if settings is not None:
        app.state.settings = settings

    @app.get("/whoami")
    async def whoami(user: str = Depends(get_current_user)) -> dict:
        return {"user": user}

    return app


class TestAnonymousAccess:
    """When OIDC is not configured, requests pass through as anonymous."""

    async def test_anonymous_when_no_oidc_settings(self) -> None:
        app = _make_app(_make_settings())
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/whoami")
        assert resp.status_code == 200
        assert resp.json()["user"] == "anonymous"

    async def test_anonymous_when_no_settings_in_state(self) -> None:
        app = _make_app()  # no settings at all
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/whoami")
        assert resp.status_code == 200
        assert resp.json()["user"] == "anonymous"

    async def test_anonymous_when_only_issuer_set(self) -> None:
        settings = _make_settings(OIDC_ISSUER_URL="https://idp.example.com")
        app = _make_app(settings)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/whoami")
        assert resp.status_code == 200
        assert resp.json()["user"] == "anonymous"


class TestOIDCEnforced:
    """When OIDC is configured, tokens are required and validated."""

    def _oidc_settings(self) -> Settings:
        return _make_settings(
            OIDC_ISSUER_URL="https://idp.example.com",
            OIDC_AUDIENCE="my-app",
        )

    async def test_401_when_no_token(self) -> None:
        app = _make_app(self._oidc_settings())
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.get("/whoami")
        assert resp.status_code == 401

    async def test_401_when_invalid_token(self) -> None:
        app = _make_app(self._oidc_settings())
        _jwks_cache["https://idp.example.com"] = {"keys": []}
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                resp = await client.get(
                    "/whoami",
                    headers={"Authorization": "Bearer bad.token.here"},
                )
            assert resp.status_code == 401
        finally:
            _jwks_cache.pop("https://idp.example.com", None)

    async def test_extracts_user_from_valid_token(self) -> None:
        app = _make_app(self._oidc_settings())
        claims = {
            "sub": "user-123",
            "email": "alice@example.com",
            "preferred_username": "alice",
            "aud": "my-app",
            "iss": "https://idp.example.com",
        }
        _jwks_cache["https://idp.example.com"] = {
            "keys": [{"kty": "RSA", "kid": "test-key"}]
        }
        try:
            with patch(
                "infra_agent.api.auth.jwt.decode", return_value=claims
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test"
                ) as client:
                    resp = await client.get(
                        "/whoami",
                        headers={
                            "Authorization": "Bearer valid.jwt.token"
                        },
                    )
            assert resp.status_code == 200
            assert resp.json()["user"] == "alice@example.com"
        finally:
            _jwks_cache.pop("https://idp.example.com", None)


class TestExtractUserIdentity:
    """Verify user identity extraction priority from JWT claims."""

    def test_prefers_email(self) -> None:
        claims = {
            "email": "bob@example.com",
            "preferred_username": "bob",
            "sub": "sub-1",
        }
        assert _extract_user_identity(claims) == "bob@example.com"

    def test_falls_back_to_preferred_username(self) -> None:
        claims = {"preferred_username": "bob", "sub": "sub-1"}
        assert _extract_user_identity(claims) == "bob"

    def test_falls_back_to_sub(self) -> None:
        claims = {"sub": "sub-1"}
        assert _extract_user_identity(claims) == "sub-1"

    def test_returns_unknown_when_empty(self) -> None:
        assert _extract_user_identity({}) == "unknown"
