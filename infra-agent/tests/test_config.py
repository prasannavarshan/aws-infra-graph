"""Tests for infra_agent.config.Settings."""

import pytest
from pydantic import SecretStr, ValidationError

from infra_agent.config import Settings


def _settings_no_env(**kwargs) -> Settings:
    """Create Settings without reading .env files."""
    return Settings(_env_file=None, **kwargs)


class TestSettingsDefaults:
    """Verify optional fields have correct defaults."""

    def test_defaults_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LITELLM_API_KEY", "sk-test")
        monkeypatch.setenv("MCP_SERVER_URL", "http://localhost:8000")
        monkeypatch.delenv("LITELLM_MODEL", raising=False)
        monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
        monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)

        s = _settings_no_env()

        assert s.LITELLM_MODEL == "gpt-4o"
        assert s.SESSION_TTL_MINUTES == 60
        assert s.LOG_LEVEL == "INFO"
        assert s.SYSTEM_PROMPT_PATH == "system_prompt.md"
        assert s.OIDC_ISSUER_URL is None
        assert s.OIDC_AUDIENCE is None

    def test_api_key_is_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LITELLM_API_KEY", "sk-secret-123")
        monkeypatch.setenv("MCP_SERVER_URL", "http://localhost:8000")

        s = _settings_no_env()

        assert isinstance(s.LITELLM_API_KEY, SecretStr)
        assert s.LITELLM_API_KEY.get_secret_value() == "sk-secret-123"
        assert "sk-secret-123" not in str(s.LITELLM_API_KEY)


class TestSettingsRequired:
    """Verify required fields cause validation errors when missing."""

    def test_missing_api_key_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("LITELLM_API_KEY", raising=False)
        monkeypatch.setenv("MCP_SERVER_URL", "http://localhost:8000")

        with pytest.raises(ValidationError):
            _settings_no_env()

    def test_missing_mcp_url_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LITELLM_API_KEY", "sk-test")
        monkeypatch.delenv("MCP_SERVER_URL", raising=False)

        with pytest.raises(ValidationError):
            _settings_no_env()


class TestSettingsOverrides:
    """Verify env vars override defaults."""

    def test_custom_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LITELLM_API_KEY", "sk-test")
        monkeypatch.setenv("MCP_SERVER_URL", "http://mcp:9000")
        monkeypatch.setenv("LITELLM_MODEL", "claude-3-opus")
        monkeypatch.setenv("SESSION_TTL_MINUTES", "30")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("OIDC_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("OIDC_AUDIENCE", "my-app")

        s = _settings_no_env()

        assert s.MCP_SERVER_URL == "http://mcp:9000"
        assert s.LITELLM_MODEL == "claude-3-opus"
        assert s.SESSION_TTL_MINUTES == 30
        assert s.LOG_LEVEL == "DEBUG"
        assert s.OIDC_ISSUER_URL == "https://auth.example.com"
        assert s.OIDC_AUDIENCE == "my-app"
