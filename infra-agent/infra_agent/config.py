"""Application settings loaded from environment variables and .env file."""

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration for the infra-agent.

    Required fields raise a ValidationError on startup if missing,
    ensuring the process fails fast with a clear message.

    Attributes:
        LITELLM_API_KEY: API key for LiteLLM inference platform.
        MCP_SERVER_URL: URL of the aws-infra-graph MCP server.
        LITELLM_MODEL: LiteLLM model identifier.
        SESSION_TTL_MINUTES: Session idle timeout in minutes.
        LOG_LEVEL: Python logging level.
        SYSTEM_PROMPT_PATH: Path to the system prompt markdown file.
        OIDC_ISSUER_URL: OIDC issuer URL for token validation.
        OIDC_AUDIENCE: OIDC audience / client ID.
    """

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        extra="ignore",
    )

    # Required
    LITELLM_API_KEY: SecretStr
    MCP_SERVER_URL: str

    # Optional with defaults
    LITELLM_BASE_URL: str | None = None
    LITELLM_MODEL: str = "gpt-4o"
    SESSION_TTL_MINUTES: int = 60
    LOG_LEVEL: str = "INFO"
    SYSTEM_PROMPT_PATH: str = "system_prompt.md"

    # Optional OIDC
    OIDC_ISSUER_URL: str | None = None
    OIDC_AUDIENCE: str | None = None

    # Optional MCP auth
    MCP_AUTH_TOKEN: str | None = None
