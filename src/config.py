"""Application configuration via environment variables."""

from pydantic_settings import BaseSettings


class AWSConfig(BaseSettings):
    """AWS-specific configuration."""

    profile: str = ""
    ssl_verify: bool = True
    org_role_arn: str = ""
    org_account_id: str = ""
    mgmt_account_id: str = ""
    cross_account_role_name: str = ""
    default_region: str = "us-east-1"
    regions: list[str] = ["us-east-1"]
    account_ids: list[str] = []
    max_concurrency: int = 5
    collector_concurrency: int = 10  # max parallel collectors per account

    model_config = {"env_prefix": "AWS_"}


class Neo4jConfig(BaseSettings):
    """Neo4j connection configuration."""

    uri: str = "bolt://localhost:7687"
    user: str = "neo4j"
    password: str = "changeme"
    write_concurrency: int = 3

    model_config = {"env_prefix": "NEO4J_"}


class ServerConfig(BaseSettings):
    """MCP server configuration."""

    transport: str = "stdio"
    host: str = "0.0.0.0"
    port: int = 8050
    auth_token: str = ""
    gchat_webhook_url: str = ""  # set via MCP_GCHAT_WEBHOOK_URL

    model_config = {"env_prefix": "MCP_"}


class Settings(BaseSettings):
    """Root settings aggregating all config sections."""

    aws: AWSConfig = AWSConfig()
    neo4j: Neo4jConfig = Neo4jConfig()
    server: ServerConfig = ServerConfig()


settings = Settings()
