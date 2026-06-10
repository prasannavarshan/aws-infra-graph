# CLAUDE.md — AWS Infrastructure Knowledge Graph

## What This Project Does

This is an MCP server that:
1. Crawls a multi-account AWS Organization using boto3
2. Builds a Neo4j knowledge graph of all resources and relationships
3. Exposes query tools via MCP so AI agents can understand the infrastructure

## Code Structure & Modularity

- Never create files longer than 500 lines. If a file approaches this limit, split it.
- Functions should not exceed 50 lines. Classes should not exceed 100 lines.
- Max line length: 100 characters.
- Organize code by responsibility:
  - `src/collector/` — AWS resource crawlers (one file per service)
  - `src/graph/` — Neo4j graph model, builder, and queries
  - `src/tools/` — MCP tool definitions (one file per tool group)
  - `src/main.py` — MCP server entry point (FastMCP + lifespan pattern)
  - `src/config.py` — Pydantic Settings configuration

## Tech Stack

- Python 3.12+ with `uv` for package management
- `mcp` SDK with `FastMCP` and lifespan pattern for the MCP server
- `boto3` for AWS API access with STS assume-role for cross-account
- `neo4j` Python driver for the knowledge graph
- `pydantic` v2 for all data models and validation
- `pydantic-settings` with `BaseSettings` for configuration via .env
- `pytest` for testing
- `ruff` for linting and formatting
- Docker Compose for Neo4j

## Style & Conventions

- Python: PEP 8 compliance, enforced by `ruff`
- Type hints on all function signatures — no `Any` unless absolutely necessary
- Use `pydantic` models for data structures, not raw dicts
- Google-style docstrings on public functions and classes
- Use `async`/`await` for all MCP tools and Neo4j queries
- Use `structlog` or standard `logging` — never `print()` for debugging
- Environment variables for all secrets and configuration — never hardcode

## Package Management

- Use `uv` (not pip) for all package operations:
  - `uv add <package>` to add dependencies
  - `uv remove <package>` to remove dependencies
  - `uv sync` to install/sync all dependencies
  - `uv run <command>` to run commands in the virtual environment

## Testing & Reliability

- All new features must include pytest tests in `/tests`
- Each test file should include: 1 happy path, 1 edge case, 1 failure/error case
- Mock boto3 calls using `botocore.stub.Stubber` or `moto`
- Run tests with: `uv run pytest tests/ -v`
- Run linting with: `uv run ruff check src/ tests/`

## Error Handling

- Use specific exception types — never bare `except:` or `except Exception:`
- AWS API errors: catch `botocore.exceptions.ClientError` and handle by error code
- Neo4j errors: catch `neo4j.exceptions.*` specifically
- Fail fast on configuration errors (missing env vars, bad credentials)
- Log errors with context (account_id, region, resource_type)

## AWS-Specific Conventions

- Always use ARN as the unique identifier for resources
- Collector functions should be idempotent — safe to re-run
- Use pagination for all AWS API calls (`get_paginator()`)
- Respect rate limits — use exponential backoff via boto3 retry config
- Cross-account access via STS `assume_role` from the management account
- Tag all graph nodes with `account_id` and `region` for filtering

## Neo4j Conventions

- Node labels: PascalCase matching AWS service names (e.g., `EC2Instance`, `SecurityGroup`)
- Relationship types: UPPER_SNAKE_CASE (e.g., `RUNS_IN`, `HAS_SG`, `TARGETS`)
- All nodes must have: `arn`, `name`, `account_id`, `region` properties
- Use parameterized Cypher queries — never string interpolation
- Batch operations using `UNWIND` for bulk inserts

## MCP Tool Design

- Tool descriptions should be clear, specific, and explain what the tool returns
- Tools should return formatted strings (not raw JSON) for readability
- Include parameter descriptions with examples in the tool docstrings
- Tools should handle errors gracefully and return helpful error messages
- Group related tools in the same file under `src/tools/`

## Security

- Never commit `.env` files, AWS credentials, or secrets
- Never log secret values (access keys, session tokens)
- Use IAM roles with least-privilege for cross-account access
- Validate all user inputs in MCP tools before passing to Cypher queries
- Neo4j credentials stored in `.env`, never in code

## Git & Workflow

- Conventional commit messages: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`
- Feature branches off `main`
- Run `uv run ruff check` and `uv run pytest` before every commit

## AI Behavior Rules

- Never assume missing context — ask or read the relevant file first
- Never hallucinate library APIs — check imports and documentation
- Confirm file paths exist before referencing them
- When adding a new AWS service collector, follow the pattern in `src/collector/base.py`
- When adding a new MCP tool, follow the pattern in existing `src/tools/` files
