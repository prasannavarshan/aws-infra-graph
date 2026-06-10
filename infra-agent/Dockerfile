# =============================================================================
# infra-agent Dockerfile
#
# Multi-stage build using uv for fast, reproducible installs.
# Build:  docker build -t infra-agent .
# Run:    docker run --env-file .env -p 8080:8080 infra-agent
# =============================================================================

# Stage 1: Install dependencies
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.5.21 /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency manifests first for layer caching
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-editable

# Stage 2: Runtime
FROM python:3.12-slim

WORKDIR /app

# Copy the virtual environment from the builder
COPY --from=builder /app/.venv /app/.venv

# Copy application source
COPY infra_agent/ infra_agent/
COPY ui/ ui/
COPY system_prompt.md ./

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 8080

# Default: run the FastAPI agent server
CMD ["python", "-m", "infra_agent"]
