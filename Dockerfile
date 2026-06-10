# Stage 1: Install dependencies with uv
FROM --platform=linux/amd64 python:3.12-slim AS builder

# Corporate CA certs — injected at build time for pip/uv to work behind proxy
ARG CA_BUNDLE=""
RUN if [ -n "$CA_BUNDLE" ]; then \
      cp "$CA_BUNDLE" /usr/local/share/ca-certificates/corporate.crt && \
      update-ca-certificates; \
    fi

COPY --from=ghcr.io/astral-sh/uv:0.5.21 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-editable

# Stage 2: Runtime
FROM --platform=linux/amd64 python:3.12-slim

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY src/ src/
COPY ORG_KNOWLEDGE.md ./

ENV PATH="/app/.venv/bin:$PATH"
ENV TRANSPORT=http
ENV PYTHONUNBUFFERED=1

RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 8050

CMD ["python", "-m", "src"]
