"""Bearer token authentication middleware for MCP HTTP transport."""

from __future__ import annotations

import hmac
import logging
import secrets

from starlette.middleware.base import (
    BaseHTTPMiddleware,
    RequestResponseEndpoint,
)
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)


def generate_token() -> str:
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(32)


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that validates Bearer tokens.

    Rejects requests without a valid Authorization header
    with HTTP 401. Uses constant-time comparison to prevent
    timing attacks.
    """

    def __init__(self, app, token: str) -> None:  # noqa: ANN001
        super().__init__(app)
        self._token = token

    # Paths that bypass authentication (e.g. ALB health checks)
    _PUBLIC_PATHS = {"/health"}

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint,
    ) -> Response:
        if request.url.path in self._PUBLIC_PATHS:
            return await call_next(request)
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                {"error": "Missing or invalid Authorization header"},
                status_code=401,
            )
        provided = auth_header[7:]  # strip "Bearer "
        if not hmac.compare_digest(provided, self._token):
            logger.warning(
                "auth_failed",
                extra={"client": request.client.host if request.client else "unknown"},
            )
            return JSONResponse(
                {"error": "Invalid token"},
                status_code=401,
            )
        return await call_next(request)
