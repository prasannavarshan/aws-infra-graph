"""OIDC/SSO authentication middleware for the infra-agent API."""

import logging
from typing import Annotated

import httpx
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from infra_agent.config import Settings

logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)

# Module-level JWKS cache: maps issuer_url → JWKS dict
_jwks_cache: dict[str, dict] = {}


def _get_settings(request: Request) -> Settings | None:
    """Retrieve Settings from app state, if available.

    Args:
        request: The incoming FastAPI request.

    Returns:
        The Settings instance or None.
    """
    return getattr(request.app.state, "settings", None)


async def _fetch_jwks(issuer_url: str) -> dict:
    """Fetch JWKS keys from the OIDC discovery endpoint, with caching.

    Args:
        issuer_url: The OIDC issuer URL.

    Returns:
        The JWKS key set as a dict.

    Raises:
        HTTPException: If the JWKS endpoint is unreachable.
    """
    if issuer_url in _jwks_cache:
        return _jwks_cache[issuer_url]

    discovery_url = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            discovery_resp = await client.get(discovery_url)
            discovery_resp.raise_for_status()
            jwks_uri = discovery_resp.json()["jwks_uri"]

            jwks_resp = await client.get(jwks_uri)
            jwks_resp.raise_for_status()
            jwks = jwks_resp.json()
    except (httpx.HTTPError, KeyError) as exc:
        logger.error("Failed to fetch JWKS from %s: %s", issuer_url, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to validate token: OIDC provider unreachable",
        ) from exc

    _jwks_cache[issuer_url] = jwks
    return jwks


def _extract_user_identity(claims: dict) -> str:
    """Extract user identity from JWT claims.

    Args:
        claims: Decoded JWT claims dict.

    Returns:
        The user identity string (email, preferred_username, or sub).
    """
    return (
        claims.get("email")
        or claims.get("preferred_username")
        or claims.get("sub", "unknown")
    )


async def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)
    ] = None,
    settings: Annotated[Settings | None, Depends(_get_settings)] = None,
) -> str:
    """FastAPI dependency that extracts the authenticated user identity.

    When OIDC is configured (OIDC_ISSUER_URL and OIDC_AUDIENCE set),
    validates the Bearer JWT token and extracts user identity.
    When OIDC is not configured, allows requests through as "anonymous".

    Args:
        credentials: Bearer token from the Authorization header.
        settings: Application settings (injected via FastAPI dependency override).

    Returns:
        The authenticated user identity string.

    Raises:
        HTTPException: 401 if token is missing or invalid when OIDC is configured.
    """
    oidc_configured = (
        settings is not None
        and settings.OIDC_ISSUER_URL is not None
        and settings.OIDC_AUDIENCE is not None
    )

    if not oidc_configured:
        return "anonymous"

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    try:
        jwks = await _fetch_jwks(settings.OIDC_ISSUER_URL)  # type: ignore[arg-type]
        claims = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=settings.OIDC_AUDIENCE,  # type: ignore[arg-type]
            issuer=settings.OIDC_ISSUER_URL,
        )
    except JWTError as exc:
        logger.warning("JWT validation failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    return _extract_user_identity(claims)
