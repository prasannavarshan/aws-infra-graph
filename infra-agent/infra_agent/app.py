"""FastAPI application factory with lifespan management."""

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from infra_agent.agent import InfraAgent
from infra_agent.api.router import create_router
from infra_agent.config import Settings
from infra_agent.sessions.manager import SessionManager
from infra_agent.sessions.store import InMemorySessionStore

logger = logging.getLogger(__name__)

_CLEANUP_INTERVAL_S = 300  # 5 minutes


async def _ttl_cleanup_loop(
    store: InMemorySessionStore,
    ttl_minutes: int,
) -> None:
    """Periodically purge expired sessions.

    Args:
        store: The session store to clean up.
        ttl_minutes: Session idle timeout in minutes.
    """
    while True:
        await asyncio.sleep(_CLEANUP_INTERVAL_S)
        removed = store.cleanup_expired(ttl_minutes)
        if removed:
            logger.info("Cleaned up %d expired sessions", removed)


def create_app(settings: Settings) -> FastAPI:
    """Build and configure the FastAPI application.

    Sets up lifespan (MCP connect/disconnect, TTL cleanup), CORS,
    and mounts the API router.

    Args:
        settings: Application configuration.

    Returns:
        A fully configured FastAPI instance.
    """
    store = InMemorySessionStore()
    session_manager = SessionManager(store)
    agent = InfraAgent(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Manage startup and shutdown lifecycle."""
        # Startup
        await agent.connect()
        cleanup_task = asyncio.create_task(
            _ttl_cleanup_loop(store, settings.SESSION_TTL_MINUTES)
        )
        logger.info("Application started")
        try:
            yield
        finally:
            # Shutdown
            cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cleanup_task
            await agent.disconnect()
            logger.info("Application shut down")

    app = FastAPI(
        title="infra-agent",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.state.settings = settings

    # CORS for Streamlit frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8501",
            "http://127.0.0.1:8501",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    router = create_router(agent, session_manager, settings)
    app.include_router(router)

    return app
