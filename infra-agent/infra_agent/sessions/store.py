"""Session persistence layer: protocol and in-memory implementation."""

from datetime import UTC, datetime, timedelta
from typing import Protocol

from infra_agent.models import Session


class SessionStore(Protocol):
    """Abstract persistence interface for conversation sessions.

    Any concrete store must implement every method listed here.
    """

    def get(self, session_id: str) -> Session | None:
        """Return the session with the given ID, or ``None`` if not found."""
        ...

    def save(self, session: Session) -> None:
        """Persist a session (insert or update)."""
        ...

    def delete(self, session_id: str) -> bool:
        """Remove a session by ID. Return ``True`` if it existed."""
        ...

    def list_by_user(self, user: str) -> list[Session]:
        """Return all sessions belonging to *user*."""
        ...

    def cleanup_expired(self, ttl_minutes: int) -> int:
        """Delete sessions whose ``last_active`` is older than *ttl_minutes* ago.

        Returns:
            The number of sessions removed.
        """
        ...


class InMemorySessionStore:
    """Dict-backed session store with TTL-based cleanup.

    Attributes:
        _sessions: Internal mapping of session_id → Session.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def get(self, session_id: str) -> Session | None:
        """Return the session with the given ID, or ``None`` if not found."""
        return self._sessions.get(session_id)

    def save(self, session: Session) -> None:
        """Persist a session (insert or update)."""
        self._sessions[session.session_id] = session

    def delete(self, session_id: str) -> bool:
        """Remove a session by ID. Return ``True`` if it existed."""
        try:
            del self._sessions[session_id]
        except KeyError:
            return False
        return True

    def list_by_user(self, user: str) -> list[Session]:
        """Return all sessions belonging to *user*."""
        return [s for s in self._sessions.values() if s.user == user]

    def cleanup_expired(self, ttl_minutes: int) -> int:
        """Delete sessions whose ``last_active`` is older than *ttl_minutes* ago.

        Returns:
            The number of sessions removed.
        """
        cutoff = datetime.now(UTC) - timedelta(minutes=ttl_minutes)
        expired_ids = [
            sid
            for sid, session in self._sessions.items()
            if session.last_active < cutoff
        ]
        for sid in expired_ids:
            del self._sessions[sid]
        return len(expired_ids)
