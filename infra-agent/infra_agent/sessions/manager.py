"""Session lifecycle manager — creates, retrieves, and updates sessions."""

from datetime import UTC, datetime
from uuid import uuid4

from infra_agent.models import Message, Session
from infra_agent.sessions.store import SessionStore


class SessionManager:
    """Orchestrates session lifecycle on top of a :class:`SessionStore`.

    Args:
        store: Any object satisfying the :class:`SessionStore` protocol.
    """

    def __init__(self, store: SessionStore) -> None:
        self._store = store

    def create_session(self, user: str | None = None) -> Session:
        """Create and persist a new session with a unique UUID.

        Args:
            user: Optional authenticated user identity.

        Returns:
            The newly created :class:`Session`.
        """
        now = datetime.now(UTC)
        session = Session(
            session_id=str(uuid4()),
            user=user,
            created_at=now,
            last_active=now,
        )
        self._store.save(session)
        return session

    def get_session(self, session_id: str) -> Session | None:
        """Retrieve an existing session by ID.

        Args:
            session_id: The unique session identifier.

        Returns:
            The :class:`Session` if found, otherwise ``None``.
        """
        return self._store.get(session_id)

    def add_turn(
        self,
        session_id: str,
        user_message: Message,
        agent_message: Message,
    ) -> None:
        """Append a user/agent message pair and update ``last_active``.

        Args:
            session_id: Target session identifier.
            user_message: The user's message.
            agent_message: The agent's reply.

        Raises:
            KeyError: If the session does not exist.
        """
        session = self._store.get(session_id)
        if session is None:
            raise KeyError(f"Session not found: {session_id}")

        session.messages.append(user_message)
        session.messages.append(agent_message)
        session.last_active = datetime.now(UTC)
        self._store.save(session)

    def delete_session(self, session_id: str) -> bool:
        """Delete a session, delegating to the underlying store.

        Args:
            session_id: The session to remove.

        Returns:
            ``True`` if the session existed and was removed.
        """
        return self._store.delete(session_id)
