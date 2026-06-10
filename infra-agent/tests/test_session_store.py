"""Tests for InMemorySessionStore."""

from datetime import UTC, datetime, timedelta

from infra_agent.models import Session
from infra_agent.sessions.store import InMemorySessionStore


def _make_session(
    session_id: str = "s1",
    user: str | None = None,
    last_active: datetime | None = None,
) -> Session:
    now = last_active or datetime.now(UTC)
    return Session(
        session_id=session_id,
        user=user,
        created_at=now,
        last_active=now,
    )


class TestInMemorySessionStore:
    """Verify InMemorySessionStore CRUD and cleanup."""

    def test_save_and_get(self) -> None:
        store = InMemorySessionStore()
        session = _make_session("abc")
        store.save(session)
        assert store.get("abc") is session

    def test_get_unknown_returns_none(self) -> None:
        store = InMemorySessionStore()
        assert store.get("nonexistent") is None

    def test_delete_existing(self) -> None:
        store = InMemorySessionStore()
        store.save(_make_session("abc"))
        assert store.delete("abc") is True
        assert store.get("abc") is None

    def test_delete_unknown_returns_false(self) -> None:
        store = InMemorySessionStore()
        assert store.delete("nope") is False

    def test_list_by_user(self) -> None:
        store = InMemorySessionStore()
        store.save(_make_session("s1", user="alice"))
        store.save(_make_session("s2", user="bob"))
        store.save(_make_session("s3", user="alice"))

        alice_sessions = store.list_by_user("alice")
        assert len(alice_sessions) == 2
        assert {s.session_id for s in alice_sessions} == {"s1", "s3"}

    def test_list_by_user_empty(self) -> None:
        store = InMemorySessionStore()
        assert store.list_by_user("ghost") == []

    def test_cleanup_expired(self) -> None:
        store = InMemorySessionStore()
        old_time = datetime.now(UTC) - timedelta(minutes=120)
        store.save(_make_session("old", last_active=old_time))
        store.save(_make_session("fresh"))

        removed = store.cleanup_expired(ttl_minutes=60)
        assert removed == 1
        assert store.get("old") is None
        assert store.get("fresh") is not None

    def test_cleanup_expired_none_expired(self) -> None:
        store = InMemorySessionStore()
        store.save(_make_session("a"))
        store.save(_make_session("b"))
        assert store.cleanup_expired(ttl_minutes=60) == 0
