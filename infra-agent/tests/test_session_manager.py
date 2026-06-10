"""Tests for SessionManager."""

from datetime import UTC, datetime

import pytest

from infra_agent.models import Message, MessageRole
from infra_agent.sessions.manager import SessionManager
from infra_agent.sessions.store import InMemorySessionStore


def _make_manager() -> SessionManager:
    return SessionManager(store=InMemorySessionStore())


class TestSessionManager:
    """Verify SessionManager lifecycle operations."""

    def test_create_session_generates_unique_ids(self) -> None:
        mgr = _make_manager()
        s1 = mgr.create_session()
        s2 = mgr.create_session()
        assert s1.session_id != s2.session_id

    def test_create_session_with_user(self) -> None:
        mgr = _make_manager()
        s = mgr.create_session(user="alice")
        assert s.user == "alice"

    def test_create_session_persists(self) -> None:
        mgr = _make_manager()
        s = mgr.create_session()
        assert mgr.get_session(s.session_id) is not None

    def test_get_session_unknown_returns_none(self) -> None:
        mgr = _make_manager()
        assert mgr.get_session("nonexistent") is None

    def test_add_turn_appends_messages(self) -> None:
        mgr = _make_manager()
        s = mgr.create_session()

        user_msg = Message(role=MessageRole.USER, content="hello")
        agent_msg = Message(role=MessageRole.AGENT, content="hi there")
        mgr.add_turn(s.session_id, user_msg, agent_msg)

        updated = mgr.get_session(s.session_id)
        assert updated is not None
        assert len(updated.messages) == 2
        assert updated.messages[0].role == MessageRole.USER
        assert updated.messages[1].role == MessageRole.AGENT

    def test_add_turn_updates_last_active(self) -> None:
        mgr = _make_manager()
        s = mgr.create_session()
        original_active = s.last_active

        user_msg = Message(role=MessageRole.USER, content="ping")
        agent_msg = Message(role=MessageRole.AGENT, content="pong")
        mgr.add_turn(s.session_id, user_msg, agent_msg)

        updated = mgr.get_session(s.session_id)
        assert updated is not None
        assert updated.last_active >= original_active

    def test_add_turn_unknown_session_raises(self) -> None:
        mgr = _make_manager()
        user_msg = Message(role=MessageRole.USER, content="hello")
        agent_msg = Message(role=MessageRole.AGENT, content="hi")
        with pytest.raises(KeyError, match="Session not found"):
            mgr.add_turn("bad-id", user_msg, agent_msg)

    def test_delete_session(self) -> None:
        mgr = _make_manager()
        s = mgr.create_session()
        assert mgr.delete_session(s.session_id) is True
        assert mgr.get_session(s.session_id) is None

    def test_delete_session_unknown_returns_false(self) -> None:
        mgr = _make_manager()
        assert mgr.delete_session("nope") is False

    def test_created_at_is_utc(self) -> None:
        mgr = _make_manager()
        s = mgr.create_session()
        assert s.created_at.tzinfo is not None
        assert s.created_at.tzinfo == UTC
        assert isinstance(s.created_at, datetime)
