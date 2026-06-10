"""Streamlit chat interface for the infra-agent.

Connects to the FastAPI backend via POST /chat and provides:
- Chat input with scrollable conversation history
- Loading spinner while the agent processes
- Collapsible tool call details per response
- Sidebar session management (new chat, session list)

Run with: streamlit run ui/app.py
"""

import os

import httpx
import streamlit as st

AGENT_API_URL = os.environ.get("AGENT_API_URL", "http://localhost:8080")
_CHAT_TIMEOUT = 120.0
_HISTORY_TIMEOUT = 30.0


def _post_chat(message: str, session_id: str | None) -> dict:
    """Send a message to the FastAPI /chat endpoint.

    Args:
        message: The user's message text.
        session_id: Optional session ID to continue a conversation.

    Returns:
        Parsed JSON response from the backend.

    Raises:
        httpx.HTTPStatusError: If the backend returns an error status.
    """
    payload: dict = {"message": message}
    if session_id:
        payload["session_id"] = session_id

    resp = httpx.post(
        f"{AGENT_API_URL}/chat",
        json=payload,
        timeout=_CHAT_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()


def _fetch_session_history(sid: str) -> list[dict]:
    """Fetch conversation history for a session from the backend.

    Args:
        sid: The session ID to fetch history for.

    Returns:
        List of message dicts from the session history.
    """
    resp = httpx.get(
        f"{AGENT_API_URL}/sessions/{sid}/history",
        timeout=_HISTORY_TIMEOUT,
    )
    resp.raise_for_status()
    history = resp.json()
    return [
        {
            "role": msg["role"],
            "content": msg["content"],
            "tool_calls": msg.get("tool_calls", []),
        }
        for msg in history.get("messages", [])
    ]


def _init_session_state() -> None:
    """Initialize Streamlit session state on first load."""
    if "session_id" not in st.session_state:
        st.session_state.session_id = None
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "session_list" not in st.session_state:
        st.session_state.session_list = []


def _start_new_chat() -> None:
    """Reset state for a new chat session."""
    st.session_state.session_id = None
    st.session_state.messages = []


def _switch_session(sid: str) -> None:
    """Switch to an existing session and reload its history.

    Args:
        sid: The session ID to switch to.
    """
    st.session_state.session_id = sid
    try:
        st.session_state.messages = _fetch_session_history(sid)
    except httpx.HTTPError:
        st.session_state.messages = []


def _render_sidebar() -> None:
    """Render the sidebar with session management controls."""
    with st.sidebar:
        st.title("Sessions")

        if st.button("➕ New Chat", use_container_width=True):
            _start_new_chat()
            st.rerun()

        st.divider()

        if not st.session_state.session_list:
            st.caption("No previous sessions")
            return

        for sid in st.session_state.session_list:
            label = f"💬 {sid[:12]}…"
            is_active = sid == st.session_state.session_id
            if st.button(
                label,
                key=f"session_{sid}",
                use_container_width=True,
                disabled=is_active,
            ):
                _switch_session(sid)
                st.rerun()


def _render_tool_calls(tool_calls: list[dict]) -> None:
    """Render tool call details in a collapsible expander.

    Args:
        tool_calls: List of tool call summary dicts from the agent response.
    """
    if not tool_calls:
        return

    with st.expander(f"🔧 Tool calls ({len(tool_calls)})", expanded=False):
        for tc in tool_calls:
            status_icon = "✅" if tc.get("success", True) else "❌"
            st.markdown(f"**{status_icon} {tc.get('tool_name', 'unknown')}**")
            if tc.get("arguments"):
                st.json(tc["arguments"])
            if tc.get("result_summary"):
                st.caption(tc["result_summary"])
            if tc.get("duration_ms") is not None:
                st.caption(f"⏱ {tc['duration_ms']}ms")
            st.divider()


def _render_chat_history() -> None:
    """Display all messages in the conversation history."""
    for msg in st.session_state.messages:
        role = "user" if msg["role"] == "user" else "assistant"
        with st.chat_message(role):
            st.markdown(msg["content"])
            if role == "assistant":
                _render_tool_calls(msg.get("tool_calls", []))


def main() -> None:
    """Main Streamlit application entry point."""
    st.set_page_config(
        page_title="infra-agent",
        page_icon="🏗️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Hide Streamlit's deploy button, hamburger menu, and footer
    # Hide sidebar close button so it can't be collapsed
    st.markdown(
        """
        <style>
        [data-testid="stToolbar"] {display: none !important;}
        footer {display: none !important;}
        [data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] {display: none !important;}
        </style>
        """,
        unsafe_allow_html=True,
    )

    _init_session_state()
    _render_sidebar()

    st.title("🏗️ infra-agent")
    st.caption("AI assistant for AWS infrastructure queries")

    _render_chat_history()

    if prompt := st.chat_input("Ask about your AWS infrastructure…"):
        st.session_state.messages.append({
            "role": "user",
            "content": prompt,
            "tool_calls": [],
        })
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"), st.spinner("Thinking…"):
            try:
                data = _post_chat(prompt, st.session_state.session_id)

                st.session_state.session_id = data["session_id"]
                if data["session_id"] not in st.session_state.session_list:
                    st.session_state.session_list.append(data["session_id"])

                st.markdown(data["response"])
                _render_tool_calls(data.get("tool_calls", []))

                st.session_state.messages.append({
                    "role": "agent",
                    "content": data["response"],
                    "tool_calls": data.get("tool_calls", []),
                })

            except httpx.ConnectError:
                st.error(
                    f"Cannot reach the agent backend at {AGENT_API_URL}. "
                    "Is the server running?"
                )
            except httpx.HTTPStatusError as exc:
                st.error(f"Backend error: {exc.response.status_code}")


if __name__ == "__main__":
    main()
