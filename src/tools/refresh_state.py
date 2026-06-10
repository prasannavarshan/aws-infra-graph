"""Shared in-memory state for graph refresh — tracks running status and last outcome."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass
class RefreshState:
    is_running: bool = False
    last_started: datetime | None = None
    last_completed: datetime | None = None
    last_result: str | None = None  # summary on success
    last_error: str | None = None   # error message on failure
    trigger: str = ""               # "scheduled" | "mcp" | "http"
    current_step: str = ""          # live progress message while running

    def start(self, trigger: str) -> None:
        self.is_running = True
        self.last_started = datetime.now(UTC)
        self.last_error = None
        self.current_step = ""
        self.trigger = trigger

    def update_step(self, message: str) -> None:
        self.current_step = message

    def complete(self, result: str) -> None:
        self.is_running = False
        self.last_completed = datetime.now(UTC)
        self.last_result = result
        self.current_step = ""

    def fail(self, error: str) -> None:
        self.is_running = False
        self.last_completed = datetime.now(UTC)
        self.last_error = error
        self.current_step = ""

    def to_dict(self) -> dict:
        def _fmt(dt: datetime | None) -> str | None:
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else None

        status = "running" if self.is_running else (
            "failed" if self.last_error else (
                "completed" if self.last_completed else "never_run"
            )
        )
        d: dict = {"status": status}
        if self.trigger:
            d["trigger"] = self.trigger
        if self.last_started:
            d["last_started"] = _fmt(self.last_started)
        if self.is_running and self.last_started:
            elapsed = (datetime.now(UTC) - self.last_started).seconds
            d["elapsed_seconds"] = elapsed
        if self.is_running and self.current_step:
            d["current_step"] = self.current_step
        if self.last_completed:
            d["last_completed"] = _fmt(self.last_completed)
        if self.last_result:
            d["last_result"] = self.last_result
        if self.last_error:
            d["last_error"] = self.last_error
        return d


# Module-level singleton — imported by admin.py and main.py
refresh_state = RefreshState()
