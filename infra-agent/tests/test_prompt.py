"""Tests for infra_agent.prompt — system prompt loader."""

import logging

import pytest

from infra_agent.prompt import _DEFAULT_PROMPT, load_system_prompt


class TestLoadSystemPrompt:
    """Verify load_system_prompt reads files and falls back correctly."""

    def test_loads_from_existing_file(self, tmp_path: pytest.TempPathFactory) -> None:
        prompt_file = tmp_path / "prompt.md"
        prompt_file.write_text("You are a test assistant.", encoding="utf-8")

        result = load_system_prompt(str(prompt_file))

        assert result == "You are a test assistant."

    def test_returns_default_when_file_missing(self) -> None:
        result = load_system_prompt("/nonexistent/path/prompt.md")

        assert result == _DEFAULT_PROMPT

    def test_logs_warning_on_fallback(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="infra_agent.prompt"):
            load_system_prompt("/nonexistent/path/prompt.md")

        assert any("not found" in record.message for record in caplog.records)

    def test_preserves_file_content_exactly(self, tmp_path: pytest.TempPathFactory) -> None:
        content = "# Title\n\nMulti-line\nprompt with **markdown**.\n"
        prompt_file = tmp_path / "system.md"
        prompt_file.write_text(content, encoding="utf-8")

        result = load_system_prompt(str(prompt_file))

        assert result == content
