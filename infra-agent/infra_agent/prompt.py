"""System prompt loader — reads prompt from file or falls back to built-in default."""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_DEFAULT_PROMPT = (
    "You are an AWS infrastructure assistant. "
    "Use the available MCP tools to query the infrastructure knowledge graph "
    "and answer questions about AWS resources, networking, security, and costs. "
    "Always back your answers with tool calls — never guess."
)


def load_system_prompt(path: str) -> str:
    """Load the system prompt from a file, falling back to a built-in default.

    Args:
        path: Filesystem path to the system prompt markdown file.

    Returns:
        The prompt text — either from the file or the built-in default.
    """
    prompt_path = Path(path)
    if prompt_path.is_file():
        logger.debug("Loading system prompt from %s", path)
        return prompt_path.read_text(encoding="utf-8")

    logger.warning(
        "System prompt file not found at '%s'; using built-in default prompt",
        path,
    )
    return _DEFAULT_PROMPT
