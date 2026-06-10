"""GChat webhook notifications — fire-and-forget, never raises."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from src.config import settings

logger = logging.getLogger(__name__)


def notify_gchat(text: str) -> None:
    """POST a plain-text message to the configured GChat webhook.

    Reads GCHAT_WEBHOOK_URL from ServerConfig (env: MCP_GCHAT_WEBHOOK_URL).
    Silently logs and returns if the URL is not configured or the POST fails.
    """
    url = settings.server.gchat_webhook_url
    if not url:
        return

    payload = json.dumps({"text": text}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except urllib.error.URLError as exc:
        logger.warning("gchat_notify_failed url_error=%s", exc)
    except Exception as exc:
        logger.warning("gchat_notify_failed error=%s", exc)
