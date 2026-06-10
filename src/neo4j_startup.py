"""Auto-start Neo4j if not already running."""

from __future__ import annotations

import asyncio
import os
import socket
from pathlib import Path
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger()

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _parse_bolt_address(uri: str) -> tuple[str, int]:
    """Extract host and port from a bolt:// URI."""
    parsed = urlparse(uri)
    host = parsed.hostname or "localhost"
    port = parsed.port or 7687
    return host, port


def _port_is_open(host: str, port: int) -> bool:
    """Quick TCP check — is something listening?"""
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


async def _run_cmd(*args: str) -> tuple[int, str]:
    """Run a shell command and return (returncode, stdout)."""
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    return proc.returncode or 0, stdout.decode()


async def _wait_for_port(
    host: str, port: int, timeout: int = 30,
) -> bool:
    """Poll TCP port until open or timeout."""
    for _ in range(timeout):
        if _port_is_open(host, port):
            return True
        await asyncio.sleep(1)
    return False


async def _try_brew_start() -> bool:
    """Check if neo4j is a brew service and start it."""
    code, output = await _run_cmd(
        "brew", "services", "list",
    )
    if code != 0:
        return False

    for line in output.splitlines():
        if "neo4j" in line:
            logger.info("neo4j_found_in_brew")
            rc, _ = await _run_cmd(
                "brew", "services", "start", "neo4j",
            )
            if rc == 0:
                logger.info("neo4j_brew_started")
                return True
            logger.warning("neo4j_brew_start_failed")
            return False

    return False


def _find_compose_cmd() -> list[str] | None:
    """Find a working compose command (podman compose or docker compose)."""
    import shutil

    if shutil.which("podman"):
        return ["podman", "compose"]
    if shutil.which("docker"):
        return ["docker", "compose"]
    return None


async def _try_docker_start() -> bool:
    """Start Neo4j via podman/docker compose from project root."""
    compose_file = _PROJECT_ROOT / "docker-compose.yml"
    if not compose_file.exists():
        return False

    cmd = _find_compose_cmd()
    if not cmd:
        logger.warning("no_compose_runtime_found")
        return False

    logger.info("neo4j_starting_compose", cmd=cmd[0])
    rc, _ = await _run_cmd(*cmd, "up", "-d")
    if rc == 0:
        logger.info("neo4j_compose_started", runtime=cmd[0])
        return True

    logger.warning("neo4j_compose_start_failed", runtime=cmd[0])
    return False


async def ensure_neo4j_running(uri: str) -> None:
    """Ensure Neo4j is reachable, starting it if needed.

    Strategy:
    1. Check if bolt port is already open → done
    2. Try brew services start neo4j
    3. Fall back to docker compose up -d
    4. Wait for port to become available

    Args:
        uri: Neo4j bolt URI (e.g. bolt://localhost:7687).
    """
    host, port = _parse_bolt_address(uri)

    if _port_is_open(host, port):
        logger.info("neo4j_already_running", host=host, port=port)
        return

    # In container environments Neo4j runs as a sidecar — skip local start attempts
    if os.getenv("DEPLOY_ENV") == "aws":
        logger.info("neo4j_waiting_for_sidecar", host=host, port=port)
        if await _wait_for_port(host, port, timeout=60):
            logger.info("neo4j_ready", host=host, port=port)
        else:
            logger.error("neo4j_sidecar_timeout", host=host, port=port)
        return

    logger.info("neo4j_not_running", host=host, port=port)

    started = await _try_brew_start()
    if not started:
        started = await _try_docker_start()

    if not started:
        logger.error("neo4j_could_not_start")
        return

    if await _wait_for_port(host, port):
        logger.info("neo4j_ready", host=host, port=port)
    else:
        logger.error(
            "neo4j_start_timeout",
            host=host, port=port,
        )
