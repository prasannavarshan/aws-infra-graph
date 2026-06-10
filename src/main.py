"""MCP server entry point using FastMCP with lifespan pattern."""

# ruff: noqa: I001 — import order matters: load_dotenv before src.* so Settings sees .env
from __future__ import annotations

from dotenv import load_dotenv
load_dotenv()

import os  # noqa: E402
import ssl  # noqa: E402

# Disable SSL verification globally when AWS_SSL_VERIFY=false.
# Required for corporate networks with SSL-intercepting proxies.
if os.getenv("AWS_SSL_VERIFY", "true").lower() == "false":
    ssl._create_default_https_context = ssl._create_unverified_context
    import urllib3  # noqa: E402
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    os.environ.setdefault("PYTHONHTTPSVERIFY", "0")

import src.logging_config  # noqa: F401, E402
import contextlib  # noqa: E402
import logging  # noqa: E402
from collections.abc import AsyncIterator  # noqa: E402
from contextlib import asynccontextmanager  # noqa: E402
from dataclasses import dataclass  # noqa: E402

from mcp.server.fastmcp import FastMCP  # noqa: E402

logger = logging.getLogger(__name__)

from src.config import settings  # noqa: E402
from src.graph.neo4j_client import Neo4jClient  # noqa: E402

# --- Tool imports ---
from src.tools.admin import get_refresh_status, refresh_graph, run_refresh  # noqa: E402
from src.tools.refresh_state import refresh_state  # noqa: E402
from src.tools.cloudwan_routes import get_cloudwan_routes  # noqa: E402
from src.tools.cloudwan_tools import check_cloudwan_connectivity  # noqa: E402
from src.tools.connectivity import analyze_connectivity, get_tgw_routes  # noqa: E402
from src.tools.cost import (  # noqa: E402
    find_idle_resources,
    get_cost_by_service,
    get_resource_density,
)
from src.tools.feedback import (  # noqa: E402
    get_org_knowledge,
    review_org_knowledge,
    save_org_knowledge,
)
from src.tools.issue_report import (  # noqa: E402
    close_issue,
    list_issues,
    report_issue,
)
from src.tools.guided_connectivity import guided_connectivity_check  # noqa: E402
from src.tools.overview import (  # noqa: E402
    get_org_overview,
    get_service_map,
    get_vpc_topology,
)
from src.tools.resource_sgs import get_resource_security_groups  # noqa: E402
from src.tools.scp import get_effective_scps  # noqa: E402
from src.tools.search import (  # noqa: E402
    find_accounts,
    find_resources,
    get_account_summary,
    get_dependencies,
    get_fleet_summary,
    get_network_path,
    get_resource,
)
from src.tools.security import (  # noqa: E402
    find_cross_account_roles,
    find_open_security_groups,
    find_public_resources,
    trace_iam_permissions,
)
from src.tools.sg_connectivity import check_sg_connectivity  # noqa: E402
from src.tools.dns_trace import trace_dns  # noqa: E402
from src.tools.trace_route import trace_route  # noqa: E402


@dataclass
class AppContext:
    """Shared application context available to all MCP tools."""

    neo4j: Neo4jClient


# Module-level store so the /refresh HTTP endpoint can access the app context
# without going through an MCP tool Context object.
_app_context: AppContext | None = None


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Initialize and tear down shared resources."""
    global _app_context
    from src.neo4j_startup import ensure_neo4j_running

    # In HTTP mode, _app_context is already set by _run_http_with_auth and
    # must persist across MCP sessions. Reuse it if available.
    if _app_context is not None:
        yield _app_context
        return

    await ensure_neo4j_running(settings.neo4j.uri)
    neo4j = Neo4jClient()
    await neo4j.connect()
    ctx = AppContext(neo4j=neo4j)
    _app_context = ctx
    try:
        yield ctx
    finally:
        _app_context = None
        await neo4j.close()


mcp = FastMCP(
    "aws-infra-graph",
    instructions=(
        "Knowledge graph of AWS infrastructure. Query resources, trace dependencies, "
        "analyze security groups, check IAM permissions, and explore network topology "
        "across a multi-account AWS Organization.\n\n"
        "When you encounter unfamiliar org-specific terms, acronyms, or team names, "
        "call get_org_knowledge to look them up before guessing.\n\n"
        "When the user provides org-specific domain knowledge (acronyms, team names, "
        "account nicknames, service terminology), use save_org_knowledge to persist it. "
        "The user can then review and approve entries with review_org_knowledge, which "
        "writes approved knowledge to ORG_KNOWLEDGE.md for future sessions."
    ),
    lifespan=app_lifespan,
    host=settings.server.host,
    port=settings.server.port,
)

# ---------------------------------------------------------------------------
# Core tools (24 tools)
# ---------------------------------------------------------------------------

# --- Search ---
mcp.tool()(find_resources)
mcp.tool()(get_resource)
mcp.tool()(get_dependencies)
mcp.tool()(get_network_path)
mcp.tool()(get_account_summary)
mcp.tool()(get_fleet_summary)
mcp.tool()(find_accounts)

# --- Connectivity ---
mcp.tool()(analyze_connectivity)
mcp.tool()(check_sg_connectivity)
mcp.tool()(guided_connectivity_check)

# --- CloudWAN / Routing ---
mcp.tool()(check_cloudwan_connectivity)
mcp.tool()(get_cloudwan_routes)
mcp.tool()(get_tgw_routes)
mcp.tool()(trace_route)
mcp.tool()(trace_dns)

# --- Security ---
mcp.tool()(find_open_security_groups)
mcp.tool()(find_public_resources)
mcp.tool()(trace_iam_permissions)
mcp.tool()(find_cross_account_roles)
mcp.tool()(get_effective_scps)
mcp.tool()(get_resource_security_groups)

# --- Overview ---
mcp.tool()(get_org_overview)
mcp.tool()(get_vpc_topology)
mcp.tool()(get_service_map)

# --- Org Knowledge (lookup — always needed for context) ---
mcp.tool()(get_org_knowledge)

# ---------------------------------------------------------------------------
# Admin tools — tool filtering is handled by LiteLLM toolsets (infra_core /
# infra_full). Server always registers all tools.
# ---------------------------------------------------------------------------

# --- Graph Admin ---
mcp.tool()(refresh_graph)
mcp.tool()(get_refresh_status)

# --- Cost ---
mcp.tool()(get_cost_by_service)
mcp.tool()(get_resource_density)
mcp.tool()(find_idle_resources)

# --- Org Knowledge (write/review) ---
mcp.tool()(save_org_knowledge)
mcp.tool()(review_org_knowledge)

# --- Issue Reporting ---
mcp.tool()(report_issue)
mcp.tool()(list_issues)
mcp.tool()(close_issue)


def _patch_tool_descriptions(server: FastMCP) -> None:
    """Inject parameter descriptions parsed from Google-style docstring Args sections.

    Bedrock's Converse API requires every tool parameter to have a non-empty description.
    FastMCP generates JSON schemas from type annotations only — it does not parse docstrings.
    This function fills the gap by reading each tool function's Args: section and writing
    the descriptions into the already-generated parameters schema.
    """
    import re

    def _parse_args(docstring: str) -> dict[str, str]:
        """Return {param_name: description} from a Google-style Args: section."""
        if not docstring:
            return {}
        args_match = re.search(r"\bArgs:\s*\n(.*?)(?:\n\s*\n\s*\S|\Z)", docstring, re.DOTALL)
        if not args_match:
            return {}
        block = args_match.group(1)
        descriptions: dict[str, str] = {}
        current_param: str | None = None
        current_lines: list[str] = []
        for line in block.splitlines():
            param_match = re.match(r"^\s{4,8}(\w+)\s*:\s*(.*)", line)
            if param_match and not re.match(r"^\s{12,}", line):
                if current_param:
                    descriptions[current_param] = " ".join(current_lines).strip()
                current_param = param_match.group(1)
                current_lines = [param_match.group(2).strip()]
            elif current_param and line.strip():
                current_lines.append(line.strip())
        if current_param:
            descriptions[current_param] = " ".join(current_lines).strip()
        return descriptions

    for tool in server._tool_manager.list_tools():
        docstring = tool.fn.__doc__ or ""
        param_descs = _parse_args(docstring)
        if not param_descs:
            continue
        props = tool.parameters.get("properties", {})
        for param, desc in param_descs.items():
            if param in props and not props[param].get("description") and desc:
                props[param]["description"] = desc


def _sanitize_tool_schemas(server: FastMCP) -> None:
    """Strip schema fields that Bedrock's Converse API rejects.

    FastMCP adds 'title' to every property and at the root of the schema,
    and injects 'default' values into optional parameters. Bedrock rejects
    both with a ValidationException: Improperly formed request.
    """
    for tool in server._tool_manager.list_tools():
        schema = tool.parameters
        schema.pop("title", None)
        for prop in schema.get("properties", {}).values():
            prop.pop("title", None)
            prop.pop("default", None)


_patch_tool_descriptions(mcp)
_sanitize_tool_schemas(mcp)


# --- Entry point ---


def _persist_token_to_env(token: str) -> None:
    """Append MCP_AUTH_TOKEN to .env file (create if needed)."""
    from pathlib import Path

    env_path = Path(__file__).resolve().parent.parent / ".env"
    line = f"\nMCP_AUTH_TOKEN={token}\n"
    if env_path.exists():
        content = env_path.read_text()
        if "MCP_AUTH_TOKEN=" in content:
            return  # already set, don't overwrite
        env_path.write_text(content.rstrip("\n") + line)
    else:
        env_path.write_text(line.lstrip("\n"))
    logger.info("Saved MCP_AUTH_TOKEN to %s", env_path)


async def _run_http_with_auth() -> None:
    """Run streamable-HTTP server with bearer token auth."""
    import uvicorn

    from src.auth import BearerAuthMiddleware, generate_token

    token = settings.server.auth_token
    if not token:
        token = generate_token()
        _persist_token_to_env(token)
        logger.info(
            "Generated MCP_AUTH_TOKEN and saved to .env."
            " Token: %s", token,
        )

    from starlette.responses import JSONResponse
    from starlette.routing import Route

    # streamable_http_app() creates its own Starlette app with its own lifespan
    # (session_manager.run()) — it does NOT run the FastMCP app_lifespan.
    # We initialise Neo4j here and keep it alive for the server's full lifetime.
    from src.neo4j_startup import ensure_neo4j_running
    await ensure_neo4j_running(settings.neo4j.uri)
    neo4j = Neo4jClient()
    await neo4j.connect()
    global _app_context
    _app_context = AppContext(neo4j=neo4j)

    starlette_app = mcp.streamable_http_app()
    starlette_app.add_middleware(BearerAuthMiddleware, token=token)

    async def health_check(request):  # noqa: ANN001, ARG001
        return JSONResponse({"status": "ok"})

    async def trigger_refresh(request):  # noqa: ANN001
        if _app_context is None:
            return JSONResponse({"error": "server not ready"}, status_code=503)
        if refresh_state.is_running:
            return JSONResponse({"error": "refresh already in progress"}, status_code=409)
        import asyncio
        asyncio.ensure_future(run_refresh(_app_context, trigger="scheduled"))
        return JSONResponse({"status": "refresh started"}, status_code=202)

    starlette_app.routes.append(Route("/health", health_check))
    starlette_app.routes.append(Route("/refresh", trigger_refresh, methods=["POST"]))

    logger.info(
        "MCP server starting on http://%s:%d/mcp (auth: bearer token)",
        settings.server.host, settings.server.port,
    )

    config = uvicorn.Config(
        starlette_app,
        host=settings.server.host,
        port=settings.server.port,
        log_level="info",
    )
    server = uvicorn.Server(config)
    try:
        await server.serve()
    finally:
        _app_context = None
        await neo4j.close()


def main():
    """Run the MCP server."""
    import anyio

    transport = os.getenv("TRANSPORT", "stdio")
    if transport in ("sse", "http"):
        anyio.run(_run_http_with_auth)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        main()
