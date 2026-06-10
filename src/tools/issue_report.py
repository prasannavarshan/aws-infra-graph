"""Issue reporting MCP tools — report and review tool quality issues."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from mcp.server.fastmcp import Context

logger = logging.getLogger(__name__)

VALID_SEVERITIES = frozenset({"high", "medium", "low"})
VALID_STATUSES = frozenset({"open", "closed", "all"})


def _get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


def _generate_issue_id() -> str:
    """Generate a timestamp-based issue ID."""
    now = datetime.now(UTC)
    return f"issue-{now.strftime('%Y%m%d')}-{now.strftime('%H%M%S')}"


async def report_issue(
    ctx: Context,
    tool_name: str,
    description: str,
    severity: str = "medium",
    query_context: str = "",
) -> str:
    """Report a bad experience or unexpected result from an MCP tool.

    Use this when a tool returns wrong data, crashes, gives confusing
    output, or behaves unexpectedly. Issues are stored in Neo4j and
    can be reviewed with list_issues.

    Args:
        tool_name: The MCP tool that caused the issue
            (e.g., "find_resources", "trace_dns").
        description: What went wrong — be specific about expected vs
            actual behaviour.
        severity: Impact level — one of: high, medium, low.
            Defaults to medium.
        query_context: Optional — the parameters or query used when
            the issue occurred (e.g., account name, resource type).

    Returns:
        Confirmation with the issue ID.
    """
    if not tool_name or not tool_name.strip():
        return "Error: tool_name cannot be empty."

    if not description or not description.strip():
        return "Error: description cannot be empty."

    if severity not in VALID_SEVERITIES:
        valid = ", ".join(sorted(VALID_SEVERITIES))
        return (
            f"Error: invalid severity '{severity}'. "
            f"Valid options: {valid}"
        )

    app = _get_app_context(ctx)
    issue_id = _generate_issue_id()
    now_iso = datetime.now(UTC).isoformat()

    query = """
    CREATE (i:ToolIssue {
        issue_id: $issue_id,
        tool_name: $tool_name,
        description: $description,
        severity: $severity,
        query_context: $query_context,
        status: "open",
        created_at: $created_at,
        closed_at: null
    })
    RETURN i.issue_id AS id
    """
    await app.neo4j.query(query, {
        "issue_id": issue_id,
        "tool_name": tool_name.strip(),
        "description": description.strip(),
        "severity": severity,
        "query_context": query_context.strip(),
        "created_at": now_iso,
    })

    logger.info(
        "issue_reported",
        extra={"issue_id": issue_id, "tool_name": tool_name, "severity": severity},
    )
    return (
        f"Issue reported: {issue_id}\n"
        f"Tool: {tool_name.strip()} | Severity: {severity}\n"
        f"Use list_issues() to see all open issues."
    )


async def list_issues(
    ctx: Context,
    status: str = "open",
    tool_name: str = "",
) -> str:
    """List reported tool issues.

    Args:
        status: Filter by status — one of: open, closed, all.
            Defaults to open.
        tool_name: Optional filter by tool name
            (e.g., "find_resources"). Leave empty to see all tools.

    Returns:
        Formatted list of issues matching the filters.
    """
    if status not in VALID_STATUSES:
        valid = ", ".join(sorted(VALID_STATUSES))
        return (
            f"Error: invalid status '{status}'. "
            f"Valid options: {valid}"
        )

    app = _get_app_context(ctx)

    status_filter = "" if status == "all" else f'AND i.status = "{status}"'

    tool_filter = ""
    params: dict = {}
    if tool_name and tool_name.strip():
        tool_filter = "AND i.tool_name = $tool_name"
        params["tool_name"] = tool_name.strip()

    cypher = f"""
    MATCH (i:ToolIssue)
    WHERE 1=1 {status_filter} {tool_filter}
    RETURN i.issue_id AS id, i.tool_name AS tool_name,
           i.description AS description, i.severity AS severity,
           i.status AS status, i.query_context AS query_context,
           i.created_at AS created_at
    ORDER BY
        CASE i.severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
        i.created_at DESC
    """
    results = await app.neo4j.query(cypher, params)

    if not results:
        filter_desc = f" for tool '{tool_name.strip()}'" if tool_name else ""
        return f"No {status} issues found{filter_desc}."

    lines = [f"Issues ({len(results)}) — status: {status}:\n"]
    for r in results:
        ctx_line = f"\n    Context: {r['query_context']}" if r["query_context"] else ""
        lines.append(
            f"  [{r['id']}] {r['tool_name']} | {r['severity'].upper()} | {r['status']}"
        )
        lines.append(f"    {r['description']}{ctx_line}")
        lines.append(f"    Reported: {r['created_at']}")
    return "\n".join(lines)


async def close_issue(
    ctx: Context,
    issue_id: str,
) -> str:
    """Close a resolved or invalid issue.

    Args:
        issue_id: The issue ID to close
            (e.g., "issue-20260325-143022").

    Returns:
        Confirmation or error message.
    """
    if not issue_id or not issue_id.strip():
        return "Error: issue_id cannot be empty."

    app = _get_app_context(ctx)
    now_iso = datetime.now(UTC).isoformat()

    cypher = """
    MATCH (i:ToolIssue {issue_id: $issue_id, status: "open"})
    SET i.status = "closed", i.closed_at = $closed_at
    RETURN i.issue_id AS id
    """
    results = await app.neo4j.query(cypher, {
        "issue_id": issue_id.strip(),
        "closed_at": now_iso,
    })

    if not results:
        return f"No open issue found with ID: {issue_id.strip()}"

    logger.info("issue_closed", extra={"issue_id": issue_id.strip()})
    return f"Issue {issue_id.strip()} closed."
