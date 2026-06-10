"""Org knowledge feedback MCP tools — save and review domain knowledge."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from mcp.server.fastmcp import Context

logger = logging.getLogger(__name__)

VALID_CATEGORIES = frozenset({
    "acronym", "service", "account", "infra", "general",
})

CATEGORY_HEADERS = {
    "acronym": "## Acronyms",
    "service": "## Services",
    "account": "## Accounts",
    "infra": "## Infrastructure",
    "general": "## General",
}

ORG_KNOWLEDGE_PATH = (
    Path(__file__).resolve().parent.parent.parent
    / "ORG_KNOWLEDGE.md"
)


def _get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


def _generate_feedback_id() -> str:
    """Generate a timestamp-based feedback ID."""
    now = datetime.now(UTC)
    return f"fb-{now.strftime('%Y%m%d')}-{now.strftime('%H%M%S')}"


def _append_to_org_knowledge(
    content: str, category: str,
) -> None:
    """Append an approved entry under the correct category section.

    Args:
        content: The knowledge text to append.
        category: One of the valid category keys.
    """
    header = CATEGORY_HEADERS[category]
    text = ORG_KNOWLEDGE_PATH.read_text(encoding="utf-8")
    lines = text.split("\n")

    insert_idx: int | None = None
    for i, line in enumerate(lines):
        if line.strip() == header:
            # Find the end of this section (next ## or EOF)
            j = i + 1
            while j < len(lines) and not lines[j].startswith("## "):
                j += 1
            # Insert before the next section (or EOF),
            # skipping trailing blank lines
            insert_idx = j
            break

    if insert_idx is None:
        # Section header not found — append at end
        lines.append(f"\n{header}\n\n- {content}")
    else:
        lines.insert(insert_idx, f"- {content}\n")

    ORG_KNOWLEDGE_PATH.write_text(
        "\n".join(lines), encoding="utf-8",
    )


async def get_org_knowledge(ctx: Context) -> str:
    """Look up org-specific terminology, acronyms, and domain knowledge.

    Call this when you encounter unfamiliar org-specific terms,
    acronyms, account names, or team references. Contains
    approved entries like "payments = Payments Service" or account
    ownership mappings.

    Returns:
        Org knowledge entries organized by category (acronyms,
        services, accounts, infrastructure, general).
    """
    if not ORG_KNOWLEDGE_PATH.exists():
        return "No org knowledge file found."

    text = ORG_KNOWLEDGE_PATH.read_text(encoding="utf-8").strip()
    if not text:
        return "Org knowledge file is empty."

    return text


async def save_org_knowledge(
    ctx: Context,
    content: str,
    category: str = "general",
) -> str:
    """Save org-specific domain knowledge as a pending entry for review.

    Use this when the user provides org-specific terminology,
    acronyms, account names, or infrastructure knowledge that
    should be remembered across sessions.

    Args:
        content: The knowledge to save (e.g., "payments = Payments Service
            team, owns payments-beta and payments-prod").
        category: Classification — one of: acronym, service,
            account, infra, general. Defaults to general.

    Returns:
        Confirmation with the entry ID.
    """
    if not content or not content.strip():
        return "Error: content cannot be empty."

    if category not in VALID_CATEGORIES:
        valid = ", ".join(sorted(VALID_CATEGORIES))
        return (
            f"Error: invalid category '{category}'. "
            f"Valid options: {valid}"
        )

    app = _get_app_context(ctx)
    feedback_id = _generate_feedback_id()
    now_iso = datetime.now(UTC).isoformat()

    query = """
    CREATE (f:Feedback {
        feedback_id: $feedback_id,
        content: $content,
        category: $category,
        status: "pending",
        created_at: $created_at,
        reviewed_at: null
    })
    RETURN f.feedback_id AS id
    """
    await app.neo4j.query(query, {
        "feedback_id": feedback_id,
        "content": content.strip(),
        "category": category,
        "created_at": now_iso,
    })

    logger.info(
        "org_knowledge_saved",
        extra={"feedback_id": feedback_id, "category": category},
    )
    return (
        f"Org knowledge saved as pending: {feedback_id}\n"
        f"Category: {category}\n"
        f"Use review_org_knowledge(action='list') to see pending items, "
        f"then approve or reject."
    )


async def review_org_knowledge(
    ctx: Context,
    action: str,
    ids: str = "",
) -> str:
    """Review, approve, or reject pending org knowledge entries.

    Args:
        action: One of: list, approve, reject.
            - list: show all pending entries.
            - approve: approve entries and write to ORG_KNOWLEDGE.md.
            - reject: reject entries (kept in Neo4j for audit).
        ids: Comma-separated entry IDs for approve/reject
            (e.g., "fb-20260222-001,fb-20260222-002").
            Required for approve and reject actions.

    Returns:
        Formatted list of entries or confirmation of action.
    """
    app = _get_app_context(ctx)

    if action == "list":
        return await _list_pending(app)
    if action == "approve":
        return await _approve(app, ids)
    if action == "reject":
        return await _reject(app, ids)

    return (
        f"Error: unknown action '{action}'. "
        f"Valid actions: list, approve, reject."
    )


async def _list_pending(app) -> str:  # noqa: ANN001
    """Query and format all pending feedback entries."""
    query = """
    MATCH (f:Feedback {status: "pending"})
    RETURN f.feedback_id AS id, f.content AS content,
           f.category AS category, f.created_at AS created_at
    ORDER BY f.created_at
    """
    results = await app.neo4j.query(query)
    if not results:
        return "No pending feedback entries."

    lines = [f"Pending feedback ({len(results)}):\n"]
    for r in results:
        lines.append(f"  [{r['id']}] ({r['category']})")
        lines.append(f"    {r['content']}")
        lines.append(f"    Created: {r['created_at']}")
    return "\n".join(lines)


async def _approve(app, ids: str) -> str:  # noqa: ANN001
    """Approve feedback entries and write to ORG_KNOWLEDGE.md."""
    if not ids or not ids.strip():
        return "Error: ids required for approve action."

    id_list = [i.strip() for i in ids.split(",") if i.strip()]
    now_iso = datetime.now(UTC).isoformat()

    query = """
    MATCH (f:Feedback)
    WHERE f.feedback_id IN $ids AND f.status = "pending"
    SET f.status = "approved", f.reviewed_at = $reviewed_at
    RETURN f.feedback_id AS id, f.content AS content,
           f.category AS category
    """
    results = await app.neo4j.query(query, {
        "ids": id_list,
        "reviewed_at": now_iso,
    })

    if not results:
        return (
            f"No pending feedback found for IDs: {', '.join(id_list)}"
        )

    lines = [f"Approved {len(results)} entry(s):\n"]
    for r in results:
        _append_to_org_knowledge(r["content"], r["category"])
        lines.append(f"  [{r['id']}] {r['content']}")

    lines.append(
        "\nEntries written to ORG_KNOWLEDGE.md."
    )
    return "\n".join(lines)


async def _reject(app, ids: str) -> str:  # noqa: ANN001
    """Reject feedback entries (kept in Neo4j for audit)."""
    if not ids or not ids.strip():
        return "Error: ids required for reject action."

    id_list = [i.strip() for i in ids.split(",") if i.strip()]
    now_iso = datetime.now(UTC).isoformat()

    query = """
    MATCH (f:Feedback)
    WHERE f.feedback_id IN $ids AND f.status = "pending"
    SET f.status = "rejected", f.reviewed_at = $reviewed_at
    RETURN f.feedback_id AS id
    """
    results = await app.neo4j.query(query, {
        "ids": id_list,
        "reviewed_at": now_iso,
    })

    if not results:
        return (
            f"No pending feedback found for IDs: {', '.join(id_list)}"
        )

    rejected = [r["id"] for r in results]
    return (
        f"Rejected {len(rejected)} entry(s): "
        f"{', '.join(rejected)}"
    )
