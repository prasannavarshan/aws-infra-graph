"""SCP analysis MCP tools — effective SCPs via OU hierarchy traversal."""

from __future__ import annotations

from mcp.server.fastmcp import Context


def get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


async def get_effective_scps(
    ctx: Context,
    account_id: str = "",
    ou_name: str = "",
) -> str:
    """Get all SCPs that apply to an account or OU, including inherited.

    Traverses the OU hierarchy from the target up to the root,
    collecting all GOVERNED_BY edges at every level. SCPs are
    inherited — a policy on a parent OU applies to all children.

    Args:
        account_id: AWS account ID (12-digit). Use find_accounts
            to resolve a name to an account ID.
        ou_name: OU name (e.g. "SLG-Prod", "Security"). Used
            instead of account_id to check SCPs on an OU directly.
            Provide either account_id or ou_name, not both.

    Returns:
        All effective SCPs grouped by where they are attached
        in the OU hierarchy, from the target up to the root.
    """
    if not account_id and not ou_name:
        return (
            "Provide either account_id or ou_name. "
            "Use find_accounts to resolve a name to an ID."
        )

    app = get_app_context(ctx)

    if account_id:
        return await _scps_for_account(app, account_id)
    return await _scps_for_ou(app, ou_name)


async def _scps_for_account(app, account_id: str) -> str:
    """Get effective SCPs for an account via OU hierarchy."""
    # Step 1: Find the account and its direct OU
    acct_query = """
    MATCH (a:Account {account_id: $account_id})
    OPTIONAL MATCH (a)-[:MEMBER_OF]->(ou:OrganizationalUnit)
    RETURN a.name AS acct_name,
           a.arn AS acct_arn,
           ou.name AS ou_name,
           ou.arn AS ou_arn
    """
    acct_result = await app.neo4j.query(
        acct_query, {"account_id": account_id},
    )
    if not acct_result:
        return f"No account found with ID: {account_id}"

    acct = acct_result[0]
    acct_name = acct.get("acct_name", account_id)

    # Step 2: Get SCPs directly on the account
    direct_query = """
    MATCH (a:Account {account_id: $account_id})
          -[:GOVERNED_BY]->(scp:ServiceControlPolicy)
    RETURN scp.name AS name, scp.arn AS arn,
           scp.aws_managed AS aws_managed,
           scp.policy_summary AS summary,
           scp.description AS description
    """
    direct_scps = await app.neo4j.query(
        direct_query, {"account_id": account_id},
    )

    # Step 3: Walk OU hierarchy and collect SCPs at each level
    hierarchy_query = """
    MATCH (a:Account {account_id: $account_id})
          -[:MEMBER_OF]->(ou:OrganizationalUnit)
    MATCH path = (ou)-[:PART_OF*0..10]->(ancestor:OrganizationalUnit)
    WITH ancestor, length(path) AS depth
    ORDER BY depth ASC
    MATCH (ancestor)-[:GOVERNED_BY]->(scp:ServiceControlPolicy)
    RETURN ancestor.name AS ou_name,
           ancestor.arn AS ou_arn,
           depth,
           scp.name AS name,
           scp.arn AS arn,
           scp.aws_managed AS aws_managed,
           scp.policy_summary AS summary,
           scp.description AS description
    ORDER BY depth ASC
    """
    hierarchy_scps = await app.neo4j.query(
        hierarchy_query, {"account_id": account_id},
    )

    return _format_effective_scps(
        f"Account {acct_name} ({account_id})",
        direct_scps,
        hierarchy_scps,
    )


async def _scps_for_ou(app, ou_name: str) -> str:
    """Get effective SCPs for an OU via hierarchy."""
    # Find the OU
    ou_query = """
    MATCH (ou:OrganizationalUnit)
    WHERE toLower(ou.name) CONTAINS toLower($ou_name)
    RETURN ou.name AS name, ou.arn AS arn
    """
    ou_result = await app.neo4j.query(
        ou_query, {"ou_name": ou_name},
    )
    if not ou_result:
        return f"No OU found matching: {ou_name}"
    if len(ou_result) > 1:
        names = [r["name"] for r in ou_result]
        return (
            f"Multiple OUs match '{ou_name}': "
            f"{', '.join(names)}. Be more specific."
        )

    ou = ou_result[0]
    target_arn = ou["arn"]

    # Direct SCPs on this OU
    direct_query = """
    MATCH (ou:OrganizationalUnit {arn: $arn})
          -[:GOVERNED_BY]->(scp:ServiceControlPolicy)
    RETURN scp.name AS name, scp.arn AS arn,
           scp.aws_managed AS aws_managed,
           scp.policy_summary AS summary,
           scp.description AS description
    """
    direct_scps = await app.neo4j.query(
        direct_query, {"arn": target_arn},
    )

    # Walk up to root
    hierarchy_query = """
    MATCH (ou:OrganizationalUnit {arn: $arn})
    MATCH path = (ou)-[:PART_OF*1..10]->(ancestor:OrganizationalUnit)
    WITH ancestor, length(path) AS depth
    ORDER BY depth ASC
    MATCH (ancestor)-[:GOVERNED_BY]->(scp:ServiceControlPolicy)
    RETURN ancestor.name AS ou_name,
           ancestor.arn AS ou_arn,
           depth,
           scp.name AS name,
           scp.arn AS arn,
           scp.aws_managed AS aws_managed,
           scp.policy_summary AS summary,
           scp.description AS description
    ORDER BY depth ASC
    """
    hierarchy_scps = await app.neo4j.query(
        hierarchy_query, {"arn": target_arn},
    )

    return _format_effective_scps(
        f"OU: {ou['name']}",
        direct_scps,
        hierarchy_scps,
    )


def _format_effective_scps(
    target: str,
    direct_scps: list[dict],
    hierarchy_scps: list[dict],
) -> str:
    """Format effective SCPs into readable output."""
    lines = [f"Effective SCPs for {target}:\n"]

    total = len(direct_scps) + len(hierarchy_scps)
    if total == 0:
        lines.append("  No SCPs found (check OU hierarchy).")
        return "\n".join(lines)

    # Direct SCPs
    if direct_scps:
        lines.append("Direct (attached to target):")
        for scp in direct_scps:
            lines.append(_format_scp_line(scp))
        lines.append("")

    # Inherited SCPs grouped by OU level
    if hierarchy_scps:
        lines.append("Inherited (from parent OUs):")
        current_ou = ""
        for scp in hierarchy_scps:
            ou = scp.get("ou_name", "")
            if ou != current_ou:
                current_ou = ou
                lines.append(f"  [{ou}]:")
            lines.append(_format_scp_line(scp, indent=4))
        lines.append("")

    lines.append(
        f"Total: {total} SCP(s) effective on {target}"
    )
    return "\n".join(lines)


def _format_scp_line(scp: dict, indent: int = 2) -> str:
    """Format a single SCP as an indented line."""
    prefix = " " * indent
    name = scp.get("name", "unnamed")
    managed = " [AWS managed]" if scp.get("aws_managed") else ""
    summary = scp.get("summary") or scp.get("description") or ""
    if summary:
        summary = f" — {summary}"
    return f"{prefix}- {name}{managed}{summary}"
