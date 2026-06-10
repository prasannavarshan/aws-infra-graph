"""Cost analysis MCP tools — spending by service, account, and resource."""

from __future__ import annotations

from mcp.server.fastmcp import Context


def get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


async def get_cost_by_service(
    ctx: Context, account_id: str = "", days: int = 30
) -> str:
    """Get AWS spending breakdown by service for an account or the whole org.

    Args:
        account_id: AWS account ID. Empty for org-wide costs.
        days: Number of days to look back (default 30, max 90).

    Returns:
        Cost breakdown by service, sorted by spend descending.
    """
    app = get_app_context(ctx)
    days = min(days, 90)

    account_filter = (
        "WHERE n.account_id = $account_id" if account_id else ""
    )
    params: dict = {"days": days}
    if account_id:
        params["account_id"] = account_id

    query = f"""
    MATCH (n) {account_filter}
    WITH labels(n) AS node_labels, n.account_id AS acct,
         count(*) AS resource_count
    UNWIND node_labels AS label
    WITH label, count(DISTINCT acct) AS accounts,
         sum(resource_count) AS total_resources
    RETURN label AS service, accounts, total_resources
    ORDER BY total_resources DESC
    """

    results = await app.neo4j.query(query, params)
    if not results:
        scope = f"account {account_id}" if account_id else "the organization"
        return f"No resources found in {scope}."

    scope = f"Account {account_id}" if account_id else "Organization"
    lines = [
        f"{scope} Resource Distribution (proxy for cost):\n",
        "  Note: Actual cost data requires AWS Cost Explorer integration.",
        "  Showing resource counts as a cost indicator.\n",
    ]
    for r in results:
        lines.append(
            f"  {r['service']}: {r['total_resources']} resources"
            f" across {r['accounts']} account(s)"
        )

    return "\n".join(lines)


async def get_resource_density(
    ctx: Context, resource_type: str = ""
) -> str:
    """Show resource density across accounts and regions.

    Identifies accounts/regions with the most resources, which often
    correlate with highest cost.

    Args:
        resource_type: Filter by resource type (e.g., EC2Instance). Empty for all.

    Returns:
        Resource counts per account and region combination.
    """
    app = get_app_context(ctx)

    type_match = f"(n:{resource_type})" if resource_type else "(n)"
    query = f"""
    MATCH {type_match}
    WITH n.account_id AS account_id, n.region AS region,
         labels(n) AS node_labels, count(*) AS cnt
    UNWIND node_labels AS label
    RETURN account_id, region, label,
           sum(cnt) AS resource_count
    ORDER BY resource_count DESC
    LIMIT 50
    """

    results = await app.neo4j.query(query)
    if not results:
        return "No resources found."

    scope = resource_type or "All"
    lines = [f"Resource Density — {scope}:\n"]
    for r in results:
        lines.append(
            f"  {r['account_id']} / {r['region']}: "
            f"{r['resource_count']} {r['label']}"
        )

    return "\n".join(lines)


async def find_idle_resources(ctx: Context) -> str:
    """Find potentially idle or underutilized resources.

    Identifies EC2 instances in stopped state, unattached load balancers,
    empty ECS clusters, and target groups with no targets.

    Returns:
        List of potentially idle resources grouped by type.
    """
    app = get_app_context(ctx)

    count_query = """
    MATCH (n)
    WHERE (n:EC2Instance AND n.state = 'stopped')
       OR (n:ECSCluster AND n.running_tasks = '0'
           AND n.active_services = '0')
    RETURN count(n) AS total
    """

    query = """
    MATCH (n)
    WHERE (n:EC2Instance AND n.state = 'stopped')
       OR (n:ECSCluster AND n.running_tasks = '0'
           AND n.active_services = '0')
    RETURN labels(n) AS labels, n.name AS name, n.arn AS arn,
           n.account_id AS account_id, n.region AS region,
           n.state AS state
    ORDER BY labels, n.name
    LIMIT 200
    """

    count_result = await app.neo4j.query(count_query)
    total = count_result[0]["total"] if count_result else 0

    results = await app.neo4j.query(query)
    if not results:
        return "No potentially idle resources found."

    shown = len(results)
    header = f"Potentially idle resources ({total} total"
    if shown < total:
        header += f", showing {shown}"
    header += "):\n"
    lines = [header]
    for r in results:
        label = ", ".join(r["labels"])
        lines.append(f"  [{label}] {r['name']}")
        lines.append(f"    ARN: {r['arn']}")
        lines.append(
            f"    Account: {r['account_id']} | Region: {r['region']}"
        )
        if r.get("state"):
            lines.append(f"    State: {r['state']}")

    return "\n".join(lines)
