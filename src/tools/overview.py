"""Overview MCP tools — org-wide dashboards and topology maps."""

from __future__ import annotations

from mcp.server.fastmcp import Context


def get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


async def get_org_overview(ctx: Context) -> str:
    """Get a high-level overview of the entire AWS Organization.

    Shows total accounts, resource counts by type, and region distribution.
    Use this when you need the LIST of account names or region breakdown.
    For categorized resource counts (Compute, Database, etc.), use
    get_fleet_summary instead. For a single account's resources, use
    get_account_summary.

    Returns:
        Organization-wide summary with accounts, resources, and regions.
    """
    app = get_app_context(ctx)

    accounts_query = """
    MATCH (a:Account)
    RETURN count(DISTINCT a.account_id) AS total_accounts,
           collect(DISTINCT a.name) AS account_names
    """

    resource_query = """
    MATCH (n)
    WITH labels(n) AS node_labels, count(*) AS cnt
    UNWIND node_labels AS label
    RETURN label, sum(cnt) AS count
    ORDER BY count DESC
    """

    region_query = """
    MATCH (n)
    WHERE n.region IS NOT NULL AND n.region <> 'global'
    RETURN n.region AS region, count(*) AS count
    ORDER BY count DESC
    """

    accounts = await app.neo4j.query(accounts_query)
    resources = await app.neo4j.query(resource_query)
    regions = await app.neo4j.query(region_query)

    lines = ["=== AWS Organization Overview ===\n"]

    if accounts:
        a = accounts[0]
        lines.append(f"Accounts ({a['total_accounts']}):")
        for name in a.get("account_names", []):
            lines.append(f"  - {name}")
        lines.append("")

    if resources:
        total = sum(r["count"] for r in resources)
        lines.append(f"Resources ({total} total):")
        for r in resources:
            lines.append(f"  {r['label']}: {r['count']}")
        lines.append("")

    if regions:
        lines.append("Regions:")
        for r in regions:
            lines.append(f"  {r['region']}: {r['count']} resources")

    if not accounts and not resources:
        return "No data in the graph. Run refresh_graph first."

    return "\n".join(lines)


async def get_vpc_topology(ctx: Context, account_id: str = "") -> str:
    """Get the VPC topology showing VPCs, subnets, peering, and sharing.

    Shows RAM-shared VPC relationships so you can see which accounts
    share VPCs and where networking resources (NAT, IGW) actually live.

    Args:
        account_id: AWS account ID. Empty for all accounts.

    Returns:
        VPC map with subnets, instance counts, peering, and shared
        VPC account IDs.
    """
    app = get_app_context(ctx)

    params = {"account_id": account_id} if account_id else {}

    # When filtering by account, also include shared VPCs
    # (VPCs owned by other accounts that this account consumes
    # via RAM sharing — linked by SHARED_WITH edges).
    if account_id:
        vpc_match = """
    MATCH (local:VPC {account_id: $account_id})
    WITH collect(DISTINCT local) AS locals
    UNWIND locals AS lv
    OPTIONAL MATCH (lv)-[:SHARED_WITH]-(owner:VPC)
    WHERE owner.account_id <> $account_id
    WITH locals + collect(DISTINCT owner) AS all_vpcs
    UNWIND all_vpcs AS vpc
    WITH DISTINCT vpc"""
    else:
        vpc_match = "MATCH (vpc:VPC)"

    query = f"""
    {vpc_match}
    OPTIONAL MATCH (subnet:Subnet)-[:PART_OF]->(vpc)
    OPTIONAL MATCH (instance:EC2Instance)-[:RUNS_IN]->(subnet)
    WITH vpc, collect(DISTINCT {{
        name: subnet.name,
        cidr: subnet.cidr_block,
        az: subnet.availability_zone
    }}) AS subnets,
    count(DISTINCT instance) AS instance_count
    OPTIONAL MATCH (vpc)-[:PEERS_WITH]-(peer:VPC)
    WITH vpc, subnets, instance_count,
         collect(DISTINCT peer.name) AS peered_vpcs
    OPTIONAL MATCH (vpc)-[:SHARED_WITH]-(shared:VPC)
    RETURN vpc.name AS vpc_name, vpc.arn AS vpc_arn,
           vpc.cidr_block AS cidr,
           vpc.secondary_cidrs AS secondary_cidrs,
           vpc.account_id AS account_id,
           vpc.owner_id AS owner_id,
           vpc.region AS region, subnets, instance_count,
           peered_vpcs,
           collect(DISTINCT shared.account_id) AS shared_accounts
    ORDER BY vpc.account_id, vpc.name
    """

    results = await app.neo4j.query(query, params)
    if not results:
        scope = f"account {account_id}" if account_id else "the org"
        return f"No VPCs found in {scope}."

    lines = [f"VPC Topology ({len(results)} VPCs):\n"]
    for r in results:
        cidr_display = r["cidr"] or "?"
        secondary = r.get("secondary_cidrs") or []
        if secondary:
            cidr_display += (
                f", {', '.join(secondary)}"
            )
        lines.append(
            f"  {r['vpc_name']} ({cidr_display})"
        )
        lines.append(
            f"    Account: {r['account_id']}"
            f" | Region: {r['region']}"
        )
        owner_id = r.get("owner_id", "")
        if owner_id and owner_id != r["account_id"]:
            lines.append(
                f"    VPC Owner: {owner_id}"
                f" (shared via RAM)"
            )
        lines.append(
            f"    Instances: {r['instance_count']}"
        )

        subnets = [s for s in r["subnets"] if s.get("name")]
        if subnets:
            lines.append(
                f"    Subnets ({len(subnets)}):"
            )
            for s in subnets:
                lines.append(
                    f"      - {s['name']}"
                    f" ({s.get('cidr', '?')})"
                    f" [{s.get('az', '?')}]"
                )

        peers = r.get("peered_vpcs", [])
        if peers:
            lines.append(f"    Peered with: {', '.join(peers)}")

        shared = [
            a for a in r.get("shared_accounts", []) if a
        ]
        if shared:
            lines.append(
                f"    Shared with: {', '.join(shared)}"
            )

        lines.append("")

    return "\n".join(lines)


async def get_service_map(ctx: Context, account_id: str = "") -> str:
    """Get a service connectivity map showing how services connect.

    Shows which resource types have relationships and how many connections
    exist between them.

    Args:
        account_id: AWS account ID. Empty for all accounts.

    Returns:
        Connectivity matrix between service types.
    """
    app = get_app_context(ctx)

    account_filter = ""
    params: dict = {}
    if account_id:
        account_filter = (
            "WHERE source.account_id = $account_id"
        )
        params["account_id"] = account_id

    query = f"""
    MATCH (source)-[r]->(target)
    {account_filter}
    WITH labels(source)[0] AS from_type, type(r) AS rel,
         labels(target)[0] AS to_type, count(*) AS cnt
    RETURN from_type, rel, to_type, cnt
    ORDER BY cnt DESC
    LIMIT 50
    """

    results = await app.neo4j.query(query, params)
    if not results:
        return "No relationships found. Run refresh_graph first."

    scope = (
        f"Account {account_id}" if account_id else "Organization"
    )
    total_edges = sum(r["cnt"] for r in results)
    lines = [
        f"{scope} Service Map ({total_edges} connections):\n"
    ]
    for r in results:
        lines.append(
            f"  {r['from_type']} --[{r['rel']}]--> "
            f"{r['to_type']} ({r['cnt']})"
        )

    return "\n".join(lines)
