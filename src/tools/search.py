"""Search and resource lookup MCP tools."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from src.tools.name_cache import (
    enrich_account,
    load_account_names,
)


def _get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


_VPC_NETWORKING_TYPES = frozenset({
    "NATGateway", "InternetGateway", "RouteTable", "VPCPeering",
})


async def find_resources(
    ctx: Context,
    resource_type: str,
    region: str = "",
    account_id: str = "",
    name_contains: str = "",
    ip_address: str = "",
    include_shared_vpc: bool = True,
) -> str:
    """Find AWS resources by type with optional filters.

    Args:
        resource_type: Node label — must be one of:
            Account, VPC, Subnet, SecurityGroup, NetworkACL,
            EC2Instance, IAMRole, IAMPolicy, IAMUser, S3Bucket,
            RDSInstance, LambdaFunction, ECSCluster, ECSService,
            EKSCluster, EKSNodegroup, LoadBalancer, TargetGroup,
            Route53Zone, Route53Record, DynamoDBTable, SQSQueue,
            SNSTopic, CloudFrontDistribution, APIGateway,
            VPCEndpoint, TransitGateway, TGWAttachment,
            TGWRouteTable, CloudWANCoreNetwork, CloudWANSegment,
            CloudWANAttachment, RouteTable, NATGateway,
            InternetGateway, VPCPeering, ElastiCacheCluster,
            ElastiCacheReplicationGroup, ElastiCacheServerlessCache,
            OpenSearchDomain, WAFWebACL,
            NetworkInterface, CloudFormationStack,
            OrganizationalUnit, ServiceControlPolicy,
            ResolverEndpoint, ResolverRule,
            CodeCommitRepo, CodePipeline, CodeBuildProject,
            K8sNamespace, K8sDeployment, K8sService,
            K8sServiceAccount, K8sNode, K8sIngress.
        region: Filter by AWS region (e.g., us-east-1).
            Empty for all regions.
        account_id: Filter by AWS account ID. Empty for all
            accounts. Use find_accounts to resolve a name to
            an account ID.
        name_contains: Filter by name substring (case-insensitive).
            Also matches against the ARN.
        ip_address: Filter by IP address — matches private_ip,
            public_ip, or CIDR blocks (cidr_block). Supports
            partial match (e.g., "10.127" finds all 10.127.x.x).
        include_shared_vpc: When True (default) and account_id is
            provided, also search for VPC networking resources
            (NATGateway, InternetGateway, RouteTable, VPCPeering)
            in shared VPC owner accounts. For RAM-shared VPCs,
            these resources live in the VPC owner account, not
            the consumer. Set False to only search the exact
            account.

    Returns:
        Formatted list of matching resources with ARN, name,
        account, and region.
    """
    app = _get_app_context(ctx)

    where_clauses = []
    params: dict = {}

    if region:
        where_clauses.append("n.region = $region")
        params["region"] = region
    if account_id:
        where_clauses.append("n.account_id = $account_id")
        params["account_id"] = account_id
    if name_contains:
        where_clauses.append(
            "(toLower(n.name) CONTAINS toLower($name_contains)"
            " OR n.arn CONTAINS $name_contains"
            " OR n.resource_arn CONTAINS $name_contains)"
        )
        params["name_contains"] = name_contains
    if ip_address:
        where_clauses.append(
            "(n.private_ip CONTAINS $ip_address"
            " OR n.public_ip CONTAINS $ip_address"
            " OR n.cidr_block CONTAINS $ip_address)"
        )
        params["ip_address"] = ip_address

    where = (
        f"WHERE {' AND '.join(where_clauses)}"
        if where_clauses else ""
    )

    use_shared = (
        include_shared_vpc
        and account_id
        and resource_type in _VPC_NETWORKING_TYPES
    )

    shared_union = ""
    if use_shared:
        shared_union = (
            f"\nUNION\n"
            f"MATCH (my_vpc:VPC {{account_id: $account_id}})"
            f"-[:SHARED_WITH]-(owner_vpc:VPC)\n"
            f"MATCH (owner_vpc)<-[:PART_OF]-(n:{resource_type})\n"
            f"RETURN n"
        )

    base_match = f"MATCH (n:{resource_type}) {where}"

    if use_shared:
        inner = f"{base_match} RETURN n{shared_union}"
        count_query = (
            f"CALL () {{ {inner} }}"
            f" RETURN count(n) AS total"
        )
        full_query = (
            f"CALL () {{ {inner} }}"
            f" RETURN n LIMIT 200"
        )
    else:
        count_query = (
            f"{base_match} RETURN count(n) AS total"
        )
        full_query = f"{base_match} RETURN n LIMIT 200"

    count_result = await app.neo4j.query(count_query, params)
    total = count_result[0]["total"] if count_result else 0

    results = await app.neo4j.query(full_query, params)
    if not results:
        return (
            f"No {resource_type} resources found"
            f" matching the filters."
        )

    acct_names = await load_account_names(app.neo4j)

    shown = len(results)
    header = f"Found {total} {resource_type} resource(s)"
    if shown < total:
        header += f" (showing {shown})"
    lines = [header + ":\n"]
    for r in results:
        node = r["n"]
        name = node.get('name', 'unnamed')
        arn = node.get('arn', 'no-arn')
        lines.append(f"  - {name} ({arn})")
        acct_label = enrich_account(
            node.get('account_id', ''), acct_names,
        )
        detail = (
            f"    Account: {acct_label}"
            f" | Region: {node.get('region')}"
        )
        if node.get('private_ip'):
            detail += f" | Private IP: {node['private_ip']}"
        if node.get('public_ip'):
            detail += f" | Public IP: {node['public_ip']}"
        if node.get('cidr_block'):
            detail += f" | CIDR: {node['cidr_block']}"
        owner = node.get('owner_id', '')
        acct = node.get('account_id', '')
        if owner and owner != acct:
            owner_label = enrich_account(owner, acct_names)
            detail += f" | Owner: {owner_label}"
        lines.append(detail)
    return "\n".join(lines)


async def get_resource(ctx: Context, arn: str) -> str:
    """Get detailed information about a specific AWS resource by its ARN.

    Args:
        arn: The full AWS ARN of the resource.

    Returns:
        All properties and relationships of the resource.
    """
    app = _get_app_context(ctx)

    node_query = "MATCH (n:Resource {arn: $arn}) RETURN n, labels(n) AS labels"
    rel_query = """
    MATCH (n:Resource {arn: $arn})-[r]-(m)
    RETURN type(r) AS rel_type, m.arn AS related_arn, m.name AS related_name,
           labels(m) AS related_labels,
           CASE WHEN startNode(r) = n THEN 'outgoing' ELSE 'incoming' END AS direction
    """

    nodes = await app.neo4j.query(node_query, {"arn": arn})
    if not nodes:
        return f"No resource found with ARN: {arn}"

    node = nodes[0]["n"]
    labels = nodes[0]["labels"]
    acct_names = await load_account_names(app.neo4j)
    acct_label = enrich_account(
        node.get('account_id', ''), acct_names,
    )

    lines = [f"Resource: {node.get('name', 'unnamed')}"]
    lines.append(f"Type: {', '.join(labels)}")
    lines.append(f"ARN: {arn}")
    lines.append(f"Account: {acct_label} | Region: {node.get('region')}")
    lines.append("\nProperties:")
    for key, value in sorted(node.items()):
        if key not in ("arn", "name", "account_id", "region"):
            lines.append(f"  {key}: {value}")

    rels = await app.neo4j.query(rel_query, {"arn": arn})
    if rels:
        lines.append(f"\nRelationships ({len(rels)}):")
        for r in rels:
            direction = "->" if r["direction"] == "outgoing" else "<-"
            lines.append(
                f"  {direction} {r['rel_type']} {r['related_name']} "
                f"({', '.join(r['related_labels'])})"
            )

    return "\n".join(lines)


async def get_dependencies(ctx: Context, arn: str, depth: int = 2) -> str:
    """Find all resources that a given resource depends on (outgoing relationships).

    Args:
        arn: The full AWS ARN of the resource.
        depth: How many relationship hops to traverse (default 2, max 5).

    Returns:
        Tree of dependencies from the resource.
    """
    app = _get_app_context(ctx)
    depth = min(depth, 5)

    query = f"""
    MATCH path = (n {{arn: $arn}})-[*1..{depth}]->(m)
    RETURN [node in nodes(path) |
        {{arn: node.arn, name: node.name, labels: labels(node)}}
    ] AS chain,
    [rel in relationships(path) | type(rel)] AS rel_types
    LIMIT 100
    """

    results = await app.neo4j.query(query, {"arn": arn})
    if not results:
        return f"No dependencies found for: {arn}"

    lines = [f"Dependencies for {arn} (depth {depth}):\n"]
    seen = set()
    for r in results:
        chain = r["chain"]
        rel_types = r["rel_types"]
        path_str = ""
        for i, node in enumerate(chain):
            if i > 0:
                path_str += f" --[{rel_types[i-1]}]--> "
            path_str += f"{node['name']} ({', '.join(node['labels'])})"
        if path_str not in seen:
            seen.add(path_str)
            lines.append(f"  {path_str}")

    return "\n".join(lines)


async def get_network_path(ctx: Context, source_arn: str, target_arn: str) -> str:
    """Trace the network path between two AWS resources.

    Shows VPCs, subnets, security groups, load balancers, and other
    resources in the shortest graph path. For full connectivity
    analysis including SG/NACL rule evaluation, use
    analyze_connectivity instead.

    This is for VPC-level path tracing (resource ARN to resource ARN).
    For CloudWAN segment-level routing between IP addresses, use
    trace_route instead.

    Args:
        source_arn: ARN of the source resource.
        target_arn: ARN of the target resource.

    Returns:
        The shortest path with all intermediate resources and relationships.
    """
    app = _get_app_context(ctx)

    query = """
    MATCH path = shortestPath((source {arn: $source_arn})-[*..20]-(target {arn: $target_arn}))
    RETURN [node in nodes(path) | {arn: node.arn, name: node.name, labels: labels(node)}] AS nodes,
           [rel in relationships(path) | type(rel)] AS relationships
    """

    results = await app.neo4j.query(query, {
        "source_arn": source_arn,
        "target_arn": target_arn,
    })
    if not results:
        return f"No path found between {source_arn} and {target_arn}."

    path = results[0]
    nodes = path["nodes"]
    rels = path["relationships"]

    lines = [f"Network path ({len(nodes)} hops):\n"]
    for i, node in enumerate(nodes):
        labels = ", ".join(node["labels"])
        lines.append(f"  [{labels}] {node['name']}")
        if i < len(rels):
            lines.append(f"    | {rels[i]}")
            lines.append("    v")

    return "\n".join(lines)


async def get_account_summary(ctx: Context, account_id: str = "") -> str:
    """Get a summary of resources in a specific AWS account.

    Returns raw resource type counts for one account. Use find_accounts
    first to resolve an account name to its ID.

    For org-wide categorized totals, use get_fleet_summary.
    For the list of all account names, use get_org_overview.

    Args:
        account_id: AWS account ID (12-digit number). Required.
            Use find_accounts to resolve a name to an account ID.

    Returns:
        Count of each resource type in the account.
    """
    app = _get_app_context(ctx)

    where = "WHERE n.account_id = $account_id" if account_id else ""
    params = {"account_id": account_id} if account_id else {}

    query = f"""
    MATCH (n) {where}
    WITH labels(n) AS node_labels, count(*) AS cnt
    UNWIND node_labels AS label
    RETURN label, sum(cnt) AS count
    ORDER BY count DESC
    """

    results = await app.neo4j.query(query, params)
    if not results:
        scope = f"account {account_id}" if account_id else "the organization"
        return f"No resources found in {scope}."

    if account_id:
        acct_names = await load_account_names(app.neo4j)
        acct_label = enrich_account(account_id, acct_names)
        scope = f"Account {acct_label}"
    else:
        scope = "Organization"
    total = sum(r["count"] for r in results)
    lines = [f"{scope} Summary ({total} total resources):\n"]
    for r in results:
        lines.append(f"  {r['label']}: {r['count']}")

    return "\n".join(lines)


_EXCLUDE_LABELS = frozenset({
    "Resource",          # internal base label on every node
    "Account",           # org structure, not a deployable resource
    "OrganizationalUnit",
    "ServiceControlPolicy",
})

# Resources that AWS RAM can share — same resource appears once per account
# that has access to it. Dedup by the resource's native ID field so we only
# count the owner's copy (owner_id == account_id on the owning node).
_RAM_SHARED_DEDUP: dict[str, str] = {
    "VPC": "vpc_id",
    "Subnet": "subnet_id",
    "SecurityGroup": "group_id",
    "TransitGateway": "tgw_id",
    "TGWAttachment": "attachment_id",
    "ResolverRule": "rule_id",
    "CloudWANAttachment": "attachment_id",
}

_CATEGORY_ORDER = [
    ("COMPUTE", ["EC2Instance", "LambdaFunction", "ECSCluster", "ECSService",
                 "EKSCluster", "EKSNodegroup"]),
    ("KUBERNETES", ["K8sNode", "K8sNamespace", "K8sDeployment", "K8sService",
                    "K8sIngress", "K8sServiceAccount"]),
    ("NETWORKING", ["VPC", "Subnet", "SecurityGroup", "NetworkACL",
                    "NetworkInterface", "RouteTable", "NATGateway",
                    "InternetGateway", "VPCPeering", "VPCEndpoint",
                    "LoadBalancer", "TargetGroup", "TransitGateway",
                    "TGWAttachment", "TGWRouteTable", "ResolverEndpoint",
                    "ResolverRule", "CloudWANCoreNetwork", "CloudWANSegment",
                    "CloudWANAttachment"]),
    ("DATABASE", ["RDSInstance", "DynamoDBTable", "ElastiCacheCluster",
                  "ElastiCacheReplicationGroup", "ElastiCacheServerlessCache",
                  "OpenSearchDomain"]),
    ("STORAGE / CDN", ["S3Bucket", "CloudFrontDistribution"]),
    ("DNS / API", ["Route53Zone", "Route53Record", "APIGateway"]),
    ("MESSAGING", ["SQSQueue", "SNSTopic"]),
    ("CICD / IaC", ["CodeCommitRepo", "CodePipeline", "CodeBuildProject",
                    "CloudFormationStack"]),
    ("SECURITY", ["IAMRole", "IAMPolicy", "IAMUser", "WAFWebACL"]),
]


async def get_fleet_summary(ctx: Context) -> str:
    """Get an executive-level resource count summary across the entire AWS fleet.

    Returns counts grouped by resource category (Compute, Networking, Database,
    etc.). RAM-shared resources (VPC, Subnet, SecurityGroup, TransitGateway,
    TGWAttachment, ResolverRule, CloudWANAttachment) are deduplicated so each
    physical resource is counted once (owner's copy only).

    Best for: "how many EC2s/lambdas/RDS do we have total?"
    NOT for: listing account names (use get_org_overview) or drilling
    into one account (use get_account_summary with account_id).
    """
    app = _get_app_context(ctx)

    # --- 1. Count RAM-shareable types: owner copy only (owner_id == account_id)
    dedup_counts: dict[str, int] = {}
    for label, id_field in _RAM_SHARED_DEDUP.items():
        query = f"""
        MATCH (n:{label})
        WHERE n.owner_id = n.account_id OR n.owner_account_id = n.account_id
        RETURN count(DISTINCT n.{id_field}) AS cnt
        """
        rows = await app.neo4j.query(query)
        dedup_counts[label] = rows[0]["cnt"] if rows else 0

    # --- 2. Count everything else (excluding internal + dedup'd labels)
    excluded = list(_EXCLUDE_LABELS | set(_RAM_SHARED_DEDUP.keys()))
    query = """
    MATCH (n)
    WITH labels(n) AS node_labels, count(*) AS cnt
    UNWIND node_labels AS label
    WITH label, sum(cnt) AS count
    WHERE NOT label IN $excluded
    RETURN label, count
    ORDER BY count DESC
    """
    rows = await app.neo4j.query(query, {"excluded": excluded})
    raw_counts: dict[str, int] = {r["label"]: r["count"] for r in rows}
    raw_counts.update(dedup_counts)

    # --- 3. Count distinct accounts
    acct_rows = await app.neo4j.query(
        "MATCH (n:Account) RETURN count(DISTINCT n.account_id) AS cnt"
    )
    num_accounts = acct_rows[0]["cnt"] if acct_rows else 0

    # --- 4. Format into categorised table
    total = sum(raw_counts.values())
    lines = [
        f"Fleet Summary — {num_accounts} accounts  "
        f"({total:,} total resources)\n",
    ]
    seen: set[str] = set()
    for category, labels in _CATEGORY_ORDER:
        category_lines = []
        for lbl in labels:
            if lbl in raw_counts:
                category_lines.append(f"  {lbl:<32} {raw_counts[lbl]:>8,}")
                seen.add(lbl)
        if category_lines:
            lines.append(category)
            lines.extend(category_lines)
            lines.append("")

    # Catch any labels not in the category map (new collectors added later)
    others = [(lbl, cnt) for lbl, cnt in raw_counts.items() if lbl not in seen]
    if others:
        lines.append("OTHER")
        for lbl, cnt in sorted(others, key=lambda x: -x[1]):
            lines.append(f"  {lbl:<32} {cnt:>8,}")

    return "\n".join(lines)


async def find_accounts(
    ctx: Context,
    name_contains: str = "",
) -> str:
    """Find AWS accounts by name (fuzzy substring match).

    Use this tool first to resolve an account name or nickname
    (e.g., "slingcore beta", "prod network") into an account ID
    that can be passed to other tools.

    Args:
        name_contains: Substring to match against account name
            (case-insensitive). Empty to list all accounts.

    Returns:
        List of matching accounts with ID and name.
    """
    app = _get_app_context(ctx)

    if name_contains:
        query = """
        MATCH (a:Account)
        WHERE toLower(a.name) CONTAINS toLower($name)
        RETURN DISTINCT a.account_id AS id, a.name AS name
        ORDER BY a.name
        """
        params = {"name": name_contains}
    else:
        query = """
        MATCH (a:Account)
        RETURN DISTINCT a.account_id AS id, a.name AS name
        ORDER BY a.name
        """
        params = {}

    results = await app.neo4j.query(query, params)
    if not results:
        return f"No accounts found matching '{name_contains}'."

    lines = [f"Found {len(results)} account(s):\n"]
    for r in results:
        lines.append(f"  {r['id']} — {r['name']}")
    return "\n".join(lines)
