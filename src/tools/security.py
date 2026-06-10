"""Security analysis MCP tools — SG rules, public exposure, IAM permissions."""

from __future__ import annotations

from mcp.server.fastmcp import Context


def get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


async def find_open_security_groups(ctx: Context, port: int = 0) -> str:
    """Find security groups with rules open to the internet (0.0.0.0/0 or ::/0).

    Args:
        port: Filter by specific port (e.g. 22, 443). 0 for all ports.

    Returns:
        List of security groups with open ingress rules and which resources use them.
    """
    app = get_app_context(ctx)

    port_filter = "AND edge.from_port <= $port AND edge.to_port >= $port" if port else ""
    params: dict = {}
    if port:
        params["port"] = port

    query = f"""
    MATCH (sg:SecurityGroup)
    WHERE sg.description IS NOT NULL
    WITH sg
    OPTIONAL MATCH (sg)<-[edge:ALLOWS_INGRESS]-(source:SecurityGroup)
    WHERE 1=1 {port_filter}
    WITH sg, collect({{
        source: source.name,
        protocol: edge.protocol,
        from_port: edge.from_port,
        to_port: edge.to_port
    }}) AS ingress_rules
    OPTIONAL MATCH (resource)-[:HAS_SG]->(sg)
    RETURN sg.name AS sg_name, sg.arn AS sg_arn,
           sg.group_id AS group_id, sg.vpc_id AS vpc_id,
           sg.account_id AS account_id,
           ingress_rules,
           collect(DISTINCT {{
               name: resource.name,
               arn: resource.arn,
               labels: labels(resource)
           }}) AS attached_resources
    ORDER BY sg.name
    LIMIT 50
    """

    results = await app.neo4j.query(query, params)
    if not results:
        return "No security groups found with open ingress rules."

    lines = [f"Security Groups with ingress rules ({len(results)}):\n"]
    for r in results:
        lines.append(f"  {r['sg_name']} ({r['group_id']})")
        lines.append(f"    ARN: {r['sg_arn']}")
        lines.append(f"    VPC: {r['vpc_id']} | Account: {r['account_id']}")

        rules = r.get("ingress_rules", [])
        valid_rules = [ru for ru in rules if ru.get("source")]
        if valid_rules:
            lines.append(f"    Ingress rules ({len(valid_rules)}):")
            for rule in valid_rules:
                lines.append(
                    f"      - from {rule['source']}"
                    f" {rule.get('protocol', 'all')}"
                    f" ports {rule.get('from_port', '*')}"
                    f"-{rule.get('to_port', '*')}"
                )

        resources = r.get("attached_resources", [])
        valid_res = [res for res in resources if res.get("arn")]
        if valid_res:
            lines.append(f"    Attached to ({len(valid_res)}):")
            for res in valid_res:
                label = ", ".join(res.get("labels", []))
                lines.append(f"      - [{label}] {res['name']}")

    return "\n".join(lines)


async def find_public_resources(ctx: Context) -> str:
    """Find resources that are publicly accessible.

    Checks for EC2 instances with public IPs, public RDS instances,
    internet-facing load balancers, and public S3 buckets.

    Returns:
        List of publicly accessible resources grouped by type.
    """
    app = get_app_context(ctx)

    count_query = """
    MATCH (n)
    WHERE (n:EC2Instance AND n.public_ip IS NOT NULL
           AND n.public_ip <> '')
       OR (n:RDSInstance AND n.publicly_accessible = true)
       OR (n:LoadBalancer AND n.scheme = 'internet-facing')
    RETURN count(n) AS total
    """

    query = """
    MATCH (n)
    WHERE (n:EC2Instance AND n.public_ip IS NOT NULL
           AND n.public_ip <> '')
       OR (n:RDSInstance AND n.publicly_accessible = true)
       OR (n:LoadBalancer AND n.scheme = 'internet-facing')
    RETURN labels(n) AS labels, n.name AS name, n.arn AS arn,
           n.account_id AS account_id, n.region AS region,
           n.public_ip AS public_ip,
           n.publicly_accessible AS publicly_accessible,
           n.scheme AS scheme, n.dns_name AS dns_name
    ORDER BY labels, n.name
    LIMIT 200
    """

    count_result = await app.neo4j.query(count_query)
    total = count_result[0]["total"] if count_result else 0

    results = await app.neo4j.query(query)
    if not results:
        return "No publicly accessible resources found."

    shown = len(results)
    header = f"Publicly accessible resources ({total} total"
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
        if r.get("public_ip"):
            lines.append(f"    Public IP: {r['public_ip']}")
        if r.get("dns_name"):
            lines.append(f"    DNS: {r['dns_name']}")
        if r.get("scheme"):
            lines.append(f"    Scheme: {r['scheme']}")

    return "\n".join(lines)


async def trace_iam_permissions(
    ctx: Context, role_name: str
) -> str:
    """Trace all policies attached to an IAM role.

    Shows the role, its attached managed policies, and what resources
    assume this role.

    Args:
        role_name: Name of the IAM role to trace (case-sensitive).

    Returns:
        Role details, attached policies, and resources that assume this role.
    """
    app = get_app_context(ctx)

    query = """
    MATCH (role:IAMRole)
    WHERE role.name = $role_name
    OPTIONAL MATCH (role)-[:HAS_POLICY]->(policy:IAMPolicy)
    WITH role, collect({
        name: policy.name,
        arn: policy.arn,
        policy_type: policy.policy_type
    }) AS policies
    OPTIONAL MATCH (resource)-[:HAS_ROLE]->(role)
    RETURN role.name AS role_name, role.arn AS role_arn,
           role.path AS path,
           role.assume_role_policy AS assume_policy,
           policies,
           collect(DISTINCT {
               name: resource.name,
               arn: resource.arn,
               labels: labels(resource)
           }) AS assuming_resources
    """

    results = await app.neo4j.query(query, {"role_name": role_name})
    if not results:
        return f"No IAM role found with name: {role_name}"

    lines = [
        f"IAM Role: {role_name} "
        f"(found in {len(results)} account(s))\n"
    ]

    for r in results:
        account = r.get("role_arn", "").split(":")[4] or "unknown"
        lines.append(f"  Account: {account}")
        lines.append(f"    ARN: {r['role_arn']}")
        lines.append(f"    Path: {r.get('path', '/')}")

        policies = r.get("policies", [])
        valid_policies = [p for p in policies if p.get("arn")]
        if valid_policies:
            lines.append(
                f"    Policies ({len(valid_policies)}):"
            )
            for p in valid_policies:
                lines.append(
                    f"      - {p['name']}"
                    f" ({p.get('policy_type', 'managed')})"
                )
        else:
            lines.append("    No attached policies.")

        resources = r.get("assuming_resources", [])
        valid_res = [
            res for res in resources if res.get("arn")
        ]
        if valid_res:
            lines.append(
                f"    Assumed by ({len(valid_res)}):"
            )
            for res in valid_res:
                label = ", ".join(res.get("labels", []))
                lines.append(
                    f"      - [{label}] {res['name']}"
                )

        lines.append("")

    return "\n".join(lines)


async def find_cross_account_roles(ctx: Context) -> str:
    """Find IAM roles that can be assumed from other AWS accounts.

    Analyzes AssumeRolePolicyDocument for cross-account trust relationships.

    Returns:
        List of roles with cross-account trust, showing which accounts can assume them.
    """
    app = get_app_context(ctx)

    query = """
    MATCH (role:IAMRole)
    WHERE role.assume_role_policy CONTAINS 'arn:aws'
      AND role.assume_role_policy CONTAINS 'sts:AssumeRole'
    RETURN role.name AS name, role.arn AS arn,
           role.account_id AS account_id,
           role.assume_role_policy AS assume_policy
    ORDER BY role.name
    LIMIT 200
    """

    count_query = """
    MATCH (role:IAMRole)
    WHERE role.assume_role_policy CONTAINS 'arn:aws'
      AND role.assume_role_policy CONTAINS 'sts:AssumeRole'
    RETURN count(role) AS total
    """
    count_result = await app.neo4j.query(count_query)
    total = count_result[0]["total"] if count_result else 0

    results = await app.neo4j.query(query)
    if not results:
        return "No cross-account roles found."

    shown = len(results)
    header = f"Roles with cross-account trust ({total} total"
    if shown < total:
        header += f", showing {shown}"
    header += "):\n"
    lines = [header]
    for r in results:
        lines.append(f"  {r['name']}")
        lines.append(f"    ARN: {r['arn']}")
        lines.append(f"    Account: {r['account_id']}")
        lines.append(f"    Trust policy: {r['assume_policy'][:200]}...")

    return "\n".join(lines)
