"""Connectivity analyzer — evaluate network reachability between resources."""

from __future__ import annotations

from mcp.server.fastmcp import Context

from src.tools.sg_eval import (  # noqa: F401
    _check_nacl_allows,
    _check_route_allows,
    _check_sg_allows,
    _check_tgw_route,
    _cidr_contains,
    _parse_nacl_rules,
    _parse_routes,
    _parse_sg_rules,
    _port_matches,
    _proto_matches,
)

# Re-export evaluation primitives for backward compatibility.
# Consumers (tests, nacl_eval, sg_connectivity, guided_connectivity)
# import these from here; they now live in src.tools.sg_eval.
__all__ = [
    "_check_nacl_allows",
    "_check_route_allows",
    "_check_sg_allows",
    "_check_tgw_route",
    "_parse_nacl_rules",
    "_parse_routes",
    "_parse_sg_rules",
    "analyze_connectivity",
    "get_tgw_routes",
]


def get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


async def get_tgw_routes(
    ctx: Context,
    tgw_id: str = "",
    route_table_id: str = "",
    target_ip: str = "",
) -> str:
    """Get Transit Gateway route table entries.

    Shows all routes in a TGW's route tables, with optional
    filtering by target IP (longest prefix match). Use this
    to inspect what CIDRs a TGW can route to and which
    attachments receive that traffic.

    Args:
        tgw_id: Transit Gateway ID (e.g. "tgw-0abc123").
            Required if route_table_id is not provided.
        route_table_id: Specific TGW route table ID
            (e.g. "tgw-rtb-0abc123"). If provided, only
            that route table is shown.
        target_ip: Optional IP to filter routes by longest
            prefix match (e.g. "10.150.1.5"). Shows only
            the best matching route per table.

    Returns:
        Formatted TGW route table entries with destination
        CIDRs, target attachments, and route types.
    """
    app = get_app_context(ctx)
    neo4j = app.neo4j

    if route_table_id:
        query = """
        MATCH (tgwrt:TGWRouteTable
               {route_table_id: $rt_id})
        OPTIONAL MATCH (tgwrt)-[:PART_OF]->(tgw:TransitGateway)
        RETURN tgwrt.route_table_id AS rt_id,
               tgwrt.name AS rt_name,
               tgwrt.routes AS routes,
               tgw.tgw_id AS tgw_id
        """
        results = await neo4j.query(
            query, {"rt_id": route_table_id},
        )
    elif tgw_id:
        query = """
        MATCH (tgw:TransitGateway {tgw_id: $tgw_id})
              <-[:PART_OF]-(tgwrt:TGWRouteTable)
        RETURN tgwrt.route_table_id AS rt_id,
               tgwrt.name AS rt_name,
               tgwrt.routes AS routes,
               tgw.tgw_id AS tgw_id
        ORDER BY tgwrt.name
        """
        results = await neo4j.query(
            query, {"tgw_id": tgw_id},
        )
    else:
        return (
            "Provide either tgw_id or route_table_id."
            " Use find_resources with"
            " resource_type=TransitGateway to find TGWs."
        )

    if not results:
        key = route_table_id or tgw_id
        return f"No TGW route tables found for: {key}"

    tgw_label = results[0].get("tgw_id") or tgw_id
    lines = [
        f"TGW Route Tables for {tgw_label}"
        f" ({len(results)} table(s)):\n",
    ]

    for row in results:
        rt_id = row["rt_id"]
        rt_name = row.get("rt_name") or rt_id
        routes_str = row.get("routes", "")
        parsed = _parse_routes(routes_str)

        if target_ip and parsed:
            lines.append(f"  {rt_name} ({rt_id}):")
            found, reason, _, _ = _check_route_allows(
                parsed, target_ip,
            )
            status = "+" if found else "X"
            lines.append(f"    {status} {reason}")
        elif parsed:
            lines.append(
                f"  {rt_name} ({rt_id})"
                f" — {len(parsed)} routes:",
            )
            for route in parsed:
                dest = route["destination"]
                tgt = route["target"]
                lines.append(f"    {dest} -> {tgt}")
        else:
            lines.append(
                f"  {rt_name} ({rt_id}) — no routes",
            )
        lines.append("")

    return "\n".join(lines)


async def _get_resource_network_context(
    neo4j, arn: str,
) -> dict:
    """Fetch SGs, NACL, route table, and IP for a resource."""
    query = """
    MATCH (n:Resource {arn: $arn})
    OPTIONAL MATCH (n)-[:HAS_SG]->(sg:SecurityGroup)
    OPTIONAL MATCH (n)-[:RUNS_IN]->(sub:Subnet)
    OPTIONAL MATCH (sub)-[:HAS_NACL]->(nacl:NetworkACL)
    OPTIONAL MATCH (sub)-[:HAS_ROUTE_TABLE]->(rt:RouteTable)
    OPTIONAL MATCH (sub)-[:PART_OF]->(vpc:VPC)
    OPTIONAL MATCH (main_rt:RouteTable {vpc_id: vpc.vpc_id, is_main: true})
    RETURN n.name AS name,
           n.private_ip AS private_ip,
           n.public_ip AS public_ip,
           vpc.vpc_id AS vpc_id,
           collect(DISTINCT {
               sg_id: sg.group_id,
               sg_name: sg.name,
               ingress: sg.ingress_rules,
               egress: sg.egress_rules
           }) AS sgs,
           collect(DISTINCT {
               nacl_id: nacl.network_acl_id,
               nacl_name: nacl.name,
               ingress: nacl.ingress_rules,
               egress: nacl.egress_rules
           }) AS nacls,
           collect(DISTINCT {
               rt_id: rt.route_table_id,
               rt_name: rt.name,
               routes: rt.routes
           }) AS route_tables,
           collect(DISTINCT {
               rt_id: main_rt.route_table_id,
               rt_name: main_rt.name,
               routes: main_rt.routes
           }) AS main_route_tables
    """
    result = await neo4j.query(query, {"arn": arn})
    if not result:
        return {}
    row = result[0]

    # Use explicit subnet RT, fall back to main RT
    rts = [r for r in row["route_tables"] if r.get("rt_id")]
    if not rts:
        rts = [
            r for r in row["main_route_tables"]
            if r.get("rt_id")
        ]

    return {
        "name": row["name"] or arn.split("/")[-1],
        "private_ip": row["private_ip"] or "",
        "public_ip": row["public_ip"] or "",
        "vpc_id": row.get("vpc_id", "") or "",
        "sgs": [s for s in row["sgs"] if s.get("sg_id")],
        "nacls": [n for n in row["nacls"] if n.get("nacl_id")],
        "route_tables": rts,
    }


async def analyze_connectivity(
    ctx: Context,
    source_arn: str,
    target_arn: str,
    port: int = 443,
    protocol: str = "tcp",
) -> str:
    """Analyze network connectivity between two AWS resources.

    Traces the graph path and evaluates security groups and NACLs
    at both source (egress) and target (ingress) to determine if
    traffic on the specified port/protocol would be allowed.

    Best used with EC2Instance or EKSNodegroup ARNs (resources
    that have private IPs and security groups). Use find_resources
    to look up ARNs first, and find_accounts to resolve account
    names to IDs.

    IMPORTANT: For EKS clusters, Lambda functions, or ElastiCache
    resources, prefer check_sg_connectivity instead — it works by
    SG name/ID and doesn't need resource ARNs or private IPs. Use
    it when checking "can Lambda X talk to EKS Y on port 443?" or
    "can EKS talk to Redis on port 6379?".

    Args:
        source_arn: ARN of the source resource (e.g.,
            arn:aws:ec2:us-east-1:123456789012:instance/i-abc123).
        target_arn: ARN of the target resource.
        port: Destination port to check (default 443).
        protocol: Protocol to check — tcp, udp, or icmp (default tcp).

    Returns:
        Detailed connectivity analysis with per-layer verdict.
    """
    app = get_app_context(ctx)
    neo4j = app.neo4j

    # 1. Get network path
    path_query = """
    MATCH path = shortestPath(
        (src {arn: $source_arn})-[*..20]-(tgt {arn: $target_arn})
    )
    RETURN [node in nodes(path) |
        {name: node.name, labels: labels(node)}
    ] AS nodes,
    [rel in relationships(path) | type(rel)] AS rels
    """
    path_result = await neo4j.query(path_query, {
        "source_arn": source_arn,
        "target_arn": target_arn,
    })

    # 2. Get network context for source and target
    src_ctx = await _get_resource_network_context(
        neo4j, source_arn,
    )
    tgt_ctx = await _get_resource_network_context(
        neo4j, target_arn,
    )

    if not src_ctx:
        return f"Source resource not found: {source_arn}"
    if not tgt_ctx:
        return f"Target resource not found: {target_arn}"

    src_name = src_ctx["name"]
    tgt_name = tgt_ctx["name"]
    src_ip = src_ctx["private_ip"]
    tgt_ip = tgt_ctx["private_ip"]

    # Extract SG IDs for SG-to-SG reference resolution
    src_sg_ids = frozenset(
        sg["sg_id"] for sg in src_ctx["sgs"] if sg.get("sg_id")
    )
    tgt_sg_ids = frozenset(
        sg["sg_id"] for sg in tgt_ctx["sgs"] if sg.get("sg_id")
    )

    lines = [
        f"Connectivity Analysis: {src_name} -> "
        f"{tgt_name} ({protocol.upper()}/{port})\n",
    ]

    # Path display
    if path_result:
        path_nodes = path_result[0]["nodes"]
        path_parts = []
        for node in path_nodes:
            label = node["labels"][0] if node["labels"] else "?"
            path_parts.append(f"[{label}] {node['name']}")
        lines.append("Path: " + " -> ".join(path_parts))
    else:
        lines.append("Path: NO PATH FOUND")
    lines.append("")

    # Track overall verdict
    all_checks: list[tuple[str, bool, str]] = []

    # 3. Source egress checks
    lines.append("Source Egress:")
    if not src_ctx["sgs"]:
        lines.append("  (no security groups attached)")
    for sg in src_ctx["sgs"]:
        egress_rules = _parse_sg_rules(sg.get("egress", ""))
        allowed, reason = _check_sg_allows(
            egress_rules, port, protocol, tgt_ip or "0.0.0.0",
            remote_sg_ids=tgt_sg_ids,
        )
        status = "+" if allowed else "X"
        verdict = "ALLOWS" if allowed else "BLOCKED"
        label = f"SG {sg['sg_id']}"
        lines.append(f"  {status} {label}: {reason} — {verdict}")
        all_checks.append((label, allowed, reason))

    for nacl in src_ctx["nacls"]:
        egress_rules = _parse_nacl_rules(
            nacl.get("egress", ""),
        )
        allowed, reason = _check_nacl_allows(
            egress_rules, port, protocol, tgt_ip or "0.0.0.0",
        )
        status = "+" if allowed else "X"
        verdict = "ALLOWS" if allowed else "BLOCKED"
        label = f"NACL {nacl['nacl_id']}"
        lines.append(
            f"  {status} {label}: {reason} — {verdict} outbound",
        )
        all_checks.append((label, allowed, reason))

    lines.append("")

    # 4. Target ingress checks
    lines.append("Target Ingress:")
    if not tgt_ctx["sgs"]:
        lines.append("  (no security groups attached)")
    for sg in tgt_ctx["sgs"]:
        ingress_rules = _parse_sg_rules(sg.get("ingress", ""))
        allowed, reason = _check_sg_allows(
            ingress_rules, port, protocol, src_ip or "0.0.0.0",
            remote_sg_ids=src_sg_ids,
        )
        status = "+" if allowed else "X"
        verdict = "ALLOWS" if allowed else "BLOCKED"
        label = f"SG {sg['sg_id']}"
        lines.append(f"  {status} {label}: {reason} — {verdict}")
        all_checks.append((label, allowed, reason))

    for nacl in tgt_ctx["nacls"]:
        ingress_rules = _parse_nacl_rules(
            nacl.get("ingress", ""),
        )
        allowed, reason = _check_nacl_allows(
            ingress_rules, port, protocol, src_ip or "0.0.0.0",
        )
        status = "+" if allowed else "X"
        verdict = "ALLOWS" if allowed else "BLOCKED"
        label = f"NACL {nacl['nacl_id']}"
        lines.append(
            f"  {status} {label}: {reason} — {verdict} inbound",
        )
        all_checks.append((label, allowed, reason))

    # 5. Routing checks
    is_cross_vpc = (
        src_ctx["vpc_id"]
        and tgt_ctx["vpc_id"]
        and src_ctx["vpc_id"] != tgt_ctx["vpc_id"]
    )

    lines.append("")
    lines.append("Source Routing:")
    if not src_ctx["route_tables"]:
        lines.append("  (no route table found)")
    for rt in src_ctx["route_tables"]:
        parsed = _parse_routes(rt.get("routes", ""))
        found, reason, tgw_id, is_local = _check_route_allows(
            parsed, tgt_ip or "",
        )
        status = "+" if found else "X"
        verdict = "ROUTE EXISTS" if found else "NO ROUTE"
        label = f"RT {rt['rt_id']}"
        lines.append(
            f"  {status} {label}: {reason} — {verdict}",
        )
        all_checks.append((label, found, reason))
        if is_local and is_cross_vpc:
            lines.append(
                f"  WARNING: Local route matched for"
                f" cross-VPC target {tgt_ip}."
                " Verify the VPC CIDR intentionally"
                " covers the target range.",
            )
        if tgw_id and found:
            tgw_ok, tgw_lines = await _check_tgw_route(
                neo4j, tgw_id, tgt_ip or "",
            )
            lines.extend(tgw_lines)
            tgw_label = f"TGW {tgw_id}"
            all_checks.append(
                (tgw_label, tgw_ok, "TGW route check"),
            )

    lines.append("")
    lines.append("Target Routing:")
    if not tgt_ctx["route_tables"]:
        lines.append("  (no route table found)")
    for rt in tgt_ctx["route_tables"]:
        parsed = _parse_routes(rt.get("routes", ""))
        found, reason, tgw_id, is_local = _check_route_allows(
            parsed, src_ip or "",
        )
        status = "+" if found else "X"
        verdict = "ROUTE EXISTS" if found else "NO ROUTE"
        label = f"RT {rt['rt_id']}"
        lines.append(
            f"  {status} {label}: {reason} — {verdict}",
        )
        all_checks.append((label, found, reason))
        if is_local and is_cross_vpc:
            lines.append(
                f"  WARNING: Local route matched for"
                f" cross-VPC target {src_ip}."
                " Verify the VPC CIDR intentionally"
                " covers the target range.",
            )
        if tgw_id and found:
            tgw_ok, tgw_lines = await _check_tgw_route(
                neo4j, tgw_id, src_ip or "",
            )
            lines.extend(tgw_lines)
            tgw_label = f"TGW {tgw_id}"
            all_checks.append(
                (tgw_label, tgw_ok, "TGW route check"),
            )

    # Cross-VPC SG reference warning
    for sg in tgt_ctx["sgs"]:
        ingress = sg.get("ingress", "")
        for src_sg in src_ctx["sgs"]:
            src_id = src_sg.get("sg_id", "")
            if src_id and f"sg:{src_id}" in ingress:
                src_vpc = src_sg.get("vpc_id", "")
                tgt_vpc = sg.get("vpc_id", "")
                if src_vpc and tgt_vpc and src_vpc != tgt_vpc:
                    lines.append("")
                    lines.append(
                        f"WARNING: SG {sg['sg_id']} references"
                        f" {src_id} across VPCs — this does NOT"
                        " allow traffic cross-VPC"
                    )

    lines.append("")

    # 6. Overall verdict
    if not all_checks:
        lines.append("Verdict: UNKNOWN (no SGs or NACLs found)")
    elif not path_result:
        lines.append("Verdict: BLOCKED")
        lines.append("Reason: No network path exists between resources")
    elif all(allowed for _, allowed, _ in all_checks):
        lines.append("Verdict: ALLOWED")
    else:
        blocked = [
            (label, reason)
            for label, allowed, reason in all_checks
            if not allowed
        ]
        lines.append("Verdict: BLOCKED")
        reasons = "; ".join(
            f"{label}: {reason}" for label, reason in blocked
        )
        lines.append(f"Reason: {reasons}")

    return "\n".join(lines)
