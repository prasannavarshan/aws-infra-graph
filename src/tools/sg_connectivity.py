"""SG-to-SG connectivity checker — evaluate traffic between security groups."""

from __future__ import annotations

import logging
import re

from mcp.server.fastmcp import Context

from src.tools.connectivity import _check_sg_allows, _parse_sg_rules
from src.tools.nacl_eval import (
    evaluate_nacl_egress,
    evaluate_nacl_ingress,
    lookup_nacls_for_sg,
)
from src.tools.name_cache import load_account_names, load_vpc_names
from src.tools.sg_format import _format_verdict
from src.tools.sg_resolve import (
    _dedup_by_group_id,
    _refresh_sg_list,
    _resolve_multiple_sgs,
)

logger = logging.getLogger(__name__)

# Re-export for backward compatibility (tests, guided_connectivity import)
__all__ = [
    "_dedup_by_group_id",
    "_find_cidr_rules",
    "_lookup_sample_ip",
    "_resolve_sg",
    "check_sg_connectivity",
]

# Re-export _resolve_sg for test compatibility
from src.tools.sg_resolve import _resolve_sg  # noqa: E402


def _get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


async def _lookup_sample_ip(
    neo4j,  # noqa: ANN001
    group_id: str,
    vpc_id: str = "",
) -> str:
    """Find a sample private IP from resources using this SG.

    First tries direct HAS_SG edges (EC2, ECS, RDS, etc.).
    Falls back to any resource in the same VPC if no direct
    match — useful when the SG is for EKS worker nodes that
    may not be in the graph at crawl time.

    Returns:
        A private IP string, or empty string if none found.
    """
    # 1. Direct: resource -> HAS_SG -> this SG
    query = """
    MATCH (n)-[:HAS_SG]->(sg:SecurityGroup {group_id: $gid})
    WHERE n.private_ip IS NOT NULL
    RETURN n.private_ip AS ip
    LIMIT 1
    """
    results = await neo4j.query(query, {"gid": group_id})
    if results:
        return results[0]["ip"]

    # 2. VPC fallback: any resource in the same VPC
    if vpc_id:
        vpc_query = """
        MATCH (n)-[:RUNS_IN]->(:Subnet)
              -[:PART_OF]->(:VPC {vpc_id: $vpc_id})
        WHERE n.private_ip IS NOT NULL
        RETURN n.private_ip AS ip
        LIMIT 1
        """
        results = await neo4j.query(
            vpc_query, {"vpc_id": vpc_id},
        )
        if results:
            return results[0]["ip"]

    return ""


def _find_cidr_rules(
    rules_str: str, port: int, protocol: str,
) -> list[str]:
    """Find CIDR-based rules matching port/protocol.

    Returns list of non-wildcard CIDRs that could match if
    we had an IP address. Used to warn about evaluation limits.
    """
    cidrs: list[str] = []
    parsed = _parse_sg_rules(rules_str)
    for rule in parsed:
        rp = rule["protocol"]
        if rp not in ("all", "-1") and rp.lower() != protocol.lower():
            continue
        ps = rule["port_str"]
        if ps != "all" and not _port_matches_simple(ps, port):
            continue
        for src in rule["sources"]:
            if src.startswith("sg:"):
                continue
            # Extract CIDRs from prefix list bracket notation
            if src.startswith("pl:"):
                pl_match = re.match(
                    r"pl:[^[]+\[([^\]]+)\]", src,
                )
                if pl_match:
                    for pl_cidr in pl_match.group(1).split(","):
                        c = pl_cidr.strip()
                        if c and c not in (
                            "0.0.0.0/0", "::/0",
                        ):
                            cidrs.append(c)
                continue
            cidr = re.sub(r"\(.*\)$", "", src)
            if cidr and cidr not in ("0.0.0.0/0", "::/0"):
                cidrs.append(cidr)
    return cidrs


def _port_matches_simple(port_str: str, target: int) -> bool:
    """Simple port match check for CIDR rule detection."""
    if port_str == "all":
        return True
    if "-" in port_str:
        low, high = port_str.split("-", 1)
        return int(low) <= target <= int(high)
    return int(port_str) == target


async def check_sg_connectivity(
    ctx: Context,
    source_sg: str,
    target_sg: str,
    port: int = 443,
    protocol: str = "tcp",
    source_account_id: str = "",
    target_account_id: str = "",
    live_refresh: bool = False,
) -> str:
    """Check if traffic is allowed between security groups.

    Evaluates egress rules on the source SG(s) and ingress
    rules on the target SG(s) for the specified port/protocol.
    Checks both CIDR-based rules and SG-to-SG references.

    Supports **union evaluation**: pass comma-separated SG
    identifiers (e.g. "sg-aaa,sg-bbb") and AWS union semantics
    apply — if ANY source SG allows egress AND ANY target SG
    allows ingress, traffic is permitted. This matches real AWS
    behavior where multiple SGs on an ENI are evaluated as a
    union.

    PREFERRED TOOL for checking connectivity involving EKS
    clusters, Lambda functions, or ElastiCache — these resources
    lack private IPs in the graph, so analyze_connectivity cannot
    fully evaluate them. This tool works by SG name/ID instead.

    Examples:
    - Single SG: check_sg_connectivity("lambda-sg",
      "eks-node-sg", port=443)
    - Union SGs: check_sg_connectivity(
      "eks-cluster-sg,eks-managed-sg", "mongodb-vpce-sg",
      port=27017)

    Args:
        source_sg: Source security group(s) — comma-separated
            group_ids (sg-xxx), exact names, or name substrings.
        target_sg: Target security group(s) — same format.
        port: Destination port to check (default 443).
        protocol: Protocol to check — tcp, udp, or icmp
            (default tcp).
        source_account_id: Optional AWS account ID to narrow
            source SG search.
        target_account_id: Optional AWS account ID to narrow
            target SG search.
        live_refresh: If True, fetch fresh SG rules from AWS
            before evaluating.

    Returns:
        Detailed SG connectivity analysis with per-direction
        verdict (egress and ingress) and overall ALLOWED/DENIED.
    """
    app = _get_app_context(ctx)
    neo4j = app.neo4j

    acct_names = await load_account_names(neo4j)
    vpc_map = await load_vpc_names(neo4j)

    # Resolve source and target SG lists
    sources = await _resolve_multiple_sgs(
        neo4j, source_sg, source_account_id,
    )
    if isinstance(sources, str):
        return f"Source SG error: {sources}"

    targets = await _resolve_multiple_sgs(
        neo4j, target_sg, target_account_id,
    )
    if isinstance(targets, str):
        return f"Target SG error: {targets}"

    # Live refresh all SGs if requested
    refreshed = False
    if live_refresh:
        sources = await _refresh_sg_list(neo4j, sources)
        targets = await _refresh_sg_list(neo4j, targets)
        refreshed = True

    # Build SG ID sets for cross-reference matching
    src_sg_ids = frozenset(
        sg["group_id"] for sg in sources
    )
    tgt_sg_ids = frozenset(
        sg["group_id"] for sg in targets
    )

    # Sample IPs — try each SG until one has an IP
    source_ip = ""
    for sg in sources:
        source_ip = await _lookup_sample_ip(
            neo4j, sg["group_id"],
            vpc_id=sg.get("vpc_id", ""),
        )
        if source_ip:
            break

    target_ip = ""
    for sg in targets:
        target_ip = await _lookup_sample_ip(
            neo4j, sg["group_id"],
            vpc_id=sg.get("vpc_id", ""),
        )
        if target_ip:
            break

    # Union egress: any source SG allows outbound?
    egress_allowed = False
    egress_reason = "no matching egress rule"
    egress_sg_name = ""
    for sg in sources:
        rules = _parse_sg_rules(sg.get("egress", ""))
        allowed, reason = _check_sg_allows(
            rules, port, protocol,
            remote_ip=target_ip,
            remote_sg_ids=tgt_sg_ids,
        )
        if allowed:
            egress_allowed = True
            egress_reason = reason
            egress_sg_name = (
                f"{sg['name']} ({sg['group_id']})"
            )
            break

    # Union ingress: any target SG allows inbound?
    ingress_allowed = False
    ingress_reason = "no matching ingress rule"
    ingress_sg_name = ""
    for sg in targets:
        rules = _parse_sg_rules(sg.get("ingress", ""))
        allowed, reason = _check_sg_allows(
            rules, port, protocol,
            remote_ip=source_ip,
            remote_sg_ids=src_sg_ids,
        )
        if allowed:
            ingress_allowed = True
            ingress_reason = reason
            ingress_sg_name = (
                f"{sg['name']} ({sg['group_id']})"
            )
            break

    # CIDR notes — check all SGs in the union
    egress_cidr_note = _build_cidr_note(
        sources, "egress", target_ip, port, protocol,
        egress_allowed,
        "no target IP found in graph."
        " Use analyze_connectivity for full check.",
    )
    ingress_cidr_note = _build_cidr_note(
        targets, "ingress", source_ip, port, protocol,
        ingress_allowed,
        "no source IP found in graph."
        " May ALLOW if source IP is in range."
        " Use analyze_connectivity for full check.",
    )

    # NACL lookup: find NACLs for source and target SGs
    src_nacls = await _lookup_nacls_for_sgs(neo4j, sources)
    tgt_nacls = await _lookup_nacls_for_sgs(neo4j, targets)

    # NACL evaluation
    nacl_egress_ok, nacl_egress_reason = evaluate_nacl_egress(
        src_nacls, port, protocol, target_ip,
    )
    nacl_ingress_ok, nacl_ingress_reason = evaluate_nacl_ingress(
        tgt_nacls, port, protocol, source_ip,
    )

    # Cross-VPC warning (compare first source vs first target)
    cross_vpc = (
        sources[0].get("vpc_id")
        and targets[0].get("vpc_id")
        and sources[0]["vpc_id"] != targets[0]["vpc_id"]
    )

    result = _format_verdict(
        sources=sources,
        targets=targets,
        port=port,
        protocol=protocol,
        egress_allowed=egress_allowed,
        egress_reason=egress_reason,
        ingress_allowed=ingress_allowed,
        ingress_reason=ingress_reason,
        cross_vpc=cross_vpc,
        egress_cidr_note=egress_cidr_note,
        ingress_cidr_note=ingress_cidr_note,
        source_ip=source_ip,
        target_ip=target_ip,
        acct_names=acct_names,
        vpc_map=vpc_map,
        egress_sg_name=egress_sg_name,
        ingress_sg_name=ingress_sg_name,
        nacl_egress_ok=nacl_egress_ok,
        nacl_egress_reason=nacl_egress_reason,
        nacl_ingress_ok=nacl_ingress_ok,
        nacl_ingress_reason=nacl_ingress_reason,
    )
    if refreshed:
        result += (
            "\n\n[SG rules refreshed from AWS"
            " before evaluation]"
        )
    return result


async def _lookup_nacls_for_sgs(
    neo4j,  # noqa: ANN001
    sgs: list[dict],
) -> list[dict[str, str]]:
    """Lookup NACLs for a list of SGs, deduped by nacl_id."""
    seen: set[str] = set()
    nacls: list[dict[str, str]] = []
    for sg in sgs:
        results = await lookup_nacls_for_sg(
            neo4j, sg["group_id"],
        )
        for nacl in results:
            nacl_id = nacl.get("nacl_id", "")
            if nacl_id and nacl_id not in seen:
                seen.add(nacl_id)
                nacls.append(nacl)
    return nacls


def _build_cidr_note(
    sgs: list[dict],
    direction: str,
    remote_ip: str,
    port: int,
    protocol: str,
    already_allowed: bool,
    suffix: str,
) -> str:
    """Build CIDR note across all SGs in a union."""
    if already_allowed or remote_ip:
        return ""
    all_cidrs: list[str] = []
    for sg in sgs:
        cidrs = _find_cidr_rules(
            sg.get(direction, ""), port, protocol,
        )
        all_cidrs.extend(cidrs)
    if all_cidrs:
        unique = list(dict.fromkeys(all_cidrs))
        return (
            f"NOTE: CIDR rules exist"
            f" ({', '.join(unique[:5])})"
            f" but {suffix}"
        )
    return ""
