"""DNS resolution trace tool — simulates Route53 Resolver algorithm."""

from __future__ import annotations

import logging

from mcp.server.fastmcp import Context

from src.tools.dns_trace_queries import (
    auto_detect_vpc,
    detect_loopback,
    find_matching_rule,
    find_ns_delegation,
    find_private_zones,
    find_public_zones,
    get_outbound_endpoint,
    longest_suffix_match,
    lookup_record,
    resolve_source_vpc,
)
from src.tools.dns_trace_resolve import (
    TraceResult,
    TraceStep,
    apply_record,
    chase_delegation,
    format_trace,
    parse_ip_list,
)

logger = logging.getLogger(__name__)

MAX_CNAME_DEPTH = 10


async def _trace_single(
    neo4j,  # noqa: ANN001
    query_name: str,
    vpc_id: str,
    vpc_name: str,
    account_id: str,
    depth: int = 0,
) -> TraceResult:
    """Core trace logic for a single DNS query."""
    result = TraceResult(
        query_name=query_name,
        source_vpc_name=vpc_name,
        source_account=account_id,
    )

    if depth > MAX_CNAME_DEPTH:
        result.verdict = "ERROR"
        result.verdict_detail = (
            f"CNAME chain exceeded max depth ({MAX_CNAME_DEPTH})"
        )
        return result

    rule = await find_matching_rule(neo4j, vpc_id, query_name)
    if not rule:
        step = TraceStep(title="Step 1: Resolver Rule Match")
        step.lines.append("No FORWARD rule matches this query")
        step.lines.append("Checking VPC private hosted zones...")
        result.steps.append(step)

        zones = await find_private_zones(neo4j, vpc_id)
        winner = _handle_step4(
            result, zones, query_name, None,
            vpc_id, account_id,
        )
        if winner:
            return await _handle_step5(
                neo4j, result, winner, query_name,
                vpc_id, vpc_name, account_id, depth,
            )

        if result.verdict != "PUBLIC DNS":
            result.verdict = "PUBLIC DNS"
            result.verdict_detail = (
                "No private resolver rule and no matching "
                "private zone -- falls through to public DNS"
            )
        return result

    _format_step1(result, rule)

    ep_id = rule.get("endpoint_id", "")
    target_ips = parse_ip_list(rule.get("target_ips"))

    if not ep_id:
        return _handle_no_endpoint(result, target_ips)

    outbound = await get_outbound_endpoint(neo4j, ep_id)
    _format_step2(result, outbound, ep_id, target_ips)

    landing_vpc_id = (
        outbound.get("vpc_id", "") if outbound else ""
    )
    exit_result = await _handle_step3(
        neo4j, result, landing_vpc_id, target_ips,
    )
    if exit_result:
        return exit_result

    zones = await find_private_zones(neo4j, landing_vpc_id)
    winner = _handle_step4(
        result, zones, query_name, outbound,
        landing_vpc_id, account_id,
    )
    if not winner:
        return result

    return await _handle_step5(
        neo4j, result, winner, query_name,
        vpc_id, vpc_name, account_id, depth,
    )


def _format_step1(result: TraceResult, rule: dict) -> None:
    """Format Step 1: Resolver Rule Match."""
    step1 = TraceStep(title="Step 1: Resolver Rule Match")
    domain = (rule.get("domain_name") or "").rstrip(".")
    step1.lines.append(f"Query suffix: {domain}")
    step1.lines.append(f"Rule: {rule.get('name', '?')}")
    step1.lines.append(
        f"Domain: {domain}. | Type: "
        f"{rule.get('rule_type', '?')}"
    )
    owner = rule.get("owner_id") or rule.get("account_id", "?")
    share = rule.get("share_status", "")
    owner_line = f"Owner: {owner}"
    if share and share != "NOT_SHARED":
        owner_line += " | Shared via RAM"
    step1.lines.append(owner_line)
    result.steps.append(step1)


def _handle_no_endpoint(
    result: TraceResult,
    target_ips: list[str],
) -> TraceResult:
    """Handle case where rule has no endpoint."""
    step2 = TraceStep(title="Step 2: Forwarding Target")
    if target_ips:
        step2.lines.append(
            f"Target IPs: {', '.join(target_ips)}"
        )
        step2.lines.append(
            "No resolver endpoint -- external DNS (on-prem)"
        )
        result.verdict = "EXTERNAL"
        result.verdict_detail = (
            "Resolution continues on external DNS servers"
        )
    else:
        step2.lines.append("No endpoint and no target IPs")
        result.verdict = "ERROR"
        result.verdict_detail = "Rule has no forwarding target"
    result.steps.append(step2)
    return result


def _format_step2(
    result: TraceResult,
    outbound: dict | None,
    ep_id: str,
    target_ips: list[str],
) -> None:
    """Format Step 2: Outbound Endpoint."""
    step2 = TraceStep(title="Step 2: Outbound Endpoint")
    if outbound:
        step2.lines.append(
            f"Endpoint: {outbound.get('name', '?')}"
            f" ({outbound.get('endpoint_id', '')})"
        )
        ob_vpc_name = outbound.get("vpc_name", "")
        ob_vpc_id = outbound.get("vpc_id", "")
        ob_cidr = outbound.get("vpc_cidr", "")
        vpc_info = ob_vpc_name or ob_vpc_id
        if ob_cidr:
            vpc_info += f" | {ob_cidr}"
        step2.lines.append(f"VPC: {vpc_info}")
        ob_ips = parse_ip_list(outbound.get("ip_addresses"))
        if ob_ips:
            step2.lines.append(
                f"Outbound IPs: {', '.join(ob_ips)}"
            )
    else:
        step2.lines.append(
            f"Endpoint {ep_id} not found in graph"
        )
    if target_ips:
        step2.lines.append(
            f"Target IPs: {', '.join(target_ips)}"
        )
    result.steps.append(step2)


async def _handle_step3(
    neo4j,  # noqa: ANN001
    result: TraceResult,
    landing_vpc_id: str,
    target_ips: list[str],
) -> TraceResult | None:
    """Handle Step 3: Loopback detection."""
    if target_ips and landing_vpc_id:
        inbound = await detect_loopback(
            neo4j, landing_vpc_id, target_ips,
        )
        if inbound:
            step3 = TraceStep(
                title="Step 3: Loopback Detected",
            )
            step3.lines.append(
                f"Inbound: {inbound.get('name', '?')}"
                f" ({inbound.get('endpoint_id', '')})"
            )
            step3.lines.append(
                "Outbound->Inbound loopback -- "
                "query re-enters Route53 Resolver"
            )
            result.steps.append(step3)
            return None

        step3 = TraceStep(
            title="Step 3: External Forwarding",
        )
        step3.lines.append(
            "Target IPs do not match any inbound endpoint"
        )
        step3.lines.append(
            "Resolution continues on external DNS"
        )
        result.steps.append(step3)
        result.verdict = "EXTERNAL"
        result.verdict_detail = (
            f"Forwarded to {', '.join(target_ips)} "
            "(external/on-prem DNS)"
        )
        return result

    if not landing_vpc_id:
        result.verdict = "UNKNOWN"
        result.verdict_detail = (
            "Could not determine landing VPC"
        )
        return result

    return None


def _handle_step4(
    result: TraceResult,
    zones: list[dict],
    query_name: str,
    outbound: dict | None,
    landing_vpc_id: str,
    account_id: str,
) -> dict | None:
    """Handle Step 4: Private zone selection."""
    step4 = TraceStep(
        title="Step 4: Private Zone Selection "
        "(Longest-Suffix Match)",
    )

    if not zones:
        step4.lines.append(
            "No private zones associated with landing VPC"
        )
        step4.lines.append("Fallback: Internet Resolver")
        result.steps.append(step4)
        result.verdict = "PUBLIC DNS"
        result.verdict_detail = (
            "No private zones in landing VPC"
        )
        return None

    winner, scored = longest_suffix_match(query_name, zones)
    landing_vpc_name = (
        outbound.get("vpc_name", "") if outbound else ""
    ) or landing_vpc_id
    step4.lines.append(
        f"VPC {landing_vpc_name} has "
        f"{len(zones)} private zone(s):"
    )
    for zname, lc, is_winner in scored:
        marker = " << WINNER" if is_winner else ""
        if lc > 0:
            step4.lines.append(
                f"  {zname}. -- {lc} labels{marker}"
            )
        else:
            step4.lines.append(f"  {zname}. -- no match")

    if winner:
        zone_acct = winner.get("account_id", "")
        if zone_acct and zone_acct != account_id:
            step4.lines.append(
                f"  Owner: {zone_acct} [cross-account]"
            )
    result.steps.append(step4)

    if not winner:
        result.verdict = "PUBLIC DNS"
        result.verdict_detail = (
            "No private zone matches query suffix"
        )

    return winner


async def _handle_step5(
    neo4j,  # noqa: ANN001
    result: TraceResult,
    winner: dict,
    query_name: str,
    vpc_id: str,
    vpc_name: str,
    account_id: str,
    depth: int,
) -> TraceResult:
    """Handle Step 5: Record lookup + NS delegation."""
    zone_id = winner.get("zone_id", "")
    zone_name = (winner.get("zone_name") or "").rstrip(".")
    record = await lookup_record(neo4j, zone_id, query_name)
    step5 = TraceStep(title="Step 5: Record Lookup")
    step5.lines.append(f"Zone: {zone_name}. ({zone_id})")

    if not record:
        delegation = await find_ns_delegation(
            neo4j, zone_id, zone_name, query_name,
        )
        if delegation:
            return await chase_delegation(
                neo4j, result, step5, delegation,
                query_name, vpc_id, vpc_name,
                account_id, depth, _trace_single,
            )

        step5.lines.append(
            f"No record found for {query_name}"
        )
        step5.lines.append(
            "Zone is authoritative -- NXDOMAIN"
        )
        result.steps.append(step5)
        result.verdict = "NXDOMAIN"
        result.verdict_detail = (
            f"Zone {zone_name} is authoritative but has "
            f"no record for {query_name}"
        )
        return result

    return await apply_record(
        result, step5, record,
        neo4j, query_name, vpc_id,
        vpc_name, account_id, depth, _trace_single,
    )


async def _trace_public(
    neo4j,  # noqa: ANN001
    query_name: str,
) -> TraceResult:
    """Trace public DNS resolution via NS delegation chain."""
    result = TraceResult(query_name=query_name)

    zones = await find_public_zones(neo4j, query_name)
    step1 = TraceStep(title="Step 1: Public Zone Match")

    if not zones:
        step1.lines.append(
            "No public hosted zone matches this query"
        )
        result.steps.append(step1)
        result.verdict = "NO ZONE"
        result.verdict_detail = (
            "No public zone in graph for this domain"
        )
        return result

    best = zones[0]
    zone_name = (best.get("zone_name") or "").rstrip(".")
    zone_id = best.get("zone_id", "")
    step1.lines.append(f"Zone: {zone_name}. ({zone_id})")
    step1.lines.append(f"Owner: {best.get('account_id', '?')}")
    step1.lines.append(
        f"Records: {best.get('record_count', '?')}"
    )
    if len(zones) > 1:
        others = [
            (z.get("zone_name") or "").rstrip(".")
            for z in zones[1:]
        ]
        step1.lines.append(
            f"Other matching zones: {', '.join(others)}"
        )
    result.steps.append(step1)

    record = await lookup_record(neo4j, zone_id, query_name)
    step2 = TraceStep(title="Step 2: Record Lookup")
    step2.lines.append(f"Zone: {zone_name}. ({zone_id})")

    if record:
        return await apply_record(
            result, step2, record,
            neo4j, query_name, "", "", "", 0,
        )

    delegation = await find_ns_delegation(
        neo4j, zone_id, zone_name, query_name,
    )
    if delegation:
        return await chase_delegation(
            neo4j, result, step2, delegation,
            query_name, "", "", "", 0,
        )

    step2.lines.append(
        f"No record found for {query_name}"
    )
    step2.lines.append(
        "Zone is authoritative -- NXDOMAIN"
    )
    result.steps.append(step2)
    result.verdict = "NXDOMAIN"
    result.verdict_detail = (
        f"Public zone {zone_name} has no record "
        f"and no NS delegation for {query_name}"
    )
    return result


async def trace_dns(
    ctx: Context,
    query_name: str,
    source_vpc: str = "",
    source_account: str = "",
    mode: str = "private",
) -> str:
    """Trace DNS resolution path for a domain name.

    Simulates Route53 resolution algorithm. In 'private' mode,
    traces the Route53 Resolver path (forwarding rules, loopback,
    private zone selection). In 'public' mode, traces the NS
    delegation chain through public hosted zones.

    Args:
        query_name: FQDN to resolve (e.g.,
            "api.prod.example.com").
        source_vpc: Source VPC name or ID (private mode only).
            If empty, auto-detects a VPC with a matching rule.
        source_account: Account name or ID to narrow VPC
            search. Optional.
        mode: "private" (default) traces via Route53 Resolver
            rules and private zones. "public" traces via NS
            delegation through public hosted zones.

    Returns:
        Step-by-step resolution trace with verdict.
    """
    app = ctx.request_context.lifespan_context
    neo4j = app.neo4j

    if mode == "public":
        result = await _trace_public(neo4j, query_name)
        return f"(PUBLIC) {format_trace(result)}"

    vpc_id = ""
    vpc_name = ""
    account_id = ""

    if source_vpc:
        vpc_info = await resolve_source_vpc(
            neo4j, source_vpc, source_account,
        )
        if not vpc_info:
            return (
                f"Could not find VPC matching '{source_vpc}'."
                " Try a VPC name or vpc-id."
            )
        vpc_id = vpc_info.get("vpc_id", "")
        vpc_name = vpc_info.get("name", vpc_id)
        account_id = vpc_info.get("account_id", "")
    else:
        vpc_info = await auto_detect_vpc(neo4j, query_name)
        if not vpc_info:
            return (
                "No source VPC specified and no VPC found with "
                "a resolver rule matching this query. "
                "Try passing source_vpc parameter."
            )
        vpc_id = vpc_info.get("vpc_id", "")
        vpc_name = vpc_info.get("name", vpc_id)
        account_id = vpc_info.get("account_id", "")

    result = await _trace_single(
        neo4j, query_name, vpc_id, vpc_name, account_id,
    )
    return format_trace(result)
