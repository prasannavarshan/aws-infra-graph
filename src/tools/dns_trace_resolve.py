"""Shared record resolution logic for DNS trace tool."""

from __future__ import annotations

from dataclasses import dataclass, field

from src.tools.dns_trace_queries import (
    find_ns_delegation,
    lookup_record,
    resolve_delegation_zone,
)

MAX_CNAME_DEPTH = 10
MAX_DELEGATION_DEPTH = 3


@dataclass
class TraceStep:
    """A single step in the DNS resolution trace."""

    title: str
    lines: list[str] = field(default_factory=list)


@dataclass
class TraceResult:
    """Full DNS resolution trace."""

    query_name: str
    source_vpc_name: str = ""
    source_account: str = ""
    steps: list[TraceStep] = field(default_factory=list)
    verdict: str = ""
    verdict_detail: str = ""


def format_trace(result: TraceResult) -> str:
    """Format a TraceResult into readable output."""
    lines: list[str] = []
    lines.append(f"DNS Trace: {result.query_name}")
    if result.source_vpc_name:
        src = f"Source: {result.source_vpc_name}"
        if result.source_account:
            src += f" ({result.source_account})"
        lines.append(src)
    lines.append("")

    for step in result.steps:
        lines.append(step.title)
        for line in step.lines:
            lines.append(f"  {line}")
        lines.append("")

    if result.verdict:
        lines.append(f"Verdict: {result.verdict}")
    if result.verdict_detail:
        lines.append(f"  {result.verdict_detail}")

    return "\n".join(lines)


def parse_ip_list(raw: list | str | None) -> list[str]:
    """Normalize IP list from graph property."""
    if not raw:
        return []
    if isinstance(raw, str):
        return [
            ip.strip() for ip in raw.split(",") if ip.strip()
        ]
    return [str(ip) for ip in raw]


async def apply_record(
    result: TraceResult,
    step: TraceStep,
    record: dict,
    neo4j,  # noqa: ANN001
    query_name: str,
    vpc_id: str,
    vpc_name: str,
    account_id: str,
    depth: int,
    trace_single_fn=None,  # noqa: ANN001
) -> TraceResult:
    """Apply a found record to the trace result."""
    rtype = record.get("record_type", "?")
    alias_target = record.get("alias_target", "")
    values = record.get("values")

    if alias_target:
        step.lines.append(
            f"Record: {record.get('name', '?')} "
            f"{rtype} ALIAS"
        )
        step.lines.append(f"  -> {alias_target}")
        result.steps.append(step)
        result.verdict = "RESOLVED (ALIAS)"
        result.verdict_detail = f"-> {alias_target}"
        return result

    if rtype == "CNAME":
        cname_target = ""
        if isinstance(values, list) and values:
            cname_target = str(values[0]).rstrip(".")
        elif isinstance(values, str):
            cname_target = values.rstrip(".")
        step.lines.append(
            f"Record: {record.get('name', '?')} CNAME"
        )
        step.lines.append(f"  -> {cname_target}")
        step.lines.append("Chasing CNAME...")
        result.steps.append(step)

        if cname_target and trace_single_fn:
            sub = await trace_single_fn(
                neo4j, cname_target, vpc_id,
                vpc_name, account_id, depth + 1,
            )
            result.steps.extend(sub.steps)
            result.verdict = sub.verdict
            result.verdict_detail = sub.verdict_detail
        elif cname_target:
            result.verdict = "CNAME"
            result.verdict_detail = f"-> {cname_target}"
        else:
            result.verdict = "ERROR"
            result.verdict_detail = "CNAME has no target value"
        return result

    step.lines.append(
        f"Record: {record.get('name', '?')} {rtype}"
    )
    if isinstance(values, list):
        for v in values:
            step.lines.append(f"  -> {v}")
    elif values:
        step.lines.append(f"  -> {values}")
    result.steps.append(step)
    result.verdict = f"RESOLVED ({rtype})"
    if isinstance(values, list) and values:
        result.verdict_detail = f"-> {values[0]}"
    elif values:
        result.verdict_detail = f"-> {values}"

    return result


async def chase_delegation(
    neo4j,  # noqa: ANN001
    result: TraceResult,
    prev_step: TraceStep,
    delegation: dict,
    query_name: str,
    vpc_id: str,
    vpc_name: str,
    account_id: str,
    depth: int,
    trace_single_fn=None,  # noqa: ANN001
) -> TraceResult:
    """Follow NS delegation chain."""
    del_name = delegation.get("name", "").rstrip(".")
    del_ns = delegation.get("values", [])
    prev_step.lines.append(
        f"No exact/wildcard record for {query_name}"
    )
    prev_step.lines.append(f"NS delegation: {del_name}")
    if del_ns:
        prev_step.lines.append(
            f"  Nameservers: {', '.join(del_ns[:2])}..."
        )
    result.steps.append(prev_step)

    cur_del_name = del_name

    for i in range(MAX_DELEGATION_DEPTH):
        del_zone = await resolve_delegation_zone(
            neo4j, cur_del_name,
        )
        if not del_zone:
            result.verdict = "DELEGATED"
            result.verdict_detail = (
                f"NS delegation to {cur_del_name} -- "
                "target zone not in graph"
            )
            return result

        step = TraceStep(
            title=f"Step {6 + i}: Following NS Delegation",
        )
        dz_name = del_zone.get("zone_name", "").rstrip(".")
        dz_id = del_zone.get("zone_id", "")
        step.lines.append(f"Zone: {dz_name}. ({dz_id})")
        acct = del_zone.get("account_id", "")
        if acct:
            step.lines.append(f"Owner: {acct}")

        rec = await lookup_record(
            neo4j, dz_id, query_name,
        )
        if rec:
            result.steps.append(step)
            return await apply_record(
                result, step, rec,
                neo4j, query_name, vpc_id,
                vpc_name, account_id, depth,
                trace_single_fn,
            )

        nested = await find_ns_delegation(
            neo4j, dz_id, dz_name, query_name,
        )
        if nested:
            cur_del_name = (
                nested.get("name", "").rstrip(".")
            )
            nested_ns = nested.get("values", [])
            step.lines.append(
                f"Further delegation: {cur_del_name}"
            )
            if nested_ns:
                step.lines.append(
                    f"  Nameservers: "
                    f"{', '.join(nested_ns[:2])}..."
                )
            result.steps.append(step)
            continue

        step.lines.append(
            f"No record for {query_name} "
            "in delegated zone"
        )
        result.steps.append(step)
        result.verdict = "NXDOMAIN"
        result.verdict_detail = (
            f"NS delegation to {dz_name} "
            f"but no record found"
        )
        return result

    result.verdict = "ERROR"
    result.verdict_detail = (
        "NS delegation chain exceeded max depth "
        f"({MAX_DELEGATION_DEPTH})"
    )
    return result
