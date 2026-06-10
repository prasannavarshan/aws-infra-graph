"""CloudWAN connectivity checker — segment-level reachability."""

from __future__ import annotations

import logging

from mcp.server.fastmcp import Context

from src.tools.cloudwan_graph import (
    analyze_direction,
    check_direct_share,
    check_hard_denies_on_path,
    find_any_path,
    find_reachable_path,
    find_segments,
    format_attachments,
    get_segment_attachments,
)
from src.tools.cloudwan_routes import (
    format_route_verification,
    verify_route_propagation,
)

logger = logging.getLogger(__name__)


def get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


async def _build_direct_verdicts(
    neo4j,  # noqa: ANN001
    lines: list[str],
    source_segment: str,
    target_segment: str,
    src_seg: dict,
    tgt_seg: dict,
    src_arn: str,
    tgt_arn: str,
    direct: list[dict],
) -> tuple[str, str]:
    """Build verdict lines for direct CONNECTS_TO edge.

    Returns:
        (forward_verdict, return_verdict) strings.
    """
    direct_path = [
        {
            "name": source_segment,
            "arn": src_arn,
            "deny_filter": src_seg.get("deny_filter"),
        },
        {
            "name": target_segment,
            "arn": tgt_arn,
            "deny_filter": tgt_seg.get("deny_filter"),
        },
    ]
    mode = direct[0].get("mode", "unknown")
    lines.append(
        f"Path: {source_segment}"
        f" -> CONNECTS_TO [mode: {mode}]"
        f" -> {target_segment}"
    )

    arns = [src_arn, tgt_arn]
    deny_query = """
    UNWIND range(0, size($arns) - 2) AS i
    WITH $arns[i] AS src_arn, $arns[i + 1] AS tgt_arn
    MATCH (s:CloudWANSegment {arn: src_arn})
          -[r:DENIES]-
          (t:CloudWANSegment {arn: tgt_arn})
    RETURN s.name AS src, t.name AS tgt,
           r.type AS type
    """
    path_denies = await neo4j.query(
        deny_query, {"arns": arns},
    )
    hard_denies = [
        d for d in path_denies
        if d.get("type") == "segment_action_deny"
    ]
    hard_block = check_hard_denies_on_path(
        direct_path, hard_denies,
    )

    if hard_block:
        lines.append(
            f"\nForward ({source_segment}"
            f" -> {target_segment}):"
        )
        lines.append("  Verdict: BLOCKED_HARD")
        lines.append(
            f"  {hard_block['src']} DENIES"
            f" {hard_block['tgt']}"
            " (segment-action deny — hard block)"
        )
        lines.append(
            f"\nReturn ({target_segment}"
            f" -> {source_segment}):"
        )
        lines.append("  Verdict: BLOCKED_HARD")
        lines.append(
            "  Same segment-action deny applies"
            " bidirectionally."
        )
        return "BLOCKED_HARD", "BLOCKED_HARD"

    fwd = analyze_direction(direct_path, True)
    ret = analyze_direction(direct_path, False)
    lines.append(
        f"\nForward ({source_segment}"
        f" -> {target_segment}):"
    )
    lines.append(f"  Verdict: {fwd['verdict']}")
    if fwd["reason"]:
        lines.append(f"  {fwd['reason']}")
    lines.append(
        f"\nReturn ({target_segment}"
        f" -> {source_segment}):"
    )
    lines.append(f"  Verdict: {ret['verdict']}")
    if ret["reason"]:
        lines.append(f"  {ret['reason']}")
    return fwd["verdict"], ret["verdict"]


async def _build_indirect_verdicts(
    neo4j,  # noqa: ANN001
    lines: list[str],
    source_segment: str,
    target_segment: str,
    src_arn: str,
    tgt_arn: str,
) -> tuple[str, str] | None:
    """Build verdict lines for indirect paths.

    Returns:
        (forward_verdict, return_verdict) or None if NO_PATH.
    """
    fwd_path = await find_reachable_path(
        neo4j, src_arn, tgt_arn, "forward",
    )
    ret_path = await find_reachable_path(
        neo4j, src_arn, tgt_arn, "return",
    )
    fallback = await find_any_path(
        neo4j, src_arn, tgt_arn,
    )

    if not fallback:
        lines.append("Verdict: NO_PATH")
        lines.append(
            "\nNo CONNECTS_TO chain found between"
            f" {source_segment} and"
            f" {target_segment}."
            " These segments are not connected via"
            " any policy share rules."
        )
        return None

    fwd_verdict = "BLOCKED"
    lines.append(
        f"\nForward ({source_segment}"
        f" -> {target_segment}):"
    )
    if fwd_path:
        fwd_segs = fwd_path["segments"]
        fwd_via = " -> ".join(
            s["name"] for s in fwd_segs
        )
        fwd_verdict = "REACHABLE"
        lines.append("  Verdict: REACHABLE")
        lines.append(f"  Via: {fwd_via}")
        lines.append(
            "  Route propagation chain unbroken"
        )
    else:
        lines.append("  Verdict: BLOCKED")
        lines.append(
            "  All paths blocked by deny-filters."
        )
        fb_segs = fallback["segments"]
        fb_via = " -> ".join(
            s["name"] for s in fb_segs
        )
        lines.append(f"  Nearest path: {fb_via}")
        block = analyze_direction(fb_segs, True)
        if block["reason"]:
            lines.append(f"  {block['reason']}")

    ret_verdict = "BLOCKED"
    lines.append(
        f"\nReturn ({target_segment}"
        f" -> {source_segment}):"
    )
    if ret_path:
        ret_segs = ret_path["segments"]
        ret_via = " -> ".join(
            s["name"] for s in ret_segs
        )
        ret_verdict = "REACHABLE"
        lines.append("  Verdict: REACHABLE")
        lines.append(f"  Via: {ret_via}")
        lines.append(
            "  Route propagation chain unbroken"
        )
    else:
        lines.append("  Verdict: BLOCKED")
        lines.append(
            "  All paths blocked by deny-filters."
        )
        fb_segs = fallback["segments"]
        fb_via = " -> ".join(
            s["name"] for s in fb_segs
        )
        lines.append(f"  Nearest path: {fb_via}")
        block = analyze_direction(fb_segs, False)
        if block["reason"]:
            lines.append(f"  {block['reason']}")

    return fwd_verdict, ret_verdict


async def check_cloudwan_connectivity(
    ctx: Context,
    source_segment: str,
    target_segment: str,
    core_network_id: str = "",
    verify_routes: bool = False,
) -> str:
    """Check if two CloudWAN segments can reach each other.

    Analyzes route propagation in BOTH directions separately,
    since deny-filters create asymmetric routing. A deny-filter
    is a route IMPORT filter: it blocks a segment from importing
    routes from listed segments, but does NOT prevent those
    segments from importing routes in the other direction.

    Shows per-direction verdicts (REACHABLE, BLOCKED, or
    BLOCKED_HARD), path, deny-filter details, and attachments.

    Args:
        source_segment: Name of the source segment
            (e.g., "OnPremShared").
        target_segment: Name of the target segment
            (e.g., "ProdSegment").
        core_network_id: Optional core network ID to filter
            by when multiple core networks exist.
        verify_routes: When True, cross-checks graph verdicts
            against actual route tables via AWS API. REACHABLE
            verdicts are downgraded to POLICY_ALLOWS when no
            routes from the source segment are found in the
            target's route table. Default: False (fast
            graph-only analysis).

    Returns:
        Formatted connectivity analysis with per-direction
        verdicts, path, deny rules, and attachment details.

    Tip:
        Use get_cloudwan_routes to verify actual runtime routes
        in each segment's route table.
    """
    app = get_app_context(ctx)
    neo4j = app.neo4j

    src_seg, tgt_seg = await find_segments(
        neo4j, source_segment, target_segment,
        core_network_id,
    )

    if not src_seg:
        return (
            f"Source segment '{source_segment}' not found"
            " in the graph. Use find_resources with "
            "resource_type=CloudWANSegment to list segments."
        )
    if not tgt_seg:
        return (
            f"Target segment '{target_segment}' not found"
            " in the graph. Use find_resources with "
            "resource_type=CloudWANSegment to list segments."
        )

    src_arn = src_seg["arn"]
    tgt_arn = tgt_seg["arn"]
    cn_id = src_seg.get("cn_id", core_network_id)

    lines: list[str] = [
        "CloudWAN Connectivity:"
        f" {source_segment} <-> {target_segment}\n",
    ]

    direct = await check_direct_share(
        neo4j, src_arn, tgt_arn,
    )

    if direct:
        fwd_v, ret_v = await _build_direct_verdicts(
            neo4j, lines, source_segment, target_segment,
            src_seg, tgt_seg, src_arn, tgt_arn, direct,
        )
    else:
        result = await _build_indirect_verdicts(
            neo4j, lines, source_segment, target_segment,
            src_arn, tgt_arn,
        )
        if result is None:
            src_atts = await get_segment_attachments(
                neo4j, src_arn,
            )
            tgt_atts = await get_segment_attachments(
                neo4j, tgt_arn,
            )
            lines.extend(format_attachments(
                "Source", source_segment, src_atts,
            ))
            lines.extend(format_attachments(
                "Target", target_segment, tgt_atts,
            ))
            return "\n".join(lines)
        fwd_v, ret_v = result

    # Route verification when requested
    if verify_routes:
        lines.extend(await _do_route_verification(
            neo4j, source_segment, target_segment,
            fwd_v, ret_v, cn_id, lines,
        ))

    # Deny-filter details
    _append_deny_filters(
        lines, src_seg, tgt_seg,
        source_segment, target_segment,
    )

    # Isolation warnings
    _append_isolation_warnings(
        lines, src_seg, tgt_seg,
        source_segment, target_segment,
    )

    # Attachments
    src_atts = await get_segment_attachments(
        neo4j, src_arn,
    )
    tgt_atts = await get_segment_attachments(
        neo4j, tgt_arn,
    )
    lines.extend(format_attachments(
        "Source", source_segment, src_atts,
    ))
    lines.extend(format_attachments(
        "Target", target_segment, tgt_atts,
    ))

    if not verify_routes:
        lines.append(
            "\nTip: Use verify_routes=True or"
            " get_cloudwan_routes to verify"
            " actual runtime routes."
        )

    return "\n".join(lines)


async def _do_route_verification(
    neo4j,  # noqa: ANN001
    source_segment: str,
    target_segment: str,
    fwd_verdict: str,
    ret_verdict: str,
    core_network_id: str,
    lines: list[str],
) -> list[str]:
    """Run route verification for REACHABLE directions.

    Returns:
        Additional output lines to append.
    """
    extra: list[str] = []

    if fwd_verdict == "REACHABLE":
        fwd_ver = await verify_route_propagation(
            neo4j, source_segment, target_segment,
            core_network_id=core_network_id,
        )
        fwd_lines = format_route_verification(
            source_segment, target_segment, fwd_ver,
        )
        extra.extend(fwd_lines)

        if (
            fwd_ver.get("verified")
            and fwd_ver.get("verdict") == "POLICY_ALLOWS"
        ):
            _replace_verdict(
                lines, "Forward", "REACHABLE",
                "POLICY_ALLOWS",
            )

    if ret_verdict == "REACHABLE":
        ret_ver = await verify_route_propagation(
            neo4j, target_segment, source_segment,
            core_network_id=core_network_id,
        )
        ret_lines = format_route_verification(
            target_segment, source_segment, ret_ver,
        )
        extra.extend(ret_lines)

        if (
            ret_ver.get("verified")
            and ret_ver.get("verdict") == "POLICY_ALLOWS"
        ):
            _replace_verdict(
                lines, "Return", "REACHABLE",
                "POLICY_ALLOWS",
            )

    return extra


def _replace_verdict(
    lines: list[str],
    direction: str,
    old_verdict: str,
    new_verdict: str,
) -> None:
    """Replace a verdict in existing output lines in-place."""
    for i, line in enumerate(lines):
        if (
            f"Verdict: {old_verdict}" in line
            and any(
                f"{direction}" in lines[j]
                for j in range(max(0, i - 2), i)
            )
        ):
            lines[i] = line.replace(
                f"Verdict: {old_verdict}",
                f"Verdict: {new_verdict}",
            )
            break


def _append_deny_filters(
    lines: list[str],
    src_seg: dict,
    tgt_seg: dict,
    source_segment: str,
    target_segment: str,
) -> None:
    """Append deny-filter details to output."""
    src_df = src_seg.get("deny_filter") or []
    tgt_df = tgt_seg.get("deny_filter") or []
    if src_df or tgt_df:
        lines.append("\nDeny-filters:")
        if src_df:
            lines.append(
                f"  {source_segment} blocks imports from: "
                + ", ".join(src_df)
            )
        if tgt_df:
            lines.append(
                f"  {target_segment} blocks imports from: "
                + ", ".join(tgt_df)
            )


def _append_isolation_warnings(
    lines: list[str],
    src_seg: dict,
    tgt_seg: dict,
    source_segment: str,
    target_segment: str,
) -> None:
    """Append isolation warnings to output."""
    warnings: list[str] = []
    if src_seg.get("isolate"):
        warnings.append(
            f"  - {source_segment} has "
            "isolate_attachments=true: attachments in "
            "this segment cannot communicate with each "
            "other."
        )
    if tgt_seg.get("isolate"):
        warnings.append(
            f"  - {target_segment} has "
            "isolate_attachments=true: attachments in "
            "this segment cannot communicate with each "
            "other."
        )
    if warnings:
        lines.append("\nIsolation warnings:")
        lines.extend(warnings)
