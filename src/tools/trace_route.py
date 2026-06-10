"""IP-based route tracing through CloudWAN segments."""

from __future__ import annotations

import ipaddress
import logging

from mcp.server.fastmcp import Context

from src.tools.cloudwan_routes import (
    _resolve_segment_info,
    fetch_segment_routes,
)
from src.tools.trace_route_match import find_matching_route
from src.tools.trace_route_resolve import (
    resolve_destination,
    resolve_source,
)

logger = logging.getLogger(__name__)


def get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


async def trace_segment_hops(
    neo4j,  # noqa: ANN001
    src_segment: str,
    dst_segment: str,
    dst_ip: str,
    core_network_id: str,
) -> list[dict]:
    """Trace the segment-level path from source to dest.

    Fetches each segment's route table to find which
    attachment propagated the route covering dst_ip,
    then resolves that attachment to its segment.

    Args:
        neo4j: Neo4j client.
        src_segment: Source segment name.
        dst_segment: Destination segment name.
        dst_ip: Destination IP for route matching.
        core_network_id: Core network ID.

    Returns:
        List of hop dicts with keys: segment, cidr,
        route_type, attachment_id, state.
    """
    if src_segment == dst_segment:
        return [{
            "segment": src_segment,
            "cidr": "direct",
            "route_type": "same-segment",
            "attachment_id": "",
            "state": "active",
        }]

    hops: list[dict] = []
    visited: set[str] = set()
    current = src_segment

    while current != dst_segment and current not in visited:
        visited.add(current)
        routes = await fetch_segment_routes(
            neo4j, current,
            core_network_id=core_network_id,
        )
        if isinstance(routes, str):
            hops.append({
                "segment": current,
                "cidr": "",
                "route_type": "error",
                "attachment_id": "",
                "state": f"route fetch failed: {routes}",
            })
            break

        match = find_matching_route(routes, dst_ip)
        if not match:
            hops.append({
                "segment": current,
                "cidr": "",
                "route_type": "no-route",
                "attachment_id": "",
                "state": f"no route to {dst_ip}",
            })
            break

        dests = match.get("Destinations", [])
        att_id = ""
        next_seg = ""
        if dests:
            dest = dests[0]
            att_id = dest.get(
                "CoreNetworkAttachmentId",
                dest.get(
                    "TransitGatewayAttachmentId", "",
                ),
            )
            next_seg = dest.get("SegmentName", "")

        if not next_seg and att_id:
            next_seg = await _lookup_attachment_segment(
                neo4j, att_id,
            )

        hops.append({
            "segment": current,
            "cidr": match.get(
                "DestinationCidrBlock", "",
            ),
            "route_type": match.get("Type", "unknown"),
            "attachment_id": att_id,
            "state": match.get("State", "unknown"),
        })

        if not next_seg or next_seg == current:
            break
        current = next_seg

    if current == dst_segment and current not in visited:
        hops.append({
            "segment": dst_segment,
            "cidr": "destination",
            "route_type": "destination",
            "attachment_id": "",
            "state": "active",
        })

    return hops


async def _lookup_attachment_segment(
    neo4j,  # noqa: ANN001
    attachment_id: str,
) -> str:
    """Look up the segment for a CloudWAN attachment."""
    query = """
    MATCH (att:CloudWANAttachment
           {attachment_id: $att_id})
          -[:PART_OF]->(seg:CloudWANSegment)
    RETURN seg.name AS name
    LIMIT 1
    """
    results = await neo4j.query(
        query, {"att_id": attachment_id},
    )
    if results:
        return results[0]["name"] or ""
    return ""


def _format_source(
    lines: list[str], source_ip: str, src_info: dict,
) -> None:
    """Append source section lines."""
    lines.append(f"Source: {source_ip}")
    if src_info.get("inferred"):
        lines.append("  (not in graph — inferred)")
    if src_info.get("resource_name"):
        lines.append(
            f"  Resource: {src_info['resource_name']}"
            f" ({src_info.get('resource_type', '')})"
        )
    if src_info.get("vpc_name"):
        lines.append(f"  VPC: {src_info['vpc_name']}")
    seg = src_info.get("segment_name", "")
    att = src_info.get("attachment_id", "")
    if seg:
        entry = f"  Segment: {seg}"
        if att:
            entry += f" via {att}"
        lines.append(entry)
    if src_info.get("matched_cidr"):
        lines.append(
            f"  Matched route: {src_info['matched_cidr']}"
        )


def _format_destination(
    lines: list[str], dest_ip: str, dst_info: dict,
) -> None:
    """Append destination section lines."""
    lines.append(f"Destination: {dest_ip}")
    if dst_info.get("resource_name"):
        rtype = dst_info.get("resource_type", "")
        rname = dst_info["resource_name"]
        detail = f"  Resource: {rname}"
        if rtype:
            detail += f" ({rtype})"
        if dst_info.get("subnet_name"):
            detail += f" in {dst_info['subnet_name']}"
            if dst_info.get("subnet_cidr"):
                detail += (
                    f" ({dst_info['subnet_cidr']})"
                )
        lines.append(detail)
    if dst_info.get("vpc_name"):
        vpc_line = f"  VPC: {dst_info['vpc_name']}"
        if dst_info.get("vpc_id"):
            vpc_line += f" ({dst_info['vpc_id']})"
        lines.append(vpc_line)
    dst_seg = dst_info.get("segment_name", "")
    dst_att = dst_info.get("attachment_id", "")
    if dst_seg:
        entry = f"  Segment: {dst_seg}"
        if dst_att:
            entry += f" via {dst_att}"
        lines.append(entry)


def _format_hops(
    lines: list[str], hops: list[dict],
) -> None:
    """Append path and hop section lines."""
    if not hops:
        lines.append("Path: NO HOPS TRACED")
        return
    if (
        len(hops) == 1
        and hops[0]["route_type"] == "same-segment"
    ):
        lines.append("Path (same segment — direct):")
        lines.append(f"  {hops[0]['segment']}")
        return

    real_hops = [
        h for h in hops
        if h["route_type"] != "destination"
    ]
    lines.append(f"Path ({len(real_hops)} hop(s)):")
    for i, hop in enumerate(hops):
        if hop["route_type"] == "destination":
            continue
        prefix = "  " if i == 0 else "    -> "
        detail = hop["segment"]
        if hop.get("cidr"):
            detail += (
                f"  [{hop['cidr']}, "
                f"{hop['route_type']}"
            )
            if hop.get("attachment_id"):
                detail += f", {hop['attachment_id']}"
            detail += "]"
        if hop["route_type"] in ("error", "no-route"):
            detail += f"  ({hop['state']})"
        lines.append(f"{prefix}{detail}")


def _get_verdict(hops: list[dict]) -> tuple[str, list[str]]:
    """Extract verdict and detail lines from hops.

    Returns:
        Tuple of (verdict_str, detail_lines).
    """
    has_error = any(
        h["route_type"] in ("error", "no-route")
        for h in hops
    )
    if has_error:
        details = [
            f"  {h['segment']}: {h['state']}"
            for h in hops
            if h["route_type"] in ("error", "no-route")
        ]
        return "NOT ROUTABLE", details
    return "ROUTABLE", [
        "  All hops have propagated routes"
        " covering the destination IP.",
    ]


def format_trace(
    source_ip: str,
    dest_ip: str,
    src_info: dict,
    dst_info: dict,
    fwd_hops: list[dict],
    ret_hops: list[dict] | None = None,
) -> str:
    """Format the trace result into readable output.

    Args:
        source_ip: Source IP address.
        dest_ip: Destination IP address.
        src_info: Resolved source info dict.
        dst_info: Resolved destination info dict.
        fwd_hops: Forward path hops from trace_segment_hops.
        ret_hops: Return path hops (optional).

    Returns:
        Formatted trace string.
    """
    lines = [
        f"Route Trace: {source_ip} -> {dest_ip}\n",
    ]
    _format_source(lines, source_ip, src_info)
    lines.append("")
    _format_destination(lines, dest_ip, dst_info)
    lines.append("")

    # Forward path
    lines.append(
        f"Forward Path: {source_ip} -> {dest_ip}",
    )
    _format_hops(lines, fwd_hops)
    fwd_verdict, fwd_details = _get_verdict(fwd_hops)
    lines.append(f"Verdict: {fwd_verdict}")
    lines.extend(fwd_details)

    # Return path
    if ret_hops is not None:
        lines.append("")
        lines.append(
            f"Return Path: {dest_ip} -> {source_ip}",
        )
        _format_hops(lines, ret_hops)
        ret_verdict, ret_details = _get_verdict(ret_hops)
        lines.append(f"Verdict: {ret_verdict}")
        lines.extend(ret_details)

    return "\n".join(lines)


async def trace_route(
    ctx: Context,
    source_ip: str,
    destination_ip: str,
    source_hint: str = "",
) -> str:
    """Trace the CloudWAN path between two IP addresses.

    Given a source and destination IP, resolves each to
    a VPC/segment (or infers on-prem entry point), then
    traces the segment-level path using runtime route
    tables. Shows each hop with CIDR, route type, and
    attachment ID.

    IMPORTANT: Do NOT pass source_hint unless the user
    explicitly names a specific segment or attachment.
    On-prem IPs may enter through any segment (e.g.,
    ProdWAN, OnPremShared) depending on BGP
    configuration. The tool automatically infers the
    correct entry segment by scanning route tables.
    Guessing the segment name (e.g., assuming "on-prem"
    means "OnPremShared") will produce wrong results.

    Args:
        source_ip: Any IP (on-prem or in-VPC).
        destination_ip: Target IP (should be resolvable
            to a VPC or resource in the graph).
        source_hint: Leave empty to auto-detect. Only
            set when the user explicitly provides a
            segment or attachment. Format:
            "segment:SegmentName" or "attachment:att-xxx".

    Returns:
        Formatted route trace showing source, destination,
        segment path with route details, and verdict.
    """
    app = get_app_context(ctx)
    neo4j = app.neo4j

    for label, ip in [
        ("source", source_ip),
        ("destination", destination_ip),
    ]:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return f"Invalid {label} IP address: {ip}"

    dst_info = await resolve_destination(
        neo4j, destination_ip,
    )
    if not dst_info:
        return (
            f"Could not resolve destination IP"
            f" {destination_ip} to any VPC or resource"
            " in the graph. The IP must belong to a known"
            " VPC CIDR block."
        )

    dst_seg = dst_info.get("segment_name", "")
    if not dst_seg:
        vpc = dst_info.get("vpc_name", destination_ip)
        return (
            f"Destination {destination_ip} resolved to"
            f" VPC {vpc}, but no CloudWAN attachment"
            " found for this VPC. The VPC may not be"
            " connected to CloudWAN."
        )

    src_info = await resolve_source(
        neo4j, source_ip, source_hint,
    )
    if not src_info:
        return (
            f"Could not resolve source IP {source_ip}."
            " It is not in any known VPC, and no CloudWAN"
            " segment has a route covering this IP."
            " Try providing source_hint='segment:NAME'"
            " to specify the entry segment."
        )

    src_seg = src_info.get("segment_name", "")
    if not src_seg:
        return (
            f"Source {source_ip} resolved but no segment"
            " found. Provide source_hint='segment:NAME'."
        )

    cn_id = ""
    cn_id_result, _, err = await _resolve_segment_info(
        neo4j, dst_seg, "", "",
    )
    if not err:
        cn_id = cn_id_result

    # Forward trace: source -> destination
    fwd_hops = await trace_segment_hops(
        neo4j, src_seg, dst_seg, destination_ip, cn_id,
    )

    # Return trace: destination -> source
    ret_hops = await trace_segment_hops(
        neo4j, dst_seg, src_seg, source_ip, cn_id,
    )

    return format_trace(
        source_ip, destination_ip,
        src_info, dst_info, fwd_hops, ret_hops,
    )
