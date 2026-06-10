"""CloudWAN route tools — runtime route fetching and verification."""

from __future__ import annotations

import asyncio
import logging

from botocore.exceptions import ClientError
from mcp.server.fastmcp import Context

from src.collector.base import (
    BOTO_CONFIG,
    get_session_for_account,
)
from src.config import settings

logger = logging.getLogger(__name__)


def get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


async def _get_core_network_info(
    neo4j,  # noqa: ANN001
    core_network_id: str,
) -> tuple[str, str]:
    """Look up global_network_id and account from core network.

    Returns:
        (global_network_id, account_id) tuple. Empty strings
        if not found.
    """
    query = """
    MATCH (cn:CloudWANCoreNetwork
           {core_network_id: $cn_id})
    RETURN cn.global_network_id AS gn_id,
           cn.account_id AS account_id
    LIMIT 1
    """
    results = await neo4j.query(
        query, {"cn_id": core_network_id},
    )
    if results:
        return (
            results[0].get("gn_id") or "",
            results[0].get("account_id") or "",
        )
    return "", ""


async def _resolve_segment_info(
    neo4j,  # noqa: ANN001
    segment_name: str,
    core_network_id: str,
    edge_location: str,
) -> tuple[str, str, str | None]:
    """Resolve core_network_id and edge_location from graph.

    Returns:
        (core_network_id, edge_location, error_message).
        error_message is None on success.
    """
    if core_network_id and edge_location:
        return core_network_id, edge_location, None

    params: dict = {"name": segment_name}
    cn_filter = ""
    if core_network_id:
        cn_filter = " AND s.core_network_id = $cn_id"
        params["cn_id"] = core_network_id

    query = f"""
    MATCH (s:CloudWANSegment {{name: $name}})
    WHERE true{cn_filter}
    RETURN s.core_network_id AS cn_id,
           s.edge_locations AS edge_locs,
           s.arn AS arn
    LIMIT 1
    """
    results = await neo4j.query(query, params)
    if not results:
        return "", "", (
            f"Segment '{segment_name}' not found."
            " Use find_resources with"
            " resource_type=CloudWANSegment."
        )
    row = results[0]
    logger.info(
        "resolve_segment_info: segment=%s cn_param=%s"
        " cn_result=%s edge_locs=%s arn=%s",
        segment_name, core_network_id,
        row["cn_id"], row.get("edge_locs"),
        row.get("arn"),
    )
    if not core_network_id:
        core_network_id = row["cn_id"]
    if not edge_location:
        locs = row.get("edge_locs") or []
        if not locs:
            return "", "", (
                f"No edge locations for segment"
                f" '{segment_name}'."
            )
        edge_location = locs[0]
    return core_network_id, edge_location, None


async def fetch_segment_routes(
    neo4j,  # noqa: ANN001
    segment_name: str,
    edge_location: str = "",
    core_network_id: str = "",
) -> list[dict] | str:
    """Fetch routes for a segment from the AWS API.

    Returns:
        List of route dicts on success, or error string.
    """
    cn_id, edge_loc, err = await _resolve_segment_info(
        neo4j, segment_name, core_network_id, edge_location,
    )
    if err:
        return err

    global_net_id, owner_account = (
        await _get_core_network_info(neo4j, cn_id)
    )
    if not global_net_id:
        return (
            f"Could not resolve global_network_id"
            f" for core network {cn_id}."
        )

    logger.info(
        "fetch_segment_routes: segment=%s cn=%s edge=%s"
        " gn=%s owner=%s",
        segment_name, cn_id, edge_loc,
        global_net_id, owner_account,
    )

    try:
        session = get_session_for_account(
            owner_account,
        ) if owner_account else get_session_for_account("")
        nm = session.client(
            "networkmanager",
            region_name="us-west-2",
            config=BOTO_CONFIG,
            verify=settings.aws.ssl_verify,
        )

        resp = await asyncio.to_thread(
            nm.get_network_routes,
            GlobalNetworkId=global_net_id,
            RouteTableIdentifier={
                "CoreNetworkSegmentEdge": {
                    "CoreNetworkId": cn_id,
                    "SegmentName": segment_name,
                    "EdgeLocation": edge_loc,
                },
            },
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]
        logger.warning(
            "fetch_segment_routes error: segment=%s"
            " edge=%s cn=%s gn=%s code=%s",
            segment_name, edge_loc, cn_id,
            global_net_id, code,
        )
        return (
            f"AWS API error fetching routes for"
            f" {segment_name} at {edge_loc}"
            f" (cn={cn_id}, gn={global_net_id}):"
            f" {code}: {msg}"
        )

    return resp.get("NetworkRoutes", [])


def _format_routes(
    segment_name: str,
    edge_location: str,
    routes: list[dict],
) -> str:
    """Format route list into readable output."""
    if not routes:
        return (
            f"No routes in {segment_name}"
            f" at {edge_location}."
        )

    lines = [
        f"Routes for segment '{segment_name}'"
        f" at {edge_location}"
        f" ({len(routes)} routes):\n",
    ]

    for route in routes:
        prefixes = route.get(
            "DestinationCidrBlock",
            route.get("PrefixListId", "unknown"),
        )
        route_type = route.get("Type", "unknown")
        state = route.get("State", "unknown")
        destinations = route.get("Destinations", [])

        att_info = ""
        if destinations:
            dest = destinations[0]
            att_id = dest.get(
                "TransitGatewayAttachmentId",
                dest.get("CoreNetworkAttachmentId", ""),
            )
            seg = dest.get("SegmentName", "")
            att_info = f" | att: {att_id}"
            if seg:
                att_info += f" (segment: {seg})"

        lines.append(
            f"  {prefixes}"
            f"  [{route_type}, {state}]{att_info}"
        )

    return "\n".join(lines)


async def get_cloudwan_routes(
    ctx: Context,
    segment_name: str,
    edge_location: str = "",
    core_network_id: str = "",
) -> str:
    """Get actual routes in a CloudWAN segment's route table.

    Calls the AWS NetworkManager API at runtime to fetch
    the real routes a segment currently has. This is the
    ground truth for what prefixes a segment can reach.

    Use this tool to verify connectivity verdicts from
    check_cloudwan_connectivity — the route table shows
    which prefixes were actually propagated or statically
    injected into each segment.

    Args:
        segment_name: Name of the CloudWAN segment
            (e.g., "OnPremShared", "ProdSegment").
        edge_location: AWS region for the edge location
            (e.g., "us-west-2"). If empty, uses the first
            edge location found for the segment.
        core_network_id: Core network ID. If empty, looks
            up the segment in the graph to find it.

    Returns:
        Formatted route table showing destination prefixes,
        route type (propagated/static), state, and source
        attachment details.
    """
    app = get_app_context(ctx)
    neo4j = app.neo4j

    routes = await fetch_segment_routes(
        neo4j, segment_name, edge_location, core_network_id,
    )
    if isinstance(routes, str):
        return routes

    cn_id, edge_loc, err = await _resolve_segment_info(
        neo4j, segment_name, core_network_id, edge_location,
    )
    if err:
        return err

    return _format_routes(segment_name, edge_loc, routes)


async def correlate_routes_to_segments(
    neo4j,  # noqa: ANN001
    routes: list[dict],
) -> dict[str, list[dict]]:
    """Group routes by originating segment name.

    Uses Destinations[0].SegmentName when present.
    Falls back to looking up CoreNetworkAttachmentId
    in the graph to find the segment.

    Args:
        neo4j: Neo4j client for attachment lookups.
        routes: Raw route dicts from get_network_routes API.

    Returns:
        Dict mapping segment name to list of route dicts.
    """
    # Collect attachment IDs that need graph lookup
    unknown_att_ids: set[str] = set()
    for route in routes:
        dests = route.get("Destinations", [])
        if not dests:
            continue
        if not dests[0].get("SegmentName"):
            att_id = dests[0].get(
                "CoreNetworkAttachmentId", "",
            )
            if att_id:
                unknown_att_ids.add(att_id)

    # Batch lookup attachment -> segment from graph
    att_to_seg: dict[str, str] = {}
    if unknown_att_ids:
        query = """
        UNWIND $att_ids AS att_id
        MATCH (a:CloudWANAttachment
               {attachment_id: att_id})
              -[:PART_OF]->(s:CloudWANSegment)
        RETURN a.attachment_id AS att_id,
               s.name AS seg_name
        """
        results = await neo4j.query(
            query, {"att_ids": list(unknown_att_ids)},
        )
        for row in results:
            att_to_seg[row["att_id"]] = row["seg_name"]

    # Group routes by segment
    by_segment: dict[str, list[dict]] = {}
    for route in routes:
        dests = route.get("Destinations", [])
        if dests:
            seg = dests[0].get("SegmentName", "")
            if not seg:
                att_id = dests[0].get(
                    "CoreNetworkAttachmentId", "",
                )
                seg = att_to_seg.get(att_id, "")
        else:
            seg = ""
        key = seg if seg else "_unknown"
        by_segment.setdefault(key, []).append(route)
    return by_segment


async def verify_route_propagation(
    neo4j,  # noqa: ANN001
    source_segment: str,
    target_segment: str,
    edge_location: str = "",
    core_network_id: str = "",
) -> dict:
    """Verify if source segment's routes exist in target.

    Fetches the target segment's route table and checks
    whether any routes originate from the source segment.

    Args:
        neo4j: Neo4j client.
        source_segment: Name of source segment.
        target_segment: Name of target segment.
        edge_location: Edge location for route table lookup.
        core_network_id: Core network ID.

    Returns:
        Dict with keys: verified, verdict, routes_from_source,
        total_routes, segment_route_counts, error.
    """
    routes = await fetch_segment_routes(
        neo4j, target_segment, edge_location,
        core_network_id,
    )

    if isinstance(routes, str):
        return {
            "verified": False,
            "verdict": None,
            "routes_from_source": 0,
            "total_routes": 0,
            "segment_route_counts": {},
            "error": routes,
        }

    if not routes:
        return {
            "verified": True,
            "verdict": "POLICY_ALLOWS",
            "routes_from_source": 0,
            "total_routes": 0,
            "segment_route_counts": {},
            "error": None,
        }

    by_segment = await correlate_routes_to_segments(
        neo4j, routes,
    )
    source_routes = by_segment.get(source_segment, [])
    counts = {
        seg: len(rts) for seg, rts in by_segment.items()
    }

    verdict = "REACHABLE" if source_routes else "POLICY_ALLOWS"

    return {
        "verified": True,
        "verdict": verdict,
        "routes_from_source": len(source_routes),
        "total_routes": len(routes),
        "segment_route_counts": counts,
        "error": None,
    }


def format_route_verification(
    source: str,
    target: str,
    verification: dict,
) -> list[str]:
    """Format route verification results for output.

    Args:
        source: Source segment name.
        target: Target segment name.
        verification: Result from verify_route_propagation.

    Returns:
        List of formatted output lines.
    """
    lines: list[str] = []

    if verification.get("error"):
        lines.append(
            f"\nRoute Verification ({target}):"
        )
        lines.append(
            f"  Warning: Could not verify routes"
            f" — {verification['error']}"
        )
        lines.append(
            "  Graph verdict retained (unverified)."
        )
        return lines

    total = verification["total_routes"]
    from_src = verification["routes_from_source"]
    counts = verification["segment_route_counts"]
    verdict = verification["verdict"]

    lines.append(
        f"\nRoute Verification ({target}):"
    )
    lines.append(
        f"  {total} total routes,"
        f" {from_src} from {source}"
    )

    if counts:
        sorted_counts = sorted(
            counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        origins = ", ".join(
            f"{seg} ({cnt})" for seg, cnt in sorted_counts
        )
        lines.append(f"  Route origins: {origins}")

    if verdict == "POLICY_ALLOWS":
        lines.append(f"  Verdict adjusted: {verdict}")
        lines.append(
            f"    Policy path exists, but no routes"
            f" from {source} found in {target}."
        )
        if counts:
            top = sorted_counts[0][0]
            if top != "_unknown":
                lines.append(
                    f"    Traffic likely flows via"
                    f" {top} instead."
                )
    else:
        lines.append(
            f"  Routes from {source} confirmed"
            f" in {target}."
        )

    return lines
