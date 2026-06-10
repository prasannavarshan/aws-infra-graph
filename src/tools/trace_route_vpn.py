"""VPN inference helpers for trace_route — find entry/exit segments."""

from __future__ import annotations

import logging

from src.tools.cloudwan_routes import fetch_segment_routes
from src.tools.trace_route_match import find_matching_route

logger = logging.getLogger(__name__)


def _make_inferred_info(
    segment_name: str,
    segment_arn: str = "",
    attachment_id: str = "",
    matched_cidr: str = "",
) -> dict:
    """Build a resolved-info dict for an inferred source."""
    info: dict = {
        "resource_name": "",
        "resource_arn": "",
        "resource_type": "",
        "vpc_name": "",
        "vpc_arn": "",
        "vpc_id": "",
        "subnet_name": "",
        "subnet_cidr": "",
        "segment_name": segment_name,
        "segment_arn": segment_arn,
        "attachment_id": attachment_id,
        "inferred": True,
    }
    if matched_cidr:
        info["matched_cidr"] = matched_cidr
    return info


async def _resolve_from_hint(
    neo4j,  # noqa: ANN001
    hint: str,
) -> dict | None:
    """Resolve source from a user-provided hint."""
    if hint.startswith("segment:"):
        seg_name = hint[len("segment:"):]
        query = """
        MATCH (s:CloudWANSegment {name: $name})
        RETURN s.name AS name, s.arn AS arn,
               s.core_network_id AS cn_id
        LIMIT 1
        """
        results = await neo4j.query(
            query, {"name": seg_name},
        )
        if results:
            row = results[0]
            return _make_inferred_info(
                segment_name=row["name"],
                segment_arn=row.get("arn") or "",
            )
        return None

    if hint.startswith("attachment:"):
        att_id = hint[len("attachment:"):]
        query = """
        MATCH (att:CloudWANAttachment
               {attachment_id: $att_id})
              -[:PART_OF]->(seg:CloudWANSegment)
        RETURN seg.name AS seg_name,
               seg.arn AS seg_arn,
               att.attachment_id AS att_id
        LIMIT 1
        """
        results = await neo4j.query(
            query, {"att_id": att_id},
        )
        if results:
            row = results[0]
            return _make_inferred_info(
                segment_name=row["seg_name"],
                segment_arn=row.get("seg_arn") or "",
                attachment_id=row.get("att_id") or "",
            )
        return None

    return None


async def _find_vpn_exit_segment(
    neo4j,  # noqa: ANN001
    ip: str,
) -> dict | None:
    """Find the VPN/CONNECT exit segment for an on-prem IP.

    Strategy:
    1. Query Neo4j for all segments with VPN/CONNECT
       attachments (graph-only, no API calls).
    2. If only one segment has VPN attachments, return it
       (unambiguous).
    3. If multiple, fall back to API-based route table
       scanning via _find_vpn_entry_segment to find the
       segment with a route actually covering the IP.

    Args:
        neo4j: Neo4j client.
        ip: On-prem destination IP address.

    Returns:
        Inferred info dict, or None.
    """
    query = """
    MATCH (att:CloudWANAttachment)-[:PART_OF]->(seg:CloudWANSegment)
    WHERE att.attachment_type IN ['SITE_TO_SITE_VPN', 'CONNECT']
    RETURN seg.name AS seg_name,
           seg.arn AS seg_arn,
           count(att) AS att_count
    ORDER BY att_count DESC
    """
    results = await neo4j.query(query, {})
    if not results:
        logger.info(
            "_find_vpn_exit_segment: no VPN/CONNECT"
            " attachments in graph",
        )
        return None

    if len(results) == 1:
        row = results[0]
        logger.info(
            "_find_vpn_exit_segment: single VPN segment=%s"
            " (%d attachments) — using graph only",
            row["seg_name"], row["att_count"],
        )
        return _make_inferred_info(
            segment_name=row["seg_name"],
            segment_arn=row.get("seg_arn") or "",
        )

    # Multiple VPN segments — need route tables to pick
    seg_names = [r["seg_name"] for r in results]
    logger.info(
        "_find_vpn_exit_segment: %d VPN segments %s"
        " — falling back to route table scan for ip=%s",
        len(results), seg_names, ip,
    )
    return await _find_vpn_entry_segment(neo4j, ip)


async def _find_vpn_entry_segment(
    neo4j,  # noqa: ANN001
    ip: str,
) -> dict | None:
    """Find the VPN/CONNECT entry segment for an on-prem IP.

    Instead of scanning all segments, queries the graph for
    VPN/CONNECT attachments, then only checks route tables
    for segments that have those attachments. Matches by
    attachment ID (definitive proof) rather than SegmentName
    (fragile).

    Args:
        neo4j: Neo4j client.
        ip: On-prem source IP address.

    Returns:
        Inferred source info dict, or None.
    """
    # Step 1: Get all VPN/CONNECT attachments with segments
    att_query = """
    MATCH (att:CloudWANAttachment)-[:PART_OF]->(seg:CloudWANSegment)
    WHERE att.attachment_type IN ['SITE_TO_SITE_VPN', 'CONNECT']
    RETURN att.attachment_id AS att_id,
           att.attachment_type AS att_type,
           seg.name AS seg_name,
           seg.core_network_id AS cn_id
    """
    attachments = await neo4j.query(att_query, {})
    if not attachments:
        logger.info(
            "_find_vpn_entry_segment: no VPN/CONNECT"
            " attachments in graph",
        )
        return None

    # Step 2: Build per-segment VPN attachment sets
    seg_vpn_atts: dict[str, set[str]] = {}
    seg_cn_ids: dict[str, str] = {}  # seg_name -> cn_id
    for att in attachments:
        seg_name = att["seg_name"]
        seg_vpn_atts.setdefault(seg_name, set()).add(
            att["att_id"],
        )
        seg_cn_ids[seg_name] = att.get("cn_id") or ""

    total_atts = sum(len(v) for v in seg_vpn_atts.values())
    logger.info(
        "_find_vpn_entry_segment: found %d VPN/CONNECT"
        " attachments across %d segments",
        total_atts, len(seg_vpn_atts),
    )

    # Step 3: Fetch route tables only for VPN segments
    fallback: dict | None = None
    for seg_name, local_atts in seg_vpn_atts.items():
        cn_id = seg_cn_ids.get(seg_name, "")
        routes = await fetch_segment_routes(
            neo4j, seg_name, core_network_id=cn_id,
        )
        if isinstance(routes, str):
            continue

        # Step 4: Find route covering source IP
        match = find_matching_route(routes, ip)
        if not match:
            continue

        dests = match.get("Destinations", [])
        att_id = ""
        if dests:
            att_id = dests[0].get(
                "CoreNetworkAttachmentId",
                dests[0].get(
                    "TransitGatewayAttachmentId", "",
                ),
            )

        info = _make_inferred_info(
            segment_name=seg_name,
            attachment_id=att_id,
            matched_cidr=match.get(
                "DestinationCidrBlock", "",
            ),
        )

        # Step 5: Route's attachment must be a VPN owned
        # by THIS segment — not a propagated route from
        # another segment's VPN.
        if att_id and att_id in local_atts:
            info["vpn_definitive"] = True
            logger.info(
                "_find_vpn_entry_segment: VPN match"
                " ip=%s segment=%s att=%s",
                ip, seg_name, att_id,
            )
            return info

        # Save first propagated match as fallback
        if fallback is None:
            info["vpn_definitive"] = False
            fallback = info

    return fallback
