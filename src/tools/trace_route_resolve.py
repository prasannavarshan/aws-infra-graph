"""IP resolution helpers for trace_route — destination and source."""

from __future__ import annotations

import ipaddress
import logging

from src.tools.trace_route_vpn import (
    _find_vpn_entry_segment,
    _find_vpn_exit_segment,
    _resolve_from_hint,
)

logger = logging.getLogger(__name__)


async def resolve_destination(
    neo4j,  # noqa: ANN001
    ip: str,
) -> dict | None:
    """Resolve a destination IP to a VPC/resource and segment.

    Steps:
    1. Exact IP match on EC2/ALB/ENI nodes (private_ip/public_ip)
    2. CIDR match on VPC/Subnet nodes (longest prefix)
    3. Follow CloudWANAttachment -> Segment edges

    Args:
        neo4j: Neo4j client.
        ip: Destination IP address.

    Returns:
        Dict with keys: resource_name, resource_arn, vpc_name,
        vpc_arn, vpc_id, subnet_name, subnet_cidr, segment_name,
        segment_arn, attachment_id. None if not resolved.
    """
    # Step 1: exact IP match
    exact_query = """
    MATCH (n)
    WHERE n.private_ip = $ip OR n.public_ip = $ip
    OPTIONAL MATCH (n)-[:RUNS_IN]->(sub:Subnet)
    OPTIONAL MATCH (sub)-[:PART_OF]->(vpc:VPC)
    RETURN n.name AS name, n.arn AS arn,
           labels(n) AS labels,
           sub.name AS subnet_name,
           sub.cidr_block AS subnet_cidr,
           vpc.name AS vpc_name, vpc.arn AS vpc_arn,
           vpc.vpc_id AS vpc_id
    LIMIT 1
    """
    exact = await neo4j.query(exact_query, {"ip": ip})
    if exact:
        row = exact[0]
        vpc_id = row.get("vpc_id") or ""
        vpc_arn = row.get("vpc_arn") or ""
        return await _enrich_with_segment(
            neo4j, {
                "resource_name": row["name"] or "unnamed",
                "resource_arn": row.get("arn") or "",
                "resource_type": (
                    row["labels"][0] if row.get("labels")
                    else "unknown"
                ),
                "vpc_name": row.get("vpc_name") or "",
                "vpc_arn": vpc_arn,
                "vpc_id": vpc_id,
                "subnet_name": row.get("subnet_name") or "",
                "subnet_cidr": row.get("subnet_cidr") or "",
            },
        )

    # Step 2a: Subnet CIDR match (most specific)
    subnet_query = """
    MATCH (sub:Subnet)-[:PART_OF]->(v:VPC)
    WHERE sub.cidr_block IS NOT NULL
    RETURN sub.name AS subnet_name,
           sub.cidr_block AS cidr_block,
           v.name AS vpc_name, v.arn AS vpc_arn,
           v.vpc_id AS vpc_id
    """
    subnets = await neo4j.query(subnet_query, {})
    best_subnet = _longest_prefix_match(subnets, ip)
    if best_subnet:
        return await _enrich_with_segment(
            neo4j, {
                "resource_name": "",
                "resource_arn": "",
                "resource_type": "",
                "vpc_name": best_subnet.get("vpc_name") or "",
                "vpc_arn": best_subnet.get("vpc_arn") or "",
                "vpc_id": best_subnet.get("vpc_id") or "",
                "subnet_name": best_subnet.get("subnet_name") or "",
                "subnet_cidr": best_subnet.get("cidr_block") or "",
            },
        )

    # Step 2b: VPC CIDR match (primary + secondary)
    cidr_query = """
    MATCH (v:VPC)
    WHERE v.cidr_block IS NOT NULL
    RETURN v.name AS name, v.arn AS arn,
           v.vpc_id AS vpc_id,
           v.cidr_block AS cidr_block,
           v.secondary_cidrs AS secondary_cidrs
    """
    vpcs = await neo4j.query(cidr_query, {})
    best_vpc = _longest_prefix_match_vpc(vpcs, ip)
    if best_vpc:
        return await _enrich_with_segment(
            neo4j, {
                "resource_name": "",
                "resource_arn": "",
                "resource_type": "",
                "vpc_name": best_vpc["name"] or "",
                "vpc_arn": best_vpc["arn"] or "",
                "vpc_id": best_vpc["vpc_id"] or "",
                "subnet_name": "",
                "subnet_cidr": "",
            },
        )

    # Step 3: On-prem — find exit segment via VPN attachments
    inferred = await _find_vpn_exit_segment(neo4j, ip)
    if inferred:
        inferred["origin"] = "on-prem-destination"
        return inferred
    return None


def _longest_prefix_match(
    nodes: list[dict], ip: str,
) -> dict | None:
    """Find the node with the longest CIDR prefix match."""
    best: dict | None = None
    best_prefix = -1
    for node in nodes:
        cidr = node.get("cidr_block", "")
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if ipaddress.ip_address(ip) not in net:
            continue
        if net.prefixlen > best_prefix:
            best_prefix = net.prefixlen
            best = node
    return best


def _longest_prefix_match_vpc(
    vpcs: list[dict], ip: str,
) -> dict | None:
    """Find VPC with longest CIDR match (primary + secondary)."""
    best: dict | None = None
    best_prefix = -1
    addr = ipaddress.ip_address(ip)
    for vpc in vpcs:
        cidrs = [vpc.get("cidr_block", "")]
        for sc in vpc.get("secondary_cidrs") or []:
            cidrs.append(sc)
        for cidr in cidrs:
            if not cidr:
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if addr not in net:
                continue
            if net.prefixlen > best_prefix:
                best_prefix = net.prefixlen
                best = vpc
    return best


async def _enrich_with_segment(
    neo4j,  # noqa: ANN001
    info: dict,
) -> dict | None:
    """Add segment/attachment info to a resolved resource."""
    vpc_id = info.get("vpc_id")
    if not vpc_id:
        info.update({
            "segment_name": "",
            "segment_arn": "",
            "attachment_id": "",
        })
        return info

    seg_query = """
    MATCH (att:CloudWANAttachment)-[:ATTACHED_TO]->
          (v:VPC {vpc_id: $vpc_id})
    MATCH (att)-[:PART_OF]->(seg:CloudWANSegment)
    RETURN seg.name AS seg_name, seg.arn AS seg_arn,
           att.attachment_id AS att_id
    LIMIT 1
    """
    results = await neo4j.query(
        seg_query, {"vpc_id": vpc_id},
    )
    if results:
        row = results[0]
        info["segment_name"] = row["seg_name"] or ""
        info["segment_arn"] = row.get("seg_arn") or ""
        info["attachment_id"] = row.get("att_id") or ""
    else:
        info["segment_name"] = ""
        info["segment_arn"] = ""
        info["attachment_id"] = ""
    return info


async def resolve_source(
    neo4j,  # noqa: ANN001
    ip: str,
    hint: str,
) -> dict | None:
    """Resolve a source IP to a segment entry point.

    1. If hint provided (e.g. "segment:OnPremShared"),
       use it directly.
    2. Exact IP match in graph → resource exists in VPC.
    3. No exact match → on-prem → VPN attachment inference.
    4. Fall back to VPC CIDR match as last resort.

    Args:
        neo4j: Neo4j client.
        ip: Source IP address.
        hint: Optional hint like "segment:SegmentName"
            or "attachment:att-xxx".

    Returns:
        Dict with segment info, or None.
    """
    if hint:
        return await _resolve_from_hint(neo4j, hint)

    graph_result = await resolve_destination(neo4j, ip)
    if graph_result and graph_result.get("segment_name"):
        if graph_result.get("resource_name"):
            logger.info(
                "resolve_source: exact resource match"
                " ip=%s resource=%s segment=%s",
                ip, graph_result["resource_name"],
                graph_result["segment_name"],
            )
            return graph_result
        logger.info(
            "resolve_source: CIDR-only VPC match for"
            " ip=%s vpc=%s segment=%s — trying"
            " VPN attachment inference instead",
            ip, graph_result.get("vpc_name"),
            graph_result["segment_name"],
        )

    # Infer from VPN/CONNECT attachments (handles on-prem)
    inferred = await _find_vpn_entry_segment(neo4j, ip)
    if inferred:
        if inferred.get("vpn_definitive"):
            return inferred
        if graph_result and graph_result.get("segment_name"):
            logger.info(
                "resolve_source: VPN inference was"
                " fallback only — preferring CIDR"
                " match ip=%s segment=%s over"
                " inferred=%s",
                ip, graph_result["segment_name"],
                inferred["segment_name"],
            )
            return graph_result
        return inferred

    # Fall back to CIDR-matched VPC if inference failed
    if graph_result and graph_result.get("segment_name"):
        logger.info(
            "resolve_source: falling back to VPC"
            " CIDR match ip=%s segment=%s",
            ip, graph_result["segment_name"],
        )
        return graph_result
    return None
