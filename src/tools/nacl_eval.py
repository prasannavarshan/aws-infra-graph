"""NACL lookup and evaluation for connectivity tools."""

from __future__ import annotations

import logging

from src.tools.connectivity import _check_nacl_allows, _parse_nacl_rules

logger = logging.getLogger(__name__)


async def lookup_nacls_for_resource(
    neo4j,  # noqa: ANN001
    arn: str,
) -> list[dict[str, str]]:
    """Fetch NACLs for a resource via its subnet.

    Traverses: resource -[:RUNS_IN]-> Subnet -[:HAS_NACL]-> NetworkACL.

    Args:
        neo4j: Neo4jClient instance.
        arn: Resource ARN.

    Returns:
        List of NACL dicts with nacl_id, name, ingress, egress.
    """
    query = """
    MATCH (r:Resource {arn: $arn})-[:RUNS_IN]->(sub:Subnet)
          -[:HAS_NACL]->(nacl:NetworkACL)
    RETURN DISTINCT nacl.network_acl_id AS nacl_id,
           nacl.name AS name,
           nacl.ingress_rules AS ingress,
           nacl.egress_rules AS egress
    """
    results = await neo4j.query(query, {"arn": arn})
    return [dict(r) for r in results if r.get("nacl_id")]


async def lookup_nacls_for_sg(
    neo4j,  # noqa: ANN001
    group_id: str,
) -> list[dict[str, str]]:
    """Fetch NACLs for subnets where resources using this SG reside.

    Traverses: resource -[:HAS_SG]-> SG, resource -[:RUNS_IN]->
    Subnet -[:HAS_NACL]-> NetworkACL.

    Args:
        neo4j: Neo4jClient instance.
        group_id: Security group ID.

    Returns:
        List of NACL dicts with nacl_id, name, ingress, egress.
    """
    query = """
    MATCH (n)-[:HAS_SG]->(:SecurityGroup {group_id: $gid}),
          (n)-[:RUNS_IN]->(sub:Subnet)
          -[:HAS_NACL]->(nacl:NetworkACL)
    RETURN DISTINCT nacl.network_acl_id AS nacl_id,
           nacl.name AS name,
           nacl.ingress_rules AS ingress,
           nacl.egress_rules AS egress
    """
    results = await neo4j.query(query, {"gid": group_id})
    return [dict(r) for r in results if r.get("nacl_id")]


def evaluate_nacl_egress(
    nacls: list[dict[str, str]],
    port: int,
    protocol: str,
    remote_ip: str,
) -> tuple[bool, str]:
    """Evaluate NACL egress rules.

    NACLs are stateless — egress must be explicitly allowed.
    If multiple NACLs, ALL must allow (resource may span subnets).

    Returns:
        (allowed, reason) tuple.
    """
    if not nacls:
        return True, "no NACL (default allow)"

    for nacl in nacls:
        rules = _parse_nacl_rules(nacl.get("egress", ""))
        allowed, reason = _check_nacl_allows(
            rules, port, protocol, remote_ip,
        )
        if not allowed:
            nacl_id = nacl.get("nacl_id", "unknown")
            return False, f"NACL {nacl_id}: {reason}"

    nacl_id = nacls[0].get("nacl_id", "unknown")
    rules = _parse_nacl_rules(nacls[0].get("egress", ""))
    _, reason = _check_nacl_allows(
        rules, port, protocol, remote_ip,
    )
    return True, f"NACL {nacl_id}: {reason}"


def evaluate_nacl_ingress(
    nacls: list[dict[str, str]],
    port: int,
    protocol: str,
    remote_ip: str,
) -> tuple[bool, str]:
    """Evaluate NACL ingress rules.

    NACLs are stateless — ingress must be explicitly allowed.
    If multiple NACLs, ALL must allow (resource may span subnets).

    Returns:
        (allowed, reason) tuple.
    """
    if not nacls:
        return True, "no NACL (default allow)"

    for nacl in nacls:
        rules = _parse_nacl_rules(nacl.get("ingress", ""))
        allowed, reason = _check_nacl_allows(
            rules, port, protocol, remote_ip,
        )
        if not allowed:
            nacl_id = nacl.get("nacl_id", "unknown")
            return False, f"NACL {nacl_id}: {reason}"

    nacl_id = nacls[0].get("nacl_id", "unknown")
    rules = _parse_nacl_rules(nacls[0].get("ingress", ""))
    _, reason = _check_nacl_allows(
        rules, port, protocol, remote_ip,
    )
    return True, f"NACL {nacl_id}: {reason}"
