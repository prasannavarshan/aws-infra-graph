"""EKS pod CIDR detection and SNAT logic for connectivity checks."""

from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger(__name__)

# RFC 6598 Shared Address Space — VPC CNI pod CIDRs live here
POD_CIDR_SUPERNET = ipaddress.ip_network("100.64.0.0/10")


async def lookup_eks_pod_cidr(
    neo4j,  # noqa: ANN001
    cluster_arn: str,
) -> str | None:
    """Find the pod CIDR for an EKS cluster from VPC secondary CIDRs.

    Traversal: EKSCluster -[:RUNS_IN]-> Subnet -[:PART_OF]-> VPC.
    Then checks VPC.secondary_cidrs for 100.64.0.0/10 subnets.

    Args:
        neo4j: Neo4jClient instance.
        cluster_arn: EKS cluster ARN.

    Returns:
        Pod CIDR string (e.g., "100.67.0.0/16") or None if
        no secondary CIDR in the 100.64.0.0/10 range found.
    """
    query = """
    MATCH (c:EKSCluster {arn: $arn})
          -[:RUNS_IN]->(:Subnet)
          -[:PART_OF]->(v:VPC)
    RETURN v.secondary_cidrs AS secondary_cidrs
    LIMIT 1
    """
    results = await neo4j.query(query, {"arn": cluster_arn})
    if not results:
        return None

    secondary = results[0].get("secondary_cidrs")
    if not secondary:
        return None

    return _find_pod_cidr(secondary)


def _find_pod_cidr(cidrs: list[str]) -> str | None:
    """Find the first CIDR within 100.64.0.0/10 from a list.

    Args:
        cidrs: List of CIDR strings.

    Returns:
        First matching CIDR or None.
    """
    for cidr_str in cidrs:
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            if net.subnet_of(POD_CIDR_SUPERNET):
                return cidr_str
        except ValueError:
            continue
    return None


async def lookup_vpc_cidrs(
    neo4j,  # noqa: ANN001
    cluster_arn: str,
) -> list[str]:
    """Get all VPC CIDRs (primary + secondary) for an EKS cluster.

    Args:
        neo4j: Neo4jClient instance.
        cluster_arn: EKS cluster ARN.

    Returns:
        List of CIDR strings, e.g.,
        ["10.150.32.0/20", "100.67.0.0/16"].
    """
    query = """
    MATCH (c:EKSCluster {arn: $arn})
          -[:RUNS_IN]->(:Subnet)
          -[:PART_OF]->(v:VPC)
    RETURN v.cidr_block AS primary,
           v.secondary_cidrs AS secondary
    LIMIT 1
    """
    results = await neo4j.query(query, {"arn": cluster_arn})
    if not results:
        return []

    row = results[0]
    cidrs: list[str] = []
    primary = row.get("primary")
    if primary:
        cidrs.append(primary)
    secondary = row.get("secondary")
    if secondary:
        cidrs.extend(secondary)
    return cidrs


def is_target_in_vpc(
    target_ip: str,
    vpc_cidrs: list[str],
) -> bool:
    """Check if a target IP falls within any VPC CIDR.

    Args:
        target_ip: IP address string.
        vpc_cidrs: List of VPC CIDR strings.

    Returns:
        True if the IP is within any CIDR.
    """
    if not target_ip:
        return False
    try:
        addr = ipaddress.ip_address(target_ip)
    except ValueError:
        return False

    for cidr_str in vpc_cidrs:
        try:
            net = ipaddress.ip_network(cidr_str, strict=False)
            if addr in net:
                return True
        except ValueError:
            continue
    return False


def pick_sample_pod_ip(pod_cidr: str) -> str:
    """Pick a representative IP from the pod CIDR.

    Returns the first usable host address in the network.

    Args:
        pod_cidr: CIDR string (e.g., "100.67.0.0/16").

    Returns:
        IP string (e.g., "100.67.0.1"), or empty string
        if the CIDR is invalid.
    """
    try:
        net = ipaddress.ip_network(pod_cidr, strict=False)
        hosts = list(net.hosts())
        return str(hosts[0]) if hosts else ""
    except (ValueError, IndexError):
        return ""
