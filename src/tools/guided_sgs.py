"""SG extraction and refresh helpers for guided connectivity."""

from __future__ import annotations

from src.tools.sg_connectivity import _dedup_by_group_id


async def _get_resource_sgs(
    neo4j,  # noqa: ANN001
    arn: str,
    label: str,
) -> tuple[list[dict[str, str]], str]:
    """Extract security groups for a resolved resource.

    Handles EKS clusters specially: traverses nodegroup ->
    LAUNCHES -> EC2Instance -> HAS_SG for worker node SGs.
    Falls back to cluster's own HAS_SG for control-plane SGs.

    Args:
        neo4j: Neo4jClient instance.
        arn: Resource ARN.
        label: Neo4j node label (e.g., "EKSCluster").

    Returns:
        Tuple of (list of SG dicts, sg_type_label string).
        sg_type_label is "worker node SGs" for EKS clusters.
    """
    if label == "EKSCluster":
        return await _get_eks_sgs(neo4j, arn)

    # Standard: direct HAS_SG edge
    query = """
    MATCH (r:Resource {arn: $arn})-[:HAS_SG]->(sg:SecurityGroup)
    RETURN sg.group_id AS group_id,
           sg.name AS name,
           sg.vpc_id AS vpc_id,
           sg.account_id AS account_id,
           sg.ingress_rules AS ingress,
           sg.egress_rules AS egress
    """
    results = await neo4j.query(query, {"arn": arn})
    sgs = _dedup_by_group_id([dict(r) for r in results])
    return sgs, "SGs"


async def _get_eks_sgs(
    neo4j,  # noqa: ANN001
    cluster_arn: str,
) -> tuple[list[dict[str, str]], str]:
    """Get EKS worker node SGs via nodegroup traversal.

    Traverses: EKSCluster <- PART_OF - EKSNodegroup
               - LAUNCHES -> EC2Instance - HAS_SG -> SG.
    Falls back to cluster's own HAS_SG if no worker SGs.

    Args:
        neo4j: Neo4jClient instance.
        cluster_arn: EKS cluster ARN.

    Returns:
        Tuple of (SG dicts, sg_type_label).
    """
    worker_query = """
    MATCH (cluster:EKSCluster {arn: $arn})
          <-[:PART_OF]-(ng:EKSNodegroup)
          -[:LAUNCHES]->(inst:EC2Instance)
          -[:HAS_SG]->(sg:SecurityGroup)
    RETURN DISTINCT sg.group_id AS group_id,
           sg.name AS name,
           sg.vpc_id AS vpc_id,
           sg.account_id AS account_id,
           sg.ingress_rules AS ingress,
           sg.egress_rules AS egress
    """
    results = await neo4j.query(
        worker_query, {"arn": cluster_arn},
    )
    if results:
        sgs = _dedup_by_group_id([dict(r) for r in results])
        return sgs, "worker node SGs"

    # Fallback: cluster's own HAS_SG (control-plane SGs)
    ctrl_query = """
    MATCH (cluster:EKSCluster {arn: $arn})
          -[:HAS_SG]->(sg:SecurityGroup)
    RETURN sg.group_id AS group_id,
           sg.name AS name,
           sg.vpc_id AS vpc_id,
           sg.account_id AS account_id,
           sg.ingress_rules AS ingress,
           sg.egress_rules AS egress
    """
    results = await neo4j.query(
        ctrl_query, {"arn": cluster_arn},
    )
    sgs = _dedup_by_group_id([dict(r) for r in results])
    return sgs, "control-plane SGs (no worker nodes found)"


def _build_sg_refs(
    src_sgs: list[dict[str, str]],
    tgt_sgs: list[dict[str, str]],
    src_region: str,
    tgt_region: str,
) -> list[dict[str, str]]:
    """Build sg_refs from SG dicts for refresh_security_groups.

    Deduplicates by group_id to avoid fetching the same SG twice.
    Uses the resolved resource's region since SG query results
    don't include region.
    """
    seen: set[str] = set()
    refs: list[dict[str, str]] = []
    for sg in src_sgs:
        gid = sg["group_id"]
        if gid not in seen:
            seen.add(gid)
            refs.append({
                "group_id": gid,
                "account_id": sg.get("account_id", ""),
                "region": src_region,
            })
    for sg in tgt_sgs:
        gid = sg["group_id"]
        if gid not in seen:
            seen.add(gid)
            refs.append({
                "group_id": gid,
                "account_id": sg.get("account_id", ""),
                "region": tgt_region,
            })
    return refs


def _replace_stale_sgs(
    src_sgs: list[dict[str, str]],
    tgt_sgs: list[dict[str, str]],
    fresh: list[dict[str, str]],
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Replace stale SG dicts with fresh ones by group_id.

    Returns updated (src_sgs, tgt_sgs).
    """
    fresh_map = {sg["group_id"]: sg for sg in fresh}
    new_src = [
        fresh_map.get(sg["group_id"], sg) for sg in src_sgs
    ]
    new_tgt = [
        fresh_map.get(sg["group_id"], sg) for sg in tgt_sgs
    ]
    return new_src, new_tgt
