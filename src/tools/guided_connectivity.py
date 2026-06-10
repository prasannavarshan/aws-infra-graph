"""Guided connectivity checker — orchestrator and SG evaluation."""

from __future__ import annotations

import logging

from mcp.server.fastmcp import Context

from src.tools.connectivity import _check_sg_allows, _parse_sg_rules
from src.tools.eks_pod_cidr import (
    is_target_in_vpc,
    lookup_eks_pod_cidr,
    lookup_vpc_cidrs,
    pick_sample_pod_ip,
)
from src.tools.guided_format import (
    _format_account_disambiguation,
    _format_disambiguation,
    _format_guided_verdict,
)
from src.tools.guided_resolve import (
    ResolvedResource,
    _parse_resource_hint,
    _resolve_account,
    _resolve_resource,
)
from src.tools.guided_sgs import (
    _build_sg_refs,
    _get_resource_sgs,
    _replace_stale_sgs,
)
from src.tools.nacl_eval import (
    evaluate_nacl_egress,
    evaluate_nacl_ingress,
    lookup_nacls_for_resource,
)
from src.tools.name_cache import load_account_names, load_vpc_names
from src.tools.sg_connectivity import _find_cidr_rules, _lookup_sample_ip
from src.tools.sg_refresh import refresh_security_groups

logger = logging.getLogger(__name__)

# Re-export for backward compatibility (tests, resource_sgs import from here)
__all__ = [
    "_evaluate_eks_pod_cidr",
    "_format_account_disambiguation",
    "_format_disambiguation",
    "_get_resource_sgs",
    "guided_connectivity_check",
]


def _get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


async def guided_connectivity_check(
    ctx: Context,
    source: str,
    target: str,
    port: int = 443,
    protocol: str = "tcp",
    source_account: str = "",
    target_account: str = "",
    live_refresh: bool = False,
) -> str:
    """Check connectivity using fuzzy resource descriptions.

    PREFERRED TOOL for "can X talk to Y?" questions. Use this first.
    Only fall back to analyze_connectivity (needs exact ARNs) or
    check_sg_connectivity (needs exact SG IDs) when this tool
    returns ambiguous results or you already have ARNs/SG IDs.

    Accepts loose, natural-language-ish inputs and resolves
    everything server-side: account -> resource -> security
    groups -> connectivity verdict. Reduces 10+ tool calls
    to a single call.

    Type hints in source/target strings:
    - "lambda my-api-auth" -> LambdaFunction
    - "prod-api EKS" -> EKSCluster
    - "redis my-cache" -> ElastiCacheCluster
    - "opensearch my-search-domain" -> OpenSearchDomain
    - "ec2 i-0abc123" -> EC2Instance

    If no keyword detected, searches all SG-bearing types.
    For EKS clusters, auto-resolves worker node SGs via
    nodegroup -> EC2 instance -> SG traversal.

    Args:
        source: Fuzzy source description. Include a type
            keyword (lambda, eks, redis, ec2, rds, alb)
            for faster resolution.
        target: Fuzzy target description.
        port: Destination port to check (default 443).
        protocol: Protocol — tcp, udp, icmp (default tcp).
        source_account: Optional account name or ID to
            narrow source search (e.g., "slingcore beta").
        target_account: Optional account name or ID to
            narrow target search.
        live_refresh: If True, fetch fresh SG rules from
            AWS before evaluating. Makes API calls to
            describe_security_groups for the involved SGs.
            Use when graph data may be stale and an
            accurate verdict is critical.

    Returns:
        Connectivity verdict with resolution trail, or
        disambiguation list if input is ambiguous.
    """
    app = _get_app_context(ctx)
    neo4j = app.neo4j

    # Load name caches for enriched output
    acct_names = await load_account_names(neo4j)
    vpc_map = await load_vpc_names(neo4j)

    # 1. Resolve accounts
    src_acct = await _resolve_account(
        neo4j, source_account,
    )
    if isinstance(src_acct, list):
        if not src_acct:
            return (
                f"No account found matching"
                f" '{source_account}'."
            )
        return _format_account_disambiguation(
            source_account, src_acct,
        )

    tgt_acct = await _resolve_account(
        neo4j, target_account,
    )
    if isinstance(tgt_acct, list):
        if not tgt_acct:
            return (
                f"No account found matching"
                f" '{target_account}'."
            )
        return _format_account_disambiguation(
            target_account, tgt_acct,
        )

    # 2. Parse resource hints
    src_hint = _parse_resource_hint(source)
    tgt_hint = _parse_resource_hint(target)

    # 3. Resolve resources
    src_res = await _resolve_resource(
        neo4j, src_hint, src_acct,
    )
    if isinstance(src_res, str):
        return f"Source: {src_res}"
    if isinstance(src_res, list):
        return _format_disambiguation(
            source, src_res, acct_names,
        )

    tgt_res = await _resolve_resource(
        neo4j, tgt_hint, tgt_acct,
    )
    if isinstance(tgt_res, str):
        return f"Target: {tgt_res}"
    if isinstance(tgt_res, list):
        return _format_disambiguation(
            target, tgt_res, acct_names,
        )

    # 4. Extract SGs (check source first to fail fast)
    src_sgs, src_sg_type = await _get_resource_sgs(
        neo4j, src_res.arn, src_res.label,
    )
    if not src_sgs:
        return (
            f"No security groups found for"
            f" {src_res.label} {src_res.name}."
            f" The resource may not be VPC-attached."
        )

    tgt_sgs, tgt_sg_type = await _get_resource_sgs(
        neo4j, tgt_res.arn, tgt_res.label,
    )
    if not tgt_sgs:
        return (
            f"No security groups found for"
            f" {tgt_res.label} {tgt_res.name}."
            f" The resource may not be VPC-attached."
        )

    # 4b. Live refresh SGs from AWS if requested
    refreshed = False
    if live_refresh:
        sg_refs = _build_sg_refs(
            src_sgs, tgt_sgs,
            src_res.region, tgt_res.region,
        )
        fresh = await refresh_security_groups(
            neo4j, sg_refs,
        )
        if fresh:
            src_sgs, tgt_sgs = _replace_stale_sgs(
                src_sgs, tgt_sgs, fresh,
            )
            refreshed = True

    # 5. Fetch NACLs for source and target
    src_nacls = await lookup_nacls_for_resource(
        neo4j, src_res.arn,
    )
    tgt_nacls = await lookup_nacls_for_resource(
        neo4j, tgt_res.arn,
    )

    # 6. Evaluate SG + NACL rules
    return await _evaluate_sg_rules(
        neo4j, source, target,
        src_res, tgt_res,
        src_sgs, tgt_sgs,
        src_sg_type, tgt_sg_type,
        port, protocol,
        acct_names, vpc_map,
        refreshed=refreshed,
        src_nacls=src_nacls,
        tgt_nacls=tgt_nacls,
    )


async def _evaluate_sg_rules(
    neo4j,  # noqa: ANN001
    source_raw: str,
    target_raw: str,
    source: ResolvedResource,
    target: ResolvedResource,
    source_sgs: list[dict[str, str]],
    target_sgs: list[dict[str, str]],
    source_sg_type: str,
    target_sg_type: str,
    port: int,
    protocol: str,
    acct_names: dict[str, str] | None = None,
    vpc_map: dict[str, dict[str, str]] | None = None,
    refreshed: bool = False,
    src_nacls: list[dict[str, str]] | None = None,
    tgt_nacls: list[dict[str, str]] | None = None,
) -> str:
    """Evaluate SG and NACL rules across all SG pairs."""
    src_sg_ids = frozenset(
        sg["group_id"] for sg in source_sgs
    )
    tgt_sg_ids = frozenset(
        sg["group_id"] for sg in target_sgs
    )

    # Lookup sample IPs for CIDR evaluation
    src_sg = source_sgs[0]
    tgt_sg = target_sgs[0]
    source_ip = await _lookup_sample_ip(
        neo4j, src_sg["group_id"],
        vpc_id=src_sg.get("vpc_id", ""),
    )
    target_ip = await _lookup_sample_ip(
        neo4j, tgt_sg["group_id"],
        vpc_id=tgt_sg.get("vpc_id", ""),
    )

    # EKS pod CIDR detection
    pod_cidr_note = ""
    if source.label == "EKSCluster":
        pod_cidr_note, _ = await _evaluate_eks_pod_cidr(
            neo4j, source, target_ip,
            target_sgs, port, protocol, src_sg_ids,
        )

    # Evaluate egress: any source SG allows outbound?
    egress_allowed = False
    egress_reason = "no matching egress rule"
    for sg in source_sgs:
        rules = _parse_sg_rules(sg.get("egress", ""))
        allowed, reason = _check_sg_allows(
            rules, port, protocol,
            remote_ip=target_ip,
            remote_sg_ids=tgt_sg_ids,
        )
        if allowed:
            egress_allowed = True
            egress_reason = reason
            break

    # Evaluate ingress: any target SG allows inbound?
    ingress_allowed = False
    ingress_reason = "no matching ingress rule"
    for sg in target_sgs:
        rules = _parse_sg_rules(sg.get("ingress", ""))
        allowed, reason = _check_sg_allows(
            rules, port, protocol,
            remote_ip=source_ip,
            remote_sg_ids=src_sg_ids,
        )
        if allowed:
            ingress_allowed = True
            ingress_reason = reason
            break

    # CIDR notes for unevaluable rules
    egress_cidr_note = ""
    if not egress_allowed and not target_ip:
        for sg in source_sgs:
            cidrs = _find_cidr_rules(
                sg.get("egress", ""), port, protocol,
            )
            if cidrs:
                egress_cidr_note = (
                    f"NOTE: CIDR rules ({', '.join(cidrs)})"
                    " but no target IP in graph."
                )
                break

    ingress_cidr_note = ""
    if not ingress_allowed and not source_ip:
        for sg in target_sgs:
            cidrs = _find_cidr_rules(
                sg.get("ingress", ""), port, protocol,
            )
            if cidrs:
                ingress_cidr_note = (
                    f"NOTE: CIDR rules ({', '.join(cidrs)})"
                    " but no source IP in graph."
                )
                break

    # NACL evaluation
    nacl_egress_ok, nacl_egress_reason = evaluate_nacl_egress(
        src_nacls or [], port, protocol, target_ip,
    )
    nacl_ingress_ok, nacl_ingress_reason = evaluate_nacl_ingress(
        tgt_nacls or [], port, protocol, source_ip,
    )

    # Cross-VPC check
    src_vpcs = {sg.get("vpc_id") for sg in source_sgs}
    tgt_vpcs = {sg.get("vpc_id") for sg in target_sgs}
    cross_vpc = bool(src_vpcs and tgt_vpcs
                     and not src_vpcs & tgt_vpcs)

    result = _format_guided_verdict(
        source_raw, target_raw,
        source, target,
        source_sgs, target_sgs,
        source_sg_type, target_sg_type,
        port, protocol,
        egress_allowed, egress_reason,
        ingress_allowed, ingress_reason,
        cross_vpc, source_ip, target_ip,
        egress_cidr_note, ingress_cidr_note,
        acct_names, vpc_map,
        pod_cidr_note=pod_cidr_note,
        nacl_egress_ok=nacl_egress_ok,
        nacl_egress_reason=nacl_egress_reason,
        nacl_ingress_ok=nacl_ingress_ok,
        nacl_ingress_reason=nacl_ingress_reason,
    )
    if refreshed:
        result += (
            "\n\n[SG rules refreshed from AWS"
            " before evaluation]"
        )
    return result


async def _evaluate_eks_pod_cidr(
    neo4j,  # noqa: ANN001
    source: ResolvedResource,
    target_ip: str,
    target_sgs: list[dict[str, str]],
    port: int,
    protocol: str,
    src_sg_ids: frozenset[str],
) -> tuple[str, str]:
    """Evaluate EKS pod CIDR impact on connectivity."""
    pod_cidr = await lookup_eks_pod_cidr(
        neo4j, source.arn,
    )
    if not pod_cidr:
        return "", ""

    vpc_cidrs = await lookup_vpc_cidrs(neo4j, source.arn)
    target_in_vpc = is_target_in_vpc(target_ip, vpc_cidrs)

    if not target_in_vpc:
        return (
            f"EKS pod CIDR: {pod_cidr} (not evaluated"
            f" — SNAT to node IP, target outside VPC)",
            "",
        )

    # Target is in-VPC → no SNAT → check pod IP
    pod_ip = pick_sample_pod_ip(pod_cidr)
    if not pod_ip:
        return "", ""

    # Evaluate ingress against pod IP
    pod_ingress_ok = False
    for sg in target_sgs:
        rules = _parse_sg_rules(sg.get("ingress", ""))
        allowed, _reason = _check_sg_allows(
            rules, port, protocol,
            remote_ip=pod_ip,
            remote_sg_ids=src_sg_ids,
        )
        if allowed:
            pod_ingress_ok = True
            break

    if pod_ingress_ok:
        return (
            f"EKS pod CIDR: {pod_cidr}"
            f" — ingress ALLOWED for pod IP {pod_ip}",
            pod_ip,
        )

    tgt_sg_ids = ", ".join(
        sg["group_id"] for sg in target_sgs
    )
    return (
        f"EKS pod CIDR: {pod_cidr}"
        f" — ingress DENIED for pod IP {pod_ip}\n"
        f"      Pods on {pod_cidr} will be blocked"
        f" (no SNAT — target is in-VPC).\n"
        f"      Add inbound rule for {pod_cidr}"
        f" to {tgt_sg_ids}.",
        pod_ip,
    )
