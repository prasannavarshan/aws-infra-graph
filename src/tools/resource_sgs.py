"""Get all security groups for a resource — single-call MCP tool."""

from __future__ import annotations

import logging
import re

from mcp.server.fastmcp import Context

from src.tools.guided_format import (
    _format_account_disambiguation,
    _format_disambiguation,
)
from src.tools.guided_resolve import (
    _parse_resource_hint,
    _resolve_account,
    _resolve_resource,
)
from src.tools.guided_sgs import _get_resource_sgs
from src.tools.name_cache import (
    enrich_account,
    enrich_vpc,
    load_account_names,
    load_sg_names,
    load_vpc_names,
)
from src.tools.sg_resolve import _dedup_by_group_id

logger = logging.getLogger(__name__)


def _get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


# --- Formatting ---


def _enrich_sg_refs_in_rule(
    rule: str,
    sg_names: dict[str, str],
) -> str:
    """Replace sg:sg-xxx with sg:sg-xxx (name) in a rule string."""
    def _replace(m: re.Match) -> str:
        sg_id = m.group(1)
        name = sg_names.get(sg_id, "")
        if name:
            return f"sg:{sg_id} ({name})"
        return f"sg:{sg_id}"
    return re.sub(r"sg:(sg-\w+)", _replace, rule)


def _format_rules(
    rules_str: str,
    direction: str,
    sg_names: dict[str, str] | None = None,
) -> list[str]:
    """Format compact rule string into individual lines.

    Args:
        rules_str: Compact rules like
            "tcp:443 from 0.0.0.0/0; all:all from sg:sg-xxx".
        direction: "from" for ingress, "to" for egress.
        sg_names: Optional SG name map for enrichment.

    Returns:
        List of formatted rule lines, or ["(none)"] if empty.
    """
    if not rules_str or not rules_str.strip():
        return ["(none)"]
    rules = [r.strip() for r in rules_str.split(";") if r.strip()]
    if not rules:
        return ["(none)"]
    lines: list[str] = []
    for rule in rules:
        if sg_names:
            rule = _enrich_sg_refs_in_rule(rule, sg_names)
        lines.append(f"  {rule}")
    return lines


def _format_sg_details(
    sg: dict,
    index: int,
    acct_names: dict[str, str],
    vpc_map: dict[str, dict[str, str]],
    sg_names: dict[str, str] | None = None,
) -> list[str]:
    """Format one security group with full rules.

    Args:
        sg: SG dict with group_id, name, vpc_id, ingress, egress.
        index: 1-based display index.
        acct_names: Account name map for enrichment.
        vpc_map: VPC name map for enrichment.
        sg_names: Optional SG name map for enriching sg: refs.

    Returns:
        List of formatted lines for this SG.
    """
    gid = sg.get("group_id", "unknown")
    name = sg.get("name", "unnamed")
    vpc_id = sg.get("vpc_id", "")

    lines = [f"  {index}. {gid} — {name}"]

    if vpc_id:
        vpc_label = enrich_vpc(vpc_id, vpc_map, acct_names)
        lines.append(f"     VPC: {vpc_label}")

    sg_acct = sg.get("account_id", "")
    if sg_acct:
        lines.append(
            f"     Account: {enrich_account(sg_acct, acct_names)}"
        )

    # Ingress rules
    lines.append("")
    lines.append("     Ingress:")
    for rule_line in _format_rules(
        sg.get("ingress", ""), "from", sg_names,
    ):
        lines.append(f"       {rule_line}")

    # Egress rules
    lines.append("")
    lines.append("     Egress:")
    for rule_line in _format_rules(
        sg.get("egress", ""), "to", sg_names,
    ):
        lines.append(f"       {rule_line}")

    return lines


def _format_resource_sgs_output(
    resource,  # noqa: ANN001 — ResolvedResource
    sgs: list[dict],
    sg_source: str,
    acct_names: dict[str, str],
    vpc_map: dict[str, dict[str, str]],
    sg_names: dict[str, str] | None = None,
) -> str:
    """Format the full output for resource security groups.

    Args:
        resource: ResolvedResource with name, label, etc.
        sgs: List of SG dicts with rules.
        sg_source: How SGs were found (e.g. "worker node SGs").
        acct_names: Account name map.
        vpc_map: VPC name map.
        sg_names: Optional SG name map for enriching sg: refs.

    Returns:
        Formatted multi-line string.
    """
    acct_label = enrich_account(resource.account_id, acct_names)
    lines = [
        f"Security Groups for {resource.label}"
        f" {resource.name}\n",
        f"Resource: {resource.name}",
        f"  Type: {resource.label}",
        f"  Account: {acct_label}",
        f"  Region: {resource.region}",
        f"  SG source: {sg_source}",
        f"\nFound {len(sgs)} security group(s):\n",
    ]

    for i, sg in enumerate(sgs, 1):
        lines.extend(
            _format_sg_details(
                sg, i, acct_names, vpc_map, sg_names,
            ),
        )
        if i < len(sgs):
            lines.append("")

    return "\n".join(lines)


# --- Deep SG Expansion ---


def _extract_sg_references(
    sgs: list[dict],
) -> set[str]:
    """Extract referenced SG IDs from rule strings.

    Scans ingress and egress rules for sg:sg-xxx references,
    excluding self-references (SGs referencing themselves).

    Returns:
        Set of sg-xxx IDs referenced by the given SGs.
    """
    own_ids = {sg.get("group_id", "") for sg in sgs}
    refs: set[str] = set()
    for sg in sgs:
        for direction in ("ingress", "egress"):
            rules_str = sg.get(direction, "")
            for m in re.finditer(r"sg:(sg-\w+)", rules_str):
                sg_id = m.group(1)
                if sg_id not in own_ids:
                    refs.add(sg_id)
    return refs


async def _fetch_referenced_sgs(
    neo4j,  # noqa: ANN001
    sg_ids: set[str],
) -> list[dict]:
    """Fetch SG details from the graph for given group IDs.

    Args:
        neo4j: Neo4jClient instance.
        sg_ids: Set of SG group IDs to fetch.

    Returns:
        List of SG dicts with group_id, name, vpc_id, etc.
    """
    if not sg_ids:
        return []
    query = """
    MATCH (sg:SecurityGroup)
    WHERE sg.group_id IN $ids
    RETURN sg.group_id AS group_id,
           sg.name AS name,
           sg.vpc_id AS vpc_id,
           sg.account_id AS account_id,
           sg.ingress_rules AS ingress,
           sg.egress_rules AS egress
    """
    return await neo4j.query(query, {"ids": list(sg_ids)})


def _format_referenced_section(
    ref_sgs: list[dict],
    acct_names: dict[str, str],
    vpc_map: dict[str, dict[str, str]],
    sg_names: dict[str, str] | None = None,
) -> str:
    """Format the 'Referenced Security Groups' expansion section.

    Args:
        ref_sgs: List of referenced SG dicts.
        acct_names: Account name map.
        vpc_map: VPC name map.
        sg_names: Optional SG name map.

    Returns:
        Formatted multi-line string for the expansion section.
    """
    lines = [
        f"\n--- Referenced Security Groups"
        f" ({len(ref_sgs)}) ---\n",
    ]
    for i, sg in enumerate(ref_sgs, 1):
        lines.extend(
            _format_sg_details(
                sg, i, acct_names, vpc_map, sg_names,
            ),
        )
        if i < len(ref_sgs):
            lines.append("")
    return "\n".join(lines)


# --- Orchestrator ---


async def get_resource_security_groups(
    ctx: Context,
    resource_name: str,
    resource_type: str = "",
    account_id: str = "",
    expand_references: bool = False,
) -> str:
    """Get all security groups for a resource with full rules.

    Use this to LIST/INSPECT what SGs are attached to a resource and
    see their ingress/egress rules. This does NOT check if traffic
    can flow between two resources — use guided_connectivity_check
    for that.

    Resolves a resource by fuzzy name and returns every SG
    attached to it, including ingress and egress rules stored
    in the graph. For EKS clusters, automatically traverses
    nodegroup -> EC2 instance -> SG to find worker node SGs.

    Zero AWS API calls — everything comes from the graph.

    Type hints in resource_name:
    - "lambda my-api-auth" -> LambdaFunction
    - "eks prod-cluster" -> EKSCluster
    - "redis my-cache" -> ElastiCacheCluster
    - "opensearch my-search-domain" -> OpenSearchDomain
    - "ec2 i-0abc123" -> EC2Instance

    Or pass resource_type separately to narrow the search.

    Supported resource types (all types with SG edges):
    EC2Instance, EKSCluster, LambdaFunction, RDSInstance,
    ElastiCacheCluster, OpenSearchDomain, LoadBalancer,
    VPCEndpoint, EKSNodegroup.

    Args:
        resource_name: Fuzzy resource name. Can include a type
            keyword (lambda, eks, redis, ec2, rds, alb,
            opensearch) for faster resolution.
        resource_type: Optional type keyword to narrow search
            (eks, lambda, ec2, redis, rds, alb, opensearch).
            If provided,
            prepended to resource_name for hint parsing.
        account_id: Optional AWS account ID or fuzzy account
            name to narrow search (e.g., "workload-beta",
            "123456789012").
        expand_references: If True, also show the full rules
            of security groups referenced in sg:sg-xxx rules
            (one level deep). Default False.

    Returns:
        Formatted list of security groups with full ingress
        and egress rules, or disambiguation list if input
        is ambiguous.
    """
    app = _get_app_context(ctx)
    neo4j = app.neo4j

    # Load name caches
    acct_names = await load_account_names(neo4j)
    vpc_map = await load_vpc_names(neo4j)
    sg_names = await load_sg_names(neo4j)

    # Resolve account if provided
    if account_id:
        resolved_acct = await _resolve_account(
            neo4j, account_id,
        )
        if isinstance(resolved_acct, list):
            if not resolved_acct:
                return (
                    f"No account found matching"
                    f" '{account_id}'."
                )
            return _format_account_disambiguation(
                account_id, resolved_acct,
            )
        acct_filter = resolved_acct
    else:
        acct_filter = ""

    # Build hint: prepend resource_type if provided
    raw_input = resource_name
    if resource_type:
        raw_input = f"{resource_type} {resource_name}"
    hint = _parse_resource_hint(raw_input)

    # Resolve resource
    resolved = await _resolve_resource(
        neo4j, hint, acct_filter,
    )
    if isinstance(resolved, str):
        return resolved
    if isinstance(resolved, list):
        return _format_disambiguation(
            resource_name, resolved, acct_names,
        )

    # Extract SGs
    sgs, sg_source = await _get_resource_sgs(
        neo4j, resolved.arn, resolved.label,
    )
    sgs = _dedup_by_group_id(sgs)

    if not sgs:
        return (
            f"No security groups found for"
            f" {resolved.label} {resolved.name}."
            f" The resource may not be VPC-attached"
            f" or SG edges are missing from the graph."
        )

    output = _format_resource_sgs_output(
        resolved, sgs, sg_source,
        acct_names, vpc_map, sg_names,
    )

    if expand_references:
        refs = _extract_sg_references(sgs)
        if refs:
            ref_sgs = await _fetch_referenced_sgs(neo4j, refs)
            ref_sgs = _dedup_by_group_id(ref_sgs)
            if ref_sgs:
                output += _format_referenced_section(
                    ref_sgs, acct_names, vpc_map, sg_names,
                )

    return output
