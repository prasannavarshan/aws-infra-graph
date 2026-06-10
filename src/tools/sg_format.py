"""Formatting helpers for SG connectivity verdicts."""

from __future__ import annotations

from src.tools.name_cache import enrich_account, enrich_vpc


def _format_sg_ambiguous(
    identifier: str, results: list[dict],
) -> str:
    """Format ambiguous SG match error."""
    candidates = [
        f"  - {r['name']} ({r['group_id']})"
        f" in {r['account_id']}"
        for r in results[:10]
    ]
    suffix = ""
    if len(results) > 10:
        suffix = f"\n  ... and {len(results) - 10} more"
    return (
        f"Multiple security groups match '{identifier}'."
        f" Please narrow your search:\n"
        + "\n".join(candidates)
        + suffix
    )


def _format_verdict(
    sources: list[dict],
    targets: list[dict],
    port: int,
    protocol: str,
    egress_allowed: bool,
    egress_reason: str,
    ingress_allowed: bool,
    ingress_reason: str,
    cross_vpc: bool,
    egress_cidr_note: str = "",
    ingress_cidr_note: str = "",
    source_ip: str = "",
    target_ip: str = "",
    acct_names: dict[str, str] | None = None,
    vpc_map: dict[str, dict[str, str]] | None = None,
    egress_sg_name: str = "",
    ingress_sg_name: str = "",
    nacl_egress_ok: bool = True,
    nacl_egress_reason: str = "",
    nacl_ingress_ok: bool = True,
    nacl_ingress_reason: str = "",
) -> str:
    """Format the connectivity check output.

    Supports both single-SG and multi-SG (union) display.
    When a single source/target is provided, output is identical
    to the legacy single-SG format. When multiple SGs are
    provided, all are listed and the allowing SG is marked.

    Args:
        sources: List of source SG dicts (group_id, name, etc.).
        targets: List of target SG dicts.
        port: Destination port checked.
        protocol: Protocol checked.
        egress_allowed: Whether egress passed union evaluation.
        egress_reason: Reason string from the allowing/denying SG.
        ingress_allowed: Whether ingress passed union evaluation.
        ingress_reason: Reason string from the allowing/denying SG.
        cross_vpc: True if source and target are in different VPCs.
        egress_cidr_note: Optional note about unevaluated CIDRs.
        ingress_cidr_note: Optional note about unevaluated CIDRs.
        source_ip: Sample IP from source side.
        target_ip: Sample IP from target side.
        acct_names: Account ID → friendly name map.
        vpc_map: VPC ID → {name, account_id} map.
        egress_sg_name: Name of the SG that allowed egress
            (empty if denied or single SG).
        ingress_sg_name: Name of the SG that allowed ingress
            (empty if denied or single SG).
    """
    proto_upper = protocol.upper()
    names = acct_names or {}
    vpcs = vpc_map or {}
    multi_src = len(sources) > 1
    multi_tgt = len(targets) > 1

    # Use first SG for header and IP labels
    source = sources[0]
    target = targets[0]

    src_ip_label = (
        f" (sample IP: {source_ip})" if source_ip else ""
    )
    tgt_ip_label = (
        f" (sample IP: {target_ip})" if target_ip else ""
    )

    # Header
    src_header = (
        f"{len(sources)} SGs (union)" if multi_src
        else f"{source['name']}"
    )
    tgt_header = (
        f"{len(targets)} SGs (union)" if multi_tgt
        else f"{target['name']}"
    )
    lines = [
        f"SG Connectivity: {src_header}"
        f" -> {tgt_header}"
        f" ({proto_upper}/{port})\n",
    ]

    # Source SG listing
    if multi_src:
        lines.append("Source SGs:")
        for s in sources:
            acct = enrich_account(s["account_id"], names)
            vpc = enrich_vpc(
                s.get("vpc_id", ""), vpcs, names,
            )
            lines.append(
                f"  - {s['name']} ({s['group_id']})"
                f" in {vpc} [{acct}]"
            )
        if source_ip:
            lines.append(f"  Sample IP: {source_ip}")
    else:
        src_acct = enrich_account(source["account_id"], names)
        src_vpc = enrich_vpc(
            source.get("vpc_id", ""), vpcs, names,
        )
        lines.append(
            f"Source: {source['name']} ({source['group_id']})"
            f" in {src_vpc}"
            f" [{src_acct}]{src_ip_label}"
        )

    # Target SG listing
    if multi_tgt:
        lines.append("Target SGs:")
        for t in targets:
            acct = enrich_account(t["account_id"], names)
            vpc = enrich_vpc(
                t.get("vpc_id", ""), vpcs, names,
            )
            lines.append(
                f"  - {t['name']} ({t['group_id']})"
                f" in {vpc} [{acct}]"
            )
        if target_ip:
            lines.append(f"  Sample IP: {target_ip}")
    else:
        tgt_acct = enrich_account(target["account_id"], names)
        tgt_vpc = enrich_vpc(
            target.get("vpc_id", ""), vpcs, names,
        )
        lines.append(
            f"Target: {target['name']} ({target['group_id']})"
            f" in {tgt_vpc}"
            f" [{tgt_acct}]{tgt_ip_label}"
        )

    # Egress evaluation
    lines.append("")
    lines.append("Egress (source -> target):")
    if multi_src and egress_allowed and egress_sg_name:
        lines.append(
            f"  {egress_sg_name}:"
            f" ALLOWED -- {egress_reason}"
        )
    elif multi_src and not egress_allowed:
        lines.append(
            f"  All {len(sources)} SGs: DENIED"
            f" -- {egress_reason}"
        )
    else:
        lines.append(
            f"  {source['group_id']}:"
            f" {'ALLOWED' if egress_allowed else 'DENIED'}"
            f" -- {egress_reason}"
        )
    if egress_cidr_note:
        lines.append(f"  {egress_cidr_note}")

    # Ingress evaluation
    lines.append("")
    lines.append("Ingress (target <- source):")
    if multi_tgt and ingress_allowed and ingress_sg_name:
        lines.append(
            f"  {ingress_sg_name}:"
            f" ALLOWED -- {ingress_reason}"
        )
    elif multi_tgt and not ingress_allowed:
        lines.append(
            f"  All {len(targets)} SGs: DENIED"
            f" -- {ingress_reason}"
        )
    else:
        lines.append(
            f"  {target['group_id']}:"
            f" {'ALLOWED' if ingress_allowed else 'DENIED'}"
            f" -- {ingress_reason}"
        )
    if ingress_cidr_note:
        lines.append(f"  {ingress_cidr_note}")

    # NACL analysis
    has_nacls = nacl_egress_reason or nacl_ingress_reason
    if has_nacls:
        lines.append("")
        lines.append("NACL Analysis:")
        if nacl_egress_reason:
            status = "ALLOWED" if nacl_egress_ok else "DENIED"
            lines.append(
                f"  Source egress: {status}"
                f" — {nacl_egress_reason}"
            )
        if nacl_ingress_reason:
            status = (
                "ALLOWED" if nacl_ingress_ok else "DENIED"
            )
            lines.append(
                f"  Target ingress: {status}"
                f" — {nacl_ingress_reason}"
            )

    # Cross-VPC warning
    if cross_vpc:
        lines.append("")
        lines.append(
            "WARNING: Source and target are in different VPCs."
            " SG-to-SG references do NOT work cross-VPC."
            " Verify routing and CIDR-based rules instead."
        )

    # Overall verdict: SGs AND NACLs must both allow
    sg_ok = egress_allowed and ingress_allowed
    nacl_ok = nacl_egress_ok and nacl_ingress_ok
    lines.append("")
    if sg_ok and nacl_ok:
        lines.append("Verdict: ALLOWED")
        layers = "SG rules"
        if has_nacls:
            layers = "SG and NACL rules"
        lines.append(
            f"  Traffic on {proto_upper}/{port} is permitted"
            f" by {layers}."
        )
    else:
        lines.append("Verdict: DENIED")
        reasons = []
        if not egress_allowed:
            label = (
                f"All {len(sources)} source SGs"
                if multi_src else source["group_id"]
            )
            reasons.append(
                f"  SG Egress on {label}: {egress_reason}"
            )
        if not ingress_allowed:
            label = (
                f"All {len(targets)} target SGs"
                if multi_tgt else target["group_id"]
            )
            reasons.append(
                f"  SG Ingress on {label}: {ingress_reason}"
            )
        if not nacl_egress_ok:
            reasons.append(
                f"  NACL Egress: {nacl_egress_reason}"
            )
        if not nacl_ingress_ok:
            reasons.append(
                f"  NACL Ingress: {nacl_ingress_reason}"
            )
        lines.extend(reasons)

    return "\n".join(lines)
