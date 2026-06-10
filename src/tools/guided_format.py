"""Formatting helpers for guided connectivity verdicts."""

from __future__ import annotations

from src.tools.guided_resolve import ResolvedResource
from src.tools.name_cache import enrich_account, enrich_vpc


def _format_disambiguation(
    raw_input: str,
    candidates: list[dict[str, str]],
    acct_names: dict[str, str] | None = None,
) -> str:
    """Format disambiguation candidates for the user."""
    names = acct_names or {}
    lines = [f"Multiple resources match '{raw_input}':\n"]
    for i, c in enumerate(candidates[:10], 1):
        acct = enrich_account(c["account_id"], names)
        lines.append(
            f"  {i}. {c['name']} ({c['label']})"
            f" — {acct} | {c['region']}"
        )
    if len(candidates) > 10:
        lines.append(f"  ... and {len(candidates) - 10} more")
    lines.append(
        "\nRe-run with a more specific name"
        " or add source_account / target_account."
    )
    return "\n".join(lines)


def _format_account_disambiguation(
    name_hint: str,
    candidates: list[dict[str, str]],
) -> str:
    """Format account disambiguation for the user."""
    lines = [f"Multiple accounts match '{name_hint}':\n"]
    for c in candidates[:10]:
        lines.append(f"  {c['id']} — {c['name']}")
    lines.append(
        "\nRe-run with a more specific account name"
        " or use the 12-digit account ID."
    )
    return "\n".join(lines)


def _format_resolution(
    label: str,
    resource: ResolvedResource,
    sgs: list[dict[str, str]],
    sg_type: str,
    acct_names: dict[str, str] | None = None,
    vpc_map: dict[str, dict[str, str]] | None = None,
) -> list[str]:
    """Format the resolution trail for one side."""
    names = acct_names or {}
    acct_label = enrich_account(resource.account_id, names)
    lines = [
        f"  {label}: {resource.label} {resource.name}",
        f"    Account: {acct_label}"
        f" | Region: {resource.region}",
    ]
    if sgs:
        sg_strs = [
            f"{sg['group_id']} ({sg['name']})" for sg in sgs
        ]
        lines.append(
            f"    {sg_type}: {', '.join(sg_strs)}"
        )
        # Show VPC with owner info
        vpc_ids = {sg.get("vpc_id", "") for sg in sgs}
        for vid in vpc_ids:
            if vid and vpc_map:
                vpc_label = enrich_vpc(
                    vid, vpc_map, names,
                )
                lines.append(f"    VPC: {vpc_label}")
            elif vid:
                lines.append(f"    VPC: {vid}")
    else:
        lines.append(f"    {sg_type}: none found")
    return lines


def _format_guided_verdict(
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
    egress_allowed: bool,
    egress_reason: str,
    ingress_allowed: bool,
    ingress_reason: str,
    cross_vpc: bool,
    source_ip: str,
    target_ip: str,
    egress_cidr_note: str,
    ingress_cidr_note: str,
    acct_names: dict[str, str] | None = None,
    vpc_map: dict[str, dict[str, str]] | None = None,
    pod_cidr_note: str = "",
    nacl_egress_ok: bool = True,
    nacl_egress_reason: str = "",
    nacl_ingress_ok: bool = True,
    nacl_ingress_reason: str = "",
) -> str:
    """Format the full guided connectivity verdict."""
    proto = protocol.upper()
    lines = [
        f"Guided Connectivity Check:"
        f" {source.name} -> {target.name}"
        f" ({proto}/{port})\n",
        "Resolution:",
    ]
    lines.extend(_format_resolution(
        "Source", source, source_sgs, source_sg_type,
        acct_names, vpc_map,
    ))
    if source_ip:
        lines.append(f"    Sample IP: {source_ip}")
    lines.append("")
    lines.extend(_format_resolution(
        "Target", target, target_sgs, target_sg_type,
        acct_names, vpc_map,
    ))
    if target_ip:
        lines.append(f"    Sample IP: {target_ip}")

    lines.append("")
    lines.append("SG Analysis:")

    src_sg_ids = ", ".join(
        sg["group_id"] for sg in source_sgs
    ) or "none"
    tgt_sg_ids = ", ".join(
        sg["group_id"] for sg in target_sgs
    ) or "none"

    lines.append(
        f"  Egress ({src_sg_ids} -> {tgt_sg_ids}):"
        f" {'ALLOWED' if egress_allowed else 'DENIED'}"
        f" — {egress_reason}"
    )
    if egress_cidr_note:
        lines.append(f"    {egress_cidr_note}")

    lines.append(
        f"  Ingress ({tgt_sg_ids} <- {src_sg_ids}):"
        f" {'ALLOWED' if ingress_allowed else 'DENIED'}"
        f" — {ingress_reason}"
    )
    if ingress_cidr_note:
        lines.append(f"    {ingress_cidr_note}")

    if pod_cidr_note:
        lines.append(f"    {pod_cidr_note}")

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

    if cross_vpc:
        lines.append("")
        lines.append(
            "WARNING: Source and target are in different"
            " VPCs. SG-to-SG references do NOT work"
            " cross-VPC."
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
            f"  Traffic on {proto}/{port} is permitted"
            f" by {layers}."
        )
    else:
        lines.append("Verdict: DENIED")
        if not egress_allowed:
            lines.append(f"  SG Egress: {egress_reason}")
        if not ingress_allowed:
            lines.append(f"  SG Ingress: {ingress_reason}")
        if not nacl_egress_ok:
            lines.append(
                f"  NACL Egress: {nacl_egress_reason}"
            )
        if not nacl_ingress_ok:
            lines.append(
                f"  NACL Ingress: {nacl_ingress_reason}"
            )

    return "\n".join(lines)
