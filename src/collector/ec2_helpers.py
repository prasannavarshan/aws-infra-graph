"""EC2 helper functions — tag parsing, rule summarization."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

logger = structlog.get_logger()


def _parse_tags(tag_list: list[dict] | None) -> dict[str, str]:
    """Convert AWS tag list to a flat dict."""
    if not tag_list:
        return {}
    return {t["Key"]: t["Value"] for t in tag_list}


def _tag_name(tags: dict[str, str]) -> str:
    """Extract the Name tag, falling back to empty string."""
    return tags.get("Name", "")


_PROTO_MAP = {"-1": "all", "6": "tcp", "17": "udp", "1": "icmp"}


def _resolve_prefix_list(
    ec2_client, pl_id: str,  # noqa: ANN001
) -> list[str]:
    """Resolve a managed prefix list to its CIDR entries.

    Args:
        ec2_client: boto3 EC2 client.
        pl_id: Prefix list ID (e.g. pl-xxx).

    Returns:
        List of CIDR strings, or empty list on error.
    """
    try:
        cidrs: list[str] = []
        paginator = ec2_client.get_paginator(
            "get_managed_prefix_list_entries",
        )
        for page in paginator.paginate(PrefixListId=pl_id):
            for entry in page.get("Entries", []):
                cidr = entry.get("Cidr", "")
                if cidr:
                    cidrs.append(cidr)
        return cidrs
    except ClientError as e:
        logger.warning(
            "prefix_list_resolve_failed",
            prefix_list_id=pl_id,
            error_code=e.response["Error"]["Code"],
        )
        return []


def summarize_rules(
    permissions: list[dict],
    ec2_client=None,  # noqa: ANN001
) -> str:
    """Summarize SG rules into a readable string.

    Includes CIDR-based, SG-based, and prefix-list-based rules.

    Args:
        permissions: List of IpPermission dicts from AWS API.
        ec2_client: Optional boto3 EC2 client for resolving
            prefix lists to CIDRs.
    """
    parts: list[str] = []
    for rule in permissions:
        proto = rule.get("IpProtocol", "-1")
        if proto == "-1":
            proto = "all"
        from_port = rule.get("FromPort", -1)
        to_port = rule.get("ToPort", -1)
        port_str = "all" if from_port == -1 else (
            str(from_port) if from_port == to_port
            else f"{from_port}-{to_port}"
        )

        sources: list[str] = []
        for r in rule.get("IpRanges", []):
            cidr = r.get("CidrIp", "")
            desc = r.get("Description", "")
            sources.append(
                f"{cidr}({desc})" if desc else cidr
            )
        for r in rule.get("Ipv6Ranges", []):
            cidr = r.get("CidrIpv6", "")
            desc = r.get("Description", "")
            sources.append(
                f"{cidr}({desc})" if desc else cidr
            )
        for pair in rule.get("UserIdGroupPairs", []):
            sg_id = pair.get("GroupId", "")
            sources.append(f"sg:{sg_id}")

        for pl in rule.get("PrefixListIds", []):
            pl_id = pl.get("PrefixListId", "")
            if not pl_id:
                continue
            desc = pl.get("Description", "")
            cidrs = (
                _resolve_prefix_list(ec2_client, pl_id)
                if ec2_client else []
            )
            if cidrs:
                cidr_str = ",".join(cidrs)
                tag = f"pl:{pl_id}[{cidr_str}]"
            else:
                tag = f"pl:{pl_id}"
            sources.append(
                f"{tag}({desc})" if desc else tag
            )

        if sources:
            parts.append(
                f"{proto}:{port_str} from {','.join(sources)}"
            )

    return "; ".join(parts) if parts else "none"


def _summarize_nacl_entries(
    entries: list[dict], *, egress: bool,
) -> str:
    """Summarize NACL entries into a readable string.

    Args:
        entries: NACL entry list from AWS API.
        egress: True for egress rules, False for ingress.
    """
    filtered = [
        e for e in entries if e.get("Egress") == egress
    ]
    filtered.sort(key=lambda e: e.get("RuleNumber", 32767))
    parts: list[str] = []
    for entry in filtered:
        rule_num = entry.get("RuleNumber", 32767)
        if rule_num == 32767:
            continue
        action = entry.get("RuleAction", "deny").upper()
        proto = _PROTO_MAP.get(
            entry.get("Protocol", "-1"),
            entry.get("Protocol", "-1"),
        )
        port_range = entry.get("PortRange", {})
        from_port = port_range.get("From", 0)
        to_port = port_range.get("To", 0)
        if proto == "all":
            port_str = "all"
        elif from_port == to_port:
            port_str = str(from_port)
        else:
            port_str = f"{from_port}-{to_port}"
        cidr = entry.get(
            "CidrBlock",
            entry.get("Ipv6CidrBlock", ""),
        )
        parts.append(
            f"Rule {rule_num} {action}"
            f" {proto}:{port_str} {cidr}"
        )
    return "; ".join(parts) if parts else "none"
