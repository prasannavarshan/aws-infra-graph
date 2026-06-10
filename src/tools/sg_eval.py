"""SG/NACL/Route evaluation primitives — pure functions, no I/O."""

from __future__ import annotations

import ipaddress
import re


def _cidr_contains(cidr: str, ip: str) -> bool:
    """Check if a CIDR block contains the given IP address.

    When ip is empty, only universal CIDRs (0.0.0.0/0, ::/0)
    match — used by SG-to-SG checks where no IP is available.
    """
    if not ip:
        return cidr in ("0.0.0.0/0", "::/0")
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(
            cidr, strict=False,
        )
    except ValueError:
        return False


def _split_sources(sources_str: str) -> list[str]:
    """Split comma-separated sources respecting brackets.

    Brackets (e.g. pl:pl-xxx[cidr1,cidr2]) may contain commas
    that should NOT be split. This splits only on commas outside
    square brackets.
    """
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for ch in sources_str:
        if ch == "[":
            depth += 1
            current.append(ch)
        elif ch == "]":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return [p for p in parts if p]


def _parse_sg_rules(rules_str: str) -> list[dict]:
    """Parse SG rule summary format into structured dicts.

    Format: 'proto:port from source1,source2; proto:port from ...'
    Example: 'tcp:443 from 0.0.0.0/0; all:all from sg:sg-abc123'
    """
    if not rules_str or rules_str == "none":
        return []
    rules = []
    for part in rules_str.split("; "):
        match = re.match(
            r"(\S+):(\S+)\s+from\s+(.+)", part.strip(),
        )
        if not match:
            continue
        proto, port_str, sources_str = match.groups()
        sources = _split_sources(sources_str)
        rules.append({
            "protocol": proto,
            "port_str": port_str,
            "sources": sources,
        })
    return rules


def _parse_nacl_rules(rules_str: str) -> list[dict]:
    """Parse NACL rule summary format into structured dicts.

    Format: 'Rule 100 ALLOW tcp:443 0.0.0.0/0; Rule 200 DENY ...'
    """
    if not rules_str or rules_str == "none":
        return []
    rules = []
    for part in rules_str.split("; "):
        match = re.match(
            r"Rule\s+(\d+)\s+(ALLOW|DENY)\s+(\S+):(\S+)\s+(\S+)",
            part.strip(),
        )
        if not match:
            continue
        rule_num, action, proto, port_str, cidr = match.groups()
        rules.append({
            "rule_number": int(rule_num),
            "action": action,
            "protocol": proto,
            "port_str": port_str,
            "cidr": cidr,
        })
    return rules


def _port_matches(port_str: str, target_port: int) -> bool:
    """Check if a port spec matches the target port."""
    if port_str == "all":
        return True
    if "-" in port_str:
        low, high = port_str.split("-", 1)
        return int(low) <= target_port <= int(high)
    return int(port_str) == target_port


def _proto_matches(rule_proto: str, target_proto: str) -> bool:
    """Check if a protocol spec matches the target protocol."""
    if rule_proto in ("all", "-1"):
        return True
    return rule_proto.lower() == target_proto.lower()


def _check_sg_allows(
    rules: list[dict],
    port: int,
    protocol: str,
    remote_ip: str,
    remote_sg_ids: frozenset[str] = frozenset(),
) -> tuple[bool, str]:
    """Evaluate SG rules for the given traffic.

    SGs are stateful: default deny, any matching rule allows.
    SG-to-SG references (sg:sg-xxx) are resolved against the
    remote resource's attached SG IDs. Note: SG references only
    work within the same VPC in AWS, but we don't enforce VPC
    matching here — the cross-VPC SG warning section handles that.

    Args:
        rules: Parsed SG rules to evaluate.
        port: Destination port.
        protocol: Protocol (tcp, udp, icmp).
        remote_ip: IP of the remote endpoint.
        remote_sg_ids: SG IDs attached to the remote resource.

    Returns:
        (allowed, reason) tuple.
    """
    for rule in rules:
        if not _proto_matches(rule["protocol"], protocol):
            continue
        if not _port_matches(rule["port_str"], port):
            continue
        for source in rule["sources"]:
            # SG-reference source (e.g. sg:sg-abc123)
            if source.startswith("sg:"):
                ref_sg_id = source[3:]  # strip "sg:" prefix
                if ref_sg_id in remote_sg_ids:
                    return True, (
                        f"{rule['protocol']}:{rule['port_str']}"
                        f" from {source} (SG match)"
                    )
                continue
            # Prefix-list source (e.g. pl:pl-xxx[cidr1,cidr2])
            if source.startswith("pl:"):
                pl_match = re.match(
                    r"pl:[^[]+\[([^\]]+)\]", source,
                )
                if not pl_match:
                    # Unresolved prefix list — skip
                    continue
                pl_cidrs = pl_match.group(1).split(",")
                for pl_cidr in pl_cidrs:
                    if _cidr_contains(pl_cidr.strip(), remote_ip):
                        return True, (
                            f"{rule['protocol']}"
                            f":{rule['port_str']}"
                            f" from {source}"
                            f" (prefix list match)"
                        )
                continue
            # Strip description suffix like '0.0.0.0/0(description)'
            cidr = re.sub(r"\(.*\)$", "", source)
            if not cidr:
                continue
            if _cidr_contains(cidr, remote_ip):
                return True, (
                    f"{rule['protocol']}:{rule['port_str']}"
                    f" from {source}"
                )
    return False, f"no rule for {protocol.upper()}/{port} from {remote_ip}"


def _check_nacl_allows(
    rules: list[dict],
    port: int,
    protocol: str,
    remote_ip: str,
) -> tuple[bool, str]:
    """Evaluate NACL rules for the given traffic.

    NACLs are stateless, evaluated in rule-number order.
    First matching rule wins.

    Returns:
        (allowed, reason) tuple.
    """
    sorted_rules = sorted(rules, key=lambda r: r["rule_number"])
    for rule in sorted_rules:
        if not _proto_matches(rule["protocol"], protocol):
            continue
        if not _port_matches(rule["port_str"], port):
            continue
        if not _cidr_contains(rule["cidr"], remote_ip):
            continue
        allowed = rule["action"] == "ALLOW"
        desc = (
            f"Rule {rule['rule_number']} {rule['action']}"
            f" {rule['protocol']}:{rule['port_str']}"
            f" {rule['cidr']}"
        )
        return allowed, desc
    return False, "no matching NACL rule (implicit deny)"


def _parse_routes(routes_str: str) -> list[dict]:
    """Parse route summary format into structured dicts.

    Format: '10.0.0.0/16 -> local; 0.0.0.0/0 -> igw-abc123'
    """
    if not routes_str or routes_str == "none":
        return []
    routes = []
    for part in routes_str.split("; "):
        pieces = part.strip().split(" -> ", 1)
        if len(pieces) != 2:
            continue
        dest, target = pieces
        routes.append({
            "destination": dest.strip(),
            "target": target.strip(),
        })
    return routes


def _check_route_allows(
    routes: list[dict], target_ip: str,
) -> tuple[bool, str, str, bool]:
    """Evaluate routes for the target IP using longest prefix match.

    Returns:
        (route_exists, description, tgw_id, is_local) tuple.
        tgw_id is non-empty when the best match targets a TGW.
        is_local is True when the best match is a local route.
    """
    if not target_ip:
        return False, "no target IP to check", "", False

    best_match: dict | None = None
    best_prefix = -1

    for route in routes:
        dest = route["destination"]
        try:
            network = ipaddress.ip_network(dest, strict=False)
        except ValueError:
            continue
        if ipaddress.ip_address(target_ip) not in network:
            continue
        if network.prefixlen > best_prefix:
            best_prefix = network.prefixlen
            best_match = route

    if best_match:
        target = best_match["target"]
        dest = best_match["destination"]
        # Extract TGW ID if route targets a TGW
        tgw_id = ""
        if target.startswith("tgw-"):
            tgw_id = target
        if target == "local":
            return (
                True, f"{dest} -> local (local route)",
                "", True,
            )
        return True, f"{dest} -> {target}", tgw_id, False

    return False, f"no route to {target_ip}", "", False


async def _check_tgw_route(
    neo4j, tgw_id: str, target_ip: str,  # noqa: ANN001
) -> tuple[bool, list[str]]:
    """Check if a TGW has a route to the target IP.

    Queries Neo4j for TGW route tables and evaluates their
    routes using longest prefix match.

    Returns:
        (route_found, detail_lines) tuple.
    """
    query = """
    MATCH (tgw:TransitGateway {tgw_id: $tgw_id})
          <-[:PART_OF]-(tgwrt:TGWRouteTable)
    RETURN tgwrt.route_table_id AS rt_id,
           tgwrt.name AS rt_name,
           tgwrt.routes AS routes
    """
    results = await neo4j.query(query, {"tgw_id": tgw_id})
    if not results:
        return False, [
            f"  X TGW {tgw_id}: no route tables found"
            " — TGW NO ROUTE",
        ]

    lines: list[str] = []
    any_found = False
    for row in results:
        rt_id = row["rt_id"]
        routes_str = row.get("routes", "")
        parsed = _parse_routes(routes_str)
        found, reason, _, _ = _check_route_allows(
            parsed, target_ip,
        )
        if found:
            any_found = True
            lines.append(
                f"  + TGW RT {rt_id}: {reason}"
                " — TGW ROUTE EXISTS",
            )
        else:
            lines.append(
                f"  - TGW RT {rt_id}: {reason}",
            )

    if not any_found:
        lines.append(
            f"  X TGW {tgw_id}: no TGW route to"
            f" {target_ip} — TGW NO ROUTE",
        )
    return any_found, lines
