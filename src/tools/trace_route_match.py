"""Route matching helpers for trace_route."""

from __future__ import annotations

import ipaddress


def find_matching_route(
    routes: list[dict], ip: str,
) -> dict | None:
    """Find the longest-prefix-match route for an IP.

    Args:
        routes: Raw route dicts from AWS get_network_routes.
        ip: IP address to match against DestinationCidrBlock.

    Returns:
        Best matching route dict, or None.
    """
    best: dict | None = None
    best_prefix = -1
    for route in routes:
        cidr = route.get("DestinationCidrBlock", "")
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
            best = route
    return best
