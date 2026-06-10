"""Neo4j query functions for DNS resolution tracing."""

from __future__ import annotations


async def resolve_source_vpc(
    neo4j,  # noqa: ANN001
    source_vpc: str,
    source_account: str,
) -> dict | None:
    """Find a VPC by name or ID, optionally filtered by account."""
    if not source_vpc:
        return None

    query = """
    MATCH (v:VPC)
    WHERE v.vpc_id = $vpc OR v.name = $vpc
    RETURN v.vpc_id AS vpc_id,
           v.name AS name,
           v.account_id AS account_id,
           v.region AS region,
           v.arn AS arn
    LIMIT 5
    """
    results = await neo4j.query(query, {"vpc": source_vpc})
    if not results:
        query = """
        MATCH (v:VPC)
        WHERE toLower(v.name) CONTAINS toLower($vpc)
        RETURN v.vpc_id AS vpc_id,
               v.name AS name,
               v.account_id AS account_id,
               v.region AS region,
               v.arn AS arn
        LIMIT 5
        """
        results = await neo4j.query(query, {"vpc": source_vpc})

    if not results:
        return None

    if source_account:
        filtered = [
            r for r in results
            if source_account in (
                r.get("account_id", ""),
                r.get("name", ""),
            )
        ]
        if filtered:
            results = filtered

    return results[0] if results else None


async def find_matching_rule(
    neo4j,  # noqa: ANN001
    vpc_id: str,
    query_name: str,
) -> dict | None:
    """Find the best-matching resolver rule for a query name.

    Picks the FORWARD rule with the longest domain_name suffix
    match (most specific).
    """
    cypher = """
    MATCH (rule:ResolverRule)-[:ASSOCIATED_WITH]->(vpc:VPC)
    WHERE vpc.vpc_id = $vpc_id
      AND rule.rule_type = 'FORWARD'
    RETURN rule.name AS name,
           rule.arn AS arn,
           rule.domain_name AS domain_name,
           rule.rule_type AS rule_type,
           rule.target_ips AS target_ips,
           rule.resolver_endpoint_id AS endpoint_id,
           rule.owner_id AS owner_id,
           rule.share_status AS share_status,
           rule.account_id AS account_id
    """
    results = await neo4j.query(cypher, {"vpc_id": vpc_id})

    qn = query_name.rstrip(".")
    best: dict | None = None
    best_labels = 0

    for rule in results:
        domain = (rule.get("domain_name") or "").rstrip(".")
        if not domain:
            continue
        if qn == domain or qn.endswith("." + domain):
            label_count = domain.count(".") + 1
            if label_count > best_labels:
                best = rule
                best_labels = label_count

    return best


async def get_outbound_endpoint(
    neo4j,  # noqa: ANN001
    endpoint_id: str,
) -> dict | None:
    """Get outbound endpoint details by endpoint_id."""
    cypher = """
    MATCH (ep:ResolverEndpoint)
    WHERE ep.endpoint_id = $ep_id
      AND ep.direction = 'OUTBOUND'
    OPTIONAL MATCH (ep)-[:PART_OF]->(vpc:VPC)
    RETURN ep.name AS name,
           ep.arn AS arn,
           ep.endpoint_id AS endpoint_id,
           ep.vpc_id AS vpc_id,
           ep.ip_addresses AS ip_addresses,
           vpc.name AS vpc_name,
           vpc.cidr_block AS vpc_cidr
    LIMIT 1
    """
    results = await neo4j.query(cypher, {"ep_id": endpoint_id})
    return results[0] if results else None


async def detect_loopback(
    neo4j,  # noqa: ANN001
    vpc_id: str,
    target_ips: list[str],
) -> dict | None:
    """Check if target IPs match an inbound endpoint in the VPC.

    Returns inbound endpoint info if loopback detected, else None.
    """
    cypher = """
    MATCH (ep:ResolverEndpoint)-[:PART_OF]->(vpc:VPC)
    WHERE vpc.vpc_id = $vpc_id
      AND ep.direction = 'INBOUND'
    RETURN ep.name AS name,
           ep.arn AS arn,
           ep.endpoint_id AS endpoint_id,
           ep.ip_addresses AS ip_addresses,
           ep.vpc_id AS vpc_id
    """
    results = await neo4j.query(cypher, {"vpc_id": vpc_id})
    target_set = set(target_ips)

    for ep in results:
        ep_ips = ep.get("ip_addresses") or []
        if isinstance(ep_ips, str):
            ep_ips = [
                ip.strip() for ip in ep_ips.split(",")
            ]
        if target_set & set(ep_ips):
            return ep

    return None


async def find_private_zones(
    neo4j,  # noqa: ANN001
    vpc_id: str,
) -> list[dict]:
    """Find all private hosted zones associated with a VPC."""
    cypher = """
    MATCH (zone:Route53Zone)-[:ASSOCIATED_WITH]->(vpc:VPC)
    WHERE vpc.vpc_id = $vpc_id
      AND zone.is_private = true
    RETURN zone.name AS zone_name,
           zone.zone_id AS zone_id,
           zone.arn AS arn,
           zone.account_id AS account_id,
           zone.record_count AS record_count
    """
    return await neo4j.query(cypher, {"vpc_id": vpc_id})


async def lookup_record(
    neo4j,  # noqa: ANN001
    zone_id: str,
    query_name: str,
) -> dict | None:
    """Find a DNS record in a zone by name.

    Tries exact match first, then wildcard patterns.
    Uses ARN prefix match instead of PART_OF traversal so
    results are reliable even when PART_OF edges are missing.
    """
    qn = query_name.rstrip(".")
    qn_dot = qn + "."
    zone_arn_prefix = (
        f"arn:aws:route53:::hostedzone/{zone_id}/record/"
    )

    cypher = """
    MATCH (rec:Route53Record)
    WHERE rec.arn STARTS WITH $zone_arn_prefix
      AND (rec.name = $qn OR rec.name = $qn_dot)
    RETURN rec.name AS name,
           rec.record_type AS record_type,
           rec.values AS values,
           rec.alias_target AS alias_target,
           rec.alias_zone_id AS alias_zone_id,
           rec.ttl AS ttl
    LIMIT 1
    """
    results = await neo4j.query(
        cypher,
        {
            "zone_arn_prefix": zone_arn_prefix,
            "qn": qn,
            "qn_dot": qn_dot,
        },
    )
    if results:
        return results[0]

    parts = qn.split(".")
    if len(parts) > 1:
        wildcard = "*." + ".".join(parts[1:])
        wildcard_dot = wildcard + "."
        results = await neo4j.query(
            cypher,
            {
                "zone_arn_prefix": zone_arn_prefix,
                "qn": wildcard,
                "qn_dot": wildcard_dot,
            },
        )
        if results:
            return results[0]

    return None


async def find_ns_delegation(
    neo4j,  # noqa: ANN001
    zone_id: str,
    zone_name: str,
    query_name: str,
) -> dict | None:
    """Walk up labels looking for NS delegation records.

    For query 'a.b.c.example.com' in zone 'example.com',
    checks for NS records at: b.c.example.com,
    c.example.com (stops before zone apex).

    Returns:
        Dict with delegation name and nameservers, or None.
    """
    qn = query_name.rstrip(".")
    zn = zone_name.rstrip(".")

    parts = qn.split(".")
    zone_parts = zn.split(".")
    zone_label_count = len(zone_parts)

    candidates: list[str] = []
    for i in range(1, len(parts) - zone_label_count + 1):
        candidate = ".".join(parts[i:])
        if candidate != zn:
            candidates.append(candidate)

    if not candidates:
        return None

    cypher = """
    MATCH (rec:Route53Record)
    WHERE rec.arn STARTS WITH $zone_arn_prefix
      AND rec.record_type = 'NS'
      AND (rec.name IN $names
           OR rec.name IN $names_dot)
    RETURN rec.name AS name, rec.values AS values
    LIMIT 1
    """
    names_dot = [c + "." for c in candidates]
    zone_arn_prefix = (
        f"arn:aws:route53:::hostedzone/{zone_id}/record/"
    )
    results = await neo4j.query(
        cypher,
        {
            "zone_arn_prefix": zone_arn_prefix,
            "names": candidates,
            "names_dot": names_dot,
        },
    )
    return results[0] if results else None


async def resolve_delegation_zone(
    neo4j,  # noqa: ANN001
    delegation_name: str,
) -> dict | None:
    """Find a Route53Zone matching the delegation name."""
    dn = delegation_name.rstrip(".")
    dn_dot = dn + "."

    cypher = """
    MATCH (z:Route53Zone)
    WHERE z.name = $dn OR z.name = $dn_dot
    RETURN z.zone_id AS zone_id,
           z.name AS zone_name,
           z.account_id AS account_id,
           z.is_private AS is_private
    LIMIT 1
    """
    results = await neo4j.query(
        cypher, {"dn": dn, "dn_dot": dn_dot},
    )
    return results[0] if results else None


def longest_suffix_match(
    query_name: str,
    zones: list[dict],
) -> tuple[dict | None, list[tuple[str, int, bool]]]:
    """Pick the zone with the most matching labels.

    Returns:
        Tuple of (winning_zone, scored_list) where scored_list
        contains (zone_name, label_count, is_winner) tuples.
    """
    qn = query_name.rstrip(".")
    scored: list[tuple[dict, str, int]] = []

    for zone in zones:
        zname = (zone.get("zone_name") or "").rstrip(".")
        if not zname:
            continue
        if qn == zname or qn.endswith("." + zname):
            label_count = zname.count(".") + 1
            scored.append((zone, zname, label_count))

    if not scored:
        display = [
            (
                (z.get("zone_name") or "").rstrip("."),
                0,
                False,
            )
            for z in zones
        ]
        return None, display

    scored.sort(key=lambda x: x[2], reverse=True)
    winner = scored[0][0]
    winner_name = scored[0][1]

    display: list[tuple[str, int, bool]] = []
    for _zone, zname, lc in scored:
        display.append((zname, lc, zname == winner_name))

    matched_names = {s[1] for s in scored}
    for zone in zones:
        zname = (zone.get("zone_name") or "").rstrip(".")
        if zname not in matched_names:
            display.append((zname, 0, False))

    return winner, display


async def auto_detect_vpc(
    neo4j,  # noqa: ANN001
    query_name: str,
) -> dict | None:
    """Find a VPC that has a resolver rule matching the query.

    Picks the rule with the longest domain suffix match,
    then returns a VPC that has that rule ASSOCIATED_WITH it
    (not the endpoint's VPC - the consumer VPC).
    """
    qn = query_name.rstrip(".")

    cypher = """
    MATCH (rule:ResolverRule)-[:ASSOCIATED_WITH]->(vpc:VPC)
    WHERE rule.rule_type = 'FORWARD'
    RETURN rule.domain_name AS domain_name,
           rule.arn AS rule_arn,
           vpc.vpc_id AS vpc_id,
           vpc.name AS name,
           vpc.account_id AS account_id
    """
    results = await neo4j.query(cypher, {})

    best: dict | None = None
    best_labels = 0

    for row in results:
        domain = (row.get("domain_name") or "").rstrip(".")
        if not domain:
            continue
        if qn == domain or qn.endswith("." + domain):
            lc = domain.count(".") + 1
            if lc > best_labels:
                best_labels = lc
                best = row

    if not best:
        return None

    return {
        "vpc_id": best.get("vpc_id", ""),
        "name": best.get("name", ""),
        "account_id": best.get("account_id", ""),
    }


async def find_public_zones(
    neo4j,  # noqa: ANN001
    query_name: str,
) -> list[dict]:
    """Find public hosted zones matching a query by suffix.

    Returns all public zones whose name is a suffix of the
    query, sorted by label count (most specific first).
    """
    cypher = """
    MATCH (z:Route53Zone)
    WHERE z.is_private = false
    RETURN z.name AS zone_name,
           z.zone_id AS zone_id,
           z.account_id AS account_id,
           z.record_count AS record_count
    """
    results = await neo4j.query(cypher, {})

    qn = query_name.rstrip(".")
    matched: list[tuple[dict, int]] = []

    for zone in results:
        zname = (zone.get("zone_name") or "").rstrip(".")
        if not zname:
            continue
        if qn == zname or qn.endswith("." + zname):
            label_count = zname.count(".") + 1
            matched.append((zone, label_count))

    matched.sort(key=lambda x: x[1], reverse=True)
    return [z for z, _ in matched]
