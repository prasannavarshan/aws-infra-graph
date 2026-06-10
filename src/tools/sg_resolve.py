"""SG resolution helpers — find security groups by ID, name, or substring."""

from __future__ import annotations

from src.tools.sg_format import _format_sg_ambiguous
from src.tools.sg_refresh import refresh_security_groups


def _dedup_by_group_id(results: list[dict]) -> list[dict]:
    """Deduplicate SGs by group_id.

    Shared VPCs cause the same SG (same group_id) to appear
    as separate nodes in different accounts. Keep the first
    occurrence of each group_id.
    """
    seen: set[str] = set()
    deduped: list[dict] = []
    for r in results:
        gid = r["group_id"]
        if gid not in seen:
            seen.add(gid)
            deduped.append(r)
    return deduped


_SG_RETURN = """
    RETURN sg.group_id AS group_id,
           sg.name AS name,
           sg.vpc_id AS vpc_id,
           sg.account_id AS account_id,
           sg.region AS region,
           sg.ingress_rules AS ingress,
           sg.egress_rules AS egress
"""


def _pick_sg(
    results: list[dict], identifier: str,
) -> dict | list[dict] | None:
    """Dedup and pick a single SG from results.

    Returns:
        Dict on single/exact match, list for ambiguous,
        or None if empty.
    """
    if not results:
        return None

    results = _dedup_by_group_id(results)
    if len(results) == 1:
        return dict(results[0])

    # Check for exact group_id or name
    exact = _dedup_by_group_id([
        r for r in results
        if r["group_id"] == identifier
        or r["name"] == identifier
    ])
    if len(exact) == 1:
        return dict(exact[0])

    return results


async def _resolve_sg(
    neo4j,  # noqa: ANN001
    identifier: str,
    account_id: str = "",
) -> dict | str:
    """Resolve a security group by group_id, name, or substring.

    Uses a 3-strategy chain with early return:
    1. Full substring + exact ID/name match
    2. All-tokens match (multi-word queries)
    3. Any-token ranked (partial match fallback)

    Args:
        neo4j: Neo4jClient instance.
        identifier: SG group_id (sg-xxx), exact name, or
            name substring (case-insensitive).
        account_id: Optional account filter to narrow scope.

    Returns:
        Dict with SG details if exactly one match found,
        or an error string if zero or multiple matches.
    """
    acct_where = ""
    params: dict[str, str] = {"id": identifier}
    if account_id:
        acct_where = " AND sg.account_id = $account_id"
        params["account_id"] = account_id

    # Strategy 1: full substring + exact ID/name
    query = f"""
    MATCH (sg:SecurityGroup)
    WHERE (sg.group_id = $id
           OR sg.name = $id
           OR toLower(sg.name) CONTAINS toLower($id))
    {acct_where}
    {_SG_RETURN}
    """
    results = await neo4j.query(query, params)
    picked = _pick_sg(results, identifier)
    if isinstance(picked, dict):
        return picked
    if isinstance(picked, list):
        return _format_sg_ambiguous(identifier, picked)

    # Strategy 2: all-tokens (multi-word only)
    tokens = [t.lower() for t in identifier.split() if t]
    if len(tokens) > 1:
        tok_params: dict = {"tokens": tokens}
        if account_id:
            tok_params["account_id"] = account_id
        query = f"""
        MATCH (sg:SecurityGroup)
        WHERE ALL(t IN $tokens
              WHERE toLower(sg.name) CONTAINS t)
        {acct_where}
        {_SG_RETURN}
        """
        results = await neo4j.query(query, tok_params)
        picked = _pick_sg(results, identifier)
        if isinstance(picked, dict):
            return picked
        if isinstance(picked, list):
            return _format_sg_ambiguous(identifier, picked)

    # Strategy 3: any-token ranked
    if tokens:
        tok_params = {"tokens": tokens}
        if account_id:
            tok_params["account_id"] = account_id
        query = f"""
        MATCH (sg:SecurityGroup)
        {"WHERE sg.account_id = $account_id" if account_id else ""}
        WITH sg,
             size([t IN $tokens
                   WHERE toLower(sg.name) CONTAINS t]) AS hits
        WHERE hits > 0
        ORDER BY hits DESC, sg.name
        {_SG_RETURN}
        LIMIT 20
        """
        results = await neo4j.query(query, tok_params)
        picked = _pick_sg(results, identifier)
        if isinstance(picked, dict):
            return picked
        if isinstance(picked, list):
            return _format_sg_ambiguous(identifier, picked)

    return f"No security group found matching '{identifier}'."


async def _resolve_multiple_sgs(
    neo4j,  # noqa: ANN001
    identifier: str,
    account_id: str = "",
) -> list[dict] | str:
    """Resolve one or more comma-separated SG identifiers.

    Splits on commas, resolves each via _resolve_sg.
    Returns list of SG dicts, or error string naming
    the failing identifier.
    """
    parts = [s.strip() for s in identifier.split(",") if s.strip()]
    results: list[dict] = []
    for part in parts:
        resolved = await _resolve_sg(neo4j, part, account_id)
        if isinstance(resolved, str):
            return f"SG '{part}': {resolved}"
        results.append(resolved)
    if not results:
        return f"No SG identifiers in '{identifier}'."
    return results


async def _refresh_sg_list(
    neo4j,  # noqa: ANN001
    sgs: list[dict],
) -> list[dict]:
    """Live-refresh a list of SGs from AWS."""
    sg_refs = [
        {
            "group_id": sg["group_id"],
            "account_id": sg.get("account_id", ""),
            "region": sg.get("region", ""),
        }
        for sg in sgs
    ]
    fresh = await refresh_security_groups(neo4j, sg_refs)
    fresh_map = {sg["group_id"]: sg for sg in fresh}
    return [
        fresh_map.get(sg["group_id"], sg) for sg in sgs
    ]
