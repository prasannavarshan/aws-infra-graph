"""Fuzzy resource resolution — parsing, account, and resource lookup."""

from __future__ import annotations

import logging

from pydantic import BaseModel

logger = logging.getLogger(__name__)


# --- Type keyword mapping ---

_TYPE_KEYWORDS: dict[str, str] = {
    "lambda": "LambdaFunction",
    "eks": "EKSCluster",
    "ec2": "EC2Instance",
    "instance": "EC2Instance",
    "redis": "ElastiCacheCluster",
    "elasticache": "ElastiCacheCluster",
    "rds": "RDSInstance",
    "alb": "LoadBalancer",
    "nlb": "LoadBalancer",
    "elb": "LoadBalancer",
    "opensearch": "OpenSearchDomain",
    "serverless": "ElastiCacheServerlessCache",
    "waf": "WAFWebACL",
    "namespace": "K8sNamespace",
    "deployment": "K8sDeployment",
    "k8s-service": "K8sService",
    "serviceaccount": "K8sServiceAccount",
    "k8s-node": "K8sNode",
    "ingress": "K8sIngress",
}

_SG_BEARING_LABELS: list[str] = [
    "LambdaFunction",
    "EKSCluster",
    "EKSNodegroup",
    "EC2Instance",
    "RDSInstance",
    "ElastiCacheCluster",
    "ElastiCacheServerlessCache",
    "LoadBalancer",
    "VPCEndpoint",
    "OpenSearchDomain",
]


# --- Models ---


class ResourceHint(BaseModel):
    """Parsed hint from a fuzzy resource input string."""

    label: str  # Neo4j node label, or "" for multi-label
    name_query: str  # cleaned name for fuzzy match


class ResolvedResource(BaseModel):
    """A resolved resource with metadata."""

    arn: str
    name: str
    label: str
    account_id: str
    region: str


# --- Parsing ---


def _parse_resource_hint(raw: str) -> ResourceHint:
    """Parse a fuzzy input string into a structured hint.

    Detects keyword prefixes/suffixes like "lambda", "eks",
    "redis" to narrow the Neo4j node label. Remaining tokens
    become the name query for fuzzy matching.

    Args:
        raw: Fuzzy input like "lambda my-api-auth"
            or "prod-api beta EKS".

    Returns:
        ResourceHint with label and name_query.
    """
    tokens = raw.strip().split()
    if not tokens:
        return ResourceHint(label="", name_query=raw.strip())

    label = ""
    remaining: list[str] = []

    for token in tokens:
        lower = token.lower()
        if not label and lower in _TYPE_KEYWORDS:
            label = _TYPE_KEYWORDS[lower]
        else:
            remaining.append(token)

    name_query = " ".join(remaining).strip()
    if not name_query:
        name_query = raw.strip()

    return ResourceHint(label=label, name_query=name_query)


# --- Account resolution ---


async def _resolve_account(
    neo4j,  # noqa: ANN001
    name_hint: str,
) -> str | list[dict[str, str]]:
    """Resolve fuzzy account name to account_id.

    Args:
        neo4j: Neo4jClient instance.
        name_hint: Account name substring or exact account ID.

    Returns:
        account_id string on single match, list of candidate
        dicts on multiple matches, or empty string if hint
        is empty.
    """
    if not name_hint:
        return ""

    # Check if it's already a 12-digit account ID
    if name_hint.isdigit() and len(name_hint) == 12:
        return name_hint

    query = """
    MATCH (a:Account)
    WHERE toLower(a.name) CONTAINS toLower($name)
    RETURN a.account_id AS id, a.name AS name
    ORDER BY a.name
    """
    results = await neo4j.query(query, {"name": name_hint})

    if not results:
        return []
    if len(results) == 1:
        return results[0]["id"]
    return [dict(r) for r in results]


# --- Resource resolution ---

_RETURN_CLAUSE = """
    RETURN r.arn AS arn, r.name AS name,
           head(labels(r)) AS label,
           r.account_id AS account_id,
           r.region AS region
    LIMIT 20
"""


def _build_base_where(
    hint: ResourceHint, account_id: str,
) -> tuple[str, str, dict[str, str]]:
    """Build MATCH clause and base WHERE for label/account.

    Returns:
        (match_clause, base_where, base_params).
        base_where may be empty if no label/account filter.
    """
    parts: list[str] = []
    params: dict[str, str] = {}

    if hint.label:
        match_clause = f"MATCH (r:{hint.label})"
    else:
        label_checks = " OR ".join(
            f"r:{lbl}" for lbl in _SG_BEARING_LABELS
        )
        match_clause = "MATCH (r)"
        parts.append(f"({label_checks})")

    if account_id:
        parts.append("r.account_id = $account_id")
        params["account_id"] = account_id

    return match_clause, " AND ".join(parts), params


async def _query_resources(
    neo4j,  # noqa: ANN001
    hint: ResourceHint,
    account_id: str,
    name_where: str,
    extra_params: dict,
) -> list[dict]:
    """Run a resource query with configurable name matching."""
    match_cl, base_where, params = _build_base_where(
        hint, account_id,
    )
    params.update(extra_params)

    where_parts = [p for p in [base_where, name_where] if p]
    where = " AND ".join(where_parts)

    query = f"{match_cl}\n    WHERE {where}\n{_RETURN_CLAUSE}"
    return await neo4j.query(query, params)


async def _query_resources_ranked(
    neo4j,  # noqa: ANN001
    hint: ResourceHint,
    account_id: str,
    tokens: list[str],
) -> list[dict]:
    """Run any-token ranked query, sorted by hit count."""
    match_cl, base_where, params = _build_base_where(
        hint, account_id,
    )
    params["tokens"] = tokens

    base_filter = f"WHERE {base_where}" if base_where else ""
    query = f"""
    {match_cl}
    {base_filter}
    WITH r,
         size([t IN $tokens
               WHERE toLower(r.name) CONTAINS t]) AS hits
    WHERE hits > 0
    ORDER BY hits DESC, r.name
    RETURN r.arn AS arn, r.name AS name,
           head(labels(r)) AS label,
           r.account_id AS account_id,
           r.region AS region
    LIMIT 20
    """
    return await neo4j.query(query, params)


def _pick_result(
    results: list[dict],
    hint: ResourceHint,
) -> ResolvedResource | list[dict] | None:
    """Dedup and pick a single result from query results.

    Returns:
        ResolvedResource on single/exact match, list for
        disambiguation, or None if no results.
    """
    if not results:
        return None

    # Deduplicate by ARN (shared VPCs can cause duplicates)
    seen: set[str] = set()
    unique: list[dict] = []
    for r in results:
        if r["arn"] not in seen:
            seen.add(r["arn"])
            unique.append(dict(r))
    results = unique

    if len(results) == 1:
        return _to_resolved(results[0])

    # Check for exact name match
    exact = [
        r for r in results if r["name"] == hint.name_query
    ]
    if len(exact) == 1:
        return _to_resolved(exact[0])

    return results


def _to_resolved(r: dict) -> ResolvedResource:
    """Convert a query result dict to ResolvedResource."""
    return ResolvedResource(
        arn=r["arn"],
        name=r["name"],
        label=r["label"],
        account_id=r["account_id"],
        region=r["region"],
    )


async def _resolve_resource(
    neo4j,  # noqa: ANN001
    hint: ResourceHint,
    account_id: str = "",
) -> ResolvedResource | list[dict[str, str]] | str:
    """Resolve a fuzzy resource hint to a concrete resource.

    Uses a 3-strategy chain with early return:
    1. Full substring match (fast, exact)
    2. All-tokens match (multi-word queries)
    3. Any-token ranked (partial match fallback)

    Args:
        neo4j: Neo4jClient instance.
        hint: Parsed ResourceHint with label and name_query.
        account_id: Optional account filter.

    Returns:
        ResolvedResource on single match, list of candidates
        for disambiguation, or error string if not found.
    """
    # Strategy 1: full substring (current behavior)
    results = await _query_resources(
        neo4j, hint, account_id,
        name_where=(
            "(toLower(r.name) CONTAINS toLower($name)"
            " OR r.arn CONTAINS $name)"
        ),
        extra_params={"name": hint.name_query},
    )
    resolved = _pick_result(results, hint)
    if resolved is not None:
        return resolved

    # Strategy 2: all-tokens (multi-word only)
    tokens = [t.lower() for t in hint.name_query.split() if t]
    if len(tokens) > 1:
        results = await _query_resources(
            neo4j, hint, account_id,
            name_where=(
                "ALL(t IN $tokens"
                " WHERE toLower(r.name) CONTAINS t)"
            ),
            extra_params={"tokens": tokens},
        )
        resolved = _pick_result(results, hint)
        if resolved is not None:
            return resolved

    # Strategy 3: any-token ranked
    if tokens:
        results = await _query_resources_ranked(
            neo4j, hint, account_id, tokens,
        )
        resolved = _pick_result(results, hint)
        if resolved is not None:
            return resolved

    return (
        f"No resource found matching '{hint.name_query}'"
        + (f" (type: {hint.label})" if hint.label else "")
        + (f" in account {account_id}" if account_id else "")
        + "."
    )
