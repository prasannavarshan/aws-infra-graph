"""Name cache — lightweight account/VPC name lookups for output enrichment."""

from __future__ import annotations


async def load_account_names(
    neo4j,  # noqa: ANN001
) -> dict[str, str]:
    """Load account_id -> account_name map from graph.

    Returns:
        Dict mapping 12-digit account IDs to human-readable
        account names.
    """
    query = """
    MATCH (a:Account)
    RETURN a.account_id AS id, a.name AS name
    """
    results = await neo4j.query(query, {})
    return {r["id"]: r["name"] for r in results}


async def load_vpc_names(
    neo4j,  # noqa: ANN001
) -> dict[str, dict[str, str]]:
    """Load vpc_id -> {name, owner_id} map from graph.

    Returns:
        Dict mapping vpc_id to a dict with name and owner_id.
    """
    query = """
    MATCH (v:VPC)
    RETURN v.vpc_id AS id, v.name AS name,
           v.owner_id AS owner_id
    """
    results = await neo4j.query(query, {})
    return {
        r["id"]: {
            "name": r.get("name", ""),
            "owner_id": r.get("owner_id", ""),
        }
        for r in results
    }


async def load_sg_names(
    neo4j,  # noqa: ANN001
) -> dict[str, str]:
    """Load group_id -> SG name map from graph.

    Returns:
        Dict mapping SG group IDs to their names.
    """
    query = """
    MATCH (sg:SecurityGroup)
    RETURN sg.group_id AS id, sg.name AS name
    """
    results = await neo4j.query(query, {})
    return {r["id"]: r["name"] for r in results}


def enrich_sg_reference(
    sg_ref: str,
    sg_names: dict[str, str],
) -> str:
    """Enrich a 'sg:sg-xxx' reference with the SG name.

    Args:
        sg_ref: String like 'sg:sg-abc123'.
        sg_names: Dict from load_sg_names.

    Returns:
        'sg:sg-abc123 (my-sg-name)' if known, unchanged if not.
    """
    if not sg_ref.startswith("sg:"):
        return sg_ref
    sg_id = sg_ref[3:]
    name = sg_names.get(sg_id, "")
    if name:
        return f"{sg_ref} ({name})"
    return sg_ref


def enrich_account(
    account_id: str,
    names: dict[str, str],
) -> str:
    """Format account_id with name if available.

    Example: '123456789012 (workload-beta)'
    """
    if not account_id:
        return "unknown"
    name = names.get(account_id, "")
    if name:
        return f"{account_id} ({name})"
    return account_id


def enrich_vpc(
    vpc_id: str,
    vpc_map: dict[str, dict[str, str]],
    account_names: dict[str, str] | None = None,
) -> str:
    """Format vpc_id with name and owner info.

    Shows '(shared, owner: ...)' when owner_id differs from
    the VPC's account context.

    Args:
        vpc_id: VPC ID to enrich.
        vpc_map: Dict from load_vpc_names.
        account_names: Optional account name map for owner.

    Example: 'vpc-xxx (my-vpc, owner: 732... (net-svc))'
    """
    if not vpc_id:
        return "unknown"
    info = vpc_map.get(vpc_id)
    if not info:
        return vpc_id
    name = info.get("name", "")
    owner_id = info.get("owner_id", "")
    parts: list[str] = []
    if name:
        parts.append(name)
    if owner_id and account_names:
        owner_label = enrich_account(owner_id, account_names)
        parts.append(f"owner: {owner_label}")
    if parts:
        return f"{vpc_id} ({', '.join(parts)})"
    return vpc_id
