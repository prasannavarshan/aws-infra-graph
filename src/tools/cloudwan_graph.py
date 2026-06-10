"""CloudWAN graph query helpers for segment connectivity analysis."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


async def find_segments(
    neo4j,  # noqa: ANN001
    source_name: str,
    target_name: str,
    core_network_id: str,
) -> tuple[dict | None, dict | None]:
    """Find source and target segment nodes by name.

    When multiple core networks exist, picks the one with
    the most attachments (the primary/active core network).

    Returns:
        (source_segment, target_segment) dicts or None.
    """
    where = ""
    params: dict = {
        "source": source_name,
        "target": target_name,
    }
    if core_network_id:
        where = " AND n.core_network_id = $cn_id"
        params["cn_id"] = core_network_id

    query = f"""
    MATCH (n:CloudWANSegment)
    WHERE n.name IN [$source, $target]{where}
    OPTIONAL MATCH (a:CloudWANAttachment)
        -[:PART_OF]->
        (:CloudWANSegment {{
            core_network_id: n.core_network_id
        }})
    WITH n, count(a) AS att_count
    ORDER BY att_count DESC
    RETURN n.name AS name, n.arn AS arn,
           n.isolate_attachments AS isolate,
           n.deny_filter AS deny_filter,
           n.core_network_id AS cn_id
    """
    results = await neo4j.query(query, params)

    source = None
    target = None
    for row in results:
        if row["name"] == source_name and source is None:
            source = row
        if row["name"] == target_name and target is None:
            target = row
    # Ensure both from same core network if possible
    if (
        source and target
        and source["cn_id"] != target["cn_id"]
    ):
        cn = source["cn_id"]
        for row in results:
            if (
                row["name"] == target_name
                and row["cn_id"] == cn
            ):
                target = row
                break

    # Fuzzy fallback: if either segment not found by exact
    # name, try CONTAINS match and suggest corrections
    if source is None or target is None:
        missing = []
        if source is None:
            missing.append(source_name)
        if target is None:
            missing.append(target_name)
        fuzzy = await _fuzzy_segment_search(
            neo4j, missing, core_network_id,
        )
        for name in missing:
            match = fuzzy.get(name)
            if match:
                if name == source_name and source is None:
                    source = match
                if name == target_name and target is None:
                    target = match

    return source, target


async def _fuzzy_segment_search(
    neo4j,  # noqa: ANN001
    names: list[str],
    core_network_id: str,
) -> dict[str, dict | None]:
    """Fuzzy-match segment names using CONTAINS.

    Tries substring match, then case-insensitive CONTAINS.
    Returns a mapping from input name to best match dict.
    """
    results_map: dict[str, dict | None] = {
        n: None for n in names
    }
    cn_filter = ""
    params: dict = {}
    if core_network_id:
        cn_filter = " AND s.core_network_id = $cn_id"
        params["cn_id"] = core_network_id

    # Fetch all segment names for matching
    query = f"""
    MATCH (s:CloudWANSegment)
    WHERE true{cn_filter}
    RETURN s.name AS name, s.arn AS arn,
           s.isolate_attachments AS isolate,
           s.deny_filter AS deny_filter,
           s.core_network_id AS cn_id
    """
    all_segs = await neo4j.query(query, params)
    if not all_segs:
        return results_map

    # Deduplicate by name (multiple core networks)
    seen_names: set[str] = set()
    unique_segs: list[dict] = []
    for s in all_segs:
        if s["name"] not in seen_names:
            seen_names.add(s["name"])
            unique_segs.append(s)

    for input_name in names:
        lower_input = input_name.lower()
        # Try CONTAINS match (bidirectional)
        matches = [
            s for s in unique_segs
            if lower_input in s["name"].lower()
            or s["name"].lower() in lower_input
        ]
        if len(matches) == 1:
            results_map[input_name] = matches[0]
            logger.info(
                "fuzzy_segment_search: '%s' -> '%s'",
                input_name, matches[0]["name"],
            )
        elif len(matches) > 1:
            # Prefer shortest name (most direct match)
            matches.sort(key=lambda s: len(s["name"]))
            results_map[input_name] = matches[0]
            logger.info(
                "fuzzy_segment_search: '%s' -> '%s'"
                " (shortest of %d matches)",
                input_name, matches[0]["name"],
                len(matches),
            )
    return results_map


async def find_reachable_path(
    neo4j,  # noqa: ANN001
    source_arn: str,
    target_arn: str,
    direction: str = "forward",
) -> dict | None:
    """Find shortest path where deny-filters don't block.

    For forward (src->tgt): each importing segment (i+1) must
    NOT deny-filter the exporting segment (i).
    For return (tgt->src): reversed -- each segment (i) must
    NOT deny-filter the segment (i+1).

    Returns:
        Dict with segments list, or None if no clean path.
    """
    if direction == "forward":
        where = """
WHERE ALL(i IN range(0, size(nodes(path))-2)
  WHERE NOT nodes(path)[i].name IN
        coalesce(nodes(path)[i+1].deny_filter, []))
"""
    else:
        where = """
WHERE ALL(i IN range(0, size(nodes(path))-2)
  WHERE NOT nodes(path)[i+1].name IN
        coalesce(nodes(path)[i].deny_filter, []))
"""
    query = f"""
    MATCH path = (s:CloudWANSegment {{arn: $src}})
                 -[:CONNECTS_TO*1..5]-
                 (t:CloudWANSegment {{arn: $tgt}})
    {where}
    RETURN [node in nodes(path) |
        {{name: node.name, arn: node.arn,
         deny_filter: node.deny_filter}}
    ] AS segments
    ORDER BY length(path) ASC
    LIMIT 1
    """
    results = await neo4j.query(query, {
        "src": source_arn, "tgt": target_arn,
    })
    return results[0] if results else None


async def find_any_path(
    neo4j,  # noqa: ANN001
    source_arn: str,
    target_arn: str,
) -> dict | None:
    """Find shortest path ignoring deny-filters (fallback).

    Used to show the user which path exists and why it's
    blocked, when no deny-filter-clean path is available.

    Returns:
        Dict with segments list, or None if no path at all.
    """
    query = """
    MATCH path = (s:CloudWANSegment {arn: $src})
                 -[:CONNECTS_TO*1..5]-
                 (t:CloudWANSegment {arn: $tgt})
    RETURN [node in nodes(path) |
        {name: node.name, arn: node.arn,
         deny_filter: node.deny_filter}
    ] AS segments
    ORDER BY length(path) ASC
    LIMIT 1
    """
    results = await neo4j.query(query, {
        "src": source_arn, "tgt": target_arn,
    })
    return results[0] if results else None


async def check_direct_share(
    neo4j,  # noqa: ANN001
    source_arn: str,
    target_arn: str,
) -> list[dict]:
    """Check for direct CONNECTS_TO edge between segments."""
    query = """
    MATCH (s:CloudWANSegment {arn: $src})
          -[r:CONNECTS_TO]-
          (t:CloudWANSegment {arn: $tgt})
    RETURN s.name AS src, t.name AS tgt,
           r.mode AS mode, r.type AS type,
           s.deny_filter AS src_deny_filter,
           t.deny_filter AS tgt_deny_filter,
           CASE WHEN startNode(r) = s
               THEN 'outgoing' ELSE 'incoming'
           END AS direction
    """
    return await neo4j.query(query, {
        "src": source_arn, "tgt": target_arn,
    })


async def get_segment_attachments(
    neo4j,  # noqa: ANN001
    segment_arn: str,
) -> list[dict]:
    """Get attachments in a segment."""
    query = """
    MATCH (att:CloudWANAttachment)-[:PART_OF]->
          (seg:CloudWANSegment {arn: $arn})
    RETURN att.name AS name,
           att.attachment_type AS type,
           att.attachment_id AS att_id,
           att.owner_account_id AS account_id
    ORDER BY att.name
    """
    return await neo4j.query(query, {"arn": segment_arn})


def format_attachments(
    label: str,
    segment_name: str,
    attachments: list[dict],
) -> list[str]:
    """Format attachment list for output."""
    lines = [f"\n{label} segment attachments ({segment_name}):"]
    if not attachments:
        lines.append("  (none)")
        return lines
    for att in attachments:
        lines.append(
            f"  - {att['name']} ({att['type']}, "
            f"{att['att_id']}, account {att['account_id']})"
        )
    return lines


def analyze_direction(
    path_segments: list[dict],
    forward: bool = True,
) -> dict:
    """Analyze one direction of route propagation along a path.

    deny-filter = route IMPORT filter. A segment with a deny-filter
    listing segment X will NOT import routes from X.

    For forward direction (A->B) through path [A, X, Y, B]:
      - Does X deny-filter A? If yes, X won't import A's routes
      - Does Y deny-filter X? If yes, Y won't get routes from X
      - Does B deny-filter Y? If yes, B won't get routes from Y

    For return direction, the path is reversed.

    Args:
        path_segments: List of segment dicts with name, arn,
            deny_filter fields. Ordered from source to target.
        forward: If True, analyze forward. If False, reverse.

    Returns:
        Dict with verdict, blocked_at, blocked_by, reason.
    """
    directed = (
        path_segments if forward
        else list(reversed(path_segments))
    )

    for i in range(1, len(directed)):
        importing_seg = directed[i]
        exporting_seg = directed[i - 1]
        deny_filter = importing_seg.get("deny_filter") or []

        if exporting_seg["name"] in deny_filter:
            return {
                "verdict": "BLOCKED",
                "blocked_at": importing_seg["name"],
                "blocked_by": exporting_seg["name"],
                "reason": (
                    f"{importing_seg['name']} has deny-filter"
                    f" blocking route imports from"
                    f" {exporting_seg['name']}"
                ),
            }

    return {
        "verdict": "REACHABLE",
        "blocked_at": "",
        "blocked_by": "",
        "reason": "Route propagation chain unbroken",
    }


def check_hard_denies_on_path(
    path_segments: list[dict],
    hard_denies: list[dict],
) -> dict | None:
    """Check if any segment-action deny exists on path.

    Args:
        path_segments: Ordered path segments.
        hard_denies: List of DENIES edges with
            type=segment_action_deny.

    Returns:
        Dict with info if blocked, None if no hard deny.
    """
    seg_names = {s["name"] for s in path_segments}
    for deny in hard_denies:
        if (
            deny.get("type") == "segment_action_deny"
            and deny["src"] in seg_names
            and deny["tgt"] in seg_names
        ):
            return {
                "src": deny["src"],
                "tgt": deny["tgt"],
            }
    return None
