"""CloudWAN policy parsing — segment-actions, deny rules, deny-filters."""

from __future__ import annotations

import structlog

from src.graph.model import (
    RelationshipType,
    ResourceEdge,
    ResourceNode,
)

logger = structlog.get_logger()


def process_policy(
    doc: dict,
    cn_id: str,
    cn_arn: str,
    account_id: str,
    nodes: list[ResourceNode],
) -> list[ResourceEdge]:
    """Parse policy document for segment-actions and attachment-policies.

    Args:
        doc: Parsed policy document JSON.
        cn_id: Core network ID.
        cn_arn: Core network ARN.
        account_id: AWS account ID of the management account.
        nodes: Node list (mutated to update core network properties).

    Returns:
        List of edges from segment-actions and deny-filters.
    """
    edges: list[ResourceEdge] = []

    # Process segment-actions (share rules)
    for action in doc.get("segment-actions", []):
        if action.get("action") == "share":
            edges.extend(
                edges_from_segment_action(
                    action, cn_id, account_id,
                ),
            )

    # Process segment-actions (deny rules)
    deny_rules: list[dict] = []
    for action in doc.get("segment-actions", []):
        if action.get("action") == "deny":
            edges.extend(
                edges_from_deny_action(
                    action, cn_id, account_id,
                ),
            )
            deny_rules.append({
                "segment": action.get("segment", ""),
                "segment_names": action.get(
                    "segment-names",
                    action.get("share-with", []),
                ),
                "mode": action.get("mode", ""),
            })

    # Store deny rules on core network node
    if deny_rules:
        set_deny_policy_rules(cn_arn, nodes, deny_rules)

    # Process create-route segment-actions
    static_routes: list[dict] = []
    for action in doc.get("segment-actions", []):
        if action.get("action") == "create-route":
            static_routes.append({
                "segment": action.get("segment", ""),
                "destination_cidr_blocks": action.get(
                    "destination-cidr-blocks", [],
                ),
            })

    if static_routes:
        _set_static_routes(cn_arn, nodes, static_routes)

    # Process deny-filter from segment definitions
    edges.extend(
        edges_from_deny_filters(
            doc.get("segments", []),
            cn_id,
            account_id,
            nodes,
        ),
    )

    # Store attachment-policies on the core network node
    att_rules = extract_attachment_rules(
        doc.get("attachment-policies", []),
    )
    if att_rules:
        set_attachment_policy_rules(cn_arn, nodes, att_rules)

    return edges


def edges_from_segment_action(
    action: dict,
    cn_id: str,
    account_id: str,
) -> list[ResourceEdge]:
    """Create CONNECTS_TO edges from a single segment-action share rule."""
    edges: list[ResourceEdge] = []
    source_seg = action.get("segment")
    share_with = action.get("share-with", [])
    mode = action.get("mode", "")

    if not source_seg:
        return edges

    source_arn = (
        f"arn:aws:networkmanager::{account_id}"
        f":core-network/{cn_id}/segment/{source_seg}"
    )

    for target_seg in share_with:
        if target_seg == "*":
            continue
        target_arn = (
            f"arn:aws:networkmanager::"
            f"{account_id}"
            f":core-network/{cn_id}"
            f"/segment/{target_seg}"
        )
        edges.append(ResourceEdge(
            source_arn=source_arn,
            target_arn=target_arn,
            relationship=RelationshipType.CONNECTS_TO,
            properties={
                "type": "segment_action",
                "mode": mode,
            },
        ))

    return edges


def edges_from_deny_action(
    action: dict,
    cn_id: str,
    account_id: str,
) -> list[ResourceEdge]:
    """Create DENIES edges from a segment-action deny rule."""
    edges: list[ResourceEdge] = []
    source_seg = action.get("segment")
    targets = action.get(
        "segment-names",
        action.get("share-with", []),
    )
    mode = action.get("mode", "")

    if not source_seg:
        return edges

    source_arn = (
        f"arn:aws:networkmanager::{account_id}"
        f":core-network/{cn_id}/segment/{source_seg}"
    )

    for target_seg in targets:
        if target_seg == "*":
            continue
        target_arn = (
            f"arn:aws:networkmanager::"
            f"{account_id}"
            f":core-network/{cn_id}"
            f"/segment/{target_seg}"
        )
        edges.append(ResourceEdge(
            source_arn=source_arn,
            target_arn=target_arn,
            relationship=RelationshipType.DENIES,
            properties={
                "type": "segment_action_deny",
                "mode": mode,
            },
        ))

    return edges


def edges_from_deny_filters(
    segments: list[dict],
    cn_id: str,
    account_id: str,
    nodes: list[ResourceNode],
) -> list[ResourceEdge]:
    """Create DENIES edges from segment deny-filter lists.

    deny-filter is a route IMPORT filter on segment definitions.
    A deny-filter on segment X listing segment Y means:
    "X will NOT import routes from Y."

    Creates a DENIES edge from X to Y with direction property
    indicating X blocks importing routes from Y.
    Also stores deny_filter list on segment nodes.
    """
    edges: list[ResourceEdge] = []

    for seg_def in segments:
        seg_name = seg_def.get("name", "")
        deny_filter = seg_def.get("deny-filter", [])
        if not seg_name or not deny_filter:
            continue

        # Store deny_filter on the segment node
        seg_arn = (
            f"arn:aws:networkmanager::"
            f"{account_id}"
            f":core-network/{cn_id}"
            f"/segment/{seg_name}"
        )
        for node in nodes:
            if node.arn == seg_arn:
                node.properties["deny_filter"] = deny_filter
                break

        for denied_seg in deny_filter:
            denied_arn = (
                f"arn:aws:networkmanager::"
                f"{account_id}"
                f":core-network/{cn_id}"
                f"/segment/{denied_seg}"
            )
            edges.append(ResourceEdge(
                source_arn=seg_arn,
                target_arn=denied_arn,
                relationship=RelationshipType.DENIES,
                properties={
                    "type": "deny_filter",
                    "direction": "blocks_import_from",
                },
            ))

    return edges


def extract_attachment_rules(
    policies: list[dict],
) -> list[dict]:
    """Extract attachment policy rules as compact dicts."""
    rules: list[dict] = []
    for policy in policies:
        rule = {
            "rule_number": policy.get(
                "rule-number", 0,
            ),
            "segment": (
                policy.get("action", {})
                .get("association-method", "") == "constant"
                and policy.get("action", {}).get("segment", "")
                or policy.get("action", {}).get("segment", "")
            ),
            "conditions": policy.get("conditions", []),
        }
        rules.append(rule)
    return rules


def set_attachment_policy_rules(
    cn_arn: str,
    nodes: list[ResourceNode],
    rules: list[dict],
) -> None:
    """Set attachment_policy_rules on the core network node."""
    for node in nodes:
        if node.arn == cn_arn:
            node.properties["attachment_policy_rules"] = rules
            break


def set_deny_policy_rules(
    cn_arn: str,
    nodes: list[ResourceNode],
    rules: list[dict],
) -> None:
    """Set deny_policy_rules on the core network node."""
    for node in nodes:
        if node.arn == cn_arn:
            node.properties["deny_policy_rules"] = rules
            break


def _set_static_routes(
    cn_arn: str,
    nodes: list[ResourceNode],
    routes: list[dict],
) -> None:
    """Set static_routes on the core network node."""
    for node in nodes:
        if node.arn == cn_arn:
            node.properties["static_routes"] = routes
            break
