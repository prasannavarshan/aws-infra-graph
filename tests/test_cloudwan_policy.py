"""Tests for CloudWAN policy parsing."""

from src.collector.cloudwan_policy import (
    _set_static_routes,
    edges_from_deny_action,
    edges_from_deny_filters,
    edges_from_segment_action,
    extract_attachment_rules,
    process_policy,
    set_attachment_policy_rules,
    set_deny_policy_rules,
)
from src.graph.model import (
    NodeLabel,
    RelationshipType,
    ResourceNode,
)

CN_ID = "cn-0abc123"
CN_ARN = "arn:aws:networkmanager::123456789012:core-network/cn-0abc123"
ACCOUNT_ID = "123456789012"


def _seg_arn(name: str) -> str:
    return (
        f"arn:aws:networkmanager::{ACCOUNT_ID}"
        f":core-network/{CN_ID}/segment/{name}"
    )


def _make_cn_node() -> ResourceNode:
    return ResourceNode(
        arn=CN_ARN,
        name="test-core-network",
        label=NodeLabel.CLOUDWAN_CORE_NETWORK,
        account_id=ACCOUNT_ID,
        region="global",
    )


class TestEdgesFromSegmentAction:
    """Tests for share rule -> CONNECTS_TO edges."""

    def test_share_creates_connects_to_edges(self):
        action = {
            "segment": "prod",
            "share-with": ["shared", "mgmt"],
            "mode": "attachment-route",
        }
        edges = edges_from_segment_action(action, CN_ID, ACCOUNT_ID)

        assert len(edges) == 2
        assert edges[0].source_arn == _seg_arn("prod")
        assert edges[0].target_arn == _seg_arn("shared")
        assert edges[0].relationship == RelationshipType.CONNECTS_TO
        assert edges[0].properties["mode"] == "attachment-route"

    def test_wildcard_target_skipped(self):
        action = {
            "segment": "prod",
            "share-with": ["*", "shared"],
        }
        edges = edges_from_segment_action(action, CN_ID, ACCOUNT_ID)

        assert len(edges) == 1
        assert edges[0].target_arn == _seg_arn("shared")

    def test_empty_segment_returns_no_edges(self):
        action = {"segment": "", "share-with": ["shared"]}
        edges = edges_from_segment_action(action, CN_ID, ACCOUNT_ID)
        assert edges == []

    def test_no_share_with_returns_no_edges(self):
        action = {"segment": "prod"}
        edges = edges_from_segment_action(action, CN_ID, ACCOUNT_ID)
        assert edges == []


class TestEdgesFromDenyAction:
    """Tests for deny rule -> DENIES edges."""

    def test_deny_creates_denies_edges(self):
        action = {
            "segment": "isolated",
            "segment-names": ["prod", "dev"],
            "mode": "attachment-route",
        }
        edges = edges_from_deny_action(action, CN_ID, ACCOUNT_ID)

        assert len(edges) == 2
        assert all(
            e.relationship == RelationshipType.DENIES
            for e in edges
        )
        assert edges[0].properties["type"] == "segment_action_deny"

    def test_deny_falls_back_to_share_with(self):
        action = {
            "segment": "isolated",
            "share-with": ["prod"],
        }
        edges = edges_from_deny_action(action, CN_ID, ACCOUNT_ID)

        assert len(edges) == 1
        assert edges[0].target_arn == _seg_arn("prod")

    def test_deny_wildcard_skipped(self):
        action = {
            "segment": "isolated",
            "segment-names": ["*"],
        }
        edges = edges_from_deny_action(action, CN_ID, ACCOUNT_ID)
        assert edges == []

    def test_deny_empty_segment_returns_no_edges(self):
        action = {"segment": "", "segment-names": ["prod"]}
        edges = edges_from_deny_action(action, CN_ID, ACCOUNT_ID)
        assert edges == []


class TestEdgesFromDenyFilters:
    """Tests for segment deny-filter -> DENIES edges."""

    def test_deny_filter_creates_edges(self):
        seg_node = ResourceNode(
            arn=_seg_arn("prod"),
            name="prod",
            label=NodeLabel.CLOUDWAN_SEGMENT,
            account_id=ACCOUNT_ID,
            region="global",
        )
        segments = [
            {"name": "prod", "deny-filter": ["dev", "staging"]},
        ]
        edges = edges_from_deny_filters(
            segments, CN_ID, ACCOUNT_ID, [seg_node],
        )

        assert len(edges) == 2
        assert edges[0].properties["type"] == "deny_filter"
        assert edges[0].properties["direction"] == "blocks_import_from"

    def test_deny_filter_mutates_node_properties(self):
        seg_node = ResourceNode(
            arn=_seg_arn("prod"),
            name="prod",
            label=NodeLabel.CLOUDWAN_SEGMENT,
            account_id=ACCOUNT_ID,
            region="global",
        )
        segments = [
            {"name": "prod", "deny-filter": ["dev"]},
        ]
        edges_from_deny_filters(
            segments, CN_ID, ACCOUNT_ID, [seg_node],
        )

        assert seg_node.properties["deny_filter"] == ["dev"]

    def test_empty_deny_filter_skipped(self):
        segments = [{"name": "prod", "deny-filter": []}]
        edges = edges_from_deny_filters(
            segments, CN_ID, ACCOUNT_ID, [],
        )
        assert edges == []

    def test_missing_name_skipped(self):
        segments = [{"deny-filter": ["dev"]}]
        edges = edges_from_deny_filters(
            segments, CN_ID, ACCOUNT_ID, [],
        )
        assert edges == []


class TestExtractAttachmentRules:
    """Tests for attachment policy extraction."""

    def test_extracts_rules(self):
        policies = [
            {
                "rule-number": 100,
                "action": {
                    "association-method": "constant",
                    "segment": "prod",
                },
                "conditions": [
                    {"type": "tag-value", "key": "env", "value": "prod"},
                ],
            },
        ]
        rules = extract_attachment_rules(policies)

        assert len(rules) == 1
        assert rules[0]["rule_number"] == 100
        assert rules[0]["segment"] == "prod"
        assert len(rules[0]["conditions"]) == 1

    def test_empty_policies(self):
        assert extract_attachment_rules([]) == []


class TestNodePropertyMutators:
    """Tests for set_attachment_policy_rules, set_deny_policy_rules,
    _set_static_routes."""

    def test_set_attachment_policy_rules(self):
        cn = _make_cn_node()
        rules = [{"rule_number": 100, "segment": "prod"}]
        set_attachment_policy_rules(CN_ARN, [cn], rules)
        assert cn.properties["attachment_policy_rules"] == rules

    def test_set_deny_policy_rules(self):
        cn = _make_cn_node()
        rules = [{"segment": "isolated", "segment_names": ["prod"]}]
        set_deny_policy_rules(CN_ARN, [cn], rules)
        assert cn.properties["deny_policy_rules"] == rules

    def test_set_static_routes(self):
        cn = _make_cn_node()
        routes = [{"segment": "prod", "destination_cidr_blocks": ["10.0.0.0/8"]}]
        _set_static_routes(CN_ARN, [cn], routes)
        assert cn.properties["static_routes"] == routes

    def test_no_matching_node_is_noop(self):
        cn = _make_cn_node()
        set_attachment_policy_rules(
            "arn:aws:networkmanager::999:core-network/other",
            [cn],
            [{"rule_number": 1}],
        )
        assert "attachment_policy_rules" not in cn.properties


class TestProcessPolicy:
    """Integration tests for the full process_policy orchestrator."""

    def test_full_policy_processing(self):
        cn = _make_cn_node()
        doc = {
            "segment-actions": [
                {
                    "action": "share",
                    "segment": "prod",
                    "share-with": ["shared"],
                    "mode": "attachment-route",
                },
                {
                    "action": "deny",
                    "segment": "isolated",
                    "segment-names": ["prod"],
                    "mode": "attachment-route",
                },
                {
                    "action": "create-route",
                    "segment": "prod",
                    "destination-cidr-blocks": ["10.0.0.0/8"],
                },
            ],
            "segments": [
                {"name": "prod", "deny-filter": ["dev"]},
            ],
            "attachment-policies": [
                {
                    "rule-number": 100,
                    "action": {
                        "association-method": "constant",
                        "segment": "prod",
                    },
                    "conditions": [],
                },
            ],
        }

        prod_seg = ResourceNode(
            arn=_seg_arn("prod"),
            name="prod",
            label=NodeLabel.CLOUDWAN_SEGMENT,
            account_id=ACCOUNT_ID,
            region="global",
        )
        nodes = [cn, prod_seg]
        edges = process_policy(doc, CN_ID, CN_ARN, ACCOUNT_ID, nodes)

        # 1 CONNECTS_TO from share + 1 DENIES from deny action + 1 DENIES from deny-filter
        connects = [
            e for e in edges
            if e.relationship == RelationshipType.CONNECTS_TO
        ]
        denies = [
            e for e in edges
            if e.relationship == RelationshipType.DENIES
        ]
        assert len(connects) == 1
        assert len(denies) == 2

        # Check node mutations
        assert "deny_policy_rules" in cn.properties
        assert "static_routes" in cn.properties
        assert "attachment_policy_rules" in cn.properties
        assert prod_seg.properties["deny_filter"] == ["dev"]

    def test_empty_policy_document(self):
        cn = _make_cn_node()
        edges = process_policy({}, CN_ID, CN_ARN, ACCOUNT_ID, [cn])
        assert edges == []

    def test_only_share_actions(self):
        cn = _make_cn_node()
        doc = {
            "segment-actions": [
                {
                    "action": "share",
                    "segment": "a",
                    "share-with": ["b", "c"],
                },
            ],
        }
        edges = process_policy(doc, CN_ID, CN_ARN, ACCOUNT_ID, [cn])
        assert len(edges) == 2
        assert all(
            e.relationship == RelationshipType.CONNECTS_TO
            for e in edges
        )
