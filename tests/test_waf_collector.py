"""Tests for WAFv2 WebACL collector."""

from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from src.collector.waf import (
    WAFCollector,
    _extract_fm_rules,
    _extract_managed_groups,
    _parse_default_action,
    _summarize_rules,
)
from src.graph.model import NodeLabel, RelationshipType


def _make_collector(regions: list[str] | None = None):
    """Create a WAFCollector with a mocked session."""
    session = MagicMock()
    return WAFCollector(
        session=session,
        account_id="123456789012",
        regions=regions or ["us-west-2"],
    )


def _make_acl_summary(
    name: str = "test-acl",
    acl_id: str = "abc-123",
    arn: str = "",
) -> dict:
    if not arn:
        arn = (
            "arn:aws:wafv2:us-west-2:123456789012"
            ":regional/webacl/test-acl/abc-123"
        )
    return {"Name": name, "Id": acl_id, "ARN": arn}


def _make_acl_detail(
    name: str = "test-acl",
    rules: list | None = None,
    default_allow: bool = True,
    capacity: int = 100,
    description: str = "Test ACL",
) -> dict:
    action = {"Allow": {}} if default_allow else {"Block": {}}
    return {
        "WebACL": {
            "Name": name,
            "Rules": rules or [],
            "DefaultAction": action,
            "Capacity": capacity,
            "Description": description,
        },
    }


def _client_error(
    code: str = "AccessDeniedException",
) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": "denied"}},
        "operation",
    )


def _scope_aware_list(
    regional_acls: list | None = None,
    cloudfront_acls: list | None = None,
):
    """Return a side_effect function for list_web_acls."""
    def _fn(**kwargs):
        scope = kwargs.get("Scope", "REGIONAL")
        if scope == "CLOUDFRONT":
            return {"WebACLs": cloudfront_acls or []}
        return {"WebACLs": regional_acls or []}
    return _fn


class TestWAFHappyPath:
    """Happy path tests for WAF collector."""

    def test_regional_acl_node_created(self):
        """Regional WebACL creates node with correct properties."""
        collector = _make_collector()
        client = MagicMock()
        collector.client = MagicMock(return_value=client)

        client.list_web_acls.side_effect = _scope_aware_list(
            regional_acls=[_make_acl_summary()],
        )
        client.get_web_acl.return_value = _make_acl_detail(
            rules=[
                {
                    "Name": "RateLimit",
                    "Statement": {
                        "RateBasedStatement": {"Limit": 2000},
                    },
                },
            ],
            capacity=150,
        )
        client.list_resources_for_web_acl.return_value = {
            "ResourceArns": [],
        }

        nodes, edges = collector.collect()

        assert len(nodes) == 1
        node = nodes[0]
        assert node.label == NodeLabel.WAF_WEB_ACL
        assert node.name == "test-acl"
        assert node.region == "us-west-2"
        assert node.properties["scope"] == "REGIONAL"
        assert node.properties["capacity"] == 150
        assert node.properties["default_action"] == "Allow"
        assert node.properties["rule_count"] == 1
        assert "RateLimit:2000" in node.properties["rules_summary"]

    def test_protects_edges_for_associated_albs(self):
        """PROTECTS edges created for associated resources."""
        collector = _make_collector()
        client = MagicMock()
        collector.client = MagicMock(return_value=client)

        acl_arn = (
            "arn:aws:wafv2:us-west-2:123456789012"
            ":regional/webacl/test-acl/abc-123"
        )
        alb_arn = (
            "arn:aws:elasticloadbalancing:us-west-2"
            ":123456789012:loadbalancer/app/my-alb/abc"
        )

        client.list_web_acls.side_effect = _scope_aware_list(
            regional_acls=[_make_acl_summary(arn=acl_arn)],
        )
        client.get_web_acl.return_value = _make_acl_detail()
        client.list_resources_for_web_acl.return_value = {
            "ResourceArns": [alb_arn],
        }

        nodes, edges = collector.collect()

        protects = [
            e for e in edges
            if e.relationship == RelationshipType.PROTECTS
        ]
        assert len(protects) == 1
        assert protects[0].source_arn == acl_arn
        assert protects[0].target_arn == alb_arn

    def test_cloudfront_scoped_acl_uses_global_region(self):
        """CloudFront-scoped WebACL gets region='global'."""
        collector = _make_collector(regions=[])
        collector.regions = []
        client = MagicMock()
        collector.client = MagicMock(return_value=client)

        cf_arn = (
            "arn:aws:wafv2:us-east-1:123456789012"
            ":global/webacl/cf-acl/def-456"
        )
        client.list_web_acls.side_effect = _scope_aware_list(
            cloudfront_acls=[
                _make_acl_summary(
                    name="cf-acl", acl_id="def-456",
                    arn=cf_arn,
                ),
            ],
        )
        client.get_web_acl.return_value = _make_acl_detail(
            name="cf-acl",
        )
        client.list_resources_for_web_acl.return_value = {
            "ResourceArns": [],
        }

        nodes, edges = collector.collect()

        assert len(nodes) == 1
        assert nodes[0].region == "global"
        assert nodes[0].properties["scope"] == "CLOUDFRONT"

    def test_managed_rule_groups_extracted(self):
        """Managed rule group names appear in properties."""
        collector = _make_collector()
        client = MagicMock()
        collector.client = MagicMock(return_value=client)

        rules = [
            {
                "Name": "AWS-CommonRuleSet",
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesCommonRuleSet",
                    },
                },
            },
            {
                "Name": "AWS-SQLi",
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "AWSManagedRulesSQLiRuleSet",
                    },
                },
            },
        ]

        client.list_web_acls.side_effect = _scope_aware_list(
            regional_acls=[_make_acl_summary()],
        )
        client.get_web_acl.return_value = _make_acl_detail(
            rules=rules,
        )
        client.list_resources_for_web_acl.return_value = {
            "ResourceArns": [],
        }

        nodes, _ = collector.collect()

        groups = nodes[0].properties["managed_rule_groups"]
        assert "AWS/AWSManagedRulesCommonRuleSet" in groups
        assert "AWS/AWSManagedRulesSQLiRuleSet" in groups


class TestWAFEdgeCases:
    """Edge case tests for WAF collector."""

    def test_no_web_acls_returns_empty(self):
        """Empty list_web_acls returns no nodes."""
        collector = _make_collector()
        client = MagicMock()
        collector.client = MagicMock(return_value=client)

        client.list_web_acls.side_effect = _scope_aware_list()

        nodes, edges = collector.collect()

        assert len(nodes) == 0

    def test_acl_with_no_associations(self):
        """WebACL with no resources still creates node."""
        collector = _make_collector()
        client = MagicMock()
        collector.client = MagicMock(return_value=client)

        client.list_web_acls.side_effect = _scope_aware_list(
            regional_acls=[_make_acl_summary()],
        )
        client.get_web_acl.return_value = _make_acl_detail()
        client.list_resources_for_web_acl.return_value = {
            "ResourceArns": [],
        }

        nodes, edges = collector.collect()

        assert len(nodes) == 1
        protects = [
            e for e in edges
            if e.relationship == RelationshipType.PROTECTS
        ]
        assert len(protects) == 0
        belongs = [
            e for e in edges
            if e.relationship == RelationshipType.BELONGS_TO
        ]
        assert len(belongs) == 1


class TestWAFErrors:
    """Error handling tests for WAF collector."""

    def test_list_web_acls_error_handled(self):
        """ClientError on list_web_acls is caught gracefully."""
        collector = _make_collector()
        client = MagicMock()
        collector.client = MagicMock(return_value=client)

        client.list_web_acls.side_effect = _client_error()

        nodes, edges = collector.collect()

        assert len(nodes) == 0
        assert len(edges) == 0

    def test_get_web_acl_error_skips_acl(self):
        """ClientError on get_web_acl skips that ACL."""
        collector = _make_collector()
        client = MagicMock()
        collector.client = MagicMock(return_value=client)

        def _list_side_effect(**kwargs):
            scope = kwargs.get("Scope", "REGIONAL")
            if scope == "REGIONAL":
                return {
                    "WebACLs": [
                        _make_acl_summary(name="good-acl"),
                        _make_acl_summary(name="bad-acl"),
                    ],
                }
            return {"WebACLs": []}

        client.list_web_acls.side_effect = _list_side_effect
        client.get_web_acl.side_effect = [
            _make_acl_detail(name="good-acl"),
            _client_error(),
        ]
        client.list_resources_for_web_acl.return_value = {
            "ResourceArns": [],
        }

        nodes, edges = collector.collect()

        assert len(nodes) == 1
        assert nodes[0].name == "good-acl"


class TestHelperFunctions:
    """Tests for module-level helper functions."""

    def test_parse_default_action_allow(self):
        assert _parse_default_action(
            {"DefaultAction": {"Allow": {}}},
        ) == "Allow"

    def test_parse_default_action_block(self):
        assert _parse_default_action(
            {"DefaultAction": {"Block": {}}},
        ) == "Block"

    def test_parse_default_action_unknown(self):
        assert _parse_default_action({}) == "unknown"

    def test_extract_managed_groups(self):
        rules = [
            {
                "Name": "r1",
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "VendorName": "AWS",
                        "Name": "CommonRuleSet",
                    },
                },
            },
            {
                "Name": "r2",
                "Statement": {"RateBasedStatement": {}},
            },
        ]
        groups = _extract_managed_groups(rules)
        assert groups == ["AWS/CommonRuleSet"]

    def test_summarize_rules_mixed(self):
        rules = [
            {
                "Name": "managed",
                "Statement": {
                    "ManagedRuleGroupStatement": {
                        "Name": "CommonRuleSet",
                    },
                },
            },
            {
                "Name": "rate",
                "Statement": {
                    "RateBasedStatement": {"Limit": 5000},
                },
            },
            {
                "Name": "custom-block",
                "Statement": {},
            },
        ]
        summary = _summarize_rules(rules)
        assert summary == (
            "CommonRuleSet, RateLimit:5000, custom-block"
        )

    def test_summarize_rules_empty(self):
        assert _summarize_rules([]) == "(no rules)"

    def test_summarize_rules_rule_group_reference(self):
        """RuleGroupReferenceStatement extracts name from ARN."""
        rules = [{
            "Name": "fm-rule",
            "Statement": {
                "RuleGroupReferenceStatement": {
                    "ARN": (
                        "arn:aws:wafv2:us-east-1:111:regional"
                        "/rulegroup/custom-block-list/abc"
                    ),
                },
            },
        }]
        assert _summarize_rules(rules) == (
            "RuleGroup:abc"
        )

    def test_extract_fm_rules_pre_and_post(self):
        """Extracts rules from both Pre and Post FM groups."""
        acl = {
            "PreProcessFirewallManagerRuleGroups": [
                {
                    "Name": "pre-rule",
                    "FirewallManagerStatement": {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": "AWSManagedRulesCommonRuleSet",
                        },
                    },
                },
            ],
            "PostProcessFirewallManagerRuleGroups": [
                {
                    "Name": "post-rule",
                    "FirewallManagerStatement": {
                        "RuleGroupReferenceStatement": {
                            "ARN": "arn:aws:wafv2:us-east-1:111"
                            ":regional/rulegroup/block/xyz",
                        },
                    },
                },
            ],
        }
        fm_rules = _extract_fm_rules(acl)
        assert len(fm_rules) == 2
        assert fm_rules[0]["Name"] == "pre-rule"
        assert "ManagedRuleGroupStatement" in fm_rules[0]["Statement"]
        assert fm_rules[1]["Name"] == "post-rule"
        assert "RuleGroupReferenceStatement" in fm_rules[1]["Statement"]

    def test_extract_fm_rules_empty(self):
        """No FM groups returns empty list."""
        assert _extract_fm_rules({}) == []
        assert _extract_fm_rules({"Rules": [{"Name": "x"}]}) == []

    def test_fm_rules_included_in_collection(self):
        """FM-managed ACL includes FM rules in node properties."""
        collector = _make_collector()
        client = MagicMock()
        collector.client = MagicMock(return_value=client)

        client.list_web_acls.side_effect = _scope_aware_list(
            regional_acls=[_make_acl_summary()],
        )
        client.get_web_acl.return_value = {
            "WebACL": {
                "Name": "test-acl",
                "Rules": [],
                "DefaultAction": {"Allow": {}},
                "Capacity": 1300,
                "ManagedByFirewallManager": True,
                "PreProcessFirewallManagerRuleGroups": [
                    {
                        "Name": "fm-common",
                        "FirewallManagerStatement": {
                            "ManagedRuleGroupStatement": {
                                "VendorName": "AWS",
                                "Name": "CommonRuleSet",
                            },
                        },
                    },
                ],
                "PostProcessFirewallManagerRuleGroups": [],
            },
        }
        client.list_resources_for_web_acl.return_value = {
            "ResourceArns": [],
        }

        nodes, _ = collector.collect()

        assert len(nodes) == 1
        props = nodes[0].properties
        assert props["rule_count"] == 1
        assert "CommonRuleSet" in props["rules_summary"]
        assert "AWS/CommonRuleSet" in props["managed_rule_groups"]
        assert props["managed_by_firewall_manager"] is True
