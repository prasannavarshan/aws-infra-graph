"""Tests for Route53 Resolver collector."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.collector.route53_resolver import Route53ResolverCollector
from src.graph.model import NodeLabel, RelationshipType


def _make_collector(
    account_id: str = "111111111111",
    regions: list[str] | None = None,
) -> Route53ResolverCollector:
    """Create a collector with a mock session."""
    session = MagicMock()
    return Route53ResolverCollector(
        session=session,
        account_id=account_id,
        regions=regions or ["us-west-2"],
    )


def _mock_client():
    """Create a mock route53resolver client."""
    client = MagicMock()

    # list_resolver_endpoints paginator
    ep_paginator = MagicMock()
    ep_paginator.paginate.return_value = [{
        "ResolverEndpoints": [
            {
                "Id": "rslvr-in-abc123",
                "Arn": (
                    "arn:aws:route53resolver:us-west-2"
                    ":111111111111"
                    ":resolver-endpoint/rslvr-in-abc123"
                ),
                "Name": "inbound-onprem",
                "Direction": "INBOUND",
                "Status": "OPERATIONAL",
                "HostVPCId": "vpc-shared-001",
                "IpAddressCount": 2,
                "SecurityGroupIds": ["sg-resolver-01"],
            },
        ],
    }]

    # list_resolver_endpoint_ip_addresses paginator
    ip_paginator = MagicMock()
    ip_paginator.paginate.return_value = [{
        "IpAddresses": [
            {"Ip": "10.0.1.50", "SubnetId": "subnet-a"},
            {"Ip": "10.0.2.50", "SubnetId": "subnet-b"},
        ],
    }]

    # list_resolver_rules paginator
    rule_paginator = MagicMock()
    rule_paginator.paginate.return_value = [{
        "ResolverRules": [
            {
                "Id": "rslvr-rr-fwd001",
                "Arn": (
                    "arn:aws:route53resolver:us-west-2"
                    ":111111111111"
                    ":resolver-rule/rslvr-rr-fwd001"
                ),
                "Name": "forward-corp-dns",
                "RuleType": "FORWARD",
                "DomainName": "corp.example.com.",
                "Status": "COMPLETE",
                "ResolverEndpointId": "rslvr-out-xyz789",
                "OwnerId": "111111111111",
                "ShareStatus": "NOT_SHARED",
                "TargetIps": [
                    {"Ip": "172.16.0.53", "Port": 53},
                    {"Ip": "172.16.1.53", "Port": 53},
                ],
            },
        ],
    }]

    # list_resolver_rule_associations paginator
    assoc_paginator = MagicMock()
    assoc_paginator.paginate.return_value = [{
        "ResolverRuleAssociations": [
            {
                "ResolverRuleId": "rslvr-rr-fwd001",
                "VPCId": "vpc-app-001",
                "Status": "COMPLETE",
            },
            {
                "ResolverRuleId": "rslvr-rr-fwd001",
                "VPCId": "vpc-app-002",
                "Status": "COMPLETE",
            },
        ],
    }]

    def _get_paginator(name):
        return {
            "list_resolver_endpoints": ep_paginator,
            "list_resolver_endpoint_ip_addresses": ip_paginator,
            "list_resolver_rules": rule_paginator,
            "list_resolver_rule_associations": assoc_paginator,
        }[name]

    client.get_paginator = _get_paginator
    client.list_tags_for_resource.return_value = {"Tags": []}
    return client


class TestResolverEndpoints:
    """Tests for resolver endpoint collection."""

    def test_happy_path(self):
        """Should collect endpoint with IPs, VPC, and SG edges."""
        collector = _make_collector()
        mock_cl = _mock_client()

        with patch.object(
            collector, "client", return_value=mock_cl,
        ):
            nodes, edges = collector.collect_in_region(
                "us-west-2",
            )

        ep_nodes = [
            n for n in nodes
            if n.label == NodeLabel.RESOLVER_ENDPOINT
        ]
        assert len(ep_nodes) == 1
        ep = ep_nodes[0]
        assert ep.name == "inbound-onprem"
        assert ep.properties["direction"] == "INBOUND"
        assert ep.properties["vpc_id"] == "vpc-shared-001"
        assert ep.properties["ip_addresses"] == [
            "10.0.1.50", "10.0.2.50",
        ]

        # VPC edge
        vpc_edges = [
            e for e in edges
            if (
                e.source_arn == ep.arn
                and e.relationship == RelationshipType.PART_OF
                and "vpc/vpc-shared-001" in e.target_arn
            )
        ]
        assert len(vpc_edges) == 1

        # SG edge
        sg_edges = [
            e for e in edges
            if (
                e.source_arn == ep.arn
                and e.relationship == RelationshipType.HAS_SG
                and "sg-resolver-01" in e.target_arn
            )
        ]
        assert len(sg_edges) == 1

    def test_endpoint_ip_failure(self):
        """Should handle IP listing failure gracefully."""
        from botocore.exceptions import ClientError

        collector = _make_collector()
        mock_cl = _mock_client()

        # Make IP listing fail
        ip_pag = MagicMock()
        ip_pag.paginate.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}},
            "ListResolverEndpointIpAddresses",
        )
        original_get_pag = mock_cl.get_paginator

        def _patched_pag(name):
            if name == "list_resolver_endpoint_ip_addresses":
                return ip_pag
            return original_get_pag(name)

        mock_cl.get_paginator = _patched_pag

        with patch.object(
            collector, "client", return_value=mock_cl,
        ):
            nodes, edges = collector.collect_in_region(
                "us-west-2",
            )

        ep_nodes = [
            n for n in nodes
            if n.label == NodeLabel.RESOLVER_ENDPOINT
        ]
        assert len(ep_nodes) == 1
        assert ep_nodes[0].properties["ip_addresses"] == []


class TestResolverRules:
    """Tests for resolver rule collection."""

    def test_happy_path(self):
        """Should collect rule with VPC associations."""
        collector = _make_collector()
        mock_cl = _mock_client()

        with patch.object(
            collector, "client", return_value=mock_cl,
        ):
            nodes, edges = collector.collect_in_region(
                "us-west-2",
            )

        rule_nodes = [
            n for n in nodes
            if n.label == NodeLabel.RESOLVER_RULE
        ]
        assert len(rule_nodes) == 1
        rule = rule_nodes[0]
        assert rule.name == "forward-corp-dns"
        assert rule.properties["domain_name"] == "corp.example.com."
        assert rule.properties["target_ips"] == [
            "172.16.0.53", "172.16.1.53",
        ]

        # ROUTES_TO endpoint edge
        routes_to = [
            e for e in edges
            if (
                e.source_arn == rule.arn
                and e.relationship == RelationshipType.ROUTES_TO
            )
        ]
        assert len(routes_to) == 1
        assert "rslvr-out-xyz789" in routes_to[0].target_arn

        # ASSOCIATED_WITH VPC edges
        assoc_edges = [
            e for e in edges
            if (
                e.source_arn == rule.arn
                and e.relationship
                == RelationshipType.ASSOCIATED_WITH
            )
        ]
        assert len(assoc_edges) == 2
        vpc_ids = {
            e.properties["vpc_id"] for e in assoc_edges
        }
        assert vpc_ids == {"vpc-app-001", "vpc-app-002"}

    def test_collection_failure(self):
        """Should handle API failure gracefully."""
        from botocore.exceptions import ClientError

        collector = _make_collector()
        mock_cl = MagicMock()
        mock_cl.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}},
            "ListResolverEndpoints",
        )

        with patch.object(
            collector, "client", return_value=mock_cl,
        ):
            nodes, edges = collector.collect_in_region(
                "us-west-2",
            )

        assert nodes == []
        assert edges == []
