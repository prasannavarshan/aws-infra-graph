"""Tests for CloudWAN (Network Manager) collector."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from src.collector.cloudwan import CloudWANCollector


def _make_collector(
    core_networks: list[dict] | None = None,
    core_network_detail: dict | None = None,
    attachments: list[dict] | None = None,
    policy_document: dict | None = None,
    policy_error: str = "",
    error: str = "",
) -> CloudWANCollector:
    """Create a CloudWANCollector with stubbed networkmanager client.

    Args:
        core_networks: Core network summaries for list_core_networks.
        core_network_detail: Detail for get_core_network.
        attachments: Attachments for list_attachments.
        policy_document: Policy doc for get_core_network_policy.
        policy_error: Error code to raise on get_core_network_policy.
        error: Error code to raise on all paginator calls.
    """
    session = MagicMock()
    collector = CloudWANCollector(
        session=session,
        account_id="123456789012",
        regions=["us-west-2"],
    )

    mock_client = MagicMock()

    if error:
        def _get_paginator(operation: str):  # noqa: ANN202
            paginator = MagicMock()
            paginator.paginate.side_effect = ClientError(
                {"Error": {"Code": error, "Message": "test"}},
                operation,
            )
            return paginator

        mock_client.get_paginator.side_effect = _get_paginator
    else:
        def _get_paginator(operation: str):  # noqa: ANN202
            paginator = MagicMock()
            if operation == "list_core_networks":
                paginator.paginate.return_value = [
                    {
                        "CoreNetworks": core_networks or [],
                    },
                ]
            elif operation == "list_attachments":
                paginator.paginate.return_value = [
                    {"Attachments": attachments or []},
                ]
            return paginator

        mock_client.get_paginator.side_effect = _get_paginator

        if core_network_detail:
            mock_client.get_core_network.return_value = {
                "CoreNetwork": core_network_detail,
            }

        # Policy mock
        if policy_error:
            mock_client.get_core_network_policy.side_effect = (
                ClientError(
                    {
                        "Error": {
                            "Code": policy_error,
                            "Message": "test",
                        },
                    },
                    "GetCoreNetworkPolicy",
                )
            )
        elif policy_document is not None:
            mock_client.get_core_network_policy.return_value = {
                "CoreNetworkPolicy": {
                    "PolicyDocument": json.dumps(
                        policy_document,
                    ),
                },
            }
        else:
            # No policy configured — raise error to trigger fallback
            mock_client.get_core_network_policy.side_effect = (
                ClientError(
                    {
                        "Error": {
                            "Code": "ResourceNotFoundException",
                            "Message": "no policy",
                        },
                    },
                    "GetCoreNetworkPolicy",
                )
            )

    collector.client = MagicMock(return_value=mock_client)
    return collector


SAMPLE_CORE_NETWORK_SUMMARY = {
    "CoreNetworkId": "core-network-001",
}

SAMPLE_CORE_NETWORK_DETAIL = {
    "CoreNetworkId": "core-network-001",
    "CoreNetworkArn": (
        "arn:aws:networkmanager::123456789012"
        ":core-network/core-network-001"
    ),
    "State": "AVAILABLE",
    "GlobalNetworkId": "global-network-001",
    "Segments": [
        {
            "Name": "production",
            "EdgeLocations": ["us-west-2", "us-east-1"],
            "SharedSegments": ["shared-services"],
            "IsolateAttachments": False,
            "RequireAttachmentAcceptance": False,
        },
        {
            "Name": "shared-services",
            "EdgeLocations": ["us-west-2", "us-east-1"],
            "SharedSegments": [],
            "IsolateAttachments": False,
            "RequireAttachmentAcceptance": False,
        },
    ],
    "Edges": [
        {"EdgeLocation": "us-west-2"},
        {"EdgeLocation": "us-east-1"},
    ],
    "Tags": [{"Key": "Name", "Value": "main-core-network"}],
}

SAMPLE_POLICY_DOCUMENT = {
    "segment-actions": [
        {
            "action": "share",
            "segment": "OnPremWAN",
            "mode": "attachment-route",
            "share-with": [
                "SegmentDevelopment",
                "Production",
            ],
        },
        {
            "action": "share",
            "segment": "Production",
            "mode": "attachment-route",
            "share-with": ["OnPremWAN"],
        },
        {
            "action": "create-route",
            "segment": "something",
            "destination-cidr-blocks": ["10.0.0.0/8"],
        },
    ],
    "attachment-policies": [
        {
            "rule-number": 100,
            "action": {
                "association-method": "constant",
                "segment": "Production",
            },
            "conditions": [
                {
                    "type": "tag-value",
                    "key": "Segment",
                    "value": "prod",
                },
            ],
        },
        {
            "rule-number": 200,
            "action": {
                "association-method": "constant",
                "segment": "Development",
            },
            "conditions": [
                {
                    "type": "tag-value",
                    "key": "Segment",
                    "value": "dev",
                },
            ],
        },
    ],
}

SAMPLE_VPC_ATTACHMENT = {
    "AttachmentId": "attachment-vpc-001",
    "CoreNetworkId": "core-network-001",
    "AttachmentType": "VPC",
    "SegmentName": "production",
    "ResourceArn": (
        "arn:aws:ec2:us-west-2:111111111111:vpc/vpc-111"
    ),
    "OwnerAccountId": "111111111111",
    "EdgeLocation": "us-west-2",
    "State": "AVAILABLE",
    "Tags": [
        {"Key": "Name", "Value": "prod-vpc-attachment"},
    ],
}

SAMPLE_TGW_ATTACHMENT = {
    "AttachmentId": "attachment-tgw-001",
    "CoreNetworkId": "core-network-001",
    "AttachmentType": "TRANSIT_GATEWAY_ROUTE_TABLE",
    "SegmentName": "shared-services",
    "ResourceArn": (
        "arn:aws:ec2:us-west-2:123456789012"
        ":transit-gateway/tgw-0abc123"
    ),
    "OwnerAccountId": "123456789012",
    "EdgeLocation": "us-west-2",
    "State": "AVAILABLE",
    "Tags": [],
}


class TestCloudWANHappyPath:
    def test_collects_core_network(self):
        """Should collect Core Network node."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
        )
        nodes, edges = collector.collect()
        cn_nodes = [
            n for n in nodes
            if n.label.value == "CloudWANCoreNetwork"
        ]
        assert len(cn_nodes) == 1
        assert cn_nodes[0].name == "main-core-network"

    def test_collects_segments(self):
        """Should create segment nodes from core network."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
        )
        nodes, _ = collector.collect()
        seg_nodes = [
            n for n in nodes
            if n.label.value == "CloudWANSegment"
        ]
        assert len(seg_nodes) == 2
        names = {s.name for s in seg_nodes}
        assert "production" in names
        assert "shared-services" in names

    def test_segment_has_edge_locations(self):
        """Segment should have edge_locations property."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
        )
        nodes, _ = collector.collect()
        prod_seg = [
            n for n in nodes
            if n.name == "production"
        ][0]
        assert "us-west-2" in prod_seg.properties[
            "edge_locations"
        ]

    def test_has_segment_edges(self):
        """Core network should have HAS_SEGMENT edges."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
        )
        _, edges = collector.collect()
        has_seg = [
            e for e in edges
            if e.relationship.value == "HAS_SEGMENT"
        ]
        assert len(has_seg) == 2

    def test_shared_segment_connects_to(self):
        """SharedSegments fallback should create CONNECTS_TO edges."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
        )
        _, edges = collector.collect()
        connects = [
            e for e in edges
            if e.relationship.value == "CONNECTS_TO"
        ]
        # Fallback: production shares with shared-services
        assert len(connects) == 1
        assert "shared-services" in connects[0].target_arn

    def test_vpc_attachment(self):
        """VPC attachment should link to core network and segment."""
        collector = _make_collector(
            attachments=[SAMPLE_VPC_ATTACHMENT],
        )
        nodes, edges = collector.collect()
        att_nodes = [
            n for n in nodes
            if n.label.value == "CloudWANAttachment"
        ]
        assert len(att_nodes) == 1
        assert att_nodes[0].properties[
            "attachment_type"
        ] == "VPC"

        # Should have ATTACHED_TO core network, PART_OF segment,
        # ATTACHED_TO resource
        attached = [
            e for e in edges
            if e.relationship.value == "ATTACHED_TO"
        ]
        part_of = [
            e for e in edges
            if e.relationship.value == "PART_OF"
        ]
        assert len(attached) == 2  # core network + VPC
        assert len(part_of) == 1
        assert "production" in part_of[0].target_arn


class TestCloudWANPolicy:
    """Tests for CloudWAN policy-based segment-actions and attachment-policies."""

    def test_policy_segment_actions_create_connects_to(self):
        """Policy segment-actions with share create CONNECTS_TO edges."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_document=SAMPLE_POLICY_DOCUMENT,
        )
        _, edges = collector.collect()
        connects = [
            e for e in edges
            if e.relationship.value == "CONNECTS_TO"
        ]
        # OnPremWAN -> SegmentDevelopment, OnPremWAN -> Production
        # Production -> OnPremWAN
        assert len(connects) == 3
        # All should have type=segment_action
        for edge in connects:
            assert edge.properties["type"] == "segment_action"
            assert edge.properties["mode"] == "attachment-route"

    def test_attachment_policy_rules_stored_on_node(self):
        """Attachment policies stored as property on core network node."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_document=SAMPLE_POLICY_DOCUMENT,
        )
        nodes, _ = collector.collect()
        cn_node = [
            n for n in nodes
            if n.label.value == "CloudWANCoreNetwork"
        ][0]
        rules = cn_node.properties.get(
            "attachment_policy_rules",
        )
        assert rules is not None
        assert len(rules) == 2
        assert rules[0]["rule_number"] == 100
        assert rules[0]["segment"] == "Production"
        assert rules[1]["rule_number"] == 200
        assert rules[1]["segment"] == "Development"

    def test_policy_fetch_fails_falls_back_to_shared_segments(self):
        """When policy fetch fails, fall back to SharedSegments edges."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_error="AccessDeniedException",
        )
        _, edges = collector.collect()
        connects = [
            e for e in edges
            if e.relationship.value == "CONNECTS_TO"
        ]
        # Fallback: production -> shared-services from SharedSegments
        assert len(connects) == 1
        assert connects[0].properties["type"] == "shared_segment"
        assert "shared-services" in connects[0].target_arn

    def test_cross_segment_path_only_via_policy(self):
        """Two attachments in isolated segments are connected only via policy.

        Scenario: GIL on-prem attachment in OnPremWAN segment,
        Slingcore Beta attachment in SegmentDevelopment segment.
        SharedSegments is empty on both — only the policy segment-action
        share rule connects them. Without policy fetch, no CONNECTS_TO
        edge exists and the path is broken.
        """
        # Segments with NO SharedSegments (policy is the only link)
        cn_detail = {
            "CoreNetworkId": "core-network-001",
            "CoreNetworkArn": (
                "arn:aws:networkmanager::123456789012"
                ":core-network/core-network-001"
            ),
            "State": "AVAILABLE",
            "GlobalNetworkId": "global-network-001",
            "Segments": [
                {
                    "Name": "OnPremWAN",
                    "EdgeLocations": ["us-west-2"],
                    "SharedSegments": [],
                },
                {
                    "Name": "SegmentDevelopment",
                    "EdgeLocations": ["us-west-2"],
                    "SharedSegments": [],
                },
            ],
            "Edges": [{"EdgeLocation": "us-west-2"}],
            "Tags": [
                {"Key": "Name", "Value": "main-cn"},
            ],
        }
        gil_attachment = {
            "AttachmentId": "att-gil-onprem",
            "CoreNetworkId": "core-network-001",
            "AttachmentType": "CONNECT",
            "SegmentName": "OnPremWAN",
            "ResourceArn": "arn:aws:ec2:us-west-2:111:vpn/vpn-gil",
            "OwnerAccountId": "111111111111",
            "EdgeLocation": "us-west-2",
            "State": "AVAILABLE",
            "Tags": [
                {"Key": "Name", "Value": "GIL-OnPrem"},
            ],
        }
        sling_attachment = {
            "AttachmentId": "att-slingcore-beta",
            "CoreNetworkId": "core-network-001",
            "AttachmentType": "VPC",
            "SegmentName": "SegmentDevelopment",
            "ResourceArn": (
                "arn:aws:ec2:us-west-2:222:vpc/vpc-sling"
            ),
            "OwnerAccountId": "222222222222",
            "EdgeLocation": "us-west-2",
            "State": "AVAILABLE",
            "Tags": [
                {"Key": "Name", "Value": "SlingcoreBeta"},
            ],
        }
        policy = {
            "segment-actions": [
                {
                    "action": "share",
                    "segment": "OnPremWAN",
                    "mode": "attachment-route",
                    "share-with": ["SegmentDevelopment"],
                },
            ],
            "attachment-policies": [],
        }

        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=cn_detail,
            attachments=[gil_attachment, sling_attachment],
            policy_document=policy,
        )
        nodes, edges = collector.collect()

        # Verify the CONNECTS_TO edge exists
        connects = [
            e for e in edges
            if e.relationship.value == "CONNECTS_TO"
        ]
        assert len(connects) == 1
        assert "OnPremWAN" in connects[0].source_arn
        assert "SegmentDevelopment" in connects[0].target_arn
        assert connects[0].properties["type"] == "segment_action"

        # Verify the full traversable path exists:
        # GIL att -> PART_OF -> OnPremWAN -> CONNECTS_TO
        #   -> SegmentDevelopment <- PART_OF <- Sling att
        node_arns = {n.arn for n in nodes}
        edge_map = {
            (e.source_arn, e.target_arn): e.relationship.value
            for e in edges
        }

        gil_arn = (
            "arn:aws:networkmanager::111111111111"
            ":attachment/att-gil-onprem"
        )
        sling_arn = (
            "arn:aws:networkmanager::222222222222"
            ":attachment/att-slingcore-beta"
        )
        onprem_seg_arn = (
            "arn:aws:networkmanager::123456789012"
            ":core-network/core-network-001"
            "/segment/OnPremWAN"
        )
        sling_seg_arn = (
            "arn:aws:networkmanager::123456789012"
            ":core-network/core-network-001"
            "/segment/SegmentDevelopment"
        )

        # All nodes exist
        assert gil_arn in node_arns
        assert sling_arn in node_arns
        assert onprem_seg_arn in node_arns
        assert sling_seg_arn in node_arns

        # Path edges exist
        assert edge_map[(gil_arn, onprem_seg_arn)] == "PART_OF"
        assert edge_map[
            (onprem_seg_arn, sling_seg_arn)
        ] == "CONNECTS_TO"
        assert edge_map[
            (sling_arn, sling_seg_arn)
        ] == "PART_OF"

    def test_cross_segment_path_missing_without_policy(self):
        """Without policy, isolated segments have no CONNECTS_TO.

        Same scenario as above, but policy fetch fails.
        Since SharedSegments is empty, there's no CONNECTS_TO
        edge and the path between segments is broken.
        """
        cn_detail = {
            "CoreNetworkId": "core-network-001",
            "CoreNetworkArn": (
                "arn:aws:networkmanager::123456789012"
                ":core-network/core-network-001"
            ),
            "State": "AVAILABLE",
            "GlobalNetworkId": "global-network-001",
            "Segments": [
                {
                    "Name": "OnPremWAN",
                    "EdgeLocations": ["us-west-2"],
                    "SharedSegments": [],
                },
                {
                    "Name": "SegmentDevelopment",
                    "EdgeLocations": ["us-west-2"],
                    "SharedSegments": [],
                },
            ],
            "Edges": [{"EdgeLocation": "us-west-2"}],
            "Tags": [],
        }

        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=cn_detail,
            policy_error="AccessDeniedException",
        )
        _, edges = collector.collect()

        # No CONNECTS_TO edges — fallback has nothing
        connects = [
            e for e in edges
            if e.relationship.value == "CONNECTS_TO"
        ]
        assert len(connects) == 0

    def test_policy_no_segment_actions_no_connects_to(self):
        """Policy with no segment-actions produces no CONNECTS_TO edges."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_document={
                "segment-actions": [],
                "attachment-policies": [],
            },
        )
        _, edges = collector.collect()
        connects = [
            e for e in edges
            if e.relationship.value == "CONNECTS_TO"
        ]
        assert len(connects) == 0


class TestCloudWANDenyRules:
    """Tests for CloudWAN deny rule collection."""

    DENY_POLICY = {
        "segment-actions": [
            {
                "action": "share",
                "segment": "OnPremWAN",
                "mode": "attachment-route",
                "share-with": ["Production"],
            },
            {
                "action": "deny",
                "segment": "Isolated",
                "segment-names": [
                    "Production",
                    "Development",
                ],
                "mode": "",
            },
        ],
        "attachment-policies": [],
    }

    def test_deny_action_creates_denies_edges(self):
        """Deny segment-actions should create DENIES edges."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_document=self.DENY_POLICY,
        )
        _, edges = collector.collect()
        denies = [
            e for e in edges
            if e.relationship.value == "DENIES"
        ]
        assert len(denies) == 2
        targets = {e.target_arn.split("/")[-1] for e in denies}
        assert "Production" in targets
        assert "Development" in targets
        for edge in denies:
            assert edge.properties["type"] == "segment_action_deny"

    def test_deny_rules_stored_on_core_network_node(self):
        """Deny rules should be stored as property on core network."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_document=self.DENY_POLICY,
        )
        nodes, _ = collector.collect()
        cn_node = [
            n for n in nodes
            if n.label.value == "CloudWANCoreNetwork"
        ][0]
        rules = cn_node.properties.get("deny_policy_rules")
        assert rules is not None
        assert len(rules) == 1
        assert rules[0]["segment"] == "Isolated"
        assert "Production" in rules[0]["segment_names"]
        assert "Development" in rules[0]["segment_names"]

    def test_deny_with_share_with_key(self):
        """Deny using share-with key (alternative format)."""
        policy = {
            "segment-actions": [
                {
                    "action": "deny",
                    "segment": "Restricted",
                    "share-with": ["Public"],
                },
            ],
            "attachment-policies": [],
        }
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_document=policy,
        )
        _, edges = collector.collect()
        denies = [
            e for e in edges
            if e.relationship.value == "DENIES"
        ]
        assert len(denies) == 1
        assert "Public" in denies[0].target_arn


class TestCloudWANDenyFilter:
    """Tests for CloudWAN deny-filter on segment definitions."""

    DENY_FILTER_POLICY = {
        "segment-actions": [
            {
                "action": "share",
                "segment": "OnPremWAN",
                "mode": "attachment-route",
                "share-with": [
                    "NonProdImportFilter",
                    "OnPremProd",
                ],
            },
        ],
        "segments": [
            {
                "name": "OnPremWAN",
                "deny-filter": [
                    "NonProdImportFilter",
                    "ProdImportFilter",
                    "Fallback",
                ],
                "isolate-attachments": True,
            },
            {
                "name": "SegmentDevelopment",
                "deny-filter": [
                    "NonProdImportFilter",
                    "ProdImportFilter",
                ],
            },
            {
                "name": "NoDenyFilter",
            },
        ],
        "attachment-policies": [],
    }

    def test_deny_filter_creates_denies_edges(self):
        """deny-filter on segments creates DENIES edges."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_document=self.DENY_FILTER_POLICY,
        )
        _, edges = collector.collect()
        denies = [
            e for e in edges
            if e.relationship.value == "DENIES"
        ]
        # OnPremWAN denies 3, SegmentDevelopment denies 2
        assert len(denies) == 5
        for edge in denies:
            assert edge.properties["type"] == "deny_filter"

    def test_deny_filter_stored_on_segment_node(self):
        """deny-filter list stored as property on segment node."""
        # Use a detail where segment names match the policy
        cn_detail = {
            "CoreNetworkId": "core-network-001",
            "CoreNetworkArn": (
                "arn:aws:networkmanager::123456789012"
                ":core-network/core-network-001"
            ),
            "State": "AVAILABLE",
            "GlobalNetworkId": "global-network-001",
            "Segments": [
                {
                    "Name": "OnPremWAN",
                    "EdgeLocations": ["us-west-2"],
                    "SharedSegments": [],
                },
                {
                    "Name": "SegmentDevelopment",
                    "EdgeLocations": ["us-west-2"],
                    "SharedSegments": [],
                },
            ],
            "Edges": [{"EdgeLocation": "us-west-2"}],
            "Tags": [{"Key": "Name", "Value": "cn"}],
        }
        policy = {
            "segment-actions": [],
            "segments": [
                {
                    "name": "OnPremWAN",
                    "deny-filter": ["Fallback", "Prod"],
                },
            ],
            "attachment-policies": [],
        }
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=cn_detail,
            policy_document=policy,
        )
        nodes, _ = collector.collect()
        seg = [
            n for n in nodes if n.name == "OnPremWAN"
        ][0]
        assert seg.properties["deny_filter"] == [
            "Fallback", "Prod",
        ]

    def test_deny_filter_coexists_with_share(self):
        """Segments can have both share and deny-filter (contradictory)."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_document=self.DENY_FILTER_POLICY,
        )
        _, edges = collector.collect()
        connects = [
            e for e in edges
            if e.relationship.value == "CONNECTS_TO"
        ]
        denies = [
            e for e in edges
            if e.relationship.value == "DENIES"
        ]
        # Share: OnPremWAN -> NonProdImportFilter, OnPremProd
        assert len(connects) == 2
        # Deny-filter: 5 deny edges total
        assert len(denies) == 5
        # OnPremWAN shares AND denies NonProdImportFilter
        shared_targets = {
            e.target_arn.split("/")[-1]
            for e in connects
        }
        denied_targets = {
            e.target_arn.split("/")[-1]
            for e in denies
            if "OnPremWAN" in e.source_arn
        }
        # Contradiction: same segment in both
        assert "NonProdImportFilter" in shared_targets
        assert "NonProdImportFilter" in denied_targets

    def test_deny_filter_skips_segments_without_deny(self):
        """Segments without deny-filter produce no DENIES edges."""
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_document=self.DENY_FILTER_POLICY,
        )
        _, edges = collector.collect()
        denies = [
            e for e in edges
            if e.relationship.value == "DENIES"
        ]
        # NoDenyFilter segment should not produce edges
        no_deny_sources = [
            e for e in denies
            if "NoDenyFilter" in e.source_arn
        ]
        assert len(no_deny_sources) == 0


class TestCloudWANDenyFilterDirection:
    """Tests for deny-filter direction property on DENIES edges."""

    def test_deny_filter_has_direction_property(self):
        """deny-filter DENIES edges have blocks_import_from direction."""
        cn_detail = {
            "CoreNetworkId": "core-network-001",
            "CoreNetworkArn": (
                "arn:aws:networkmanager::123456789012"
                ":core-network/core-network-001"
            ),
            "State": "AVAILABLE",
            "GlobalNetworkId": "global-network-001",
            "Segments": [
                {
                    "Name": "SegA",
                    "EdgeLocations": ["us-west-2"],
                    "SharedSegments": [],
                },
            ],
            "Edges": [{"EdgeLocation": "us-west-2"}],
            "Tags": [{"Key": "Name", "Value": "cn"}],
        }
        policy = {
            "segment-actions": [],
            "segments": [
                {
                    "name": "SegA",
                    "deny-filter": ["SegB", "SegC"],
                },
            ],
            "attachment-policies": [],
        }
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=cn_detail,
            policy_document=policy,
        )
        _, edges = collector.collect()
        denies = [
            e for e in edges
            if e.relationship.value == "DENIES"
        ]
        assert len(denies) == 2
        for edge in denies:
            assert edge.properties["type"] == "deny_filter"
            assert (
                edge.properties["direction"]
                == "blocks_import_from"
            )

    def test_segment_action_deny_has_no_direction(self):
        """segment-action deny edges should NOT have direction."""
        policy = {
            "segment-actions": [
                {
                    "action": "deny",
                    "segment": "Isolated",
                    "segment-names": ["Public"],
                },
            ],
            "attachment-policies": [],
        }
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_document=policy,
        )
        _, edges = collector.collect()
        denies = [
            e for e in edges
            if e.relationship.value == "DENIES"
        ]
        assert len(denies) == 1
        assert denies[0].properties["type"] == "segment_action_deny"
        assert "direction" not in denies[0].properties


class TestCloudWANCreateRoute:
    """Tests for create-route segment-action parsing."""

    def test_create_route_stored_as_static_routes(self):
        """create-route actions stored as static_routes on CN node."""
        policy = {
            "segment-actions": [
                {
                    "action": "create-route",
                    "segment": "OnPremWAN",
                    "destination-cidr-blocks": [
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                    ],
                },
                {
                    "action": "create-route",
                    "segment": "Production",
                    "destination-cidr-blocks": [
                        "192.168.0.0/16",
                    ],
                },
                {
                    "action": "share",
                    "segment": "OnPremWAN",
                    "mode": "attachment-route",
                    "share-with": ["Production"],
                },
            ],
            "attachment-policies": [],
        }
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_document=policy,
        )
        nodes, _ = collector.collect()
        cn_node = [
            n for n in nodes
            if n.label.value == "CloudWANCoreNetwork"
        ][0]
        routes = cn_node.properties.get("static_routes")
        assert routes is not None
        assert len(routes) == 2
        assert routes[0]["segment"] == "OnPremWAN"
        assert "10.0.0.0/8" in routes[0][
            "destination_cidr_blocks"
        ]
        assert routes[1]["segment"] == "Production"

    def test_no_create_route_no_static_routes(self):
        """Without create-route, no static_routes property."""
        policy = {
            "segment-actions": [
                {
                    "action": "share",
                    "segment": "OnPremWAN",
                    "mode": "attachment-route",
                    "share-with": ["Production"],
                },
            ],
            "attachment-policies": [],
        }
        collector = _make_collector(
            core_networks=[SAMPLE_CORE_NETWORK_SUMMARY],
            core_network_detail=SAMPLE_CORE_NETWORK_DETAIL,
            policy_document=policy,
        )
        nodes, _ = collector.collect()
        cn_node = [
            n for n in nodes
            if n.label.value == "CloudWANCoreNetwork"
        ][0]
        assert "static_routes" not in cn_node.properties


class TestCloudWANEdgeCases:
    def test_empty_returns_nothing(self):
        """No core networks or attachments returns empty."""
        collector = _make_collector()
        nodes, edges = collector.collect()
        assert len(nodes) == 0
        assert len(edges) == 0

    def test_collect_in_region_returns_empty(self):
        """collect_in_region is a no-op for global service."""
        collector = _make_collector()
        nodes, edges = collector.collect_in_region("us-east-1")
        assert len(nodes) == 0
        assert len(edges) == 0


class TestCloudWANErrors:
    def test_handles_gracefully(self):
        """API error should return empty, not crash."""
        collector = _make_collector(
            error="AccessDeniedException",
        )
        nodes, edges = collector.collect()
        assert len(nodes) == 0
        assert len(edges) == 0
