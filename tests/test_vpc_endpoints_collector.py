"""Tests for VPC Endpoints collector."""

from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from src.collector.vpc_endpoints import VPCEndpointsCollector


def _make_collector(
    endpoints: list[dict] | None = None,
    error: str = "",
) -> VPCEndpointsCollector:
    """Create a VPCEndpointsCollector with stubbed EC2 client."""
    session = MagicMock()
    collector = VPCEndpointsCollector(
        session=session,
        account_id="123456789012",
        regions=["us-west-2"],
    )

    mock_client = MagicMock()
    mock_paginator = MagicMock()

    if error:
        mock_paginator.paginate.side_effect = ClientError(
            {"Error": {"Code": error, "Message": "test"}},
            "DescribeVpcEndpoints",
        )
    else:
        mock_paginator.paginate.return_value = [
            {"VpcEndpoints": endpoints or []},
        ]

    mock_client.get_paginator.return_value = mock_paginator
    collector.client = MagicMock(return_value=mock_client)

    return collector


SAMPLE_INTERFACE_ENDPOINT = {
    "VpcEndpointId": "vpce-0abc123",
    "VpcEndpointType": "Interface",
    "ServiceName": "com.amazonaws.us-west-2.s3",
    "State": "available",
    "VpcId": "vpc-111",
    "PrivateDnsEnabled": True,
    "SubnetIds": ["subnet-aaa", "subnet-bbb"],
    "NetworkInterfaceIds": ["eni-111", "eni-222"],
    "Groups": [
        {"GroupId": "sg-001", "GroupName": "vpce-sg"},
    ],
    "Tags": [{"Key": "Name", "Value": "s3-endpoint"}],
}

SAMPLE_GATEWAY_ENDPOINT = {
    "VpcEndpointId": "vpce-0def456",
    "VpcEndpointType": "Gateway",
    "ServiceName": "com.amazonaws.us-west-2.dynamodb",
    "State": "available",
    "VpcId": "vpc-111",
    "PrivateDnsEnabled": False,
    "RouteTableIds": ["rtb-aaa"],
    "Tags": [],
}


class TestVPCEndpointsHappyPath:
    def test_collects_endpoints(self):
        """Should collect both interface and gateway endpoints."""
        collector = _make_collector(
            [SAMPLE_INTERFACE_ENDPOINT, SAMPLE_GATEWAY_ENDPOINT],
        )
        nodes, edges = collector.collect()
        assert len(nodes) == 2

    def test_interface_endpoint_properties(self):
        """Interface endpoint should have correct properties."""
        collector = _make_collector(
            [SAMPLE_INTERFACE_ENDPOINT],
        )
        nodes, edges = collector.collect()
        node = nodes[0]

        assert node.name == "s3-endpoint"
        assert node.properties["endpoint_type"] == "Interface"
        assert node.properties["service_name"] == (
            "com.amazonaws.us-west-2.s3"
        )
        assert node.properties["state"] == "available"
        assert node.properties["private_dns_enabled"] is True
        assert node.properties["vpc_id"] == "vpc-111"

    def test_part_of_vpc_edge(self):
        """Endpoint should have PART_OF edge to VPC."""
        collector = _make_collector(
            [SAMPLE_INTERFACE_ENDPOINT],
        )
        nodes, edges = collector.collect()
        part_of = [
            e for e in edges if e.relationship.value == "PART_OF"
        ]
        assert len(part_of) == 1
        assert "vpc/vpc-111" in part_of[0].target_arn

    def test_has_sg_edge_for_interface(self):
        """Interface endpoint should have HAS_SG edge."""
        collector = _make_collector(
            [SAMPLE_INTERFACE_ENDPOINT],
        )
        nodes, edges = collector.collect()
        sg_edges = [
            e for e in edges if e.relationship.value == "HAS_SG"
        ]
        assert len(sg_edges) == 1
        assert "sg-001" in sg_edges[0].target_arn

    def test_connects_to_service_edge(self):
        """Endpoint should have CONNECTS_TO edge."""
        collector = _make_collector(
            [SAMPLE_INTERFACE_ENDPOINT],
        )
        nodes, edges = collector.collect()
        connects = [
            e for e in edges
            if e.relationship.value == "CONNECTS_TO"
        ]
        assert len(connects) == 1
        assert connects[0].properties["service_name"] == (
            "com.amazonaws.us-west-2.s3"
        )


class TestVPCEndpointsEdgeCases:
    def test_empty_region(self):
        """Empty region returns nothing."""
        collector = _make_collector([])
        nodes, edges = collector.collect()
        assert len(nodes) == 0
        assert len(edges) == 0

    def test_gateway_has_no_sg_edges(self):
        """Gateway endpoints have no security groups."""
        collector = _make_collector(
            [SAMPLE_GATEWAY_ENDPOINT],
        )
        nodes, edges = collector.collect()
        sg_edges = [
            e for e in edges if e.relationship.value == "HAS_SG"
        ]
        assert len(sg_edges) == 0


class TestVPCEndpointsErrors:
    def test_handles_gracefully(self):
        """API error should return empty, not crash."""
        collector = _make_collector(
            error="UnauthorizedOperation",
        )
        nodes, edges = collector.collect()
        assert len(nodes) == 0
        assert len(edges) == 0
