"""Tests for Transit Gateway collector."""

from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from src.collector.transit_gateway import (
    TransitGatewayCollector,
    _summarize_tgw_routes,
)


def _make_collector(
    tgws: list[dict] | None = None,
    attachments: list[dict] | None = None,
    route_tables: list[dict] | None = None,
    tgw_routes: list[dict] | None = None,
    route_search_error: str = "",
    error: str = "",
) -> TransitGatewayCollector:
    """Create a TransitGatewayCollector with stubbed EC2 client."""
    session = MagicMock()
    collector = TransitGatewayCollector(
        session=session,
        account_id="123456789012",
        regions=["us-west-2"],
    )

    mock_client = MagicMock()

    def _get_paginator(operation: str):  # noqa: ANN202
        paginator = MagicMock()
        if error:
            paginator.paginate.side_effect = ClientError(
                {"Error": {"Code": error, "Message": "test"}},
                operation,
            )
            return paginator

        if operation == "describe_transit_gateways":
            paginator.paginate.return_value = [
                {"TransitGateways": tgws or []},
            ]
        elif operation == "describe_transit_gateway_attachments":
            paginator.paginate.return_value = [
                {"TransitGatewayAttachments": attachments or []},
            ]
        elif operation == "describe_transit_gateway_route_tables":
            paginator.paginate.return_value = [
                {"TransitGatewayRouteTables": route_tables or []},
            ]
        return paginator

    mock_client.get_paginator.side_effect = _get_paginator

    # Stub search_transit_gateway_routes
    if route_search_error:
        mock_client.search_transit_gateway_routes.side_effect = (
            ClientError(
                {
                    "Error": {
                        "Code": route_search_error,
                        "Message": "test",
                    },
                },
                "SearchTransitGatewayRoutes",
            )
        )
    else:
        mock_client.search_transit_gateway_routes.return_value = {
            "Routes": tgw_routes or [],
        }

    collector.client = MagicMock(return_value=mock_client)

    return collector


SAMPLE_TGW = {
    "TransitGatewayId": "tgw-0abc123",
    "TransitGatewayArn": (
        "arn:aws:ec2:us-west-2:123456789012"
        ":transit-gateway/tgw-0abc123"
    ),
    "State": "available",
    "OwnerId": "123456789012",
    "Options": {
        "AmazonSideAsn": 64512,
        "AutoAcceptSharedAttachments": "enable",
        "DefaultRouteTableAssociation": "enable",
        "DefaultRouteTablePropagation": "enable",
    },
    "Tags": [{"Key": "Name", "Value": "main-tgw"}],
}

SAMPLE_VPC_ATTACHMENT = {
    "TransitGatewayAttachmentId": "tgw-attach-0abc",
    "TransitGatewayId": "tgw-0abc123",
    "TransitGatewayOwnerId": "999999999999",
    "ResourceType": "vpc",
    "ResourceId": "vpc-111",
    "ResourceOwnerId": "111111111111",
    "State": "available",
    "Association": {
        "TransitGatewayRouteTableId": "tgw-rtb-001",
        "State": "associated",
    },
    "Tags": [{"Key": "Name", "Value": "vpc-attachment"}],
}

SAMPLE_PEERING_ATTACHMENT = {
    "TransitGatewayAttachmentId": "tgw-attach-0def",
    "TransitGatewayId": "tgw-0abc123",
    "TransitGatewayOwnerId": "999999999999",
    "ResourceType": "peering",
    "ResourceId": "tgw-0xyz789",
    "ResourceOwnerId": "222222222222",
    "State": "available",
    "Association": {},
    "Tags": [],
}

SAMPLE_ROUTE_TABLE = {
    "TransitGatewayRouteTableId": "tgw-rtb-001",
    "TransitGatewayId": "tgw-0abc123",
    "State": "available",
    "DefaultAssociationRouteTable": True,
    "DefaultPropagationRouteTable": True,
    "Tags": [{"Key": "Name", "Value": "main-rt"}],
}


class TestTransitGatewayHappyPath:
    def test_collects_tgw(self):
        """Should collect Transit Gateway nodes."""
        collector = _make_collector(tgws=[SAMPLE_TGW])
        nodes, edges = collector.collect()
        tgw_nodes = [
            n for n in nodes if n.label.value == "TransitGateway"
        ]
        assert len(tgw_nodes) == 1
        assert tgw_nodes[0].name == "main-tgw"

    def test_tgw_properties(self):
        """TGW node should have correct properties."""
        collector = _make_collector(tgws=[SAMPLE_TGW])
        nodes, _ = collector.collect()
        tgw = [
            n for n in nodes
            if n.label.value == "TransitGateway"
        ][0]
        assert tgw.properties["tgw_id"] == "tgw-0abc123"
        assert tgw.properties["state"] == "available"
        assert tgw.properties["amazon_side_asn"] == 64512

    def test_vpc_attachment_creates_edges(self):
        """VPC attachment should link to TGW and VPC."""
        collector = _make_collector(
            attachments=[SAMPLE_VPC_ATTACHMENT],
        )
        nodes, edges = collector.collect()
        attached = [
            e for e in edges
            if e.relationship.value == "ATTACHED_TO"
        ]
        # One to TGW, one to VPC
        assert len(attached) == 2
        tgw_edge = [
            e for e in attached
            if "transit-gateway/" in e.target_arn
        ]
        vpc_edge = [
            e for e in attached
            if "vpc/" in e.target_arn
        ]
        assert len(tgw_edge) == 1
        assert len(vpc_edge) == 1
        assert "vpc-111" in vpc_edge[0].target_arn

    def test_tgw_edge_uses_owner_account(self):
        """TGW ATTACHED_TO edge should use TGW owner, not collector."""
        collector = _make_collector(
            attachments=[SAMPLE_VPC_ATTACHMENT],
        )
        _, edges = collector.collect()
        tgw_edge = [
            e for e in edges
            if e.relationship.value == "ATTACHED_TO"
            and "transit-gateway/" in e.target_arn
        ][0]
        # TGW owner is 999999999999, not collector's 123456789012
        assert ":999999999999:" in tgw_edge.target_arn

    def test_vpc_edge_uses_resource_owner(self):
        """VPC ATTACHED_TO edge should use resource owner account."""
        collector = _make_collector(
            attachments=[SAMPLE_VPC_ATTACHMENT],
        )
        _, edges = collector.collect()
        vpc_edge = [
            e for e in edges
            if e.relationship.value == "ATTACHED_TO"
            and "vpc/" in e.target_arn
        ][0]
        # Resource owner is 111111111111
        assert ":111111111111:" in vpc_edge.target_arn

    def test_peering_attachment_peers_with(self):
        """Peering attachment should have PEERS_WITH edge."""
        collector = _make_collector(
            attachments=[SAMPLE_PEERING_ATTACHMENT],
        )
        nodes, edges = collector.collect()
        peers = [
            e for e in edges
            if e.relationship.value == "PEERS_WITH"
        ]
        assert len(peers) == 1
        assert "tgw-0xyz789" in peers[0].target_arn

    def test_route_table_part_of_tgw(self):
        """Route table should have PART_OF edge to TGW."""
        collector = _make_collector(
            route_tables=[SAMPLE_ROUTE_TABLE],
        )
        nodes, edges = collector.collect()
        part_of = [
            e for e in edges
            if e.relationship.value == "PART_OF"
        ]
        assert len(part_of) == 1
        assert "tgw-0abc123" in part_of[0].target_arn


class TestTransitGatewayEdgeCases:
    def test_empty_region(self):
        """Empty region returns nothing."""
        collector = _make_collector()
        nodes, edges = collector.collect()
        assert len(nodes) == 0
        assert len(edges) == 0

    def test_full_collection(self):
        """All resource types collected together."""
        collector = _make_collector(
            tgws=[SAMPLE_TGW],
            attachments=[
                SAMPLE_VPC_ATTACHMENT,
                SAMPLE_PEERING_ATTACHMENT,
            ],
            route_tables=[SAMPLE_ROUTE_TABLE],
        )
        nodes, edges = collector.collect()
        # 1 TGW + 2 attachments + 1 route table
        assert len(nodes) == 4


class TestTransitGatewayErrors:
    def test_handles_gracefully(self):
        """API error should return empty, not crash."""
        collector = _make_collector(
            error="UnauthorizedOperation",
        )
        nodes, edges = collector.collect()
        assert len(nodes) == 0
        assert len(edges) == 0


class TestSummarizeTGWRoutes:
    """Tests for TGW route summarization."""

    def test_single_route(self):
        routes = [{
            "DestinationCidrBlock": "10.0.0.0/8",
            "TransitGatewayAttachments": [{
                "TransitGatewayAttachmentId": "tgw-attach-abc",
            }],
        }]
        result = _summarize_tgw_routes(routes)
        assert result == "10.0.0.0/8 -> tgw-attach-abc"

    def test_multiple_routes(self):
        routes = [
            {
                "DestinationCidrBlock": "10.0.0.0/8",
                "TransitGatewayAttachments": [{
                    "TransitGatewayAttachmentId": "tgw-attach-a",
                }],
            },
            {
                "DestinationCidrBlock": "10.150.0.0/16",
                "TransitGatewayAttachments": [{
                    "TransitGatewayAttachmentId": "tgw-attach-b",
                }],
            },
        ]
        result = _summarize_tgw_routes(routes)
        assert "10.0.0.0/8 -> tgw-attach-a" in result
        assert "10.150.0.0/16 -> tgw-attach-b" in result

    def test_no_attachments_shows_blackhole(self):
        routes = [{
            "DestinationCidrBlock": "10.0.0.0/8",
            "TransitGatewayAttachments": [],
        }]
        result = _summarize_tgw_routes(routes)
        assert "blackhole" in result

    def test_empty_routes(self):
        assert _summarize_tgw_routes([]) == "none"


class TestTGWRouteTableRoutes:
    """Tests for TGW route table route fetching."""

    def test_route_table_has_routes_property(self):
        """Route table node should have routes from search API."""
        tgw_routes = [{
            "DestinationCidrBlock": "10.150.0.0/16",
            "TransitGatewayAttachments": [{
                "TransitGatewayAttachmentId": "tgw-attach-abc",
            }],
        }]
        collector = _make_collector(
            route_tables=[SAMPLE_ROUTE_TABLE],
            tgw_routes=tgw_routes,
        )
        nodes, _ = collector.collect()
        rt_nodes = [
            n for n in nodes
            if n.label.value == "TGWRouteTable"
        ]
        assert len(rt_nodes) == 1
        assert "10.150.0.0/16 -> tgw-attach-abc" in (
            rt_nodes[0].properties["routes"]
        )

    def test_route_search_error_graceful(self):
        """API error on route search should not crash."""
        collector = _make_collector(
            route_tables=[SAMPLE_ROUTE_TABLE],
            route_search_error="AccessDenied",
        )
        nodes, _ = collector.collect()
        rt_nodes = [
            n for n in nodes
            if n.label.value == "TGWRouteTable"
        ]
        assert len(rt_nodes) == 1
        # Routes should be "none" when search fails
        assert rt_nodes[0].properties["routes"] == "none"
