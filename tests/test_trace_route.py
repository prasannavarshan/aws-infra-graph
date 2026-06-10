"""Tests for trace_route MCP tool and helper functions."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.tools.trace_route import (
    format_trace,
    trace_route,
    trace_segment_hops,
)
from src.tools.trace_route_match import find_matching_route
from src.tools.trace_route_resolve import (
    resolve_destination,
    resolve_source,
)


def _make_neo4j(query_fn) -> AsyncMock:
    """Create a mock Neo4j client."""
    neo4j = AsyncMock()
    neo4j.query = AsyncMock(side_effect=query_fn)
    return neo4j


def _make_ctx(query_fn) -> MagicMock:
    """Create a mock MCP Context with a custom query fn."""
    neo4j = _make_neo4j(query_fn)
    app_ctx = MagicMock()
    app_ctx.neo4j = neo4j
    ctx = MagicMock()
    ctx.request_context.lifespan_context = app_ctx
    return ctx


# --- find_matching_route tests ---


class TestFindMatchingRoute:
    """Tests for find_matching_route."""

    def test_exact_match(self):
        """Should match most specific CIDR."""
        routes = [
            {"DestinationCidrBlock": "10.0.0.0/8",
             "Type": "propagated"},
            {"DestinationCidrBlock": "10.127.0.0/16",
             "Type": "propagated"},
            {"DestinationCidrBlock": "10.127.32.0/20",
             "Type": "propagated"},
        ]
        result = find_matching_route(routes, "10.127.33.15")
        assert result is not None
        assert result["DestinationCidrBlock"] == "10.127.32.0/20"

    def test_no_match(self):
        """Should return None when no CIDR covers the IP."""
        routes = [
            {"DestinationCidrBlock": "10.127.0.0/16"},
        ]
        assert find_matching_route(routes, "192.168.1.1") is None

    def test_empty_routes(self):
        """Should return None for empty route list."""
        assert find_matching_route([], "10.0.0.1") is None

    def test_invalid_cidr_skipped(self):
        """Should skip routes with invalid CIDR blocks."""
        routes = [
            {"DestinationCidrBlock": "not-a-cidr"},
            {"DestinationCidrBlock": "10.0.0.0/8",
             "Type": "propagated"},
        ]
        result = find_matching_route(routes, "10.1.2.3")
        assert result is not None
        assert result["DestinationCidrBlock"] == "10.0.0.0/8"


# --- resolve_destination tests ---


class TestResolveDestination:
    """Tests for resolve_destination."""

    @pytest.mark.asyncio
    async def test_exact_ip_match(self):
        """Should find resource by exact private_ip."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return [{
                    "name": "web-server-01",
                    "arn": "arn:aws:ec2:us-west-2:123:i/i-abc",
                    "labels": ["EC2Instance"],
                    "subnet_name": "private-sub-1",
                    "subnet_cidr": "10.127.32.0/20",
                    "vpc_name": "prod-vpc",
                    "vpc_arn": "arn:aws:ec2:us-west-2:123:vpc/vpc-1",
                    "vpc_id": "vpc-1",
                }]
            if "CloudWANAttachment" in cypher:
                return [{
                    "seg_name": "SLINGCoreBeta",
                    "seg_arn": "arn:seg:1",
                    "att_id": "att-vpc-456",
                }]
            return []

        neo4j = _make_neo4j(_query)
        result = await resolve_destination(
            neo4j, "10.127.33.15",
        )
        assert result is not None
        assert result["resource_name"] == "web-server-01"
        assert result["segment_name"] == "SLINGCoreBeta"
        assert result["attachment_id"] == "att-vpc-456"

    @pytest.mark.asyncio
    async def test_cidr_match(self):
        """Should match IP to VPC CIDR when no exact match."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return []
            if "sub:Subnet" in cypher:
                return []
            if "v:VPC" in cypher and "secondary_cidrs" in cypher:
                return [
                    {"name": "vpc-a", "arn": "arn:vpc:a",
                     "vpc_id": "vpc-a",
                     "cidr_block": "10.0.0.0/8",
                     "secondary_cidrs": None},
                    {"name": "vpc-b", "arn": "arn:vpc:b",
                     "vpc_id": "vpc-b",
                     "cidr_block": "10.127.0.0/16",
                     "secondary_cidrs": None},
                ]
            if "CloudWANAttachment" in cypher:
                return [{
                    "seg_name": "SLINGCoreBeta",
                    "seg_arn": "arn:seg:1",
                    "att_id": "att-vpc-b",
                }]
            return []

        neo4j = _make_neo4j(_query)
        result = await resolve_destination(
            neo4j, "10.127.33.15",
        )
        assert result is not None
        assert result["vpc_name"] == "vpc-b"
        assert result["segment_name"] == "SLINGCoreBeta"

    @pytest.mark.asyncio
    async def test_secondary_cidr_match(self):
        """Should match IP to VPC secondary CIDR."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return []
            if "sub:Subnet" in cypher:
                return []
            if "v:VPC" in cypher and "secondary_cidrs" in cypher:
                return [
                    {"name": "main-vpc", "arn": "arn:vpc:m",
                     "vpc_id": "vpc-main",
                     "cidr_block": "10.0.0.0/16",
                     "secondary_cidrs": [
                         "10.182.12.0/22",
                     ]},
                ]
            if "CloudWANAttachment" in cypher:
                return [{
                    "seg_name": "Production",
                    "seg_arn": "arn:seg:prod",
                    "att_id": "att-main",
                }]
            return []

        neo4j = _make_neo4j(_query)
        result = await resolve_destination(
            neo4j, "10.182.12.18",
        )
        assert result is not None
        assert result["vpc_name"] == "main-vpc"
        assert result["vpc_id"] == "vpc-main"
        assert result["segment_name"] == "Production"

    @pytest.mark.asyncio
    async def test_subnet_cidr_match(self):
        """Should match IP to subnet CIDR (more specific)."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return []
            if "sub:Subnet" in cypher:
                return [
                    {"subnet_name": "priv-sub-a",
                     "cidr_block": "10.127.1.0/24",
                     "vpc_name": "vpc-b",
                     "vpc_arn": "arn:vpc:b",
                     "vpc_id": "vpc-b"},
                ]
            if "CloudWANAttachment" in cypher:
                return [{
                    "seg_name": "SLINGCoreBeta",
                    "seg_arn": "arn:seg:1",
                    "att_id": "att-vpc-b",
                }]
            return []

        neo4j = _make_neo4j(_query)
        result = await resolve_destination(
            neo4j, "10.127.1.55",
        )
        assert result is not None
        assert result["vpc_name"] == "vpc-b"
        assert result["subnet_name"] == "priv-sub-a"
        assert result["subnet_cidr"] == "10.127.1.0/24"

    @pytest.mark.asyncio
    async def test_not_found(self):
        """Should return None when IP doesn't match anything."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return []
            if "v:VPC" in cypher:
                return [
                    {"name": "vpc-a", "arn": "arn:vpc:a",
                     "vpc_id": "vpc-a",
                     "cidr_block": "10.127.0.0/16"},
                ]
            return []

        neo4j = _make_neo4j(_query)
        result = await resolve_destination(
            neo4j, "192.168.1.1",
        )
        assert result is None


# --- resolve_source tests ---


class TestResolveSource:
    """Tests for resolve_source."""

    @pytest.mark.asyncio
    async def test_in_graph(self):
        """Should resolve source from graph when IP is in VPC."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return [{
                    "name": "app-server",
                    "arn": "arn:aws:ec2:us-west-2:123:i/i-src",
                    "labels": ["EC2Instance"],
                    "subnet_name": "sub-1",
                    "subnet_cidr": "10.128.0.0/20",
                    "vpc_name": "app-vpc",
                    "vpc_arn": "arn:vpc:app",
                    "vpc_id": "vpc-app",
                }]
            if "CloudWANAttachment" in cypher:
                return [{
                    "seg_name": "SLINGDev",
                    "seg_arn": "arn:seg:dev",
                    "att_id": "att-dev-1",
                }]
            return []

        neo4j = _make_neo4j(_query)
        result = await resolve_source(
            neo4j, "10.128.5.10", "",
        )
        assert result is not None
        assert result["segment_name"] == "SLINGDev"

    @pytest.mark.asyncio
    async def test_with_segment_hint(self):
        """Should use segment hint directly."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "CloudWANSegment" in cypher and "name" in (params or {}):
                return [{
                    "name": "OnPremShared",
                    "arn": "arn:seg:onprem",
                    "cn_id": "cn-001",
                }]
            return []

        neo4j = _make_neo4j(_query)
        result = await resolve_source(
            neo4j, "10.200.5.42", "segment:OnPremShared",
        )
        assert result is not None
        assert result["segment_name"] == "OnPremShared"
        assert result.get("inferred") is True

    @pytest.mark.asyncio
    async def test_with_attachment_hint(self):
        """Should use attachment hint directly."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "CloudWANAttachment" in cypher and "att_id" in (params or {}):
                return [{
                    "seg_name": "OnPremShared",
                    "seg_arn": "arn:seg:onprem",
                    "att_id": "att-vpn-123",
                }]
            return []

        neo4j = _make_neo4j(_query)
        result = await resolve_source(
            neo4j, "10.200.5.42", "attachment:att-vpn-123",
        )
        assert result is not None
        assert result["segment_name"] == "OnPremShared"
        assert result["attachment_id"] == "att-vpn-123"

    @pytest.mark.asyncio
    async def test_inferred_from_routes(self):
        """Should infer source segment from VPN attachments."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            # resolve_destination calls (returns nothing)
            if "private_ip" in cypher:
                return []
            if "v:VPC" in cypher and "cidr_block" in cypher:
                return []
            # Graph-only VPN lookup (resolve_destination)
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
                and "count" in cypher
            ):
                return []
            # VPN attachment query for inference
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
            ):
                return [{
                    "att_id": "att-vpn-123",
                    "att_type": "SITE_TO_SITE_VPN",
                    "seg_name": "OnPremShared",
                    "cn_id": "cn-001",
                }]
            # _resolve_segment_info
            if "CloudWANSegment" in cypher:
                return [{
                    "cn_id": "cn-001",
                    "edge_locs": ["us-west-2"],
                    "arn": "arn:seg:onprem",
                }]
            # _get_core_network_info
            if "CloudWANCoreNetwork" in cypher:
                return [{
                    "gn_id": "gn-001",
                    "account_id": "123456789012",
                }]
            return []

        neo4j = _make_neo4j(_query)

        mock_routes = [
            {
                "DestinationCidrBlock": "10.200.0.0/16",
                "Type": "propagated",
                "State": "active",
                "Destinations": [{
                    "CoreNetworkAttachmentId": "att-vpn-123",
                    "SegmentName": "OnPremShared",
                }],
            },
        ]

        with patch(
            "src.tools.trace_route_vpn"
            ".fetch_segment_routes",
            new_callable=AsyncMock,
            return_value=mock_routes,
        ):
            result = await resolve_source(
                neo4j, "10.200.5.42", "",
            )
        assert result is not None
        assert result["segment_name"] == "OnPremShared"
        assert result["attachment_id"] == "att-vpn-123"
        assert result["matched_cidr"] == "10.200.0.0/16"

    @pytest.mark.asyncio
    async def test_prefers_vpn_attachment_match(self):
        """Should prefer segment where route's attachment ID
        matches a known VPN/CONNECT attachment.

        Both segments have a route for the source IP, but only
        SegmentSharedWAN's route points to a VPN attachment ID.
        SegmentProductionWAN's route points to a non-VPN
        attachment (propagated from SegmentSharedWAN).
        """
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return []
            if "v:VPC" in cypher and "cidr_block" in cypher:
                return []
            # Graph-only VPN lookup (resolve_destination)
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
                and "count" in cypher
            ):
                return []
            # VPN attachment query — both segments have VPNs
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
            ):
                return [
                    {
                        "att_id": "att-vpn-prod",
                        "att_type": "SITE_TO_SITE_VPN",
                        "seg_name": "SegmentProductionWAN",
                        "cn_id": "cn-001",
                    },
                    {
                        "att_id": "att-vpn",
                        "att_type": "SITE_TO_SITE_VPN",
                        "seg_name": "SegmentSharedWAN",
                        "cn_id": "cn-001",
                    },
                ]
            return []

        neo4j = _make_neo4j(_query)

        def _mock_fetch(neo4j, segment_name, **kwargs):
            """Both segments have the route, but only
            SegmentSharedWAN's route uses a VPN attachment."""
            if segment_name == "SegmentProductionWAN":
                return [{
                    "DestinationCidrBlock": "10.126.0.0/17",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [{
                        "CoreNetworkAttachmentId": "att-wan",
                        "SegmentName": "SegmentSharedWAN",
                    }],
                }]
            if segment_name == "SegmentSharedWAN":
                return [{
                    "DestinationCidrBlock": "10.126.0.0/17",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [{
                        "CoreNetworkAttachmentId": "att-vpn",
                        "SegmentName": "SegmentSharedWAN",
                    }],
                }]
            return []

        with patch(
            "src.tools.trace_route_vpn"
            ".fetch_segment_routes",
            side_effect=_mock_fetch,
        ):
            result = await resolve_source(
                neo4j, "10.126.12.90", "",
            )
        assert result is not None
        assert result["segment_name"] == "SegmentSharedWAN"
        assert result["attachment_id"] == "att-vpn"

    @pytest.mark.asyncio
    async def test_falls_back_to_propagated(self):
        """Should fall back to propagated route when route's
        attachment ID doesn't match any VPN attachment."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return []
            if "v:VPC" in cypher and "cidr_block" in cypher:
                return []
            # Graph-only VPN lookup (resolve_destination)
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
                and "count" in cypher
            ):
                return []
            # VPN attachment query — one VPN in ProdWAN
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
            ):
                return [{
                    "att_id": "att-vpn-prod",
                    "att_type": "SITE_TO_SITE_VPN",
                    "seg_name": "SegmentProductionWAN",
                    "cn_id": "cn-001",
                }]
            return []

        neo4j = _make_neo4j(_query)

        def _mock_fetch(neo4j, segment_name, **kwargs):
            """Route points to att-wan which is NOT a VPN
            attachment — should be saved as fallback."""
            return [{
                "DestinationCidrBlock": "10.126.0.0/17",
                "Type": "propagated",
                "State": "active",
                "Destinations": [{
                    "CoreNetworkAttachmentId": "att-wan",
                    "SegmentName": "SegmentSharedWAN",
                }],
            }]

        with patch(
            "src.tools.trace_route_vpn"
            ".fetch_segment_routes",
            side_effect=_mock_fetch,
        ):
            result = await resolve_source(
                neo4j, "10.126.12.90", "",
            )
        assert result is not None
        assert result["segment_name"] == "SegmentProductionWAN"

    @pytest.mark.asyncio
    async def test_cidr_preferred_over_vpn_fallback(self):
        """CIDR match should win over VPN fallback when the
        VPN inference is not definitive.

        10.150.36.137 is a VPC IP (CIDR match →
        SegmentDevelopment). VPN inference finds a propagated
        route in SegmentSharedWAN covering 10.150.32.0/20 but
        the route's attachment is NOT a local VPN — it's a
        fallback. CIDR match should win.
        """
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return []
            # VPC CIDR match
            if "v:VPC" in cypher and "cidr_block" in cypher:
                return [{
                    "name": "dev-vpc",
                    "arn": "arn:vpc:dev",
                    "vpc_id": "vpc-dev",
                    "cidr_block": "10.150.32.0/20",
                }]
            # CloudWAN attachment for VPC
            if (
                "CloudWANAttachment" in cypher
                and "ATTACHED_TO" in cypher
            ):
                return [{
                    "seg_name": "SegmentDevelopment",
                    "seg_arn": "arn:seg:dev",
                    "att_id": "att-vpc-dev",
                }]
            # Graph-only VPN lookup (resolve_destination)
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
                and "count" in cypher
            ):
                return []
            # VPN attachment query for inference
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
            ):
                return [{
                    "att_id": "att-vpn-wan",
                    "att_type": "SITE_TO_SITE_VPN",
                    "seg_name": "SegmentSharedWAN",
                    "cn_id": "cn-001",
                }]
            return []

        neo4j = _make_neo4j(_query)

        def _mock_fetch(neo4j, segment_name, **kwargs):
            """SegmentSharedWAN has a propagated route for
            10.150.32.0/20 but via a VPC attachment, not a
            local VPN attachment."""
            return [{
                "DestinationCidrBlock": "10.150.32.0/20",
                "Type": "propagated",
                "State": "active",
                "Destinations": [{
                    "CoreNetworkAttachmentId": "att-vpc-dev",
                    "SegmentName": "SegmentDevelopment",
                }],
            }]

        with patch(
            "src.tools.trace_route_vpn"
            ".fetch_segment_routes",
            side_effect=_mock_fetch,
        ):
            result = await resolve_source(
                neo4j, "10.150.36.137", "",
            )
        assert result is not None
        # Should pick SegmentDevelopment (CIDR match), NOT
        # SegmentSharedWAN (VPN fallback)
        assert result["segment_name"] == "SegmentDevelopment"

    @pytest.mark.asyncio
    async def test_cidr_match_skipped_for_onprem(self):
        """CIDR-only VPC match should be skipped in favor
        of VPN attachment inference for on-prem IPs.

        This is the DC1 bug: a VPC CIDR covering
        10.126.0.0/17 exists in SegmentProductionWAN,
        but the actual VPN entry point is SegmentSharedWAN.
        """
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            # No exact IP match (on-prem, not in graph)
            if "private_ip" in cypher:
                return []
            # VPC with CIDR covering the on-prem IP
            if "v:VPC" in cypher and "cidr_block" in cypher:
                return [{
                    "name": "prod-vpc",
                    "arn": "arn:vpc:prod",
                    "vpc_id": "vpc-prod",
                    "cidr_block": "10.126.0.0/17",
                }]
            # That VPC is attached to SegmentProductionWAN
            if (
                "CloudWANAttachment" in cypher
                and "ATTACHED_TO" in cypher
            ):
                return [{
                    "seg_name": "SegmentProductionWAN",
                    "seg_arn": "arn:seg:prodwan",
                    "att_id": "att-prodwan",
                }]
            # VPN attachments for inference
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
            ):
                return [
                    {
                        "att_id": "att-vpn-prod",
                        "att_type": "SITE_TO_SITE_VPN",
                        "seg_name": "SegmentProductionWAN",
                        "cn_id": "cn-001",
                    },
                    {
                        "att_id": "att-vpn",
                        "att_type": "SITE_TO_SITE_VPN",
                        "seg_name": "SegmentSharedWAN",
                        "cn_id": "cn-001",
                    },
                ]
            return []

        neo4j = _make_neo4j(_query)

        def _mock_fetch(neo4j, segment_name, **kwargs):
            if segment_name == "SegmentProductionWAN":
                return [{
                    "DestinationCidrBlock": "10.126.0.0/17",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [{
                        "CoreNetworkAttachmentId": "att-w",
                        "SegmentName": "SegmentSharedWAN",
                    }],
                }]
            if segment_name == "SegmentSharedWAN":
                return [{
                    "DestinationCidrBlock": "10.126.0.0/17",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [{
                        "CoreNetworkAttachmentId": "att-vpn",
                        "SegmentName": "SegmentSharedWAN",
                    }],
                }]
            return []

        with patch(
            "src.tools.trace_route_vpn"
            ".fetch_segment_routes",
            side_effect=_mock_fetch,
        ):
            result = await resolve_source(
                neo4j, "10.126.12.90", "",
            )
        assert result is not None
        # Should pick SegmentSharedWAN (VPN attachment match),
        # NOT SegmentProductionWAN (VPC CIDR match)
        assert result["segment_name"] == "SegmentSharedWAN"

    @pytest.mark.asyncio
    async def test_not_found(self):
        """Should return None when source can't be resolved."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            return []

        neo4j = _make_neo4j(_query)
        result = await resolve_source(
            neo4j, "172.16.0.1", "",
        )
        assert result is None


# --- trace_segment_hops tests ---


class TestTraceSegmentHops:
    """Tests for trace_segment_hops."""

    @pytest.mark.asyncio
    async def test_same_segment(self):
        """Same segment should return single direct hop."""
        neo4j = _make_neo4j(lambda *a, **k: [])
        hops = await trace_segment_hops(
            neo4j, "SegA", "SegA", "10.0.0.1", "cn-001",
        )
        assert len(hops) == 1
        assert hops[0]["route_type"] == "same-segment"

    @pytest.mark.asyncio
    async def test_multi_hop(self):
        """Should trace through multiple segments."""
        mock_routes_a = [
            {
                "DestinationCidrBlock": "10.127.0.0/16",
                "Type": "propagated",
                "State": "active",
                "Destinations": [{
                    "CoreNetworkAttachmentId": "att-1",
                    "SegmentName": "SharedWAN",
                }],
            },
        ]
        mock_routes_shared = [
            {
                "DestinationCidrBlock": "10.127.0.0/16",
                "Type": "propagated",
                "State": "active",
                "Destinations": [{
                    "CoreNetworkAttachmentId": "att-2",
                    "SegmentName": "SegB",
                }],
            },
        ]

        call_idx = 0

        async def _mock_fetch(
            neo4j, segment_name, **kwargs,
        ):
            nonlocal call_idx
            call_idx += 1
            if segment_name == "SegA":
                return mock_routes_a
            if segment_name == "SharedWAN":
                return mock_routes_shared
            return []

        neo4j = _make_neo4j(lambda *a, **k: [])

        with patch(
            "src.tools.trace_route.fetch_segment_routes",
            side_effect=_mock_fetch,
        ):
            hops = await trace_segment_hops(
                neo4j, "SegA", "SegB",
                "10.127.33.15", "cn-001",
            )

        assert len(hops) == 3
        assert hops[0]["segment"] == "SegA"
        assert hops[1]["segment"] == "SharedWAN"
        assert hops[2]["segment"] == "SegB"
        assert hops[2]["route_type"] == "destination"

    @pytest.mark.asyncio
    async def test_no_route_found(self):
        """Should report no-route when segment has no match."""
        async def _mock_fetch(
            neo4j, segment_name, **kwargs,
        ):
            return [
                {
                    "DestinationCidrBlock": "172.16.0.0/16",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [],
                },
            ]

        neo4j = _make_neo4j(lambda *a, **k: [])

        with patch(
            "src.tools.trace_route.fetch_segment_routes",
            side_effect=_mock_fetch,
        ):
            hops = await trace_segment_hops(
                neo4j, "SegA", "SegB",
                "10.127.33.15", "cn-001",
            )

        assert len(hops) == 1
        assert hops[0]["route_type"] == "no-route"

    @pytest.mark.asyncio
    async def test_route_fetch_error(self):
        """Should report error when route fetch fails."""
        async def _mock_fetch(
            neo4j, segment_name, **kwargs,
        ):
            return "AWS API error: AccessDenied"

        neo4j = _make_neo4j(lambda *a, **k: [])

        with patch(
            "src.tools.trace_route.fetch_segment_routes",
            side_effect=_mock_fetch,
        ):
            hops = await trace_segment_hops(
                neo4j, "SegA", "SegB",
                "10.127.33.15", "cn-001",
            )

        assert len(hops) == 1
        assert hops[0]["route_type"] == "error"


# --- format_trace tests ---


class TestFormatTrace:
    """Tests for format_trace."""

    def test_routable_output(self):
        """Should produce ROUTABLE verdict for good path."""
        src = {
            "resource_name": "",
            "segment_name": "OnPremShared",
            "attachment_id": "att-vpn-1",
            "inferred": True,
            "matched_cidr": "10.200.0.0/16",
        }
        dst = {
            "resource_name": "web-01",
            "resource_type": "EC2Instance",
            "vpc_name": "prod-vpc",
            "vpc_id": "vpc-123",
            "subnet_name": "sub-a",
            "subnet_cidr": "10.127.32.0/20",
            "segment_name": "SLINGCoreBeta",
            "attachment_id": "att-vpc-2",
        }
        fwd_hops = [
            {
                "segment": "OnPremShared",
                "cidr": "10.127.0.0/16",
                "route_type": "propagated",
                "attachment_id": "att-1",
                "state": "active",
            },
            {
                "segment": "SLINGCoreBeta",
                "cidr": "destination",
                "route_type": "destination",
                "attachment_id": "",
                "state": "active",
            },
        ]
        ret_hops = [
            {
                "segment": "SLINGCoreBeta",
                "cidr": "10.200.0.0/16",
                "route_type": "propagated",
                "attachment_id": "att-2",
                "state": "active",
            },
            {
                "segment": "OnPremShared",
                "cidr": "destination",
                "route_type": "destination",
                "attachment_id": "",
                "state": "active",
            },
        ]
        output = format_trace(
            "10.200.5.42", "10.127.33.15",
            src, dst, fwd_hops, ret_hops,
        )
        assert "ROUTABLE" in output
        assert "Forward Path" in output
        assert "Return Path" in output
        assert "OnPremShared" in output
        assert "SLINGCoreBeta" in output
        assert "10.200.5.42" in output
        assert "10.127.33.15" in output

    def test_not_routable_output(self):
        """Should produce NOT ROUTABLE for broken path."""
        src = {"segment_name": "SegA"}
        dst = {"segment_name": "SegB"}
        fwd_hops = [
            {
                "segment": "SegA",
                "cidr": "",
                "route_type": "no-route",
                "attachment_id": "",
                "state": "no route to 10.0.0.1",
            },
        ]
        output = format_trace(
            "10.1.1.1", "10.0.0.1", src, dst, fwd_hops,
        )
        assert "NOT ROUTABLE" in output

    def test_same_segment(self):
        """Should show direct path for same segment."""
        src = {"segment_name": "SegA"}
        dst = {"segment_name": "SegA"}
        fwd_hops = [{
            "segment": "SegA",
            "cidr": "direct",
            "route_type": "same-segment",
            "attachment_id": "",
            "state": "active",
        }]
        output = format_trace(
            "10.0.0.1", "10.0.0.2", src, dst, fwd_hops,
        )
        assert "same segment" in output

    def test_bidirectional_asymmetric(self):
        """Forward ROUTABLE but return NOT ROUTABLE."""
        src = {"segment_name": "SegA"}
        dst = {"segment_name": "SegB"}
        fwd_hops = [
            {
                "segment": "SegA",
                "cidr": "10.0.0.0/8",
                "route_type": "propagated",
                "attachment_id": "att-1",
                "state": "active",
            },
            {
                "segment": "SegB",
                "cidr": "destination",
                "route_type": "destination",
                "attachment_id": "",
                "state": "active",
            },
        ]
        ret_hops = [
            {
                "segment": "SegB",
                "cidr": "",
                "route_type": "no-route",
                "attachment_id": "",
                "state": "no route to 10.1.1.1",
            },
        ]
        output = format_trace(
            "10.1.1.1", "10.0.0.1",
            src, dst, fwd_hops, ret_hops,
        )
        # Forward should be ROUTABLE
        fwd_section = output.split("Return Path")[0]
        assert "ROUTABLE" in fwd_section
        # Return should be NOT ROUTABLE
        ret_section = output.split("Return Path")[1]
        assert "NOT ROUTABLE" in ret_section


# --- trace_route (orchestrator) tests ---


class TestTraceRoute:
    """Tests for trace_route MCP tool."""

    @pytest.mark.asyncio
    async def test_invalid_source_ip(self):
        """Should reject invalid source IP."""
        ctx = _make_ctx(lambda *a, **k: [])
        result = await trace_route(
            ctx, "not-an-ip", "10.0.0.1",
        )
        assert "Invalid source IP" in result

    @pytest.mark.asyncio
    async def test_invalid_dest_ip(self):
        """Should reject invalid destination IP."""
        ctx = _make_ctx(lambda *a, **k: [])
        result = await trace_route(
            ctx, "10.0.0.1", "not-an-ip",
        )
        assert "Invalid destination IP" in result

    @pytest.mark.asyncio
    async def test_dest_not_found(self):
        """Should return error when dest IP not resolved."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            return []

        ctx = _make_ctx(_query)
        result = await trace_route(
            ctx, "10.200.5.42", "192.168.99.99",
        )
        assert "Could not resolve destination" in result

    @pytest.mark.asyncio
    async def test_no_cloudwan_attachment(self):
        """Should error when VPC has no CloudWAN attachment."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return [{
                    "name": "server-1",
                    "arn": "arn:ec2:i-1",
                    "labels": ["EC2Instance"],
                    "subnet_name": "sub",
                    "subnet_cidr": "10.50.0.0/20",
                    "vpc_name": "isolated-vpc",
                    "vpc_arn": "arn:vpc:iso",
                    "vpc_id": "vpc-iso",
                }]
            # No CloudWAN attachment
            if "CloudWANAttachment" in cypher:
                return []
            return []

        ctx = _make_ctx(_query)
        result = await trace_route(
            ctx, "10.200.1.1", "10.50.0.5",
        )
        assert "no CloudWAN attachment" in result

    @pytest.mark.asyncio
    async def test_end_to_end_happy_path(self):
        """Full happy path: on-prem -> CloudWAN -> VPC."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            # Destination resolution
            if "private_ip" in cypher:
                ip = (params or {}).get("ip", "")
                if ip == "10.127.33.15":
                    return [{
                        "name": "alb-prod",
                        "arn": "arn:alb:1",
                        "labels": ["LoadBalancer"],
                        "subnet_name": "sub-a",
                        "subnet_cidr": "10.127.32.0/20",
                        "vpc_name": "SLINGCoreBeta-VPC",
                        "vpc_arn": "arn:vpc:beta",
                        "vpc_id": "vpc-beta",
                    }]
                return []
            # VPC CIDR (not needed — exact match found)
            if "v:VPC" in cypher and "cidr_block" in cypher:
                return []
            # CloudWAN attachment for VPC
            if (
                "CloudWANAttachment" in cypher
                and "ATTACHED_TO" in cypher
            ):
                return [{
                    "seg_name": "SLINGCoreBeta",
                    "seg_arn": "arn:seg:beta",
                    "att_id": "att-vpc-456",
                }]
            # Segment hint resolution
            if (
                "CloudWANSegment" in cypher
                and "name" in (params or {})
            ):
                name = params.get("name", "")
                if name == "OnPremShared":
                    return [{
                        "name": "OnPremShared",
                        "arn": "arn:seg:onprem",
                        "cn_id": "cn-001",
                    }]
                return [{
                    "cn_id": "cn-001",
                    "edge_locs": ["us-west-2"],
                    "arn": "arn:seg:beta",
                }]
            return []

        ctx = _make_ctx(_query)

        def _mock_routes(neo4j, segment_name, **kwargs):
            if segment_name == "OnPremShared":
                return [{
                    "DestinationCidrBlock": "10.127.0.0/16",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [{
                        "CoreNetworkAttachmentId":
                            "att-vpc-456",
                        "SegmentName": "SLINGCoreBeta",
                    }],
                }]
            if segment_name == "SLINGCoreBeta":
                return [{
                    "DestinationCidrBlock": "10.200.0.0/16",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [{
                        "CoreNetworkAttachmentId":
                            "att-vpn-1",
                        "SegmentName": "OnPremShared",
                    }],
                }]
            return []

        with patch(
            "src.tools.trace_route.fetch_segment_routes",
            side_effect=_mock_routes,
        ):
            result = await trace_route(
                ctx,
                "10.200.5.42",
                "10.127.33.15",
                source_hint="segment:OnPremShared",
            )

        assert "ROUTABLE" in result
        assert "Forward Path" in result
        assert "Return Path" in result
        assert "OnPremShared" in result
        assert "SLINGCoreBeta" in result
        assert "10.200.5.42" in result
        assert "10.127.33.15" in result
        assert "alb-prod" in result

    @pytest.mark.asyncio
    async def test_source_not_found(self):
        """Should error when source IP can't be resolved."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            ip = (params or {}).get("ip", "")
            # Destination resolves fine
            if "private_ip" in cypher and ip == "10.127.33.15":
                return [{
                    "name": "server",
                    "arn": "arn:ec2:1",
                    "labels": ["EC2Instance"],
                    "subnet_name": "sub",
                    "subnet_cidr": "10.127.32.0/20",
                    "vpc_name": "vpc-prod",
                    "vpc_arn": "arn:vpc:prod",
                    "vpc_id": "vpc-prod",
                }]
            if "private_ip" in cypher:
                return []
            if "CloudWANAttachment" in cypher and "ATTACHED_TO" in cypher:
                return [{
                    "seg_name": "SLINGCoreBeta",
                    "seg_arn": "arn:seg:1",
                    "att_id": "att-1",
                }]
            if "v:VPC" in cypher:
                return []
            if "seg:CloudWANSegment" in cypher:
                return []
            return []

        ctx = _make_ctx(_query)
        result = await trace_route(
            ctx, "172.30.0.1", "10.127.33.15",
        )
        assert "Could not resolve source" in result


# --- on-prem destination resolution tests ---


class TestOnPremDestination:
    """Tests for on-prem IP as destination."""

    @pytest.mark.asyncio
    async def test_onprem_destination_single_vpn_segment(self):
        """Single VPN segment — graph-only, no API calls."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return []
            if "v:VPC" in cypher and "cidr_block" in cypher:
                return []
            # Single VPN segment in graph
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
                and "count" in cypher
            ):
                return [{
                    "seg_name": "SegmentSharedWAN",
                    "seg_arn": "arn:seg:wan",
                    "att_count": 12,
                }]
            return []

        neo4j = _make_neo4j(_query)
        result = await resolve_destination(
            neo4j, "10.126.12.90",
        )
        assert result is not None
        assert result["segment_name"] == "SegmentSharedWAN"
        assert result["origin"] == "on-prem-destination"
        assert result.get("inferred") is True

    @pytest.mark.asyncio
    async def test_onprem_destination_multi_vpn_falls_back(self):
        """Multiple VPN segments — falls back to API route
        table scan to pick the correct one."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return []
            if "v:VPC" in cypher and "cidr_block" in cypher:
                return []
            # Multiple VPN segments in graph
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
                and "count" in cypher
            ):
                return [
                    {"seg_name": "SegmentSharedWAN",
                     "seg_arn": "arn:seg:wan",
                     "att_count": 12},
                    {"seg_name": "OnPremShared",
                     "seg_arn": "arn:seg:onprem",
                     "att_count": 8},
                ]
            # _find_vpn_entry_segment attachment query
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
            ):
                return [
                    {"att_id": "att-vpn-wan",
                     "att_type": "SITE_TO_SITE_VPN",
                     "seg_name": "SegmentSharedWAN",
                     "cn_id": "cn-001"},
                    {"att_id": "att-vpn-onprem",
                     "att_type": "SITE_TO_SITE_VPN",
                     "seg_name": "OnPremShared",
                     "cn_id": "cn-001"},
                ]
            return []

        neo4j = _make_neo4j(_query)

        def _mock_fetch(neo4j, segment_name, **kwargs):
            if segment_name == "SegmentSharedWAN":
                return [{
                    "DestinationCidrBlock": "10.126.0.0/17",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [{
                        "CoreNetworkAttachmentId":
                            "att-vpn-wan",
                    }],
                }]
            return []

        with patch(
            "src.tools.trace_route_vpn"
            ".fetch_segment_routes",
            side_effect=_mock_fetch,
        ):
            result = await resolve_destination(
                neo4j, "10.126.12.90",
            )
        assert result is not None
        assert result["segment_name"] == "SegmentSharedWAN"
        assert result["attachment_id"] == "att-vpn-wan"
        assert result["origin"] == "on-prem-destination"

    @pytest.mark.asyncio
    async def test_onprem_destination_not_found(self):
        """Should return None when no VPN attachments exist."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "private_ip" in cypher:
                return []
            if "v:VPC" in cypher and "cidr_block" in cypher:
                return []
            if "CloudWANAttachment" in cypher:
                return []
            return []

        neo4j = _make_neo4j(_query)
        result = await resolve_destination(
            neo4j, "192.168.99.99",
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_bidirectional_with_onprem_dest(self):
        """Trace with on-prem destination should work
        bidirectionally."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            ip = (params or {}).get("ip", "")
            # Source resolves via exact IP
            if "private_ip" in cypher and ip == "10.150.36.137":
                return [{
                    "name": "dev-server",
                    "arn": "arn:ec2:dev",
                    "labels": ["EC2Instance"],
                    "subnet_name": "sub-dev",
                    "subnet_cidr": "10.150.32.0/20",
                    "vpc_name": "dev-vpc",
                    "vpc_arn": "arn:vpc:dev",
                    "vpc_id": "vpc-dev",
                }]
            if "private_ip" in cypher:
                return []
            if "v:VPC" in cypher and "cidr_block" in cypher:
                return []
            # VPC attachment for source VPC
            if (
                "CloudWANAttachment" in cypher
                and "ATTACHED_TO" in cypher
            ):
                return [{
                    "seg_name": "SegmentDevelopment",
                    "seg_arn": "arn:seg:dev",
                    "att_id": "att-vpc-dev",
                }]
            # Graph VPN segment lookup (dest resolution)
            if (
                "CloudWANAttachment" in cypher
                and "SITE_TO_SITE_VPN" in cypher
                and "count" in cypher
            ):
                return [{
                    "seg_name": "SegmentSharedWAN",
                    "seg_arn": "arn:seg:wan",
                    "att_count": 12,
                }]
            # Segment info for cn_id resolution
            if "CloudWANSegment" in cypher:
                return [{
                    "cn_id": "cn-001",
                    "edge_locs": ["us-west-2"],
                    "arn": "arn:seg:dev",
                }]
            return []

        ctx = _make_ctx(_query)

        def _mock_routes(neo4j, segment_name, **kwargs):
            if segment_name == "SegmentDevelopment":
                return [{
                    "DestinationCidrBlock": "10.126.0.0/17",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [{
                        "CoreNetworkAttachmentId":
                            "att-wan",
                        "SegmentName": "SegmentSharedWAN",
                    }],
                }]
            if segment_name == "SegmentSharedWAN":
                return [{
                    "DestinationCidrBlock": "10.150.0.0/16",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [{
                        "CoreNetworkAttachmentId":
                            "att-vpc-dev",
                        "SegmentName": "SegmentDevelopment",
                    }],
                }]
            return []

        with patch(
            "src.tools.trace_route.fetch_segment_routes",
            side_effect=_mock_routes,
        ):
            result = await trace_route(
                ctx, "10.150.36.137", "10.126.12.90",
            )

        assert "Forward Path" in result
        assert "Return Path" in result
        assert "SegmentDevelopment" in result
        assert "SegmentSharedWAN" in result
