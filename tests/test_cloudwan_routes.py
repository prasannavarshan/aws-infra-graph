"""Tests for CloudWAN route tools and verification functions."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from src.tools.cloudwan_routes import (
    correlate_routes_to_segments,
    fetch_segment_routes,
    format_route_verification,
    get_cloudwan_routes,
    verify_route_propagation,
)

SRC_ARN = (
    "arn:aws:networkmanager::123456789012"
    ":core-network/cn-001/segment/OnPremShared"
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


class TestGetCloudwanRoutes:
    """Tests for get_cloudwan_routes MCP tool."""

    @pytest.mark.asyncio
    async def test_happy_path_returns_routes(self):
        """Should format routes from AWS API response."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "CloudWANSegment" in cypher:
                return [
                    {
                        "cn_id": "cn-001",
                        "edge_locs": ["us-west-2"],
                        "arn": SRC_ARN,
                    },
                ]
            if "CloudWANCoreNetwork" in cypher:
                return [{"gn_id": "gn-001", "account_id": "123456789012"}]
            return []

        ctx = _make_ctx(_query)

        mock_nm = MagicMock()
        mock_nm.get_network_routes.return_value = {
            "NetworkRoutes": [
                {
                    "DestinationCidrBlock": "10.182.0.0/16",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [
                        {
                            "CoreNetworkAttachmentId": "att-1",
                            "SegmentName": "OnPremShared",
                        },
                    ],
                },
                {
                    "DestinationCidrBlock": "10.183.0.0/16",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [],
                },
            ],
        }

        mock_session = MagicMock()
        mock_session.client.return_value = mock_nm

        with patch(
            "src.tools.cloudwan_routes.get_session_for_account",
            return_value=mock_session,
        ):
            result = await get_cloudwan_routes(
                ctx, "OnPremShared",
            )

        assert "10.182.0.0/16" in result
        assert "10.183.0.0/16" in result
        assert "propagated" in result
        assert "att-1" in result
        assert "2 routes" in result

    @pytest.mark.asyncio
    async def test_segment_not_found(self):
        """Should return error when segment not in graph."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            return []

        ctx = _make_ctx(_query)
        result = await get_cloudwan_routes(
            ctx, "NonExistent",
        )
        assert "not found" in result

    @pytest.mark.asyncio
    async def test_aws_api_error(self):
        """Should return error message on ClientError."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "CloudWANSegment" in cypher:
                return [
                    {
                        "cn_id": "cn-001",
                        "edge_locs": ["us-west-2"],
                        "arn": SRC_ARN,
                    },
                ]
            if "CloudWANCoreNetwork" in cypher:
                return [{"gn_id": "gn-001", "account_id": "123456789012"}]
            return []

        ctx = _make_ctx(_query)

        mock_nm = MagicMock()
        mock_nm.get_network_routes.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ValidationException",
                    "Message": "Invalid segment",
                },
            },
            "GetNetworkRoutes",
        )

        mock_session = MagicMock()
        mock_session.client.return_value = mock_nm

        with patch(
            "src.tools.cloudwan_routes.get_session_for_account",
            return_value=mock_session,
        ):
            result = await get_cloudwan_routes(
                ctx, "OnPremShared",
            )

        assert "AWS API error" in result
        assert "ValidationException" in result


class TestFetchSegmentRoutes:
    """Tests for fetch_segment_routes helper."""

    @pytest.mark.asyncio
    async def test_happy_path_returns_route_list(self):
        """Should return list of route dicts."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "CloudWANSegment" in cypher:
                return [
                    {
                        "cn_id": "cn-001",
                        "edge_locs": ["us-west-2"],
                        "arn": SRC_ARN,
                    },
                ]
            if "CloudWANCoreNetwork" in cypher:
                return [{"gn_id": "gn-001", "account_id": "123456789012"}]
            return []

        neo4j = _make_neo4j(_query)

        mock_nm = MagicMock()
        mock_nm.get_network_routes.return_value = {
            "NetworkRoutes": [
                {
                    "DestinationCidrBlock": "10.0.0.0/8",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [
                        {"SegmentName": "TestSeg"},
                    ],
                },
            ],
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_nm

        with patch(
            "src.tools.cloudwan_routes.get_session_for_account",
            return_value=mock_session,
        ):
            result = await fetch_segment_routes(
                neo4j, "OnPremShared",
            )

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["DestinationCidrBlock"] == "10.0.0.0/8"

    @pytest.mark.asyncio
    async def test_empty_routes(self):
        """Should return empty list when no routes."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "CloudWANSegment" in cypher:
                return [
                    {
                        "cn_id": "cn-001",
                        "edge_locs": ["us-west-2"],
                        "arn": SRC_ARN,
                    },
                ]
            if "CloudWANCoreNetwork" in cypher:
                return [{"gn_id": "gn-001", "account_id": "123456789012"}]
            return []

        neo4j = _make_neo4j(_query)

        mock_nm = MagicMock()
        mock_nm.get_network_routes.return_value = {
            "NetworkRoutes": [],
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_nm

        with patch(
            "src.tools.cloudwan_routes.get_session_for_account",
            return_value=mock_session,
        ):
            result = await fetch_segment_routes(
                neo4j, "OnPremShared",
            )

        assert isinstance(result, list)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_api_error_returns_string(self):
        """Should return error string on ClientError."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "CloudWANSegment" in cypher:
                return [
                    {
                        "cn_id": "cn-001",
                        "edge_locs": ["us-west-2"],
                        "arn": SRC_ARN,
                    },
                ]
            if "CloudWANCoreNetwork" in cypher:
                return [{"gn_id": "gn-001", "account_id": "123456789012"}]
            return []

        neo4j = _make_neo4j(_query)

        mock_nm = MagicMock()
        mock_nm.get_network_routes.side_effect = ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "No access",
                },
            },
            "GetNetworkRoutes",
        )
        mock_session = MagicMock()
        mock_session.client.return_value = mock_nm

        with patch(
            "src.tools.cloudwan_routes.get_session_for_account",
            return_value=mock_session,
        ):
            result = await fetch_segment_routes(
                neo4j, "OnPremShared",
            )

        assert isinstance(result, str)
        assert "AWS API error" in result


class TestCorrelateRoutesToSegments:
    """Tests for correlate_routes_to_segments."""

    @pytest.mark.asyncio
    async def test_groups_by_segment_name(self):
        """Routes grouped by SegmentName."""
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(return_value=[])
        routes = [
            {
                "DestinationCidrBlock": "10.0.0.0/16",
                "Destinations": [
                    {"SegmentName": "SegA"},
                ],
            },
            {
                "DestinationCidrBlock": "10.1.0.0/16",
                "Destinations": [
                    {"SegmentName": "SegB"},
                ],
            },
            {
                "DestinationCidrBlock": "10.2.0.0/16",
                "Destinations": [
                    {"SegmentName": "SegA"},
                ],
            },
        ]
        result = await correlate_routes_to_segments(
            neo4j, routes,
        )
        assert len(result["SegA"]) == 2
        assert len(result["SegB"]) == 1

    @pytest.mark.asyncio
    async def test_fallback_to_graph_lookup(self):
        """Routes without SegmentName resolved via graph."""
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(return_value=[
            {"att_id": "att-1", "seg_name": "SegFromGraph"},
        ])
        routes = [
            {
                "DestinationCidrBlock": "10.0.0.0/16",
                "Destinations": [
                    {"CoreNetworkAttachmentId": "att-1"},
                ],
            },
        ]
        result = await correlate_routes_to_segments(
            neo4j, routes,
        )
        assert "SegFromGraph" in result
        assert len(result["SegFromGraph"]) == 1

    @pytest.mark.asyncio
    async def test_unresolvable_goes_to_unknown(self):
        """Routes without SegmentName or graph match."""
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(return_value=[])
        routes = [
            {
                "DestinationCidrBlock": "10.0.0.0/16",
                "Destinations": [
                    {"CoreNetworkAttachmentId": "att-999"},
                ],
            },
        ]
        result = await correlate_routes_to_segments(
            neo4j, routes,
        )
        assert "_unknown" in result

    @pytest.mark.asyncio
    async def test_empty_destinations(self):
        """Routes with empty Destinations go to _unknown."""
        neo4j = AsyncMock()
        neo4j.query = AsyncMock(return_value=[])
        routes = [
            {
                "DestinationCidrBlock": "10.0.0.0/16",
                "Destinations": [],
            },
        ]
        result = await correlate_routes_to_segments(
            neo4j, routes,
        )
        assert "_unknown" in result


class TestVerifyRoutePropagation:
    """Tests for verify_route_propagation."""

    @pytest.mark.asyncio
    async def test_routes_confirmed_reachable(self):
        """REACHABLE when source routes in target."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "CloudWANSegment" in cypher:
                return [
                    {
                        "cn_id": "cn-001",
                        "edge_locs": ["us-west-2"],
                        "arn": SRC_ARN,
                    },
                ]
            if "CloudWANCoreNetwork" in cypher:
                return [{"gn_id": "gn-001", "account_id": "123456789012"}]
            return []

        neo4j = _make_neo4j(_query)

        mock_nm = MagicMock()
        mock_nm.get_network_routes.return_value = {
            "NetworkRoutes": [
                {
                    "DestinationCidrBlock": "10.0.0.0/16",
                    "Destinations": [
                        {"SegmentName": "SegSrc"},
                    ],
                },
            ],
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_nm

        with patch(
            "src.tools.cloudwan_routes.get_session_for_account",
            return_value=mock_session,
        ):
            result = await verify_route_propagation(
                neo4j, "SegSrc", "SegTgt",
            )

        assert result["verified"] is True
        assert result["verdict"] == "REACHABLE"
        assert result["routes_from_source"] == 1
        assert result["error"] is None

    @pytest.mark.asyncio
    async def test_no_routes_policy_allows(self):
        """POLICY_ALLOWS when no source routes in target."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "CloudWANSegment" in cypher:
                return [
                    {
                        "cn_id": "cn-001",
                        "edge_locs": ["us-west-2"],
                        "arn": SRC_ARN,
                    },
                ]
            if "CloudWANCoreNetwork" in cypher:
                return [{"gn_id": "gn-001", "account_id": "123456789012"}]
            return []

        neo4j = _make_neo4j(_query)

        mock_nm = MagicMock()
        mock_nm.get_network_routes.return_value = {
            "NetworkRoutes": [
                {
                    "DestinationCidrBlock": "10.0.0.0/16",
                    "Destinations": [
                        {"SegmentName": "OtherSeg"},
                    ],
                },
            ],
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_nm

        with patch(
            "src.tools.cloudwan_routes.get_session_for_account",
            return_value=mock_session,
        ):
            result = await verify_route_propagation(
                neo4j, "SegSrc", "SegTgt",
            )

        assert result["verified"] is True
        assert result["verdict"] == "POLICY_ALLOWS"
        assert result["routes_from_source"] == 0

    @pytest.mark.asyncio
    async def test_api_error_returns_unverified(self):
        """API error returns verified=False with error."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "CloudWANSegment" in cypher:
                return [
                    {
                        "cn_id": "cn-001",
                        "edge_locs": ["us-west-2"],
                        "arn": SRC_ARN,
                    },
                ]
            if "CloudWANCoreNetwork" in cypher:
                return [{"gn_id": "gn-001", "account_id": "123456789012"}]
            return []

        neo4j = _make_neo4j(_query)

        mock_nm = MagicMock()
        mock_nm.get_network_routes.side_effect = ClientError(
            {
                "Error": {
                    "Code": "ThrottlingException",
                    "Message": "Rate exceeded",
                },
            },
            "GetNetworkRoutes",
        )
        mock_session = MagicMock()
        mock_session.client.return_value = mock_nm

        with patch(
            "src.tools.cloudwan_routes.get_session_for_account",
            return_value=mock_session,
        ):
            result = await verify_route_propagation(
                neo4j, "SegSrc", "SegTgt",
            )

        assert result["verified"] is False
        assert result["error"] is not None
        assert "AWS API error" in result["error"]


class TestFormatRouteVerification:
    """Tests for format_route_verification."""

    def test_format_policy_allows(self):
        """Formats POLICY_ALLOWS with route origins."""
        verification = {
            "verified": True,
            "verdict": "POLICY_ALLOWS",
            "routes_from_source": 0,
            "total_routes": 47,
            "segment_route_counts": {
                "SegmentSharedWAN": 23,
                "SLINGShared": 12,
                "_unknown": 12,
            },
            "error": None,
        }
        lines = format_route_verification(
            "OnPremShared", "SegmentDevelopment",
            verification,
        )
        text = "\n".join(lines)
        assert "Route Verification" in text
        assert "47 total routes" in text
        assert "0 from OnPremShared" in text
        assert "SegmentSharedWAN" in text
        assert "POLICY_ALLOWS" in text
        assert "Traffic likely flows via" in text

    def test_format_reachable_confirmed(self):
        """Formats confirmed REACHABLE."""
        verification = {
            "verified": True,
            "verdict": "REACHABLE",
            "routes_from_source": 5,
            "total_routes": 30,
            "segment_route_counts": {
                "SegSrc": 5,
                "OtherSeg": 25,
            },
            "error": None,
        }
        lines = format_route_verification(
            "SegSrc", "SegTgt", verification,
        )
        text = "\n".join(lines)
        assert "confirmed" in text
        assert "5 from SegSrc" in text

    def test_format_error_fallback(self):
        """Formats API error with warning."""
        verification = {
            "verified": False,
            "verdict": None,
            "routes_from_source": 0,
            "total_routes": 0,
            "segment_route_counts": {},
            "error": "AWS API error: ThrottlingException",
        }
        lines = format_route_verification(
            "SegSrc", "SegTgt", verification,
        )
        text = "\n".join(lines)
        assert "Warning" in text
        assert "retained" in text
