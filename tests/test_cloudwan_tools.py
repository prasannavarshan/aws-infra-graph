"""Tests for CloudWAN connectivity checker tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.tools.cloudwan_tools import (
    check_cloudwan_connectivity,
)


def _make_ctx(query_results: dict[str, list]) -> MagicMock:
    """Create a mock MCP Context with a Neo4j client.

    Args:
        query_results: Map of query substring -> results.
            The mock returns the first matching result list
            based on substring match against the Cypher query.
    """
    neo4j = AsyncMock()

    async def _query(cypher: str, params: dict | None = None):
        for key, result in query_results.items():
            if key in cypher:
                return result
        return []

    neo4j.query = AsyncMock(side_effect=_query)

    app_ctx = MagicMock()
    app_ctx.neo4j = neo4j

    ctx = MagicMock()
    ctx.request_context.lifespan_context = app_ctx
    return ctx


def _make_ctx_fn(query_fn) -> MagicMock:
    """Create a mock MCP Context with a custom query function."""
    neo4j = AsyncMock()
    neo4j.query = AsyncMock(side_effect=query_fn)

    app_ctx = MagicMock()
    app_ctx.neo4j = neo4j

    ctx = MagicMock()
    ctx.request_context.lifespan_context = app_ctx
    return ctx


# Shared test data
SRC_ARN = (
    "arn:aws:networkmanager::123456789012"
    ":core-network/cn-001/segment/OnPremWAN"
)
TGT_ARN = (
    "arn:aws:networkmanager::123456789012"
    ":core-network/cn-001/segment/ProdSegment"
)
MID_ARN = (
    "arn:aws:networkmanager::123456789012"
    ":core-network/cn-001/segment/Transit"
)


class TestDirectShare:
    """Happy path: direct CONNECTS_TO between segments."""

    @pytest.mark.asyncio
    async def test_direct_share_returns_reachable(self):
        ctx = _make_ctx({
            "n.name IN": [
                {
                    "name": "OnPremWAN",
                    "arn": SRC_ARN,
                    "isolate": False,
                    "deny_filter": None,
                    "cn_id": "cn-001",
                },
                {
                    "name": "ProdSegment",
                    "arn": TGT_ARN,
                    "isolate": False,
                    "deny_filter": None,
                    "cn_id": "cn-001",
                },
            ],
            "CONNECTS_TO": [
                {
                    "src": "OnPremWAN",
                    "tgt": "ProdSegment",
                    "mode": "attachment-route",
                    "type": "segment_action",
                    "src_deny_filter": None,
                    "tgt_deny_filter": None,
                    "direction": "outgoing",
                },
            ],
            "UNWIND range": [],
            "PART_OF": [],
        })
        result = await check_cloudwan_connectivity(
            ctx, "OnPremWAN", "ProdSegment",
        )
        assert "REACHABLE" in result
        assert "Forward" in result
        assert "Return" in result
        assert "attachment-route" in result


class TestIndirectPath:
    """Happy path: indirect path through intermediate segments."""

    @pytest.mark.asyncio
    async def test_indirect_path_returns_reachable(self):
        path_segs = [
            {
                "name": "OnPremWAN",
                "arn": SRC_ARN,
                "deny_filter": None,
            },
            {
                "name": "Transit",
                "arn": MID_ARN,
                "deny_filter": None,
            },
            {
                "name": "ProdSegment",
                "arn": TGT_ARN,
                "deny_filter": None,
            },
        ]

        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "n.name IN" in cypher:
                return [
                    {
                        "name": "OnPremWAN",
                        "arn": SRC_ARN,
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                    {
                        "name": "ProdSegment",
                        "arn": TGT_ARN,
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                ]
            if (
                "CONNECTS_TO" in cypher
                and "*1..5" not in cypher
            ):
                # Direct edge check — no direct edge
                return []
            if "nodes(path)[i].name" in cypher:
                # Forward reachable path query
                return [{"segments": path_segs}]
            if "nodes(path)[i+1].name" in cypher:
                # Return reachable path query
                return [{"segments": path_segs}]
            if "CONNECTS_TO*1..5" in cypher:
                # Fallback any-path query
                return [{"segments": path_segs}]
            if "PART_OF" in cypher:
                return []
            return []

        ctx = _make_ctx_fn(_query)
        result = await check_cloudwan_connectivity(
            ctx, "OnPremWAN", "ProdSegment",
        )
        assert "REACHABLE" in result
        assert "Transit" in result
        assert "Forward" in result
        assert "Return" in result


class TestDenyBlocks:
    """Edge case: segment-action deny (hard block)."""

    @pytest.mark.asyncio
    async def test_deny_returns_blocked_hard(self):
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "n.name IN" in cypher:
                return [
                    {
                        "name": "OnPremWAN",
                        "arn": SRC_ARN,
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                    {
                        "name": "ProdSegment",
                        "arn": TGT_ARN,
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                ]
            if (
                "CONNECTS_TO" in cypher
                and "*1..5" not in cypher
            ):
                return [
                    {
                        "src": "OnPremWAN",
                        "tgt": "ProdSegment",
                        "mode": "attachment-route",
                        "type": "segment_action",
                        "src_deny_filter": None,
                        "tgt_deny_filter": None,
                        "direction": "outgoing",
                    },
                ]
            if "UNWIND range" in cypher:
                return [
                    {
                        "src": "OnPremWAN",
                        "tgt": "ProdSegment",
                        "type": "segment_action_deny",
                    },
                ]
            if "PART_OF" in cypher:
                return []
            return []

        ctx = _make_ctx_fn(_query)
        result = await check_cloudwan_connectivity(
            ctx, "OnPremWAN", "ProdSegment",
        )
        assert "BLOCKED_HARD" in result
        assert "segment-action deny" in result


class TestNoPath:
    """Edge case: no CONNECTS_TO chain exists."""

    @pytest.mark.asyncio
    async def test_no_path_returns_no_path(self):
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "n.name IN" in cypher:
                return [
                    {
                        "name": "OnPremWAN",
                        "arn": SRC_ARN,
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                    {
                        "name": "ProdSegment",
                        "arn": TGT_ARN,
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                ]
            if "CONNECTS_TO" in cypher:
                return []
            if "PART_OF" in cypher:
                return []
            return []

        ctx = _make_ctx_fn(_query)
        result = await check_cloudwan_connectivity(
            ctx, "OnPremWAN", "ProdSegment",
        )
        assert "NO_PATH" in result


class TestIsolationWarning:
    """Edge case: segment has isolate_attachments=true."""

    @pytest.mark.asyncio
    async def test_isolation_warning_included(self):
        ctx = _make_ctx({
            "n.name IN": [
                {
                    "name": "OnPremWAN",
                    "arn": SRC_ARN,
                    "isolate": True,
                    "deny_filter": None,
                    "cn_id": "cn-001",
                },
                {
                    "name": "ProdSegment",
                    "arn": TGT_ARN,
                    "isolate": False,
                    "deny_filter": None,
                    "cn_id": "cn-001",
                },
            ],
            "CONNECTS_TO": [
                {
                    "src": "OnPremWAN",
                    "tgt": "ProdSegment",
                    "mode": "attachment-route",
                    "type": "segment_action",
                    "src_deny_filter": None,
                    "tgt_deny_filter": None,
                    "direction": "outgoing",
                },
            ],
            "UNWIND range": [],
            "PART_OF": [],
        })
        result = await check_cloudwan_connectivity(
            ctx, "OnPremWAN", "ProdSegment",
        )
        assert "REACHABLE" in result
        assert "isolate_attachments=true" in result
        assert "OnPremWAN" in result


class TestSegmentNotFound:
    """Error case: segment not found in graph."""

    @pytest.mark.asyncio
    async def test_source_not_found(self):
        ctx = _make_ctx({
            "n.name IN": [
                {
                    "name": "ProdSegment",
                    "arn": TGT_ARN,
                    "isolate": False,
                    "deny_filter": None,
                    "cn_id": "cn-001",
                },
            ],
        })
        result = await check_cloudwan_connectivity(
            ctx, "NonExistent", "ProdSegment",
        )
        assert "not found" in result
        assert "NonExistent" in result

    @pytest.mark.asyncio
    async def test_target_not_found(self):
        ctx = _make_ctx({
            "n.name IN": [
                {
                    "name": "OnPremWAN",
                    "arn": SRC_ARN,
                    "isolate": False,
                    "deny_filter": None,
                    "cn_id": "cn-001",
                },
            ],
        })
        result = await check_cloudwan_connectivity(
            ctx, "OnPremWAN", "NonExistent",
        )
        assert "not found" in result
        assert "NonExistent" in result


class TestAsymmetricConnectivity:
    """Tests for asymmetric deny-filter routing."""

    @pytest.mark.asyncio
    async def test_forward_blocked_return_reachable(self):
        """OnPremWAN -> ProdSegment blocked, reverse works."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "n.name IN" in cypher:
                return [
                    {
                        "name": "OnPremWAN",
                        "arn": SRC_ARN,
                        "isolate": False,
                        "deny_filter": [
                            "NonProdImportFilter",
                            "Fallback",
                        ],
                        "cn_id": "cn-001",
                    },
                    {
                        "name": "ProdSegment",
                        "arn": TGT_ARN,
                        "isolate": False,
                        "deny_filter": [
                            "NonProdImportFilter",
                            "Fallback",
                        ],
                        "cn_id": "cn-001",
                    },
                ]
            if (
                "CONNECTS_TO" in cypher
                and "*1..5" not in cypher
            ):
                return [
                    {
                        "src": "OnPremWAN",
                        "tgt": "ProdSegment",
                        "mode": "attachment-route",
                        "type": "segment_action",
                        "src_deny_filter": [
                            "NonProdImportFilter",
                            "Fallback",
                        ],
                        "tgt_deny_filter": [
                            "NonProdImportFilter",
                            "Fallback",
                        ],
                        "direction": "outgoing",
                    },
                ]
            if "UNWIND range" in cypher:
                return []
            if "PART_OF" in cypher:
                return []
            return []

        ctx = _make_ctx_fn(_query)
        result = await check_cloudwan_connectivity(
            ctx, "OnPremWAN", "ProdSegment",
        )
        assert "Forward" in result
        assert "Return" in result
        assert "REACHABLE" in result
        assert "Deny-filters:" in result

    @pytest.mark.asyncio
    async def test_asymmetric_via_intermediate(self):
        """Forward blocked at intermediate, return reachable."""
        path_segs = [
            {
                "name": "SegA",
                "arn": "arn:seg/SegA",
                "deny_filter": None,
            },
            {
                "name": "SegX",
                "arn": "arn:seg/SegX",
                "deny_filter": ["SegA"],
            },
            {
                "name": "SegB",
                "arn": "arn:seg/SegB",
                "deny_filter": None,
            },
        ]

        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "n.name IN" in cypher:
                return [
                    {
                        "name": "SegA",
                        "arn": "arn:seg/SegA",
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                    {
                        "name": "SegB",
                        "arn": "arn:seg/SegB",
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                ]
            if (
                "CONNECTS_TO" in cypher
                and "*1..5" not in cypher
            ):
                return []
            if "nodes(path)[i].name" in cypher:
                return []
            if "nodes(path)[i+1].name" in cypher:
                return [{"segments": path_segs}]
            if "CONNECTS_TO*1..5" in cypher:
                return [{"segments": path_segs}]
            if "PART_OF" in cypher:
                return []
            return []

        ctx = _make_ctx_fn(_query)
        result = await check_cloudwan_connectivity(
            ctx, "SegA", "SegB",
        )
        assert "Forward" in result
        assert "BLOCKED" in result
        assert "SegX has deny-filter" in result
        assert "Return" in result
        assert "REACHABLE" in result

    @pytest.mark.asyncio
    async def test_both_directions_blocked(self):
        """Both directions blocked by deny-filters."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "n.name IN" in cypher:
                return [
                    {
                        "name": "SegA",
                        "arn": "arn:seg/SegA",
                        "isolate": False,
                        "deny_filter": ["SegB"],
                        "cn_id": "cn-001",
                    },
                    {
                        "name": "SegB",
                        "arn": "arn:seg/SegB",
                        "isolate": False,
                        "deny_filter": ["SegA"],
                        "cn_id": "cn-001",
                    },
                ]
            if (
                "CONNECTS_TO" in cypher
                and "*1..5" not in cypher
            ):
                return [
                    {
                        "src": "SegA",
                        "tgt": "SegB",
                        "mode": "attachment-route",
                        "type": "segment_action",
                        "src_deny_filter": ["SegB"],
                        "tgt_deny_filter": ["SegA"],
                        "direction": "outgoing",
                    },
                ]
            if "UNWIND range" in cypher:
                return []
            if "PART_OF" in cypher:
                return []
            return []

        ctx = _make_ctx_fn(_query)
        result = await check_cloudwan_connectivity(
            ctx, "SegA", "SegB",
        )
        assert "Forward" in result
        assert "Return" in result
        assert result.count("BLOCKED") >= 2

    @pytest.mark.asyncio
    async def test_shortest_blocked_longer_reachable(self):
        """Shortest path blocked, longer path reachable."""
        short_path = [
            {
                "name": "SegA",
                "arn": "arn:seg/SegA",
                "deny_filter": None,
            },
            {
                "name": "SegX",
                "arn": "arn:seg/SegX",
                "deny_filter": ["SegA"],
            },
            {
                "name": "SegB",
                "arn": "arn:seg/SegB",
                "deny_filter": None,
            },
        ]
        long_path = [
            {
                "name": "SegA",
                "arn": "arn:seg/SegA",
                "deny_filter": None,
            },
            {
                "name": "SegY",
                "arn": "arn:seg/SegY",
                "deny_filter": None,
            },
            {
                "name": "SegB",
                "arn": "arn:seg/SegB",
                "deny_filter": None,
            },
        ]

        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "n.name IN" in cypher:
                return [
                    {
                        "name": "SegA",
                        "arn": "arn:seg/SegA",
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                    {
                        "name": "SegB",
                        "arn": "arn:seg/SegB",
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                ]
            if (
                "CONNECTS_TO" in cypher
                and "*1..5" not in cypher
            ):
                return []
            if "nodes(path)[i].name" in cypher:
                return [{"segments": long_path}]
            if "nodes(path)[i+1].name" in cypher:
                return [{"segments": long_path}]
            if "CONNECTS_TO*1..5" in cypher:
                return [{"segments": short_path}]
            if "PART_OF" in cypher:
                return []
            return []

        ctx = _make_ctx_fn(_query)
        result = await check_cloudwan_connectivity(
            ctx, "SegA", "SegB",
        )
        assert "Forward" in result
        assert "REACHABLE" in result
        assert "SegY" in result
        assert "All paths blocked" not in result


class TestDenyFilter:
    """Tests for deny-filter display in output."""

    @pytest.mark.asyncio
    async def test_deny_filter_displayed_in_output(self):
        """deny-filter lists shown in output for context."""
        ctx = _make_ctx({
            "n.name IN": [
                {
                    "name": "OnPremWAN",
                    "arn": SRC_ARN,
                    "isolate": False,
                    "deny_filter": [
                        "NonProdImportFilter",
                        "ProdImportFilter",
                    ],
                    "cn_id": "cn-001",
                },
                {
                    "name": "ProdSegment",
                    "arn": TGT_ARN,
                    "isolate": False,
                    "deny_filter": [
                        "NonProdImportFilter",
                    ],
                    "cn_id": "cn-001",
                },
            ],
            "CONNECTS_TO": [
                {
                    "src": "OnPremWAN",
                    "tgt": "ProdSegment",
                    "mode": "attachment-route",
                    "type": "segment_action",
                    "src_deny_filter": [
                        "NonProdImportFilter",
                        "ProdImportFilter",
                    ],
                    "tgt_deny_filter": [
                        "NonProdImportFilter",
                    ],
                    "direction": "outgoing",
                },
            ],
            "UNWIND range": [],
            "PART_OF": [],
        })
        result = await check_cloudwan_connectivity(
            ctx, "OnPremWAN", "ProdSegment",
        )
        assert "Deny-filters:" in result
        assert "OnPremWAN blocks imports from:" in result
        assert "NonProdImportFilter" in result
        assert "ProdImportFilter" in result
        assert (
            "ProdSegment blocks imports from:" in result
        )


class TestVerifyRoutesParam:
    """Tests for verify_routes=True route verification."""

    @pytest.mark.asyncio
    async def test_verify_routes_false_no_api_call(self):
        """Default verify_routes=False skips route check."""
        ctx = _make_ctx({
            "n.name IN": [
                {
                    "name": "OnPremWAN",
                    "arn": SRC_ARN,
                    "isolate": False,
                    "deny_filter": None,
                    "cn_id": "cn-001",
                },
                {
                    "name": "ProdSegment",
                    "arn": TGT_ARN,
                    "isolate": False,
                    "deny_filter": None,
                    "cn_id": "cn-001",
                },
            ],
            "CONNECTS_TO": [
                {
                    "src": "OnPremWAN",
                    "tgt": "ProdSegment",
                    "mode": "attachment-route",
                    "type": "segment_action",
                    "src_deny_filter": None,
                    "tgt_deny_filter": None,
                    "direction": "outgoing",
                },
            ],
            "UNWIND range": [],
            "PART_OF": [],
        })
        result = await check_cloudwan_connectivity(
            ctx, "OnPremWAN", "ProdSegment",
            verify_routes=False,
        )
        assert "REACHABLE" in result
        assert "Route Verification" not in result
        assert "verify_routes=True" in result

    @pytest.mark.asyncio
    async def test_verify_routes_downgrades_to_policy(
        self,
    ):
        """verify_routes=True downgrades when no routes."""
        call_count = {"fetch": 0}

        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "n.name IN" in cypher:
                return [
                    {
                        "name": "OnPremWAN",
                        "arn": SRC_ARN,
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                    {
                        "name": "ProdSegment",
                        "arn": TGT_ARN,
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                ]
            if (
                "CONNECTS_TO" in cypher
                and "*1..5" not in cypher
            ):
                return [
                    {
                        "src": "OnPremWAN",
                        "tgt": "ProdSegment",
                        "mode": "attachment-route",
                        "type": "segment_action",
                        "src_deny_filter": None,
                        "tgt_deny_filter": None,
                        "direction": "outgoing",
                    },
                ]
            if "UNWIND range" in cypher:
                return []
            if "PART_OF" in cypher:
                return []
            if "CloudWANSegment" in cypher and "name" in cypher:
                call_count["fetch"] += 1
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

        ctx = _make_ctx_fn(_query)

        mock_nm = MagicMock()
        # Return routes from SharedWAN, not OnPremWAN
        mock_nm.get_network_routes.return_value = {
            "NetworkRoutes": [
                {
                    "DestinationCidrBlock": "10.0.0.0/16",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [
                        {
                            "CoreNetworkAttachmentId": "a-1",
                            "SegmentName": "SharedWAN",
                        },
                    ],
                },
            ],
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_nm

        from unittest.mock import patch
        with patch(
            "src.tools.cloudwan_routes.get_session_for_account",
            return_value=mock_session,
        ):
            result = await check_cloudwan_connectivity(
                ctx, "OnPremWAN", "ProdSegment",
                verify_routes=True,
            )

        assert "POLICY_ALLOWS" in result
        assert "Route Verification" in result
        assert "SharedWAN" in result
        assert call_count["fetch"] >= 1

    @pytest.mark.asyncio
    async def test_verify_routes_confirms_reachable(self):
        """verify_routes=True keeps REACHABLE when confirmed."""
        async def _query(
            cypher: str, params: dict | None = None,
        ):
            if "n.name IN" in cypher:
                return [
                    {
                        "name": "SegA",
                        "arn": "arn:seg/SegA",
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                    {
                        "name": "SegB",
                        "arn": "arn:seg/SegB",
                        "isolate": False,
                        "deny_filter": None,
                        "cn_id": "cn-001",
                    },
                ]
            if (
                "CONNECTS_TO" in cypher
                and "*1..5" not in cypher
            ):
                return [
                    {
                        "src": "SegA",
                        "tgt": "SegB",
                        "mode": "attachment-route",
                        "type": "segment_action",
                        "src_deny_filter": None,
                        "tgt_deny_filter": None,
                        "direction": "outgoing",
                    },
                ]
            if "UNWIND range" in cypher:
                return []
            if "PART_OF" in cypher:
                return []
            if "CloudWANSegment" in cypher and "name" in cypher:
                return [
                    {
                        "cn_id": "cn-001",
                        "edge_locs": ["us-west-2"],
                        "arn": "arn:seg/SegB",
                    },
                ]
            if "CloudWANCoreNetwork" in cypher:
                return [{"gn_id": "gn-001", "account_id": "123456789012"}]
            return []

        ctx = _make_ctx_fn(_query)

        mock_nm = MagicMock()
        # Both directions have routes from the other segment
        mock_nm.get_network_routes.return_value = {
            "NetworkRoutes": [
                {
                    "DestinationCidrBlock": "10.0.0.0/16",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [
                        {
                            "CoreNetworkAttachmentId": "a-1",
                            "SegmentName": "SegA",
                        },
                    ],
                },
                {
                    "DestinationCidrBlock": "10.1.0.0/16",
                    "Type": "propagated",
                    "State": "active",
                    "Destinations": [
                        {
                            "CoreNetworkAttachmentId": "a-2",
                            "SegmentName": "SegB",
                        },
                    ],
                },
            ],
        }
        mock_session = MagicMock()
        mock_session.client.return_value = mock_nm

        from unittest.mock import patch
        with patch(
            "src.tools.cloudwan_routes.get_session_for_account",
            return_value=mock_session,
        ):
            result = await check_cloudwan_connectivity(
                ctx, "SegA", "SegB",
                verify_routes=True,
            )

        assert "REACHABLE" in result
        assert "POLICY_ALLOWS" not in result
        assert "confirmed" in result
