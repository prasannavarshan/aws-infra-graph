"""Tests for the GraphBuilder orchestrator."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.collector.base import BaseCollector
from src.graph.builder import GraphBuilder
from src.graph.model import (
    NodeLabel,
    RelationshipType,
    ResourceEdge,
    ResourceNode,
)


class FakeCollector(BaseCollector):
    """Test collector that returns fixed data."""

    def collect_in_region(self, region):
        node = ResourceNode(
            arn=f"arn:aws:test:{region}:{self.account_id}:fake/1",
            name="fake-resource",
            label=NodeLabel.VPC,
            account_id=self.account_id,
            region=region,
        )
        edge = ResourceEdge(
            source_arn=node.arn,
            target_arn=(
                f"arn:aws:organizations::{self.account_id}:account"
            ),
            relationship=RelationshipType.BELONGS_TO,
        )
        return [node], [edge]


class ExclusiveEdgeCollector(BaseCollector):
    """Test collector that returns exclusive edge types."""

    def collect_in_region(self, region):
        inst_arn = (
            f"arn:aws:ec2:{region}:{self.account_id}:i/i-1"
        )
        node = ResourceNode(
            arn=inst_arn,
            name="test-instance",
            label=NodeLabel.EC2_INSTANCE,
            account_id=self.account_id,
            region=region,
        )
        sg_edge = ResourceEdge(
            source_arn=inst_arn,
            target_arn=(
                f"arn:aws:ec2:{region}"
                f":{self.account_id}:sg/sg-1"
            ),
            relationship=RelationshipType.HAS_SG,
        )
        subnet_edge = ResourceEdge(
            source_arn=inst_arn,
            target_arn=(
                f"arn:aws:ec2:{region}"
                f":{self.account_id}:subnet/sub-1"
            ),
            relationship=RelationshipType.RUNS_IN,
        )
        belongs_edge = ResourceEdge(
            source_arn=inst_arn,
            target_arn=(
                f"arn:aws:organizations::"
                f"{self.account_id}:account"
            ),
            relationship=RelationshipType.BELONGS_TO,
        )
        return [node], [sg_edge, subnet_edge, belongs_edge]


class EmptyCollector(BaseCollector):
    """Test collector that returns nothing."""

    def collect_in_region(self, region):
        return [], []


class SlowCollector(BaseCollector):
    """Test collector that sleeps to simulate slow API calls."""

    def collect_in_region(self, region):
        time.sleep(0.1)
        node = ResourceNode(
            arn=(
                f"arn:aws:test:{region}:{self.account_id}:slow/1"
            ),
            name="slow-resource",
            label=NodeLabel.VPC,
            account_id=self.account_id,
            region=region,
        )
        return [node], []


class FailingCollector(BaseCollector):
    """Test collector that raises an exception."""

    def collect_in_region(self, region):
        raise RuntimeError("Simulated AWS API failure")


def _mock_settings(max_concurrency=5, collector_concurrency=10, write_concurrency=3):
    """Create mock settings with configurable concurrency."""
    mock = MagicMock()
    mock.aws.account_ids = []
    mock.aws.cross_account_role_name = ""
    mock.aws.max_concurrency = max_concurrency
    mock.aws.collector_concurrency = collector_concurrency
    mock.aws.ssl_verify = True
    mock.neo4j.write_concurrency = write_concurrency
    return mock


class TestGraphBuilderHappyPath:
    @pytest.mark.asyncio
    async def test_build_calls_upsert(self):
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=1)

        with patch(
            "src.graph.builder.get_session_for_account"
        ) as mock_session:
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[FakeCollector],
            )
            result = await builder.build(
                account_ids=["123456789012"]
            )

        assert result["total_nodes"] == 1
        assert result["total_edges"] == 1
        mock_neo4j.upsert_nodes.assert_awaited_once()
        mock_neo4j.upsert_edges.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_build_multiple_collectors(self):
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=2)
        mock_neo4j.upsert_edges = AsyncMock(return_value=2)

        with patch(
            "src.graph.builder.get_session_for_account"
        ) as mock_session:
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[
                    FakeCollector, FakeCollector,
                ],
            )
            result = await builder.build(
                account_ids=["123456789012"]
            )

        assert result["total_nodes"] == 2
        assert result["total_edges"] == 2


class TestGraphBuilderEdgeCases:
    @pytest.mark.asyncio
    async def test_empty_collector_skips_upsert(self):
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=0)
        mock_neo4j.upsert_edges = AsyncMock(return_value=0)

        with patch(
            "src.graph.builder.get_session_for_account"
        ) as mock_session:
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[EmptyCollector],
            )
            result = await builder.build(
                account_ids=["123456789012"]
            )

        assert result["total_nodes"] == 0
        assert result["total_edges"] == 0
        mock_neo4j.upsert_nodes.assert_not_awaited()
        mock_neo4j.upsert_edges.assert_not_awaited()


class TestCollectAccount:
    """Tests for the _collect_account method."""

    @pytest.mark.asyncio
    async def test_collect_single_account(self):
        """Verify _collect_account returns nodes/edges."""
        mock_neo4j = AsyncMock()

        with patch(
            "src.graph.builder.get_session_for_account"
        ) as mock_session:
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[FakeCollector],
            )
            nodes, edges = await builder._collect_account(
                account_id="111111111111",
                regions=["us-east-1"],
                mgmt_account="111111111111",
                on_progress=None,
                idx=1,
                total=1,
            )

        assert len(nodes) == 1
        assert len(edges) == 1
        assert nodes[0].account_id == "111111111111"

    @pytest.mark.asyncio
    async def test_collect_skips_management_only(self):
        """Management-only collectors are skipped for members."""

        class MgmtOnlyCollector(BaseCollector):
            management_only = True

            def collect_in_region(self, region):
                node = ResourceNode(
                    arn=f"arn:aws:org:{region}:{self.account_id}:mgmt/1",
                    name="mgmt-resource",
                    label=NodeLabel.ORGANIZATION,
                    account_id=self.account_id,
                    region=region,
                )
                return [node], []

        mock_neo4j = AsyncMock()

        with patch(
            "src.graph.builder.get_session_for_account"
        ) as mock_session:
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[
                    FakeCollector, MgmtOnlyCollector,
                ],
            )
            # Member account — MgmtOnlyCollector should be skipped
            nodes, edges = await builder._collect_account(
                account_id="222222222222",
                regions=["us-east-1"],
                mgmt_account="111111111111",
                on_progress=None,
                idx=1,
                total=1,
            )

        assert len(nodes) == 1
        assert all(
            n.account_id == "222222222222" for n in nodes
        )


class TestParallelCollection:
    """Tests for concurrent account collection."""

    @pytest.mark.asyncio
    async def test_concurrent_accounts(self):
        """Multiple accounts run concurrently, not sequentially."""
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=0)

        accounts = [f"{i:012d}" for i in range(1, 5)]

        with (
            patch(
                "src.graph.builder.get_session_for_account"
            ) as mock_session,
            patch(
                "src.graph.builder.settings",
                _mock_settings(max_concurrency=4),
            ),
        ):
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[SlowCollector],
            )
            start = time.monotonic()
            result = await builder.build(
                account_ids=accounts,
            )
            elapsed = time.monotonic() - start

        assert result["total_nodes"] == 4
        # Sequential would take ~0.4s (4 x 0.1s).
        # Parallel with concurrency=4 should take ~0.1s.
        # Use 0.35s as threshold to allow for overhead.
        assert elapsed < 0.35, (
            f"Took {elapsed:.2f}s — expected parallel execution"
        )

    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrency(self):
        """Semaphore caps concurrent accounts."""
        active = []
        max_seen = 0

        original_collect = GraphBuilder._collect_account

        async def tracking_collect(
            self, account_id, regions, mgmt_account,
            on_progress, idx, total,
        ):
            nonlocal max_seen
            active.append(account_id)
            if len(active) > max_seen:
                max_seen = len(active)
            await asyncio.sleep(0.05)
            active.remove(account_id)
            return await original_collect(
                self, account_id, regions, mgmt_account,
                on_progress, idx, total,
            )

        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=0)

        accounts = [f"{i:012d}" for i in range(1, 7)]

        with (
            patch(
                "src.graph.builder.get_session_for_account"
            ) as mock_session,
            patch(
                "src.graph.builder.settings",
                _mock_settings(max_concurrency=2),
            ),
            patch.object(
                GraphBuilder, "_collect_account",
                tracking_collect,
            ),
        ):
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[FakeCollector],
            )
            await builder.build(account_ids=accounts)

        assert max_seen <= 2, (
            f"Max concurrent was {max_seen}, expected <= 2"
        )

    @pytest.mark.asyncio
    async def test_failing_account_does_not_block_others(self):
        """One failing account doesn't prevent others."""
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=1)

        call_count = 0

        original_collect = GraphBuilder._collect_account

        async def sometimes_fail(
            self, account_id, regions, mgmt_account,
            on_progress, idx, total,
        ):
            nonlocal call_count
            call_count += 1
            if account_id == "000000000002":
                raise RuntimeError("Account 2 failed")
            return await original_collect(
                self, account_id, regions, mgmt_account,
                on_progress, idx, total,
            )

        accounts = [
            "000000000001",
            "000000000002",
            "000000000003",
        ]

        with (
            patch(
                "src.graph.builder.get_session_for_account"
            ) as mock_session,
            patch(
                "src.graph.builder.settings",
                _mock_settings(max_concurrency=5),
            ),
            patch.object(
                GraphBuilder, "_collect_account",
                sometimes_fail,
            ),
        ):
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[FakeCollector],
            )
            result = await builder.build(
                account_ids=accounts,
            )

        # 2 accounts succeeded, 1 failed
        assert result["total_nodes"] == 2
        assert result["total_edges"] == 2
        # All 3 accounts were attempted
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_post_build_hooks_run_after_all_accounts(self):
        """Post-build hooks execute after all accounts finish."""
        hook_order: list[str] = []

        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=0)

        async def track_query(query, *args, **kwargs):
            if "SHARED_WITH" in query:
                hook_order.append("bridge_vpcs")
            elif "LAUNCHES" in query:
                hook_order.append("link_eks")
            return [{"bridged": 0, "linked": 0}]

        mock_neo4j.query = AsyncMock(side_effect=track_query)

        original_collect = GraphBuilder._collect_account

        async def track_collect(
            self, account_id, regions, mgmt_account,
            on_progress, idx, total,
        ):
            result = await original_collect(
                self, account_id, regions, mgmt_account,
                on_progress, idx, total,
            )
            hook_order.append(f"collected_{account_id}")
            return result

        with (
            patch(
                "src.graph.builder.get_session_for_account"
            ) as mock_session,
            patch(
                "src.graph.builder.settings",
                _mock_settings(max_concurrency=5),
            ),
            patch.object(
                GraphBuilder, "_collect_account",
                track_collect,
            ),
        ):
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[FakeCollector],
            )
            await builder.build(
                account_ids=["111111111111", "222222222222"],
            )

        # Both hooks must come after all collections
        bridge_idx = hook_order.index("bridge_vpcs")
        link_idx = hook_order.index("link_eks")
        collect_indices = [
            i for i, v in enumerate(hook_order)
            if v.startswith("collected_")
        ]
        assert all(
            bridge_idx > ci for ci in collect_indices
        )
        assert all(
            link_idx > ci for ci in collect_indices
        )


class TestEKSInstanceLinking:
    """Tests for _link_eks_instances post-build hook."""

    @pytest.mark.asyncio
    async def test_link_eks_instances_calls_query(self):
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=1)
        mock_neo4j.query = AsyncMock(
            return_value=[{"linked": 5}],
        )

        with patch(
            "src.graph.builder.get_session_for_account"
        ) as mock_session:
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[FakeCollector],
            )
            await builder.build(
                account_ids=["123456789012"],
            )

        # Should have called query for shared VPCs + EKS linking
        query_calls = mock_neo4j.query.call_args_list
        eks_calls = [
            c for c in query_calls
            if "LAUNCHES" in str(c)
        ]
        assert len(eks_calls) == 1

    @pytest.mark.asyncio
    async def test_link_eks_instances_zero_links(self):
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=0)
        mock_neo4j.upsert_edges = AsyncMock(return_value=0)
        mock_neo4j.query = AsyncMock(
            return_value=[{"linked": 0, "bridged": 0}],
        )

        with patch(
            "src.graph.builder.get_session_for_account"
        ) as mock_session:
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[EmptyCollector],
            )
            result = await builder.build(
                account_ids=["123456789012"],
            )

        assert result["total_nodes"] == 0

    @pytest.mark.asyncio
    async def test_link_eks_instances_handles_error(self):
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=1)

        call_count = 0

        async def query_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [{"bridged": 0}]
            raise RuntimeError("Neo4j connection lost")

        mock_neo4j.query = AsyncMock(
            side_effect=query_side_effect,
        )

        with patch(
            "src.graph.builder.get_session_for_account"
        ) as mock_session:
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[FakeCollector],
            )
            result = await builder.build(
                account_ids=["123456789012"],
            )

        assert result["total_nodes"] == 1


class TestExclusiveEdgeRouting:
    """Tests that exclusive edges go through delete-then-upsert."""

    @pytest.mark.asyncio
    async def test_exclusive_edges_routed_separately(self):
        """HAS_SG/RUNS_IN go to upsert_edges_exclusive,
        BELONGS_TO goes to upsert_edges."""
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges_exclusive = AsyncMock(
            return_value=2,
        )

        with patch(
            "src.graph.builder.get_session_for_account"
        ) as mock_session:
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[ExclusiveEdgeCollector],
            )
            result = await builder.build(
                account_ids=["123456789012"],
            )

        # Exclusive: HAS_SG + RUNS_IN = 2 edges
        exc_call = (
            mock_neo4j.upsert_edges_exclusive.call_args
        )
        exc_edges = exc_call[0][0]
        assert len(exc_edges) == 2
        exc_types = {e.relationship for e in exc_edges}
        assert exc_types == {
            RelationshipType.HAS_SG,
            RelationshipType.RUNS_IN,
        }

        # Additive: BELONGS_TO = 1 edge
        add_call = mock_neo4j.upsert_edges.call_args
        add_edges = add_call[0][0]
        assert len(add_edges) == 1
        assert (
            add_edges[0].relationship
            == RelationshipType.BELONGS_TO
        )

        # Total = 2 (exclusive) + 1 (additive)
        assert result["total_edges"] == 3

    @pytest.mark.asyncio
    async def test_only_additive_edges_skips_exclusive(self):
        """When no exclusive edges, upsert_edges_exclusive
        is not called."""
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges_exclusive = AsyncMock(
            return_value=0,
        )

        with patch(
            "src.graph.builder.get_session_for_account"
        ) as mock_session:
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[FakeCollector],
            )
            await builder.build(
                account_ids=["123456789012"],
            )

        mock_neo4j.upsert_edges_exclusive.assert_not_awaited()
        mock_neo4j.upsert_edges.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_only_exclusive_edges_skips_additive(self):
        """When all edges are exclusive, upsert_edges
        is not called for edges."""

        class OnlySGCollector(BaseCollector):
            def collect_in_region(self, region):
                node = ResourceNode(
                    arn=(
                        f"arn:aws:ec2:{region}"
                        f":{self.account_id}:i/i-1"
                    ),
                    name="x",
                    label=NodeLabel.EC2_INSTANCE,
                    account_id=self.account_id,
                    region=region,
                )
                edge = ResourceEdge(
                    source_arn=node.arn,
                    target_arn=(
                        f"arn:aws:ec2:{region}"
                        f":{self.account_id}:sg/sg-1"
                    ),
                    relationship=RelationshipType.HAS_SG,
                )
                return [node], [edge]

        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=0)
        mock_neo4j.upsert_edges_exclusive = AsyncMock(
            return_value=1,
        )

        with patch(
            "src.graph.builder.get_session_for_account"
        ) as mock_session:
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[OnlySGCollector],
            )
            await builder.build(
                account_ids=["123456789012"],
            )

        mock_neo4j.upsert_edges_exclusive.assert_awaited_once()
        mock_neo4j.upsert_edges.assert_not_awaited()


class TestGraphBuilderAutoDetect:
    @pytest.mark.asyncio
    async def test_build_empty_accounts_auto_detects(self):
        """When no accounts and no cross-account role, auto-detect."""
        mock_neo4j = AsyncMock()
        mock_neo4j.upsert_nodes = AsyncMock(return_value=1)
        mock_neo4j.upsert_edges = AsyncMock(return_value=1)

        with (
            patch(
                "src.graph.builder.settings",
            ) as mock_settings,
            patch(
                "src.graph.builder.get_current_account_id",
            ) as mock_detect,
            patch(
                "src.graph.builder.get_session_for_account",
            ) as mock_session,
        ):
            mock_settings.aws.account_ids = []
            mock_settings.aws.cross_account_role_name = ""
            mock_settings.aws.max_concurrency = 5
            mock_settings.aws.collector_concurrency = 10
            mock_settings.neo4j.write_concurrency = 3
            mock_detect.return_value = "999888777666"
            mock_session.return_value = MagicMock()

            builder = GraphBuilder(
                neo4j=mock_neo4j,
                collector_classes=[FakeCollector],
            )
            result = await builder.build()

        mock_detect.assert_called()
        assert result["total_nodes"] == 1
        assert result["total_edges"] == 1
