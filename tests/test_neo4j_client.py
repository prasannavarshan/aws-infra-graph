"""Tests for the Neo4j client — mocked async driver."""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode
from src.graph.neo4j_client import Neo4jClient


def _mock_session(mock_run_result):
    """Create a mock async session that works as async context manager."""
    session = AsyncMock()
    session.run = AsyncMock(return_value=mock_run_result)

    @asynccontextmanager
    async def session_cm(**kwargs):
        yield session

    return session, session_cm


@pytest.fixture()
def client():
    """Create a Neo4jClient with dummy config."""
    return Neo4jClient(
        uri="bolt://localhost:7687",
        user="neo4j",
        password="test",
    )


class TestNeo4jClientConnect:
    """Connection lifecycle tests."""

    @pytest.mark.asyncio
    async def test_connect_establishes_driver(self, client):
        with patch(
            "src.graph.neo4j_client.AsyncGraphDatabase"
        ) as mock_gdb:
            mock_driver = AsyncMock()
            mock_driver.verify_connectivity = AsyncMock()
            _, session_cm = _mock_session(MagicMock(data=lambda: [{"count(n)": 0}]))
            mock_driver.session = session_cm
            mock_gdb.driver.return_value = mock_driver

            await client.connect()

            mock_gdb.driver.assert_called_once_with(
                "bolt://localhost:7687",
                auth=("neo4j", "test"),
            )
            mock_driver.verify_connectivity.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_close_closes_driver(self, client):
        mock_driver = AsyncMock()
        client._driver = mock_driver

        await client.close()

        mock_driver.close.assert_awaited_once()

    def test_driver_property_raises_if_not_connected(self, client):
        with pytest.raises(RuntimeError, match="not connected"):
            _ = client.driver


class TestNeo4jClientUpsertNodes:
    """Tests for bulk node upsert."""

    @pytest.mark.asyncio
    async def test_upsert_nodes_returns_count(self, client):
        mock_record = MagicMock()
        mock_record.__getitem__ = MagicMock(return_value=5)
        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=mock_record)

        session, session_cm = _mock_session(mock_result)
        mock_driver = MagicMock()
        mock_driver.session = session_cm
        client._driver = mock_driver

        nodes = [
            ResourceNode(
                arn="arn:aws:ec2:us-east-1:123:vpc/vpc-123",
                name="test-vpc",
                label=NodeLabel.VPC,
                account_id="123456789012",
                region="us-east-1",
                properties={"cidr_block": "10.0.0.0/16"},
            )
        ]

        count = await client.upsert_nodes(nodes)
        assert count == 5
        session.run.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_upsert_nodes_empty_returns_zero(self, client):
        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=None)

        session, session_cm = _mock_session(mock_result)
        mock_driver = MagicMock()
        mock_driver.session = session_cm
        client._driver = mock_driver

        count = await client.upsert_nodes([])
        assert count == 0


class TestNeo4jClientUpsertEdges:
    """Tests for bulk edge upsert."""

    @pytest.mark.asyncio
    async def test_upsert_edges_returns_count(self, client):
        mock_record = MagicMock()
        mock_record.__getitem__ = MagicMock(return_value=3)
        mock_result = AsyncMock()
        mock_result.single = AsyncMock(return_value=mock_record)

        session, session_cm = _mock_session(mock_result)
        mock_driver = MagicMock()
        mock_driver.session = session_cm
        client._driver = mock_driver

        edges = [
            ResourceEdge(
                source_arn="arn:aws:ec2:us-east-1:123:instance/i-1",
                target_arn="arn:aws:ec2:us-east-1:123:subnet/sub-1",
                relationship=RelationshipType.RUNS_IN,
            )
        ]

        count = await client.upsert_edges(edges)
        assert count == 3


class TestNeo4jClientQuery:
    """Tests for generic Cypher query execution."""

    @pytest.mark.asyncio
    async def test_query_returns_records(self, client):
        record1 = MagicMock()
        record1.data.return_value = {"name": "vpc-1"}
        record2 = MagicMock()
        record2.data.return_value = {"name": "vpc-2"}

        # Create an async iterator from the records
        async def async_iter():
            for r in [record1, record2]:
                yield r

        mock_result = MagicMock()
        mock_result.__aiter__ = lambda self: async_iter()

        session, session_cm = _mock_session(mock_result)
        session.run = AsyncMock(return_value=mock_result)
        mock_driver = MagicMock()
        mock_driver.session = session_cm
        client._driver = mock_driver

        results = await client.query(
            "MATCH (n:VPC) RETURN n.name AS name"
        )
        assert len(results) == 2
        assert results[0]["name"] == "vpc-1"


class TestNeo4jClientUpsertEdgesExclusive:
    """Tests for exclusive edge upsert (stale edge deletion)."""

    @pytest.mark.asyncio
    async def test_exclusive_deletes_stale_then_upserts(
        self, client,
    ):
        """Stale edges are deleted before new ones are upserted."""
        call_order: list[str] = []

        delete_record = MagicMock()
        delete_record.__getitem__ = MagicMock(return_value=2)
        delete_result = AsyncMock()
        delete_result.single = AsyncMock(
            return_value=delete_record,
        )

        upsert_record = MagicMock()
        upsert_record.__getitem__ = MagicMock(return_value=3)
        upsert_result = AsyncMock()
        upsert_result.single = AsyncMock(
            return_value=upsert_record,
        )

        session = AsyncMock()

        async def track_run(query, **kwargs):
            if "DELETE" in query:
                call_order.append("delete")
                return delete_result
            call_order.append("upsert")
            return upsert_result

        session.run = AsyncMock(side_effect=track_run)

        @asynccontextmanager
        async def session_cm(**kwargs):
            yield session

        mock_driver = MagicMock()
        mock_driver.session = session_cm
        client._driver = mock_driver

        edges = [
            ResourceEdge(
                source_arn="arn:aws:ec2:us-east-1:123:i/i-1",
                target_arn="arn:aws:ec2:us-east-1:123:sg/sg-new",
                relationship=RelationshipType.HAS_SG,
            ),
        ]

        count = await client.upsert_edges_exclusive(edges)
        assert count == 3
        assert call_order == ["delete", "upsert"]

    @pytest.mark.asyncio
    async def test_exclusive_empty_returns_zero(self, client):
        """Empty edge list returns zero without DB calls."""
        mock_driver = MagicMock()
        client._driver = mock_driver

        count = await client.upsert_edges_exclusive([])
        assert count == 0

    @pytest.mark.asyncio
    async def test_exclusive_groups_by_source_and_type(
        self, client,
    ):
        """Multiple edges from same source are grouped correctly."""
        delete_record = MagicMock()
        delete_record.__getitem__ = MagicMock(return_value=0)
        delete_result = AsyncMock()
        delete_result.single = AsyncMock(
            return_value=delete_record,
        )

        upsert_record = MagicMock()
        upsert_record.__getitem__ = MagicMock(return_value=2)
        upsert_result = AsyncMock()
        upsert_result.single = AsyncMock(
            return_value=upsert_record,
        )

        captured_params: list[dict] = []

        session = AsyncMock()

        async def capture_run(query, **kwargs):
            if "DELETE" in query:
                captured_params.append(kwargs)
                return delete_result
            return upsert_result

        session.run = AsyncMock(side_effect=capture_run)

        @asynccontextmanager
        async def session_cm(**kwargs):
            yield session

        mock_driver = MagicMock()
        mock_driver.session = session_cm
        client._driver = mock_driver

        src = "arn:aws:ec2:us-east-1:123:i/i-1"
        edges = [
            ResourceEdge(
                source_arn=src,
                target_arn="arn:aws:ec2:us-east-1:123:sg/sg-1",
                relationship=RelationshipType.HAS_SG,
            ),
            ResourceEdge(
                source_arn=src,
                target_arn="arn:aws:ec2:us-east-1:123:sg/sg-2",
                relationship=RelationshipType.HAS_SG,
            ),
        ]

        await client.upsert_edges_exclusive(edges)

        # Should produce 1 pair with both targets in keep list
        pairs = captured_params[0]["pairs"]
        assert len(pairs) == 1
        assert pairs[0]["source_arn"] == src
        assert pairs[0]["rel_type"] == "HAS_SG"
        assert set(pairs[0]["keep_targets"]) == {
            "arn:aws:ec2:us-east-1:123:sg/sg-1",
            "arn:aws:ec2:us-east-1:123:sg/sg-2",
        }


class TestNeo4jClientClearGraph:
    """Tests for graph clearing."""

    @pytest.mark.asyncio
    async def test_clear_graph_runs_delete(self, client):
        mock_result = AsyncMock()
        session, session_cm = _mock_session(mock_result)
        mock_driver = MagicMock()
        mock_driver.session = session_cm
        client._driver = mock_driver

        await client.clear_graph()

        session.run.assert_awaited_once_with(
            "MATCH (n) DETACH DELETE n"
        )
