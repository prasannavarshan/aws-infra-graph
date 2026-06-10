"""Neo4j connection manager and query runner."""

from __future__ import annotations

import asyncio

import structlog
from neo4j import AsyncDriver, AsyncGraphDatabase
from neo4j.exceptions import TransientError

from src.config import settings
from src.graph.model import ResourceEdge, ResourceNode

logger = structlog.get_logger()

_NEO4J_PRIMITIVES = (str, int, float, bool)


def _serialize_value(v):  # noqa: ANN001, ANN202
    """Serialize a property value for Neo4j storage.

    Neo4j supports primitives and flat lists of primitives.
    Complex types (dicts, lists of dicts) are stringified.
    """
    if isinstance(v, _NEO4J_PRIMITIVES):
        return v
    if isinstance(v, list) and all(
        isinstance(item, _NEO4J_PRIMITIVES)
        for item in v
    ):
        return v
    return str(v)


_DEADLOCK_MAX_RETRIES = 3
_DEADLOCK_BASE_DELAY = 0.5
_UPSERT_BATCH_SIZE = 500


async def _run_with_retry(session, query, **kwargs):  # noqa: ANN001, ANN003, ANN202
    """Run a Cypher query with retry on deadlock (TransientError)."""
    for attempt in range(_DEADLOCK_MAX_RETRIES + 1):
        try:
            result = await session.run(query, **kwargs)
            return await result.single()
        except TransientError:
            if attempt == _DEADLOCK_MAX_RETRIES:
                raise
            delay = _DEADLOCK_BASE_DELAY * (2 ** attempt)
            logger.warning(
                "neo4j_deadlock_retry",
                attempt=attempt + 1,
                delay=delay,
            )
            await asyncio.sleep(delay)
    return None  # unreachable


class Neo4jClient:
    """Async Neo4j client for the infrastructure knowledge graph.

    Handles connection lifecycle, bulk inserts, and Cypher queries.
    """

    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
    ):
        self._uri = uri or settings.neo4j.uri
        self._user = user or settings.neo4j.user
        self._password = password or settings.neo4j.password
        self._driver: AsyncDriver | None = None

    async def connect(self) -> None:
        """Establish connection to Neo4j."""
        logger.info("neo4j_connecting", uri=self._uri)
        self._driver = AsyncGraphDatabase.driver(
            self._uri,
            auth=(self._user, self._password),
        )
        await self._driver.verify_connectivity()
        await self._ensure_indexes()
        logger.info("neo4j_connected")

    async def _ensure_indexes(self) -> None:
        """Create indexes and constraints for the shared Resource label.

        All nodes carry a secondary :Resource label (added by upsert_nodes).
        The uniqueness constraint on arn prevents duplicate nodes from
        concurrent apoc.merge.node calls and implicitly creates an index.

        A plain index on the same property blocks constraint creation, so we
        drop idx_arn_resource first if it exists (idempotent — IF EXISTS).
        Called once at connect time; safe to re-run.
        """
        async with self.driver.session() as session:
            await session.run(
                "DROP INDEX idx_arn_resource IF EXISTS"
            )
            await session.run(
                "CREATE CONSTRAINT unique_resource_arn IF NOT EXISTS "
                "FOR (n:Resource) REQUIRE n.arn IS UNIQUE"
            )
        logger.info("neo4j_indexes_ensured")

    async def close(self) -> None:
        """Close the Neo4j connection."""
        if self._driver:
            await self._driver.close()
            logger.info("neo4j_disconnected")

    @property
    def driver(self) -> AsyncDriver:
        if not self._driver:
            raise RuntimeError("Neo4j client not connected. Call connect() first.")
        return self._driver

    async def upsert_nodes(self, nodes: list[ResourceNode]) -> int:
        """Bulk upsert resource nodes into Neo4j.

        Uses MERGE on ARN to avoid duplicates.

        Args:
            nodes: List of ResourceNode models to insert.

        Returns:
            Number of nodes upserted.
        """
        query = """
        UNWIND $nodes AS node
        CALL apoc.merge.node(
            [node.label, 'Resource'],
            {arn: node.arn},
            node.properties,
            node.properties
        ) YIELD node AS n
        RETURN count(n)
        """
        node_dicts = [
            {
                "label": node.label.value,
                "arn": node.arn,
                "properties": {
                    "arn": node.arn,
                    "name": node.name,
                    "account_id": node.account_id,
                    "region": node.region,
                    "tags": str(node.tags),
                    "last_crawled": node.last_crawled.isoformat(),
                    **{k: _serialize_value(v)
                       for k, v in node.properties.items()},
                },
            }
            for node in nodes
        ]

        count = 0
        for i in range(0, len(node_dicts), _UPSERT_BATCH_SIZE):
            batch = node_dicts[i:i + _UPSERT_BATCH_SIZE]
            async with self.driver.session() as session:
                record = await _run_with_retry(session, query, nodes=batch)
                count += record[0] if record else 0
        logger.info("nodes_upserted", count=count)
        return count

    async def upsert_edges(self, edges: list[ResourceEdge]) -> int:
        """Bulk upsert relationship edges into Neo4j.

        Uses MERGE to avoid duplicate relationships.

        Args:
            edges: List of ResourceEdge models to insert.

        Returns:
            Number of edges upserted.
        """
        query = """
        UNWIND $edges AS edge
        MATCH (source:Resource {arn: edge.source_arn})
        MATCH (target:Resource {arn: edge.target_arn})
        CALL apoc.merge.relationship(
            source,
            edge.relationship,
            {},
            edge.properties,
            target
        ) YIELD rel
        RETURN count(rel)
        """
        edge_dicts = [
            {
                "source_arn": edge.source_arn,
                "target_arn": edge.target_arn,
                "relationship": edge.relationship.value,
                "properties": {k: _serialize_value(v)
                               for k, v in edge.properties.items()},
            }
            for edge in edges
        ]

        count = 0
        for i in range(0, len(edge_dicts), _UPSERT_BATCH_SIZE):
            batch = edge_dicts[i:i + _UPSERT_BATCH_SIZE]
            async with self.driver.session() as session:
                record = await _run_with_retry(session, query, edges=batch)
                count += record[0] if record else 0
        logger.info("edges_upserted", count=count)
        return count

    async def upsert_edges_exclusive(
        self, edges: list[ResourceEdge],
    ) -> int:
        """Upsert edges after deleting stale ones of the same type.

        For relationship types in EXCLUSIVE_EDGE_TYPES, the collector
        provides the complete current set per source node. Any
        existing edges of the same type from the same source that
        are NOT in the new set are stale and must be removed.

        Args:
            edges: Complete set of exclusive edges from this crawl.

        Returns:
            Number of edges upserted.
        """
        if not edges:
            return 0

        # Group by (source_arn, rel_type) to find all sources
        groups: dict[tuple[str, str], list[str]] = {}
        for edge in edges:
            key = (
                edge.source_arn,
                edge.relationship.value,
            )
            groups.setdefault(key, []).append(
                edge.target_arn,
            )

        # Delete edges that are no longer in the current set
        delete_query = """
        UNWIND $pairs AS pair
        MATCH (source:Resource {arn: pair.source_arn})
              -[r]->
              (target)
        WHERE type(r) = pair.rel_type
          AND NOT target.arn IN pair.keep_targets
        DELETE r
        RETURN count(r) AS deleted
        """
        pairs = [
            {
                "source_arn": src,
                "rel_type": rel,
                "keep_targets": targets,
            }
            for (src, rel), targets in groups.items()
        ]

        async with self.driver.session() as session:
            record = await _run_with_retry(
                session, delete_query, pairs=pairs,
            )
            deleted = record["deleted"] if record else 0
            if deleted:
                logger.info(
                    "stale_edges_deleted", count=deleted,
                )

        return await self.upsert_edges(edges)

    async def query(self, cypher: str, parameters: dict | None = None) -> list[dict]:
        """Execute a Cypher query and return results as dicts.

        Args:
            cypher: Cypher query string with $parameter placeholders.
            parameters: Query parameters (safe from injection).

        Returns:
            List of result records as dictionaries.
        """
        async with self.driver.session() as session:
            result = await session.run(cypher, parameters or {})
            records = [record.data() async for record in result]
            return records

    async def get_graph_stats(self) -> dict:
        """Get node/relationship counts for optimization analysis.

        Returns:
            Dict with node_counts (label->count),
            rel_counts (type->count), and totals.
        """
        node_query = """
        MATCH (n)
        RETURN head(labels(n)) AS label, count(n) AS count
        ORDER BY count DESC
        """
        rel_query = """
        MATCH ()-[r]->()
        RETURN type(r) AS rel_type, count(r) AS count
        ORDER BY count DESC
        """
        nodes = await self.query(node_query)
        rels = await self.query(rel_query)

        total_nodes = sum(r["count"] for r in nodes)
        total_rels = sum(r["count"] for r in rels)

        return {
            "node_counts": {
                r["label"]: r["count"] for r in nodes
            },
            "rel_counts": {
                r["rel_type"]: r["count"] for r in rels
            },
            "total_nodes": total_nodes,
            "total_rels": total_rels,
            "label_count": len(nodes),
            "rel_type_count": len(rels),
        }

    async def clear_graph(self) -> None:
        """Delete all nodes and relationships. Use with caution."""
        async with self.driver.session() as session:
            await session.run("MATCH (n) DETACH DELETE n")
            logger.warning("graph_cleared")
