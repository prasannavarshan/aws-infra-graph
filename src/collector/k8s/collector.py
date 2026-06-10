"""K8s collector orchestrator — iterates clusters, calls resource collectors."""

from __future__ import annotations

import structlog

from src.collector.k8s.auth import (
    ClusterConnection,
    get_cluster_connection,
)
from src.collector.k8s.resources import (
    collect_ingresses,
    collect_namespaces,
    collect_nodes,
    collect_service_accounts,
    collect_services,
    collect_workloads,
)
from src.graph.model import ResourceEdge, ResourceNode

logger = structlog.get_logger()


class K8sCollector:
    """Collects Kubernetes resources from EKS clusters.

    Unlike BaseCollector, this iterates over cluster ARNs
    (discovered from the graph) rather than AWS regions.

    Args:
        session: boto3 Session for the target account.
        account_id: AWS account ID owning the clusters.
        cluster_infos: List of dicts with 'arn', 'name',
            'region' for each cluster to collect from.
    """

    def __init__(
        self,
        session,  # noqa: ANN001
        account_id: str,
        cluster_infos: list[dict[str, str]],
    ):
        self.session = session
        self.account_id = account_id
        self.cluster_infos = cluster_infos

    def collect(
        self,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect K8s resources from all clusters.

        Iterates each cluster, gets a connection, and calls
        all resource collection functions. Failures in one
        cluster or resource type don't block others.

        Returns:
            Tuple of (nodes, edges) for all clusters.
        """
        all_nodes: list[ResourceNode] = []
        all_edges: list[ResourceEdge] = []

        for info in self.cluster_infos:
            cluster_name = info["name"]
            region = info["region"]
            try:
                self._collect_cluster(
                    cluster_name, region,
                    all_nodes, all_edges,
                )
            except Exception:
                logger.exception(
                    "k8s_cluster_collection_failed",
                    cluster=cluster_name,
                    account_id=self.account_id,
                    region=region,
                )

        logger.info(
            "k8s_collection_complete",
            account_id=self.account_id,
            clusters=len(self.cluster_infos),
            nodes=len(all_nodes),
            edges=len(all_edges),
        )
        return all_nodes, all_edges

    def _collect_cluster(
        self,
        cluster_name: str,
        region: str,
        all_nodes: list[ResourceNode],
        all_edges: list[ResourceEdge],
    ) -> None:
        """Collect all resource types for a single cluster."""
        conn = get_cluster_connection(
            self.session,
            cluster_name,
            region,
            self.account_id,
        )
        if not conn:
            logger.warning(
                "k8s_skipping_cluster",
                cluster=cluster_name,
                reason="connection_failed",
            )
            return

        logger.info(
            "k8s_collecting_cluster",
            cluster=cluster_name,
            account_id=self.account_id,
        )

        collectors = [
            ("namespaces", self._collect_namespaces),
            ("nodes", self._collect_nodes),
            ("workloads", self._collect_workloads),
            ("service_accounts", self._collect_sas),
            ("ingresses", self._collect_ingresses),
        ]

        # Workloads returns selectors needed by services
        dep_selectors: dict[str, dict[str, str]] = {}

        for name, collector_fn in collectors:
            try:
                result = collector_fn(conn, dep_selectors)
                if result:
                    nodes, edges = result[0], result[1]
                    all_nodes.extend(nodes)
                    all_edges.extend(edges)
                    if len(result) > 2:
                        dep_selectors = result[2]
            except Exception:
                logger.exception(
                    "k8s_resource_collection_failed",
                    resource_type=name,
                    cluster=cluster_name,
                )

        # Services need deployment selectors
        try:
            nodes, edges = collect_services(
                conn, dep_selectors,
            )
            all_nodes.extend(nodes)
            all_edges.extend(edges)
        except Exception:
            logger.exception(
                "k8s_resource_collection_failed",
                resource_type="services",
                cluster=cluster_name,
            )

    def _collect_namespaces(
        self,
        conn: ClusterConnection,
        _selectors: dict,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        return collect_namespaces(conn)

    def _collect_nodes(
        self,
        conn: ClusterConnection,
        _selectors: dict,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        return collect_nodes(conn)

    def _collect_workloads(
        self,
        conn: ClusterConnection,
        _selectors: dict,
    ) -> tuple[
        list[ResourceNode],
        list[ResourceEdge],
        dict[str, dict[str, str]],
    ]:
        return collect_workloads(conn)

    def _collect_sas(
        self,
        conn: ClusterConnection,
        _selectors: dict,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        return collect_service_accounts(conn)

    def _collect_ingresses(
        self,
        conn: ClusterConnection,
        _selectors: dict,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        return collect_ingresses(conn)
