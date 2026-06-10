"""Graph builder — orchestrates collectors and populates Neo4j."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

import structlog
from botocore.exceptions import ClientError

from src.collector.base import (
    BOTO_CONFIG,
    BaseCollector,
    get_current_account_id,
    get_management_session,
    get_org_session,
    get_session_for_account,
)
from src.config import settings
from src.graph.model import (
    EXCLUSIVE_EDGE_TYPES,
    ResourceEdge,
    ResourceNode,
)
from src.graph.neo4j_client import Neo4jClient

# Type alias for optional progress callback
ProgressFn = Callable[[float, float, str], Awaitable[None]]

logger = structlog.get_logger()


def discover_org_accounts() -> list[str]:
    """Discover active accounts from AWS Organizations.

    Uses the management session to call organizations:ListAccounts
    and returns only ACTIVE account IDs.

    Returns:
        List of active AWS account IDs in the organization.

    Raises:
        ClientError: If the Organizations API call fails.
    """
    session = get_org_session()
    org_client = session.client(
        "organizations",
        config=BOTO_CONFIG,
        verify=settings.aws.ssl_verify,
    )
    paginator = org_client.get_paginator("list_accounts")

    account_ids: list[str] = []
    for page in paginator.paginate():
        for account in page["Accounts"]:
            if account["Status"] == "ACTIVE":
                account_ids.append(account["Id"])

    logger.info(
        "discovered_org_accounts",
        count=len(account_ids),
    )
    return account_ids


class GraphBuilder:
    """Orchestrates AWS collection and Neo4j graph population.

    Args:
        neo4j: Connected Neo4jClient instance.
        collector_classes: List of BaseCollector subclasses to run.
    """

    def __init__(
        self,
        neo4j: Neo4jClient,
        collector_classes: list[type[BaseCollector]],
    ):
        self.neo4j = neo4j
        self.collector_classes = collector_classes

    async def _collect_account(
        self,
        account_id: str,
        regions: list[str] | None,
        mgmt_account: str,
        on_progress: ProgressFn | None,
        idx: int,
        total: int,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect all resources for a single account.

        Args:
            account_id: AWS account ID to collect from.
            regions: Regions to crawl. None for configured.
            mgmt_account: Management account ID for filtering.
            on_progress: Optional progress callback.
            idx: 1-based index of this account in the batch.
            total: Total number of accounts being collected.

        Returns:
            Tuple of (nodes, edges) collected from this account.
        """
        active_collectors = [
            c for c in self.collector_classes
            if not (
                getattr(c, "management_only", False)
                and account_id != mgmt_account
            )
            and not (
                getattr(c, "run_once", False)
                and idx != 1
            )
        ]
        if not active_collectors:
            return [], []

        session = get_session_for_account(account_id)
        collector_sem = asyncio.Semaphore(
            settings.aws.collector_concurrency,
        )

        async def _run_collector(
            c_idx: int, collector_cls: type[BaseCollector],
        ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
            c_name = collector_cls.__name__.replace("Collector", "")
            if on_progress:
                if total == 1:
                    progress_cur = c_idx
                    progress_total = len(active_collectors)
                else:
                    progress_cur = idx
                    progress_total = total
                await on_progress(
                    progress_cur,
                    progress_total,
                    f"[{idx}/{total}] {account_id}"
                    f" — {c_name}"
                    f" [{c_idx}/{len(active_collectors)}]",
                )
            async with collector_sem:
                collector = collector_cls(session, account_id, regions)
                t0 = time.monotonic()
                nodes, edges = await asyncio.to_thread(collector.collect)
                elapsed = time.monotonic() - t0
                logger.info(
                    "collector_done",
                    account_id=account_id,
                    collector=c_name,
                    nodes=len(nodes),
                    edges=len(edges),
                    duration_s=round(elapsed, 1),
                )
                return nodes, edges

        results = await asyncio.gather(
            *[
                _run_collector(c_idx, cls)
                for c_idx, cls in enumerate(active_collectors, 1)
            ],
            return_exceptions=True,
        )

        all_nodes: list[ResourceNode] = []
        all_edges: list[ResourceEdge] = []
        for r in results:
            if isinstance(r, Exception):
                logger.exception(
                    "collector_failed",
                    account_id=account_id,
                    exc=str(r),
                )
                continue
            nodes, edges = r
            all_nodes.extend(nodes)
            all_edges.extend(edges)

        return all_nodes, all_edges

    async def build(
        self,
        account_ids: list[str] | None = None,
        regions: list[str] | None = None,
        on_progress: ProgressFn | None = None,
        include_k8s: bool = False,
        setup_access: bool = False,
    ) -> dict:
        """Crawl accounts in parallel and populate the graph.

        Runs up to ``max_concurrency`` accounts concurrently using
        an asyncio semaphore. Each account's boto3 collectors run
        in a thread via ``asyncio.to_thread`` so they don't block
        the event loop.

        When no account_ids are provided and none are configured:
        - If cross_account_role_name is set, auto-discovers accounts
          from AWS Organizations API.
        - Otherwise, falls back to detecting the current account via
          STS get-caller-identity.

        Args:
            account_ids: Specific accounts to crawl. None for auto.
            regions: Specific regions to crawl. None for configured.
            on_progress: Async callback(current, total, message)
                for streaming progress to the MCP client.
            include_k8s: When True, collect K8s resources from
                EKS clusters after AWS collection completes.
            setup_access: When True and include_k8s is True,
                auto-create EKS access entries if missing.

        Returns:
            Dict with total_nodes and total_edges counts.
        """
        accounts = account_ids or settings.aws.account_ids
        if not accounts:
            accounts = self._resolve_accounts()

        total_nodes = 0
        total_edges = 0
        completed_accounts = 0
        failed_accounts: list[str] = []
        total_accounts = len(accounts)
        mgmt_account = get_current_account_id()
        # Collection semaphore: limits concurrent AWS API calls.
        collect_sem = asyncio.Semaphore(settings.aws.max_concurrency)
        # Write semaphore: limits concurrent Neo4j writes (NEO4J_WRITE_CONCURRENCY, default 3).
        write_sem = asyncio.Semaphore(settings.neo4j.write_concurrency)

        async def _collect_and_upsert(
            idx: int, account_id: str,
        ) -> None:
            nonlocal total_nodes, total_edges, completed_accounts
            logger.info(
                "building_graph_for_account",
                account_id=account_id,
                progress=f"{idx}/{total_accounts}",
            )
            if on_progress:
                await on_progress(
                    completed_accounts,
                    total_accounts,
                    f"[{idx}/{total_accounts}]"
                    f" {account_id} — starting",
                )

            try:
                t_collect = time.monotonic()
                async with collect_sem:
                    nodes, edges = await self._collect_account(
                        account_id, regions, mgmt_account,
                        on_progress, idx, total_accounts,
                    )
                collect_s = round(time.monotonic() - t_collect, 1)

                async with write_sem:
                    t_write = time.monotonic()
                    if nodes:
                        total_nodes += await self.neo4j.upsert_nodes(
                            nodes,
                        )
                    if edges:
                        exclusive = [
                            e for e in edges
                            if e.relationship in EXCLUSIVE_EDGE_TYPES
                        ]
                        additive = [
                            e for e in edges
                            if e.relationship
                            not in EXCLUSIVE_EDGE_TYPES
                        ]
                        if exclusive:
                            total_edges += (
                                await self.neo4j
                                .upsert_edges_exclusive(exclusive)
                            )
                        if additive:
                            total_edges += (
                                await self.neo4j.upsert_edges(
                                    additive,
                                )
                            )
                write_s = round(time.monotonic() - t_write, 1)
            except Exception:
                completed_accounts += 1
                failed_accounts.append(account_id)
                logger.exception(
                    "account_collection_failed",
                    account_id=account_id,
                )
                return

            completed_accounts += 1
            logger.info(
                "account_graph_built",
                account_id=account_id,
                progress=f"{completed_accounts}/{total_accounts}",
                nodes=len(nodes),
                edges=len(edges),
                total_nodes=total_nodes,
                total_edges=total_edges,
                collect_s=collect_s,
                write_s=write_s,
            )

        tasks = [
            _collect_and_upsert(idx, aid)
            for idx, aid in enumerate(accounts, 1)
        ]
        await asyncio.gather(*tasks)

        await self._bridge_shared_vpcs()
        await self._link_dns_zone_vpcs()
        await self._link_eks_instances()
        await self._link_pipeline_to_stacks()

        if include_k8s:
            k8s_result = await self._collect_k8s_resources(
                on_progress, setup_access,
            )
            total_nodes += k8s_result.get("nodes", 0)
            total_edges += k8s_result.get("edges", 0)
            await self._link_k8s_cross_boundary()

        return {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "total_accounts": total_accounts,
            "failed_accounts": failed_accounts,
        }

    async def _bridge_shared_vpcs(self) -> None:
        """Create SHARED_WITH edges between VPC nodes with same VPC ID.

        AWS RAM-shared VPCs appear as separate nodes per account
        (different ARNs, same VPC ID). This bridges them so path
        queries can traverse across account boundaries.
        """
        # Group VPCs by VPC ID, then bridge across accounts.
        # Avoids full cartesian product and deprecated id().
        simple_query = """
        MATCH (v:VPC)
        WITH split(v.arn, '/')[-1] AS vpc_id, collect(v) AS vpcs
        WHERE size(vpcs) > 1
        UNWIND range(0, size(vpcs)-2) AS i
        UNWIND range(i+1, size(vpcs)-1) AS j
        WITH vpcs[i] AS v1, vpcs[j] AS v2
        WHERE v1.account_id <> v2.account_id
        MERGE (v1)-[:SHARED_WITH]->(v2)
        RETURN count(*) AS bridged
        """
        try:
            result = await self.neo4j.query(simple_query)
            count = result[0]["bridged"] if result else 0
            if count:
                logger.info(
                    "shared_vpc_bridges_created",
                    count=count,
                )
        except Exception:
            logger.exception("shared_vpc_bridging_failed")

    async def _link_dns_zone_vpcs(self) -> None:
        """Fix cross-account Route53 zone-to-VPC associations.

        The Route53 collector builds ASSOCIATED_WITH edges using
        the zone owner's account ID in the VPC ARN, but cross-
        account VPCs have a different account ID. This step
        finds dangling edges and relinks them to the real VPC
        node by matching vpc_id.
        """
        query = """
        MATCH (zone:Route53Zone)
        WHERE zone.is_private = true
          AND zone.vpc_associations IS NOT NULL
        UNWIND zone.vpc_associations AS raw
        WITH zone,
             split(raw, ' ')[0] AS vpc_id
        WHERE vpc_id <> ''
        MATCH (vpc:VPC {vpc_id: vpc_id})
        MERGE (zone)-[:ASSOCIATED_WITH]->(vpc)
        RETURN count(*) AS linked
        """
        try:
            result = await self.neo4j.query(query)
            count = result[0]["linked"] if result else 0
            if count:
                logger.info(
                    "dns_zone_vpc_cross_account_linked",
                    count=count,
                )
        except Exception:
            logger.exception(
                "dns_zone_vpc_linking_failed",
            )

    async def _link_eks_instances(self) -> None:
        """Create LAUNCHES edges from EKS node groups to their EC2 instances.

        AWS tags EKS-managed instances with `eks:nodegroup-name`.
        We match node groups to instances that share the same subnet,
        account, and have matching nodegroup name in their tags.
        """
        query = """
        MATCH (ng:EKSNodegroup)-[:RUNS_IN]->(s:Subnet)
              <-[:RUNS_IN]-(inst:EC2Instance)
        WHERE inst.account_id = ng.account_id
          AND inst.tags CONTAINS ng.name
        MERGE (ng)-[:LAUNCHES]->(inst)
        RETURN count(*) AS linked
        """
        try:
            result = await self.neo4j.query(query)
            count = result[0]["linked"] if result else 0
            if count:
                logger.info(
                    "eks_instances_linked",
                    count=count,
                )
        except Exception:
            logger.exception("eks_instance_linking_failed")

    async def _collect_k8s_resources(
        self,
        on_progress: ProgressFn | None,
        setup_access: bool,
    ) -> dict[str, int]:
        """Collect K8s resources from EKS clusters in the graph.

        Queries Neo4j for existing EKSCluster nodes, groups by
        account, and runs K8sCollector for each account's clusters.

        Args:
            on_progress: Optional progress callback.
            setup_access: Auto-create access entries if missing.

        Returns:
            Dict with 'nodes' and 'edges' counts.
        """
        from src.collector.k8s import K8sCollector
        from src.collector.k8s.setup_access import (
            ensure_cluster_access,
        )

        query = """
        MATCH (c:EKSCluster)
        WHERE c.status = 'ACTIVE'
        RETURN c.arn AS arn, c.name AS name,
               c.region AS region, c.account_id AS account_id
        """
        clusters = await self.neo4j.query(query)
        if not clusters:
            logger.info("k8s_no_eks_clusters_found")
            return {"nodes": 0, "edges": 0}

        # Group by account_id
        by_account: dict[str, list[dict[str, str]]] = {}
        for c in clusters:
            acct = c["account_id"]
            by_account.setdefault(acct, []).append({
                "arn": c["arn"],
                "name": c["name"],
                "region": c["region"],
            })

        total_nodes = 0
        total_edges = 0

        for acct_id, infos in by_account.items():
            if on_progress:
                await on_progress(
                    0, 0,
                    f"K8s: {acct_id} "
                    f"({len(infos)} clusters)",
                )

            try:
                session = get_session_for_account(acct_id)

                if setup_access:
                    mgmt_session = get_management_session()
                    sts = mgmt_session.client("sts")
                    identity = sts.get_caller_identity()
                    principal_arn = identity["Arn"]
                    for info in infos:
                        ensure_cluster_access(
                            session,
                            info["name"],
                            info["region"],
                            principal_arn,
                        )

                collector = K8sCollector(
                    session, acct_id, infos,
                )
                nodes, edges = await asyncio.to_thread(
                    collector.collect,
                )

                if nodes:
                    total_nodes += (
                        await self.neo4j.upsert_nodes(nodes)
                    )
                if edges:
                    exclusive = [
                        e for e in edges
                        if e.relationship
                        in EXCLUSIVE_EDGE_TYPES
                    ]
                    additive = [
                        e for e in edges
                        if e.relationship
                        not in EXCLUSIVE_EDGE_TYPES
                    ]
                    if exclusive:
                        total_edges += (
                            await self.neo4j
                            .upsert_edges_exclusive(
                                exclusive,
                            )
                        )
                    if additive:
                        total_edges += (
                            await self.neo4j
                            .upsert_edges(additive)
                        )
            except Exception:
                logger.exception(
                    "k8s_account_collection_failed",
                    account_id=acct_id,
                )

        logger.info(
            "k8s_collection_complete",
            nodes=total_nodes,
            edges=total_edges,
        )
        return {"nodes": total_nodes, "edges": total_edges}

    async def _link_pipeline_to_stacks(self) -> None:
        """Link CodePipeline DEPLOYS_TO edges to real CFN stacks.

        Pipeline deploy stages reference stacks by name, but the
        graph stores stacks with full ARNs (including UUID).
        This creates direct DEPLOYS_TO edges from pipelines to
        matching CloudFormationStack nodes by stack name and
        target account.
        """
        query = """
        MATCH (p:CodePipeline)
        WHERE p.arn IS NOT NULL
        MATCH (s:CloudFormationStack)
        WHERE s.name STARTS WITH 'cacicd-'
        WITH p, s,
             [stage IN p.stages
              WHERE stage CONTAINS ':CloudFormation'
             ] AS cf_stages
        WHERE s.name CONTAINS split(p.name, '-pipeline')[0]
           OR p.name CONTAINS s.name
        MERGE (p)-[:DEPLOYS_TO]->(s)
        RETURN count(*) AS linked
        """
        try:
            result = await self.neo4j.query(query)
            count = result[0]["linked"] if result else 0
            if count:
                logger.info(
                    "pipeline_stack_links_created",
                    count=count,
                )
        except Exception:
            logger.exception(
                "pipeline_stack_linking_failed",
            )

    async def _link_k8s_cross_boundary(self) -> None:
        """Create EXPOSES_VIA edges from K8s Services/Ingresses to LBs.

        Matches by external_hostname on K8s resources to
        dns_name on LoadBalancer nodes.
        """
        query = """
        MATCH (k)
        WHERE (k:K8sService OR k:K8sIngress)
          AND k.external_hostname IS NOT NULL
          AND k.external_hostname <> ''
        MATCH (lb:LoadBalancer)
        WHERE lb.dns_name = k.external_hostname
        MERGE (k)-[:EXPOSES_VIA]->(lb)
        RETURN count(*) AS linked
        """
        try:
            result = await self.neo4j.query(query)
            count = result[0]["linked"] if result else 0
            if count:
                logger.info(
                    "k8s_lb_cross_boundary_linked",
                    count=count,
                )
        except Exception:
            logger.exception(
                "k8s_cross_boundary_linking_failed",
            )

    def _resolve_accounts(self) -> list[str]:
        """Resolve which accounts to crawl when none are configured.

        Returns:
            List of account IDs to crawl.
        """
        if settings.aws.cross_account_role_name:
            try:
                accounts = discover_org_accounts()
                if accounts:
                    return accounts
            except ClientError:
                logger.exception("org_discovery_failed")

        detected = get_current_account_id()
        logger.info("auto_detected_account", account_id=detected)
        return [detected]
