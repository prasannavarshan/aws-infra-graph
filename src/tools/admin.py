"""Admin MCP tools — graph refresh and collector management."""

from __future__ import annotations

import asyncio
import logging

from mcp.server.fastmcp import Context

from src.collector import (
    APIGatewayCollector,
    CloudFormationCollector,
    CloudFrontCollector,
    CloudWANCollector,
    CodeBuildCollector,
    CodeCommitCollector,
    CodePipelineCollector,
    DynamoDBCollector,
    EC2Collector,
    ECSCollector,
    EKSCollector,
    ElastiCacheCollector,
    ELBCollector,
    IAMCollector,
    LambdaCollector,
    OpenSearchCollector,
    OrganizationsCollector,
    RDSCollector,
    Route53Collector,
    Route53ResolverCollector,
    S3Collector,
    SNSCollector,
    SQSCollector,
    TransitGatewayCollector,
    VPCEndpointsCollector,
    VPCNetworkingCollector,
    WAFCollector,
)
from src.graph.builder import GraphBuilder
from src.notifications import notify_gchat
from src.tools.refresh_state import refresh_state

logger = logging.getLogger(__name__)


def _get_app_context(ctx: Context):
    """Extract the AppContext from an MCP tool context."""
    return ctx.request_context.lifespan_context


def _fmt_duration(seconds: float) -> str:
    """Format elapsed seconds as e.g. '42 min 17 sec' or '58 sec'."""
    m, s = divmod(int(seconds), 60)
    return f"{m} min {s} sec" if m else f"{s} sec"


async def run_refresh(
    app,
    account_id: str = "",
    collectors: str = "",
    regions: str = "",
    include_k8s: bool = False,
    setup_access: bool = False,
    on_progress=None,
    trigger: str = "http",
) -> str:
    """Core refresh logic — callable from MCP tool or HTTP endpoint."""
    if refresh_state.is_running:
        return "Refresh already in progress. Call get_refresh_status() for details."

    k8s_only = False
    if collectors:
        names = [n.strip() for n in collectors.split(",")]
        if names == ["K8s"]:
            k8s_only = True
            selected = []
        else:
            selected = []
            for name in names:
                cls = COLLECTOR_NAMES.get(name)
                if not cls:
                    available = ", ".join(sorted(COLLECTOR_NAMES))
                    return f"Unknown collector: {name}. Available: {available}, K8s"
                selected.append(cls)
    else:
        selected = ALL_COLLECTORS

    region_list = (
        [r.strip() for r in regions.split(",")]
        if regions else None
    )

    async def _noop(cur: float, total: float, msg: str) -> None:
        pass

    progress = on_progress or _noop
    refresh_state.start(trigger)
    started = refresh_state.last_started
    try:
        if k8s_only:
            builder = GraphBuilder(neo4j=app.neo4j, collector_classes=[])
            result = await builder.build(
                account_ids=[account_id] if account_id else None,
                regions=region_list,
                on_progress=progress,
                include_k8s=True,
                setup_access=setup_access,
            )
        else:
            builder = GraphBuilder(neo4j=app.neo4j, collector_classes=selected)
            result = await builder.build(
                account_ids=[account_id] if account_id else None,
                regions=region_list,
                on_progress=progress,
                include_k8s=include_k8s,
                setup_access=setup_access,
            )

        from datetime import UTC, datetime
        elapsed = _fmt_duration((datetime.now(UTC) - started).total_seconds())
        total = result.get("total_accounts", 0)
        failed = result.get("failed_accounts", [])
        ok_count = total - len(failed)
        acct_str = f"{ok_count}/{total}" if total else "?"
        if failed:
            acct_str += f" ({len(failed)} failed: {', '.join(failed)})"

        summary = (
            f"Graph refreshed: {result['total_nodes']} nodes, "
            f"{result['total_edges']} edges — {acct_str} accounts — {elapsed}."
        )
        refresh_state.complete(summary)
        logger.info("refresh_complete: %s", summary)

        status = "❌ partial" if failed else "✅"
        notify_gchat(
            f"*[infra-graph] Graph refresh complete {status}*\n"
            f"Duration: {elapsed}\n"
            f"Accounts: {acct_str}\n"
            f"Nodes: {result['total_nodes']:,} | Edges: {result['total_edges']:,}\n"
            f"Trigger: {trigger}"
        )
        return summary
    except Exception as exc:
        from datetime import UTC, datetime
        elapsed = _fmt_duration((datetime.now(UTC) - started).total_seconds())
        error_str = str(exc)
        refresh_state.fail(error_str)
        logger.error("refresh_failed: %s", exc)
        notify_gchat(
            f"*[infra-graph] Graph refresh failed ❌*\n"
            f"Duration: {elapsed}\n"
            f"Error: `{error_str[:300]}`\n"
            f"Trigger: {trigger}"
        )
        raise


async def _fire_and_forget(app, kwargs: dict) -> None:
    """Run refresh in background — used by the fire-and-forget MCP tool path."""
    async def _track_progress(cur: float, total: float, msg: str) -> None:
        refresh_state.update_step(msg)

    await run_refresh(app, on_progress=_track_progress, **kwargs)


ALL_COLLECTORS = [
    OrganizationsCollector,
    EC2Collector,
    IAMCollector,
    S3Collector,
    RDSCollector,
    LambdaCollector,
    ECSCollector,
    EKSCollector,
    ElastiCacheCollector,
    ELBCollector,
    OpenSearchCollector,
    Route53Collector,
    Route53ResolverCollector,
    DynamoDBCollector,
    SQSCollector,
    SNSCollector,
    CloudFrontCollector,
    APIGatewayCollector,
    VPCEndpointsCollector,
    VPCNetworkingCollector,
    TransitGatewayCollector,
    CloudWANCollector,
    CloudFormationCollector,
    WAFCollector,
    CodeCommitCollector,
    CodePipelineCollector,
    CodeBuildCollector,
]

COLLECTOR_NAMES = {
    cls.__name__.replace("Collector", ""): cls
    for cls in ALL_COLLECTORS
}


async def refresh_graph(
    ctx: Context,
    account_id: str = "",
    collectors: str = "",
    regions: str = "",
    include_k8s: bool = False,
    setup_access: bool = False,
) -> str:
    """Re-crawl AWS resources and update the knowledge graph (fire-and-forget).

    Starts the refresh in the background and returns immediately.
    Call get_refresh_status() to check progress or outcome.
    A full org crawl typically takes 40-50 minutes.

    Args:
        account_id: Specific account to refresh. Empty for all accounts.
        collectors: Comma-separated collector names (e.g. "EC2,IAM,S3").
            Empty for all collectors. Use "K8s" for K8s-only collection.
            Available: Organizations, EC2, IAM, S3, RDS, Lambda,
            ECS, EKS, ElastiCache, ELB, OpenSearch, Route53,
            DynamoDB, SQS, SNS, CloudFront, APIGateway,
            VPCEndpoints, VPCNetworking, TransitGateway,
            CloudWAN, CloudFormation, WAF,
            Route53Resolver, CodeCommit, CodePipeline, CodeBuild, K8s.
        regions: Comma-separated regions (e.g. "us-west-2,us-east-1").
            Empty for all configured regions.
        include_k8s: Also collect K8s resources from EKS clusters.
        setup_access: Auto-create EKS access entries if missing.

    Returns:
        Confirmation that refresh started, or error if already running.
    """
    if refresh_state.is_running:
        return (
            "Refresh already in progress. "
            "Call get_refresh_status() for details."
        )
    app = _get_app_context(ctx)
    asyncio.ensure_future(_fire_and_forget(app, {
        "account_id": account_id,
        "collectors": collectors,
        "regions": regions,
        "include_k8s": include_k8s,
        "setup_access": setup_access,
        "trigger": "mcp",
    }))
    return (
        "Refresh started in the background. "
        "Call get_refresh_status() to check progress."
    )


async def get_refresh_status(ctx: Context) -> str:  # noqa: ARG001
    """Return the current status of the graph refresh.

    Shows whether a refresh is running, when it last ran,
    how long it has been running, and whether it succeeded or failed.

    Returns:
        Status summary including last_started, last_completed,
        last_result, last_error, elapsed_seconds if running.
    """
    state = refresh_state.to_dict()
    lines = [f"status: {state['status']}"]
    if "trigger" in state:
        lines.append(f"trigger: {state['trigger']}")
    if "last_started" in state:
        lines.append(f"last_started: {state['last_started']}")
    if "elapsed_seconds" in state:
        elapsed = state["elapsed_seconds"]
        lines.append(f"elapsed: {elapsed // 60}m {elapsed % 60}s")
    if "current_step" in state:
        lines.append(f"current_step: {state['current_step']}")
    if "last_completed" in state:
        lines.append(f"last_completed: {state['last_completed']}")
    if "last_result" in state:
        lines.append(f"last_result: {state['last_result']}")
    if "last_error" in state:
        lines.append(f"last_error: {state['last_error']}")
    if state["status"] == "never_run":
        lines.append("No refresh has run since the server started.")
    return "\n".join(lines)
