"""Headless CLI for scheduled graph refresh (no MCP server needed)."""

from __future__ import annotations

import asyncio
import sys

from dotenv import load_dotenv

load_dotenv()

import logging  # noqa: E402

import src.logging_config  # noqa: F401, E402
from src.graph.neo4j_client import Neo4jClient  # noqa: E402

logger = logging.getLogger(__name__)


async def refresh() -> None:
    """Connect to Neo4j and run a full graph build."""
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

    neo4j = Neo4jClient()
    await neo4j.connect()
    try:
        collectors = [
            OrganizationsCollector, EC2Collector, IAMCollector,
            S3Collector, RDSCollector, LambdaCollector,
            ECSCollector, EKSCollector, ElastiCacheCollector,
            ELBCollector, OpenSearchCollector, Route53Collector,
            Route53ResolverCollector, DynamoDBCollector,
            SQSCollector, SNSCollector, CloudFrontCollector,
            APIGatewayCollector, TransitGatewayCollector,
            CloudWANCollector, VPCNetworkingCollector,
            VPCEndpointsCollector, CloudFormationCollector,
            CodeCommitCollector, CodePipelineCollector,
            CodeBuildCollector, WAFCollector,
        ]
        builder = GraphBuilder(neo4j=neo4j, collector_classes=collectors)
        logger.info("Starting full graph refresh")
        stats = await builder.build()
        logger.info(
            "Graph refresh complete: %d nodes, %d edges",
            stats.nodes, stats.edges,
        )
    finally:
        await neo4j.close()


def main() -> None:
    """CLI entry point."""
    if len(sys.argv) < 2 or sys.argv[1] != "refresh":
        print("Usage: python -m src.cli refresh")
        sys.exit(1)
    asyncio.run(refresh())


if __name__ == "__main__":
    main()
