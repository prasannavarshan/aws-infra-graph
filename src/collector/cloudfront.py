"""CloudFront collector — Distributions with origin configuration."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class CloudFrontCollector(BaseCollector):
    """Collects CloudFront distributions.

    CloudFront is global — overrides collect() to avoid region iteration.
    """

    def collect(self) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect all CloudFront distributions."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("cloudfront", "us-east-1")
            self._collect_distributions(client, nodes, edges)
        except ClientError as e:
            logger.error(
                "cloudfront_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

        logger.info(
            "cloudfront_collected",
            account_id=self.account_id,
            distributions=len(nodes),
        )
        return nodes, edges

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Not used — CloudFront is global."""
        return [], []

    def _collect_distributions(
        self,
        client,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """List and process all CloudFront distributions."""
        try:
            paginator = client.get_paginator(
                "list_distributions"
            )
            for page in paginator.paginate():
                dist_list = page.get("DistributionList", {})
                for dist in dist_list.get("Items", []):
                    self._process_distribution(
                        dist, nodes, edges
                    )
        except ClientError as e:
            logger.error(
                "cloudfront_list_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

    def _process_distribution(
        self,
        dist: dict,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single CloudFront distribution."""
        arn = dist.get("ARN", "")
        origins = dist.get("Origins", {}).get("Items", [])
        origin_domains = [
            o.get("DomainName", "") for o in origins
        ]

        nodes.append(ResourceNode(
            arn=arn,
            name=dist.get("DomainName", ""),
            label=NodeLabel.CLOUDFRONT_DISTRIBUTION,
            account_id=self.account_id,
            region="global",
            properties={
                "distribution_id": dist.get("Id", ""),
                "status": dist.get("Status", ""),
                "domain_name": dist.get("DomainName", ""),
                "enabled": dist.get("Enabled", False),
                "http_version": dist.get("HttpVersion", ""),
                "price_class": dist.get("PriceClass", ""),
                "origin_domains": origin_domains,
                "aliases": dist.get("Aliases", {}).get(
                    "Items", []
                ),
            },
        ))
        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=(
                f"arn:aws:organizations"
                f"::{self.account_id}:account"
            ),
            relationship=RelationshipType.BELONGS_TO,
        ))

        # Link to S3 origins
        for origin in origins:
            domain = origin.get("DomainName", "")
            if ".s3." in domain or domain.endswith(
                ".s3.amazonaws.com"
            ):
                bucket_name = domain.split(".s3")[0]
                edges.append(ResourceEdge(
                    source_arn=arn,
                    target_arn=f"arn:aws:s3:::{bucket_name}",
                    relationship=RelationshipType.DISTRIBUTES,
                ))
