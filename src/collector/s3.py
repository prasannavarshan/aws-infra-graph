"""S3 collector — S3 Buckets with versioning and encryption metadata."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError
from botocore.exceptions import ConnectionError as BotoConnectionError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class S3Collector(BaseCollector):
    """Collects S3 Buckets.

    S3 list-buckets is global but each bucket has a region.
    Overrides collect() to list once then enrich per-bucket.
    """

    def collect(self) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect all S3 buckets (global list, per-bucket enrichment)."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            s3 = self.client("s3", "us-east-1")
            response = s3.list_buckets()
            for bucket in response.get("Buckets", []):
                try:
                    self._process_bucket(s3, bucket, nodes, edges)
                except (ClientError, BotoConnectionError):
                    logger.warning(
                        "s3_bucket_skipped",
                        bucket=bucket["Name"],
                        account_id=self.account_id,
                    )
        except ClientError as e:
            logger.error(
                "s3_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

        logger.info(
            "s3_collected",
            account_id=self.account_id,
            buckets=len(nodes),
        )
        return nodes, edges

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Not used — S3 uses global listing."""
        return [], []

    def _process_bucket(
        self,
        s3,
        bucket: dict,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Enrich a single bucket with location, versioning, encryption."""
        name = bucket["Name"]
        region = self._get_bucket_region(s3, name)
        arn = f"arn:aws:s3:::{name}"

        versioning = self._get_versioning(s3, name)
        encryption = self._get_encryption(s3, name)

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.S3_BUCKET,
            account_id=self.account_id,
            region=region,
            properties={
                "creation_date": str(bucket.get("CreationDate", "")),
                "versioning": versioning,
                "encryption": encryption,
            },
        ))
        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=f"arn:aws:organizations::{self.account_id}:account",
            relationship=RelationshipType.BELONGS_TO,
        ))

    def _get_bucket_region(self, s3, bucket_name: str) -> str:
        """Get the region of a bucket."""
        try:
            resp = s3.get_bucket_location(Bucket=bucket_name)
            location = resp.get("LocationConstraint")
            return location or "us-east-1"
        except (ClientError, BotoConnectionError):
            return "unknown"

    def _get_versioning(self, s3, bucket_name: str) -> str:
        """Get the versioning status of a bucket."""
        try:
            resp = s3.get_bucket_versioning(Bucket=bucket_name)
            return resp.get("Status", "Disabled")
        except (ClientError, BotoConnectionError):
            return "unknown"

    def _get_encryption(self, s3, bucket_name: str) -> str:
        """Get the default encryption config of a bucket."""
        try:
            resp = s3.get_bucket_encryption(Bucket=bucket_name)
            rules = resp.get(
                "ServerSideEncryptionConfiguration", {}
            ).get("Rules", [])
            if rules:
                algo = rules[0].get(
                    "ApplyServerSideEncryptionByDefault", {}
                ).get("SSEAlgorithm", "none")
                return algo
            return "none"
        except (ClientError, BotoConnectionError):
            return "none"
