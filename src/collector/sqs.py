"""SQS collector — SQS Queues with attributes."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class SQSCollector(BaseCollector):
    """Collects SQS queues."""

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect SQS queues in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("sqs", region)
            queue_urls = self._list_queues(client)
            for url in queue_urls:
                self._process_queue(client, url, region, nodes, edges)
        except ClientError as e:
            logger.error(
                "sqs_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _list_queues(self, client) -> list[str]:
        """List all queue URLs with pagination."""
        urls: list[str] = []
        paginator = client.get_paginator("list_queues")
        for page in paginator.paginate():
            urls.extend(page.get("QueueUrls", []))
        return urls

    def _process_queue(
        self,
        client,
        queue_url: str,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Get queue attributes and create node + edges."""
        try:
            resp = client.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=["All"],
            )
            attrs = resp.get("Attributes", {})
            arn = attrs.get("QueueArn", "")
            name = queue_url.rsplit("/", 1)[-1]

            nodes.append(ResourceNode(
                arn=arn,
                name=name,
                label=NodeLabel.SQS_QUEUE,
                account_id=self.account_id,
                region=region,
                properties={
                    "queue_url": queue_url,
                    "visibility_timeout": int(
                        attrs.get("VisibilityTimeout", 30)
                    ),
                    "max_message_size": int(
                        attrs.get("MaximumMessageSize", 262144)
                    ),
                    "message_retention": int(
                        attrs.get("MessageRetentionPeriod", 345600)
                    ),
                    "delay_seconds": int(
                        attrs.get("DelaySeconds", 0)
                    ),
                    "approximate_messages": int(
                        attrs.get(
                            "ApproximateNumberOfMessages", 0
                        )
                    ),
                    "fifo_queue": attrs.get(
                        "FifoQueue", "false"
                    ) == "true",
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

            # Dead-letter queue relationship
            dlq_arn = self._get_dlq_arn(attrs)
            if dlq_arn:
                edges.append(ResourceEdge(
                    source_arn=arn,
                    target_arn=dlq_arn,
                    relationship=RelationshipType.PUBLISHES_TO,
                    properties={"type": "dead_letter_queue"},
                ))
        except ClientError as e:
            logger.warning(
                "sqs_attributes_failed",
                queue_url=queue_url,
                error_code=e.response["Error"]["Code"],
            )

    def _get_dlq_arn(self, attrs: dict) -> str:
        """Extract dead-letter queue ARN from redrive policy."""
        import json

        policy_str = attrs.get("RedrivePolicy", "")
        if not policy_str:
            return ""
        try:
            policy = json.loads(policy_str)
            return policy.get("deadLetterTargetArn", "")
        except (json.JSONDecodeError, TypeError):
            return ""
