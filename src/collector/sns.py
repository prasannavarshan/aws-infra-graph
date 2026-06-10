"""SNS collector — SNS Topics and Subscriptions."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class SNSCollector(BaseCollector):
    """Collects SNS topics and their subscriptions."""

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect SNS topics in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("sns", region)
            self._collect_topics(client, region, nodes, edges)
        except ClientError as e:
            logger.error(
                "sns_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _collect_topics(
        self,
        client,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """List topics and enrich with attributes."""
        paginator = client.get_paginator("list_topics")
        for page in paginator.paginate():
            for topic in page.get("Topics", []):
                arn = topic["TopicArn"]
                self._process_topic(client, arn, region, nodes, edges)

    def _process_topic(
        self,
        client,
        arn: str,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Get topic attributes and subscriptions."""
        try:
            attrs_resp = client.get_topic_attributes(TopicArn=arn)
            attrs = attrs_resp.get("Attributes", {})
            name = arn.rsplit(":", 1)[-1]

            nodes.append(ResourceNode(
                arn=arn,
                name=name,
                label=NodeLabel.SNS_TOPIC,
                account_id=self.account_id,
                region=region,
                properties={
                    "display_name": attrs.get("DisplayName", ""),
                    "subscription_count": int(
                        attrs.get(
                            "SubscriptionsConfirmed", 0
                        )
                    ),
                    "fifo_topic": attrs.get(
                        "FifoTopic", "false"
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

            self._collect_subscriptions(client, arn, edges)
        except ClientError as e:
            logger.warning(
                "sns_topic_failed",
                topic_arn=arn,
                error_code=e.response["Error"]["Code"],
            )

    def _collect_subscriptions(
        self,
        client,
        topic_arn: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Create SUBSCRIBES_TO edges for topic subscriptions."""
        try:
            paginator = client.get_paginator(
                "list_subscriptions_by_topic"
            )
            for page in paginator.paginate(TopicArn=topic_arn):
                for sub in page.get("Subscriptions", []):
                    endpoint = sub.get("Endpoint", "")
                    protocol = sub.get("Protocol", "")
                    # Link to SQS/Lambda if the endpoint is an ARN
                    if endpoint.startswith("arn:aws:"):
                        edges.append(ResourceEdge(
                            source_arn=topic_arn,
                            target_arn=endpoint,
                            relationship=RelationshipType.PUBLISHES_TO,
                            properties={"protocol": protocol},
                        ))
        except ClientError as e:
            logger.warning(
                "sns_subscriptions_failed",
                topic_arn=topic_arn,
                error_code=e.response["Error"]["Code"],
            )
