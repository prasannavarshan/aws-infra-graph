"""DynamoDB collector — Tables with capacity and encryption metadata."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class DynamoDBCollector(BaseCollector):
    """Collects DynamoDB tables."""

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect DynamoDB tables in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("dynamodb", region)
            table_names = self._list_tables(client)
            for name in table_names:
                self._describe_table(client, name, region, nodes, edges)
        except ClientError as e:
            logger.error(
                "dynamodb_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _list_tables(self, client) -> list[str]:
        """List all table names with pagination."""
        names: list[str] = []
        paginator = client.get_paginator("list_tables")
        for page in paginator.paginate():
            names.extend(page.get("TableNames", []))
        return names

    def _describe_table(
        self,
        client,
        table_name: str,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Describe a single table and create node + edges."""
        try:
            resp = client.describe_table(TableName=table_name)
            table = resp["Table"]
            arn = table["TableArn"]

            billing = table.get("BillingModeSummary", {})
            sse = table.get("SSEDescription", {})

            nodes.append(ResourceNode(
                arn=arn,
                name=table_name,
                label=NodeLabel.DYNAMODB_TABLE,
                account_id=self.account_id,
                region=region,
                properties={
                    "table_status": table.get("TableStatus", ""),
                    "item_count": table.get("ItemCount", 0),
                    "table_size_bytes": table.get(
                        "TableSizeBytes", 0
                    ),
                    "billing_mode": billing.get(
                        "BillingMode", "PROVISIONED"
                    ),
                    "read_capacity": table.get(
                        "ProvisionedThroughput", {}
                    ).get("ReadCapacityUnits", 0),
                    "write_capacity": table.get(
                        "ProvisionedThroughput", {}
                    ).get("WriteCapacityUnits", 0),
                    "encryption": sse.get("SSEType", "none"),
                    "gsi_count": len(
                        table.get("GlobalSecondaryIndexes", [])
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
        except ClientError as e:
            logger.warning(
                "dynamodb_describe_failed",
                table_name=table_name,
                error_code=e.response["Error"]["Code"],
            )
