"""API Gateway collector — REST and HTTP APIs."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class APIGatewayCollector(BaseCollector):
    """Collects API Gateway REST APIs and HTTP APIs (v2)."""

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect API Gateway resources in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        self._collect_rest_apis(region, nodes, edges)
        self._collect_http_apis(region, nodes, edges)

        return nodes, edges

    def _collect_rest_apis(
        self,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect REST APIs (API Gateway v1)."""
        try:
            client = self.client("apigateway", region)
            paginator = client.get_paginator("get_rest_apis")
            for page in paginator.paginate():
                for api in page.get("items", []):
                    api_id = api["id"]
                    arn = (
                        f"arn:aws:apigateway:{region}"
                        f"::/restapis/{api_id}"
                    )
                    nodes.append(ResourceNode(
                        arn=arn,
                        name=api.get("name", api_id),
                        label=NodeLabel.API_GATEWAY,
                        account_id=self.account_id,
                        region=region,
                        properties={
                            "api_id": api_id,
                            "api_type": "REST",
                            "description": api.get(
                                "description", ""
                            ),
                            "endpoint_type": ",".join(
                                api.get(
                                    "endpointConfiguration", {}
                                ).get("types", [])
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
            logger.error(
                "apigateway_rest_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _collect_http_apis(
        self,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect HTTP APIs (API Gateway v2)."""
        try:
            client = self.client("apigatewayv2", region)
            resp = client.get_apis()
            for api in resp.get("Items", []):
                api_id = api["ApiId"]
                arn = (
                    f"arn:aws:apigateway:{region}"
                    f"::/apis/{api_id}"
                )
                nodes.append(ResourceNode(
                    arn=arn,
                    name=api.get("Name", api_id),
                    label=NodeLabel.API_GATEWAY,
                    account_id=self.account_id,
                    region=region,
                    properties={
                        "api_id": api_id,
                        "api_type": api.get(
                            "ProtocolType", "HTTP"
                        ),
                        "description": api.get(
                            "Description", ""
                        ),
                        "api_endpoint": api.get(
                            "ApiEndpoint", ""
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

                self._link_lambda_integrations(
                    client, api_id, arn, region, edges
                )
        except ClientError as e:
            logger.error(
                "apigateway_http_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _link_lambda_integrations(
        self,
        client,
        api_id: str,
        api_arn: str,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Link API Gateway to Lambda integrations."""
        try:
            resp = client.get_integrations(ApiId=api_id)
            for integration in resp.get("Items", []):
                uri = integration.get("IntegrationUri", "")
                if ":lambda:" in uri and ":function:" in uri:
                    edges.append(ResourceEdge(
                        source_arn=api_arn,
                        target_arn=uri,
                        relationship=RelationshipType.INVOKES,
                    ))
        except ClientError as e:
            logger.warning(
                "apigateway_integrations_failed",
                api_id=api_id,
                error_code=e.response["Error"]["Code"],
            )
