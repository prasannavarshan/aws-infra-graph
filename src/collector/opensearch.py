"""OpenSearch collector — domains with VPC/SG relationships."""

from __future__ import annotations

import json

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import (
    NodeLabel,
    RelationshipType,
    ResourceEdge,
    ResourceNode,
)

logger = structlog.get_logger()

# describe_domains accepts max 5 domain names per call
_BATCH_SIZE = 5


class OpenSearchCollector(BaseCollector):
    """Collects OpenSearch domains with VPC and security group edges."""

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect OpenSearch domains in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            client = self.client("opensearch", region)
            self._collect_domains(client, region, nodes, edges)
        except ClientError as e:
            logger.error(
                "opensearch_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _collect_domains(
        self,
        client: object,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """List and describe all OpenSearch domains in the region."""
        try:
            resp = client.list_domain_names()  # type: ignore[union-attr]
        except ClientError as e:
            logger.error(
                "opensearch_list_domains_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )
            return

        domain_names = [
            d["DomainName"] for d in resp.get("DomainNames", [])
        ]
        if not domain_names:
            return

        # Batch describe_domains in chunks of 5
        for i in range(0, len(domain_names), _BATCH_SIZE):
            batch = domain_names[i : i + _BATCH_SIZE]
            try:
                desc = client.describe_domains(  # type: ignore[union-attr]
                    DomainNames=batch,
                )
            except ClientError as e:
                logger.error(
                    "opensearch_describe_domains_failed",
                    error_code=e.response["Error"]["Code"],
                    account_id=self.account_id,
                    region=region,
                    batch=batch,
                )
                continue

            for domain in desc.get("DomainStatusList", []):
                self._process_domain(domain, region, nodes, edges)

    def _process_domain(
        self,
        domain: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single OpenSearch domain into node and edges."""
        arn = domain.get("ARN", "")
        name = domain.get("DomainName", "")

        vpc_opts = domain.get("VPCOptions", {})
        vpc_id = vpc_opts.get("VPCId", "")

        # Endpoint: VPC domains use Endpoints dict, public use Endpoint
        endpoint = ""
        endpoints = domain.get("Endpoints", {})
        if endpoints:
            endpoint = endpoints.get("vpc", "")
        if not endpoint:
            endpoint = domain.get("Endpoint", "")

        cluster_cfg = domain.get("ClusterConfig", {})
        encryption = domain.get("EncryptionAtRestOptions", {})
        n2n = domain.get("NodeToNodeEncryptionOptions", {})
        advanced_sec = domain.get("AdvancedSecurityOptions", {})

        # Access policies as compact JSON string
        access_policies = domain.get("AccessPolicies", "")
        if isinstance(access_policies, dict):
            access_policies = json.dumps(access_policies)

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.OPENSEARCH_DOMAIN,
            account_id=self.account_id,
            region=region,
            properties={
                "domain_id": domain.get("DomainId", ""),
                "engine_version": domain.get(
                    "EngineVersion", ""
                ),
                "instance_type": cluster_cfg.get(
                    "InstanceType", ""
                ),
                "instance_count": cluster_cfg.get(
                    "InstanceCount", 0
                ),
                "dedicated_master": cluster_cfg.get(
                    "DedicatedMasterEnabled", False
                ),
                "zone_awareness": cluster_cfg.get(
                    "ZoneAwarenessEnabled", False
                ),
                "endpoint": endpoint,
                "vpc_id": vpc_id,
                "encryption_at_rest": encryption.get(
                    "Enabled", False
                ),
                "node_to_node_encryption": n2n.get(
                    "Enabled", False
                ),
                "fine_grained_access": advanced_sec.get(
                    "Enabled", False
                ),
                "access_policies": access_policies,
            },
        ))

        self._add_vpc_edges(arn, vpc_opts, region, edges)

        # BELONGS_TO account edge
        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=(
                f"arn:aws:organizations:::{self.account_id}"
            ),
            relationship=RelationshipType.BELONGS_TO,
        ))

    def _add_vpc_edges(
        self,
        arn: str,
        vpc_options: dict,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Create HAS_SG and RUNS_IN edges from VPC config."""
        for sg_id in vpc_options.get("SecurityGroupIds", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:ec2:{region}:{self.account_id}"
                    f":security-group/{sg_id}"
                ),
                relationship=RelationshipType.HAS_SG,
            ))

        for subnet_id in vpc_options.get("SubnetIds", []):
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=(
                    f"arn:aws:ec2:{region}:{self.account_id}"
                    f":subnet/{subnet_id}"
                ),
                relationship=RelationshipType.RUNS_IN,
            ))
