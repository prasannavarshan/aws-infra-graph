"""CloudFormation collector — stacks with MANAGES edges to owned resources."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.collector.cloudformation_arn import physical_id_to_arn
from src.graph.model import (
    NodeLabel,
    RelationshipType,
    ResourceEdge,
    ResourceNode,
)

logger = structlog.get_logger()

# Stacks in these states are deleted or being deleted — skip them.
_SKIP_STATUSES = frozenset({
    "DELETE_COMPLETE",
    "DELETE_IN_PROGRESS",
})


class CloudFormationCollector(BaseCollector):
    """Collects CloudFormation stacks and links them to managed resources."""

    def collect_in_region(
        self, region: str,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect CloudFormation stacks in a single region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            cfn = self.client("cloudformation", region)
            paginator = cfn.get_paginator("describe_stacks")
            for page in paginator.paginate():
                for stack in page["Stacks"]:
                    if stack.get("StackStatus") in _SKIP_STATUSES:
                        continue
                    self._process_stack(
                        cfn, stack, region, nodes, edges,
                    )
        except ClientError as e:
            logger.error(
                "cloudformation_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

        return nodes, edges

    def _process_stack(
        self,
        cfn,
        stack: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single CloudFormation stack into nodes and edges."""
        arn = stack["StackId"]
        name = stack["StackName"]

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.CLOUDFORMATION_STACK,
            account_id=self.account_id,
            region=region,
            properties=self._build_properties(stack),
        ))

        # MANAGES edges to stack resources
        self._collect_stack_resources(
            cfn, arn, name, region, edges,
        )

        # Nested stack → parent PART_OF edge
        parent_id = stack.get("ParentId")
        if parent_id:
            self._add_nested_stack_edge(arn, parent_id, edges)

        # HAS_ROLE edge for CFN service role
        role_arn = stack.get("RoleARN")
        if role_arn:
            self._add_role_edge(arn, role_arn, edges)

    def _build_properties(self, stack: dict) -> dict:
        """Extract stack properties for the graph node."""
        drift = stack.get("DriftInformation", {})
        return {
            "status": stack.get("StackStatus", ""),
            "description": stack.get("Description", ""),
            "creation_time": str(
                stack.get("CreationTime", "")
            ),
            "last_updated_time": str(
                stack.get("LastUpdatedTime", "")
            ),
            "role_arn": stack.get("RoleARN", ""),
            "parent_id": stack.get("ParentId", ""),
            "root_id": stack.get("RootId", ""),
            "drift_status": drift.get(
                "StackDriftStatus", ""
            ),
            "termination_protection": stack.get(
                "EnableTerminationProtection", False
            ),
            "parameters": _summarize_parameters(
                stack.get("Parameters", [])
            ),
            "outputs": _summarize_outputs(
                stack.get("Outputs", [])
            ),
        }

    def _collect_stack_resources(
        self,
        cfn,
        stack_arn: str,
        stack_name: str,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Create MANAGES edges from stack to its resources."""
        try:
            paginator = cfn.get_paginator(
                "list_stack_resources"
            )
            resources: list[dict] = []
            for page in paginator.paginate(
                StackName=stack_name,
            ):
                for res in page.get(
                    "StackResourceSummaries", [],
                ):
                    resources.append(res)
                    self._add_manages_edge(
                        stack_arn, res, region, edges,
                    )
        except ClientError as e:
            logger.warning(
                "list_stack_resources_failed",
                stack=stack_name,
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _add_manages_edge(
        self,
        stack_arn: str,
        resource: dict,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Add a MANAGES edge if we can map the physical ID to an ARN."""
        resource_type = resource.get(
            "ResourceType", ""
        )
        physical_id = resource.get(
            "PhysicalResourceId", ""
        )
        if not physical_id:
            return

        target_arn = physical_id_to_arn(
            resource_type=resource_type,
            physical_id=physical_id,
            region=region,
            account_id=self.account_id,
        )
        if not target_arn:
            return

        edges.append(ResourceEdge(
            source_arn=stack_arn,
            target_arn=target_arn,
            relationship=RelationshipType.MANAGES,
            properties={
                "logical_id": resource.get(
                    "LogicalResourceId", ""
                ),
                "resource_type": resource_type,
            },
        ))

    def _add_nested_stack_edge(
        self,
        child_arn: str,
        parent_arn: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Add PART_OF edge from child stack to parent stack."""
        edges.append(ResourceEdge(
            source_arn=child_arn,
            target_arn=parent_arn,
            relationship=RelationshipType.PART_OF,
        ))

    def _add_role_edge(
        self,
        stack_arn: str,
        role_arn: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Add HAS_ROLE edge from stack to its service role."""
        edges.append(ResourceEdge(
            source_arn=stack_arn,
            target_arn=role_arn,
            relationship=RelationshipType.HAS_ROLE,
        ))


def _summarize_parameters(params: list[dict]) -> str:
    """Compact summary of stack parameters."""
    if not params:
        return ""
    parts = []
    for p in params:
        key = p.get("ParameterKey", "")
        val = p.get("ParameterValue", "")
        if "****" in val:
            val = "***"
        parts.append(f"{key}={val}")
    return "; ".join(parts)


def _summarize_outputs(outputs: list[dict]) -> str:
    """Compact summary of stack outputs."""
    if not outputs:
        return ""
    parts = []
    for o in outputs:
        key = o.get("OutputKey", "")
        val = o.get("OutputValue", "")
        parts.append(f"{key}={val}")
    return "; ".join(parts)
