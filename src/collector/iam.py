"""IAM collector — Roles, Policies, and Users."""

from __future__ import annotations

import json

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class IAMCollector(BaseCollector):
    """Collects IAM Roles, Policies, and Users.

    IAM is a global service — overrides collect() to avoid region iteration.
    """

    def collect(self) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect all IAM resources (global, single call)."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            iam = self.client("iam", "us-east-1")
            self._collect_roles(iam, nodes, edges)
            self._collect_policies(iam, nodes, edges)
            self._collect_users(iam, nodes, edges)
        except ClientError as e:
            logger.error(
                "iam_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

        logger.info(
            "iam_collected",
            account_id=self.account_id,
            nodes=len(nodes),
            edges=len(edges),
        )
        return nodes, edges

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Not used — IAM is a global service."""
        return [], []

    def _collect_roles(
        self,
        iam,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect IAM roles and their attached policies."""
        try:
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    arn = role["Arn"]
                    nodes.append(ResourceNode(
                        arn=arn,
                        name=role["RoleName"],
                        label=NodeLabel.IAM_ROLE,
                        account_id=self.account_id,
                        region="global",
                        properties={
                            "role_id": role["RoleId"],
                            "path": role.get("Path", "/"),
                            "assume_role_policy": json.dumps(
                                role.get("AssumeRolePolicyDocument", {})
                            ),
                            "max_session_duration": role.get(
                                "MaxSessionDuration", 3600
                            ),
                        },
                    ))
                    self._collect_role_policies(iam, role["RoleName"], arn, edges)
        except ClientError as e:
            logger.error(
                "iam_roles_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

    def _collect_role_policies(
        self,
        iam,
        role_name: str,
        role_arn: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Collect managed policies attached to a role."""
        try:
            paginator = iam.get_paginator("list_attached_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for policy in page["AttachedPolicies"]:
                    edges.append(ResourceEdge(
                        source_arn=role_arn,
                        target_arn=policy["PolicyArn"],
                        relationship=RelationshipType.HAS_POLICY,
                    ))
        except ClientError as e:
            logger.warning(
                "role_policies_failed",
                role_name=role_name,
                error_code=e.response["Error"]["Code"],
            )

    def _collect_policies(
        self,
        iam,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect customer-managed IAM policies."""
        try:
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for policy in page["Policies"]:
                    nodes.append(ResourceNode(
                        arn=policy["Arn"],
                        name=policy["PolicyName"],
                        label=NodeLabel.IAM_POLICY,
                        account_id=self.account_id,
                        region="global",
                        properties={
                            "policy_id": policy["PolicyId"],
                            "path": policy.get("Path", "/"),
                            "policy_type": "customer_managed",
                            "attachment_count": policy.get(
                                "AttachmentCount", 0
                            ),
                            "is_attachable": policy.get(
                                "IsAttachable", True
                            ),
                        },
                    ))
        except ClientError as e:
            logger.error(
                "iam_policies_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

    def _collect_users(
        self,
        iam,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect IAM users and their attached policies."""
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    arn = user["Arn"]
                    nodes.append(ResourceNode(
                        arn=arn,
                        name=user["UserName"],
                        label=NodeLabel.IAM_USER,
                        account_id=self.account_id,
                        region="global",
                        properties={
                            "user_id": user["UserId"],
                            "path": user.get("Path", "/"),
                            "create_date": str(
                                user.get("CreateDate", "")
                            ),
                        },
                    ))
                    self._collect_user_policies(
                        iam, user["UserName"], arn, edges
                    )
        except ClientError as e:
            logger.error(
                "iam_users_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

    def _collect_user_policies(
        self,
        iam,
        user_name: str,
        user_arn: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Collect managed policies attached to a user."""
        try:
            paginator = iam.get_paginator("list_attached_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for policy in page["AttachedPolicies"]:
                    edges.append(ResourceEdge(
                        source_arn=user_arn,
                        target_arn=policy["PolicyArn"],
                        relationship=RelationshipType.HAS_POLICY,
                    ))
        except ClientError as e:
            logger.warning(
                "user_policies_failed",
                user_name=user_name,
                error_code=e.response["Error"]["Code"],
            )
