"""Organizations collector — accounts, OU hierarchy, and SCPs."""

from __future__ import annotations

import json

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BOTO_CONFIG, BaseCollector, get_org_session
from src.config import settings
from src.graph.model import (
    NodeLabel,
    RelationshipType,
    ResourceEdge,
    ResourceNode,
)

logger = structlog.get_logger()


class OrganizationsCollector(BaseCollector):
    """Enumerates AWS accounts, OU hierarchy, and SCPs.

    This collector is global (not regional) — it overrides collect()
    to make a single set of API calls instead of iterating regions.
    Uses get_org_session() to call Organizations API from a delegated
    admin account when running remotely (AWS_ORG_ACCOUNT_ID).
    """

    run_once: bool = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._root_id: str = ""
        self._arn_map: dict[str, str] = {}  # id → real ARN

    def collect(
        self,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect accounts, OUs, and SCPs."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        try:
            org_session = get_org_session()
            org = org_session.client(
                "organizations", "us-east-1",
                config=BOTO_CONFIG,
                verify=settings.aws.ssl_verify,
            )
            self._collect_ou_hierarchy(org, nodes, edges)
            self._collect_accounts(org, nodes, edges)
            self._collect_scps(org, nodes, edges)
        except ClientError as e:
            logger.error(
                "organizations_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

        logger.info(
            "organizations_collected",
            account_id=self.account_id,
            accounts_found=len(
                [n for n in nodes if n.label == NodeLabel.ACCOUNT]
            ),
            ous_found=len(
                [
                    n for n in nodes
                    if n.label == NodeLabel.ORGANIZATIONAL_UNIT
                ]
            ),
            scps_found=len(
                [
                    n for n in nodes
                    if n.label == NodeLabel.SERVICE_CONTROL_POLICY
                ]
            ),
        )
        return nodes, edges

    def collect_in_region(
        self, region: str,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Not used — Organizations is a global service."""
        return [], []

    # --- OU hierarchy ---

    def _collect_ou_hierarchy(
        self,
        org,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Walk the OU tree starting from the root."""
        try:
            roots = org.list_roots()["Roots"]
            if not roots:
                return
            root = roots[0]
            self._root_id = root["Id"]
            root_arn = root["Arn"]
            self._arn_map[self._root_id] = root_arn

            nodes.append(ResourceNode(
                arn=root_arn,
                name=root.get("Name", "Root"),
                label=NodeLabel.ORGANIZATIONAL_UNIT,
                account_id=self.account_id,
                region="global",
                properties={
                    "ou_id": self._root_id,
                    "ou_name": root.get("Name", "Root"),
                    "ou_type": "ROOT",
                },
            ))

            self._walk_ous(
                org, self._root_id, root_arn, nodes, edges,
            )
        except ClientError as e:
            logger.warning(
                "ou_hierarchy_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

    def _walk_ous(
        self,
        org,
        parent_id: str,
        parent_arn: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Recursively list OUs under a parent."""
        try:
            paginator = org.get_paginator(
                "list_organizational_units_for_parent"
            )
            for page in paginator.paginate(ParentId=parent_id):
                for ou in page["OrganizationalUnits"]:
                    ou_id = ou["Id"]
                    ou_arn = ou["Arn"]
                    self._arn_map[ou_id] = ou_arn

                    nodes.append(ResourceNode(
                        arn=ou_arn,
                        name=ou.get("Name", ou_id),
                        label=NodeLabel.ORGANIZATIONAL_UNIT,
                        account_id=self.account_id,
                        region="global",
                        properties={
                            "ou_id": ou_id,
                            "ou_name": ou.get("Name", ou_id),
                            "ou_type": "ORGANIZATIONAL_UNIT",
                        },
                    ))

                    edges.append(ResourceEdge(
                        source_arn=ou_arn,
                        target_arn=parent_arn,
                        relationship=RelationshipType.PART_OF,
                    ))

                    self._walk_ous(
                        org, ou_id, ou_arn, nodes, edges,
                    )
        except ClientError as e:
            logger.warning(
                "ou_list_failed",
                parent_id=parent_id,
                error_code=e.response["Error"]["Code"],
            )

    # --- Accounts ---

    def _collect_accounts(
        self,
        org,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Paginate through all accounts and create nodes."""
        paginator = org.get_paginator("list_accounts")
        for page in paginator.paginate():
            for account in page["Accounts"]:
                account_id = account["Id"]
                arn = account["Arn"]
                name = account.get("Name", account_id)

                nodes.append(ResourceNode(
                    arn=arn,
                    name=name,
                    label=NodeLabel.ACCOUNT,
                    account_id=account_id,
                    region="global",
                    properties={
                        "account_id": account_id,
                        "account_name": name,
                        "email": account.get("Email", ""),
                        "status": account.get(
                            "Status", ""
                        ),
                        "joined_method": account.get(
                            "JoinedMethod", ""
                        ),
                    },
                ))

                self._collect_account_parents(
                    org, account_id, arn, edges,
                )

    def _collect_account_parents(
        self,
        org,
        account_id: str,
        account_arn: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Collect the OU parent for an account as a MEMBER_OF edge."""
        try:
            parents = org.list_parents(ChildId=account_id)
            for parent in parents.get("Parents", []):
                parent_id = parent["Id"]
                parent_type = parent["Type"]
                target_arn = self._parent_arn(
                    parent_type, parent_id,
                )
                edges.append(ResourceEdge(
                    source_arn=account_arn,
                    target_arn=target_arn,
                    relationship=RelationshipType.MEMBER_OF,
                    properties={
                        "parent_type": parent_type,
                        "parent_id": parent_id,
                    },
                ))
        except ClientError as e:
            logger.warning(
                "account_parent_lookup_failed",
                account_id=account_id,
                error_code=e.response["Error"]["Code"],
            )

    # --- SCPs ---

    def _collect_scps(
        self,
        org,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect Service Control Policies and their targets."""
        try:
            paginator = org.get_paginator("list_policies")
            for page in paginator.paginate(
                Filter="SERVICE_CONTROL_POLICY",
            ):
                for policy_summary in page["Policies"]:
                    self._process_scp(
                        org, policy_summary, nodes, edges,
                    )
        except ClientError as e:
            logger.warning(
                "scp_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
            )

    def _process_scp(
        self,
        org,
        policy_summary: dict,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single SCP: create node + GOVERNED_BY edges."""
        policy_id = policy_summary["Id"]
        policy_arn = policy_summary["Arn"]

        # Get full policy document
        doc_str = ""
        summary = ""
        try:
            detail = org.describe_policy(PolicyId=policy_id)
            content = detail["Policy"]["Content"]
            doc_str = content
            summary = _summarize_policy(content)
        except ClientError as e:
            logger.warning(
                "describe_policy_failed",
                policy_id=policy_id,
                error_code=e.response["Error"]["Code"],
            )

        aws_managed = policy_summary.get(
            "AwsManaged", False
        )
        nodes.append(ResourceNode(
            arn=policy_arn,
            name=policy_summary.get("Name", policy_id),
            label=NodeLabel.SERVICE_CONTROL_POLICY,
            account_id=self.account_id,
            region="global",
            properties={
                "policy_id": policy_id,
                "policy_name": policy_summary.get(
                    "Name", ""
                ),
                "aws_managed": aws_managed,
                "description": policy_summary.get(
                    "Description", ""
                ),
                "policy_document": doc_str,
                "policy_summary": summary,
            },
        ))

        # Find targets (OUs/accounts) this SCP is attached to
        self._collect_scp_targets(
            org, policy_id, policy_arn, edges,
        )

    def _collect_scp_targets(
        self,
        org,
        policy_id: str,
        policy_arn: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Create GOVERNED_BY edges from targets to SCP."""
        try:
            paginator = org.get_paginator(
                "list_targets_for_policy"
            )
            for page in paginator.paginate(
                PolicyId=policy_id,
            ):
                for target in page["Targets"]:
                    target_arn = target["Arn"]
                    edges.append(ResourceEdge(
                        source_arn=target_arn,
                        target_arn=policy_arn,
                        relationship=(
                            RelationshipType.GOVERNED_BY
                        ),
                        properties={
                            "target_type": target.get(
                                "Type", ""
                            ),
                        },
                    ))
        except ClientError as e:
            logger.warning(
                "scp_targets_failed",
                policy_id=policy_id,
                error_code=e.response["Error"]["Code"],
            )

    # --- ARN helpers ---

    def _root_arn(self, root_id: str) -> str:
        """Build ARN for an organization root."""
        return (
            f"arn:aws:organizations::{self.account_id}"
            f":root/{root_id}"
        )

    def _parent_arn(
        self, parent_type: str, parent_id: str,
    ) -> str:
        """Resolve ARN for a parent (root or OU) from lookup map."""
        cached = self._arn_map.get(parent_id)
        if cached:
            return cached
        # Fallback: construct ARN (shouldn't reach here)
        if parent_type == "ROOT":
            return self._root_arn(parent_id)
        return (
            f"arn:aws:organizations::{self.account_id}"
            f":ou/{self._root_id}/{parent_id}"
        )


def _summarize_policy(content: str) -> str:
    """Compact one-liner summarizing an SCP document."""
    try:
        doc = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return content[:200] if content else ""

    statements = doc.get("Statement", [])
    parts = []
    for stmt in statements:
        effect = stmt.get("Effect", "")
        actions = stmt.get("Action", stmt.get("NotAction", []))
        if isinstance(actions, str):
            actions = [actions]
        action_str = ", ".join(actions[:5])
        if len(actions) > 5:
            action_str += f" (+{len(actions) - 5} more)"
        parts.append(f"{effect}: {action_str}")
    return "; ".join(parts)
