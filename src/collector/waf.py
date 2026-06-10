"""WAFv2 collector — WebACLs with resource associations."""

from __future__ import annotations

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


class WAFCollector(BaseCollector):
    """Collects WAFv2 WebACLs and their resource associations.

    WAFv2 has two scopes:
    - REGIONAL: protects ALBs, API Gateway, AppSync, Cognito, etc.
    - CLOUDFRONT: protects CloudFront distributions (us-east-1 only)
    """

    def collect(
        self,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect WAFv2 WebACLs across all regions + CloudFront."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        # Regional WebACLs — per region
        for region in self.regions:
            self._collect_scoped_acls(
                region, "REGIONAL", region, nodes, edges,
            )

        # CloudFront WebACLs — always us-east-1
        self._collect_scoped_acls(
            "us-east-1", "CLOUDFRONT", "global", nodes, edges,
        )

        logger.info(
            "waf_collected",
            account_id=self.account_id,
            web_acls=len(nodes),
        )
        return nodes, edges

    def collect_in_region(
        self, region: str,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Not used — WAF uses custom collect()."""
        return [], []

    def _collect_scoped_acls(
        self,
        api_region: str,
        scope: str,
        node_region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """List and process WebACLs for a given scope/region."""
        try:
            client = self.client("wafv2", api_region)
            self._list_and_process(
                client, scope, node_region, nodes, edges,
            )
        except ClientError as e:
            logger.error(
                "waf_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                scope=scope,
                region=api_region,
            )

    def _list_and_process(
        self,
        client: object,
        scope: str,
        node_region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Paginate list_web_acls and process each ACL."""
        next_marker: str | None = None

        while True:
            kwargs: dict = {"Scope": scope, "Limit": 100}
            if next_marker:
                kwargs["NextMarker"] = next_marker

            resp = client.list_web_acls(  # type: ignore[union-attr]
                **kwargs,
            )

            for summary in resp.get("WebACLs", []):
                self._process_acl(
                    client, summary, scope,
                    node_region, nodes, edges,
                )

            next_marker = resp.get("NextMarker")
            if not next_marker:
                break

    def _process_acl(
        self,
        client: object,
        summary: dict,
        scope: str,
        node_region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Fetch full ACL details and create node + edges."""
        name = summary.get("Name", "")
        acl_id = summary.get("Id", "")
        arn = summary.get("ARN", "")

        # Get full details
        try:
            detail_resp = client.get_web_acl(  # type: ignore[union-attr]
                Name=name, Scope=scope, Id=acl_id,
            )
        except ClientError as e:
            logger.warning(
                "waf_get_acl_failed",
                error_code=e.response["Error"]["Code"],
                acl_name=name,
                account_id=self.account_id,
            )
            return

        acl = detail_resp.get("WebACL", {})
        rules = acl.get("Rules", [])
        fm_rules = _extract_fm_rules(acl)
        all_rules = rules + fm_rules
        default_action = _parse_default_action(acl)
        managed_groups = _extract_managed_groups(all_rules)

        nodes.append(ResourceNode(
            arn=arn,
            name=name,
            label=NodeLabel.WAF_WEB_ACL,
            account_id=self.account_id,
            region=node_region,
            properties={
                "scope": scope,
                "capacity": acl.get("Capacity", 0),
                "default_action": default_action,
                "rule_count": len(all_rules),
                "rules_summary": _summarize_rules(all_rules),
                "managed_rule_groups": managed_groups,
                "description": acl.get("Description", ""),
                "managed_by_firewall_manager": acl.get(
                    "ManagedByFirewallManager", False,
                ),
            },
        ))

        # BELONGS_TO account
        edges.append(ResourceEdge(
            source_arn=arn,
            target_arn=(
                f"arn:aws:organizations:::{self.account_id}"
            ),
            relationship=RelationshipType.BELONGS_TO,
        ))

        # PROTECTS edges from associated resources
        self._add_association_edges(
            client, arn, edges,
        )

    def _add_association_edges(
        self,
        client: object,
        acl_arn: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Fetch and create PROTECTS edges for associated resources."""
        try:
            resp = client.list_resources_for_web_acl(  # type: ignore[union-attr]
                WebACLArn=acl_arn,
            )
        except ClientError as e:
            logger.warning(
                "waf_list_resources_failed",
                error_code=e.response["Error"]["Code"],
                acl_arn=acl_arn,
                account_id=self.account_id,
            )
            return

        for resource_arn in resp.get("ResourceArns", []):
            edges.append(ResourceEdge(
                source_arn=acl_arn,
                target_arn=resource_arn,
                relationship=RelationshipType.PROTECTS,
            ))


def _extract_fm_rules(acl: dict) -> list[dict]:
    """Extract Firewall Manager-injected rules as regular rule dicts.

    FM pushes rules via PreProcess/PostProcessFirewallManagerRuleGroups
    which have a different structure than regular Rules. This normalizes
    them so _summarize_rules and _extract_managed_groups can process them.
    """
    fm_rules: list[dict] = []
    for key in (
        "PreProcessFirewallManagerRuleGroups",
        "PostProcessFirewallManagerRuleGroups",
    ):
        for entry in acl.get(key, []):
            fm_stmt = entry.get("FirewallManagerStatement", {})
            # Normalize to same shape as a regular rule
            statement: dict = {}
            if fm_stmt.get("ManagedRuleGroupStatement"):
                statement["ManagedRuleGroupStatement"] = (
                    fm_stmt["ManagedRuleGroupStatement"]
                )
            elif fm_stmt.get("RuleGroupReferenceStatement"):
                statement["RuleGroupReferenceStatement"] = (
                    fm_stmt["RuleGroupReferenceStatement"]
                )
            fm_rules.append({
                "Name": entry.get("Name", ""),
                "Statement": statement,
            })
    return fm_rules


def _parse_default_action(acl: dict) -> str:
    """Extract default action as 'Allow' or 'Block'."""
    action = acl.get("DefaultAction", {})
    if "Allow" in action:
        return "Allow"
    if "Block" in action:
        return "Block"
    return "unknown"


def _extract_managed_groups(rules: list[dict]) -> list[str]:
    """Extract managed rule group names from rules."""
    groups: list[str] = []
    for rule in rules:
        stmt = rule.get("Statement", {})
        mrg = stmt.get("ManagedRuleGroupStatement", {})
        if mrg:
            vendor = mrg.get("VendorName", "")
            name = mrg.get("Name", "")
            label = f"{vendor}/{name}" if vendor else name
            groups.append(label)
    return groups


def _summarize_rules(rules: list[dict]) -> str:
    """Create compact one-line summary of WebACL rules."""
    parts: list[str] = []
    for rule in rules:
        name = rule.get("Name", "")
        stmt = rule.get("Statement", {})

        if stmt.get("ManagedRuleGroupStatement"):
            mrg = stmt["ManagedRuleGroupStatement"]
            parts.append(mrg.get("Name", name))
        elif stmt.get("RateBasedStatement"):
            limit = stmt["RateBasedStatement"].get("Limit", 0)
            parts.append(f"RateLimit:{limit}")
        elif stmt.get("RuleGroupReferenceStatement"):
            rg_arn = stmt["RuleGroupReferenceStatement"].get(
                "ARN", "",
            )
            # Extract rule group name from ARN
            rg_name = rg_arn.rsplit("/", 1)[-1] if rg_arn else name
            parts.append(f"RuleGroup:{rg_name}")
        else:
            parts.append(name)

    return ", ".join(parts) if parts else "(no rules)"
