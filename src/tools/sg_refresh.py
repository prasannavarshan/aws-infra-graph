"""Live SG refresh — fetch fresh rules from AWS and upsert to Neo4j."""

from __future__ import annotations

from collections import defaultdict

import structlog
from botocore.exceptions import ClientError

from src.collector.base import (
    BOTO_CONFIG,
    get_session_for_account,
)
from src.collector.ec2_helpers import summarize_rules
from src.config import settings
from src.graph.model import NodeLabel, ResourceNode
from src.graph.neo4j_client import Neo4jClient

logger = structlog.get_logger()


async def refresh_security_groups(
    neo4j: Neo4jClient,
    sg_refs: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Fetch fresh SG rules from AWS and upsert to Neo4j.

    Groups SGs by (account_id, region), calls
    describe_security_groups per group, upserts nodes,
    and returns fresh SG dicts for the caller to use.

    Args:
        neo4j: Neo4jClient for upserting refreshed nodes.
        sg_refs: List of dicts with keys: group_id,
            account_id, region.

    Returns:
        List of fresh SG dicts with keys: group_id, name,
        vpc_id, account_id, ingress, egress.
    """
    # Group by (account_id, region) for batch API calls
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for ref in sg_refs:
        key = (ref["account_id"], ref["region"])
        groups[key].append(ref["group_id"])

    fresh_sgs: list[dict[str, str]] = []
    nodes: list[ResourceNode] = []

    for (account_id, region), group_ids in groups.items():
        try:
            sgs = _fetch_sgs_from_aws(
                account_id, region, group_ids,
            )
        except ClientError as e:
            logger.warning(
                "sg_refresh_failed",
                account_id=account_id,
                region=region,
                error_code=e.response["Error"]["Code"],
            )
            continue

        ec2_client = _get_ec2_client(account_id, region)
        for sg in sgs:
            sg_dict, node = _build_sg_result(
                sg, account_id, region,
                ec2_client=ec2_client,
            )
            fresh_sgs.append(sg_dict)
            nodes.append(node)

    if nodes:
        await neo4j.upsert_nodes(nodes)
        logger.info(
            "sg_refresh_upserted",
            count=len(nodes),
        )

    return fresh_sgs


def _get_ec2_client(
    account_id: str, region: str,
):
    """Create an EC2 client for the given account/region."""
    session = get_session_for_account(account_id)
    return session.client(
        "ec2",
        region_name=region,
        config=BOTO_CONFIG,
        verify=settings.aws.ssl_verify,
    )


def _fetch_sgs_from_aws(
    account_id: str,
    region: str,
    group_ids: list[str],
) -> list[dict]:
    """Call describe_security_groups for the given account/region.

    Args:
        account_id: AWS account to assume into.
        region: AWS region.
        group_ids: List of SG group IDs to fetch.

    Returns:
        List of raw SG dicts from the AWS API.
    """
    ec2 = _get_ec2_client(account_id, region)
    response = ec2.describe_security_groups(
        GroupIds=group_ids,
    )
    return response.get("SecurityGroups", [])


def _build_sg_result(
    sg: dict,
    account_id: str,
    region: str,
    ec2_client=None,  # noqa: ANN001
) -> tuple[dict[str, str], ResourceNode]:
    """Build a fresh SG dict and ResourceNode from AWS response.

    Args:
        sg: Raw SG dict from describe_security_groups.
        account_id: AWS account ID.
        region: AWS region.
        ec2_client: Optional EC2 client for prefix list resolution.

    Returns:
        Tuple of (sg_dict for tool use, ResourceNode for upsert).
    """
    group_id = sg["GroupId"]
    ingress = summarize_rules(
        sg.get("IpPermissions", []),
        ec2_client=ec2_client,
    )
    egress = summarize_rules(
        sg.get("IpPermissionsEgress", []),
        ec2_client=ec2_client,
    )
    tags = {
        t["Key"]: t["Value"]
        for t in sg.get("Tags", [])
    }
    name = tags.get("Name", "") or sg.get(
        "GroupName", group_id,
    )

    sg_dict: dict[str, str] = {
        "group_id": group_id,
        "name": name,
        "vpc_id": sg.get("VpcId", ""),
        "account_id": account_id,
        "ingress": ingress,
        "egress": egress,
    }

    arn = (
        f"arn:aws:ec2:{region}:{account_id}"
        f":security-group/{group_id}"
    )
    node = ResourceNode(
        arn=arn,
        name=name,
        label=NodeLabel.SECURITY_GROUP,
        account_id=account_id,
        region=region,
        tags=tags,
        properties={
            "group_id": group_id,
            "group_name": sg.get("GroupName", ""),
            "vpc_id": sg.get("VpcId", ""),
            "description": sg.get("Description", ""),
            "ingress_rules": ingress,
            "egress_rules": egress,
            "owner_id": sg.get("OwnerId", account_id),
        },
    )
    return sg_dict, node
