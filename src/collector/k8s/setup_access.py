"""K8s access entry management — create EKS access entries for API access."""

from __future__ import annotations

import structlog
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from src.config import settings

logger = structlog.get_logger()

BOTO_CONFIG = BotoConfig(
    retries={"max_attempts": 3, "mode": "adaptive"},
)

# The EKS admin view policy for read-only K8s access
_ADMIN_VIEW_POLICY = (
    "arn:aws:eks::aws:cluster-access-policy/"
    "AmazonEKSAdminViewPolicy"
)


def check_access_entry(
    session,  # noqa: ANN001
    cluster_name: str,
    region: str,
    principal_arn: str,
) -> bool:
    """Check if an EKS access entry exists for the principal.

    Args:
        session: boto3 Session for the account.
        cluster_name: EKS cluster name.
        region: AWS region.
        principal_arn: IAM principal ARN to check.

    Returns:
        True if access entry exists, False otherwise.
    """
    eks = session.client(
        "eks",
        region_name=region,
        config=BOTO_CONFIG,
        verify=settings.aws.ssl_verify,
    )
    try:
        eks.describe_access_entry(
            clusterName=cluster_name,
            principalArn=principal_arn,
        )
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        logger.warning(
            "k8s_access_check_failed",
            cluster=cluster_name,
            error_code=e.response["Error"]["Code"],
        )
        return False


def setup_cluster_access(
    session,  # noqa: ANN001
    cluster_name: str,
    region: str,
    principal_arn: str,
) -> bool:
    """Create an EKS access entry with admin view policy.

    Args:
        session: boto3 Session for the account.
        cluster_name: EKS cluster name.
        region: AWS region.
        principal_arn: IAM principal ARN to grant access.

    Returns:
        True if setup succeeded, False on error.
    """
    eks = session.client(
        "eks",
        region_name=region,
        config=BOTO_CONFIG,
        verify=settings.aws.ssl_verify,
    )
    try:
        eks.create_access_entry(
            clusterName=cluster_name,
            principalArn=principal_arn,
            type="STANDARD",
        )
        logger.info(
            "k8s_access_entry_created",
            cluster=cluster_name,
            principal=principal_arn,
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code != "ResourceInUseException":
            logger.warning(
                "k8s_access_entry_create_failed",
                cluster=cluster_name,
                error_code=code,
            )
            return False

    try:
        eks.associate_access_policy(
            clusterName=cluster_name,
            principalArn=principal_arn,
            policyArn=_ADMIN_VIEW_POLICY,
            accessScope={"type": "cluster"},
        )
        logger.info(
            "k8s_access_policy_associated",
            cluster=cluster_name,
            principal=principal_arn,
        )
        return True
    except ClientError as e:
        logger.warning(
            "k8s_access_policy_failed",
            cluster=cluster_name,
            error_code=e.response["Error"]["Code"],
        )
        return False


def ensure_cluster_access(
    session,  # noqa: ANN001
    cluster_name: str,
    region: str,
    principal_arn: str,
) -> bool:
    """Ensure access entry exists, creating if needed.

    Args:
        session: boto3 Session for the account.
        cluster_name: EKS cluster name.
        region: AWS region.
        principal_arn: IAM principal ARN.

    Returns:
        True if access is available, False on failure.
    """
    if check_access_entry(
        session, cluster_name, region, principal_arn,
    ):
        return True

    logger.info(
        "k8s_setting_up_access",
        cluster=cluster_name,
        principal=principal_arn,
    )
    return setup_cluster_access(
        session, cluster_name, region, principal_arn,
    )
