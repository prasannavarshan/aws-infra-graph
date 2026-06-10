"""Base collector with cross-account STS assume-role support."""

import boto3
import structlog
from botocore.config import Config as BotoConfig

from src.config import settings
from src.graph.model import ResourceEdge, ResourceNode

logger = structlog.get_logger()

# Retry config for AWS API calls
BOTO_CONFIG = BotoConfig(
    retries={"max_attempts": 3, "mode": "adaptive"},
    max_pool_connections=25,
)

# Cached management account ID (populated on first call)
_mgmt_account_id: str | None = None


def get_management_session() -> boto3.Session:
    """Return a boto3 session for the management account.

    Uses the configured AWS_PROFILE when set, otherwise falls back to
    the default credential chain (env vars, instance profile, etc.).

    Returns:
        A boto3 Session using the management account credentials.
    """
    profile = settings.aws.profile
    if profile:
        logger.info("using_profile_session", profile=profile)
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def get_org_session() -> boto3.Session:
    """Return a session that can call Organizations API.

    When AWS_ORG_ACCOUNT_ID is set, assumes OrganizationAccessRole in that
    account (e.g. a delegated admin) to access Organizations APIs.
    Otherwise falls back to the management session.
    """
    org_account = settings.aws.org_account_id
    if org_account and settings.aws.cross_account_role_name:
        return get_session_for_account(org_account)
    return get_management_session()


def get_current_account_id() -> str:
    """Detect the current AWS account ID via STS get-caller-identity.

    The result is cached after the first call to avoid repeated API calls.

    Returns:
        The 12-digit AWS account ID of the current credentials.
    """
    global _mgmt_account_id  # noqa: PLW0603
    if _mgmt_account_id is not None:
        return _mgmt_account_id
    session = get_management_session()
    sts = session.client(
        "sts", config=BOTO_CONFIG, verify=settings.aws.ssl_verify,
    )
    identity = sts.get_caller_identity()
    _mgmt_account_id = identity["Account"]
    return _mgmt_account_id


def get_session_for_account(account_id: str) -> boto3.Session:
    """Create a boto3 session for the target account.

    In single-account mode (AWS_CROSS_ACCOUNT_ROLE_NAME is empty),
    returns the management session using current credentials/profile.

    In multi-account mode, assumes a role in the target account via STS
    using the management session for the assume-role call.  If the target
    account is the management account itself, the management session is
    returned directly (StackSets with SERVICE_MANAGED permissions do not
    deploy roles to the management account).

    Args:
        account_id: The AWS account ID to assume into.

    Returns:
        A boto3 Session with credentials for the target account.
    """
    if not settings.aws.cross_account_role_name:
        logger.info("using_default_session", account_id=account_id)
        return get_management_session()

    # Skip assume-role for the management account — OrganizationAccessRole
    # is not deployed there (StackSets SERVICE_MANAGED skips it).
    # When AWS_MGMT_ACCOUNT_ID is set (remote deployment), use that.
    # Otherwise fall back to current account ID (local deployment
    # where the profile IS the management account).
    mgmt_account = settings.aws.mgmt_account_id or get_current_account_id()
    if account_id == mgmt_account:
        logger.info(
            "skipping_assume_role_for_management_account",
            account_id=account_id,
        )
        return get_management_session()

    role_arn = (
        f"arn:aws:iam::{account_id}:role/"
        f"{settings.aws.cross_account_role_name}"
    )
    logger.info("assuming_role", account_id=account_id, role_arn=role_arn)

    session = get_management_session()
    sts = session.client(
        "sts", config=BOTO_CONFIG, verify=settings.aws.ssl_verify,
    )
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=f"aws-infra-graph-{account_id}",
        DurationSeconds=3600,
    )

    credentials = response["Credentials"]
    return boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


class BaseCollector:
    """Base class for AWS resource collectors.

    Subclasses implement `collect_in_region()` to gather resources
    for a specific account and region.

    Attributes:
        session: boto3 Session for the target account.
        account_id: The AWS account ID being crawled.
        regions: List of regions to crawl.
    """

    def __init__(self, session: boto3.Session, account_id: str, regions: list[str] | None = None):
        self.session = session
        self.account_id = account_id
        self.regions = regions or settings.aws.regions

    def collect(self) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect resources across all configured regions.

        Returns:
            Tuple of (nodes, edges) discovered across all regions.
        """
        all_nodes: list[ResourceNode] = []
        all_edges: list[ResourceEdge] = []

        for region in self.regions:
            logger.info(
                "collecting",
                collector=self.__class__.__name__,
                account_id=self.account_id,
                region=region,
            )
            try:
                nodes, edges = self.collect_in_region(region)
                all_nodes.extend(nodes)
                all_edges.extend(edges)
                logger.info(
                    "collected",
                    collector=self.__class__.__name__,
                    account_id=self.account_id,
                    region=region,
                    nodes=len(nodes),
                    edges=len(edges),
                )
            except Exception:
                logger.exception(
                    "collection_failed",
                    collector=self.__class__.__name__,
                    account_id=self.account_id,
                    region=region,
                )

        return all_nodes, all_edges

    def collect_in_region(self, region: str) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect resources in a specific region. Override in subclasses.

        Args:
            region: AWS region name (e.g., 'us-east-1').

        Returns:
            Tuple of (nodes, edges) discovered in this region.
        """
        raise NotImplementedError

    def client(self, service: str, region: str):
        """Create a boto3 client for the given service and region.

        Args:
            service: AWS service name (e.g., 'ec2', 'iam').
            region: AWS region name.

        Returns:
            A boto3 service client.
        """
        return self.session.client(
            service,
            region_name=region,
            config=BOTO_CONFIG,
            verify=settings.aws.ssl_verify,
        )
