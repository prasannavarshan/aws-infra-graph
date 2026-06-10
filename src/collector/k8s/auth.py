"""K8s authentication — EKS bearer token and API client."""

from __future__ import annotations

import base64
import json
import ssl
import urllib.request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode

import structlog
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.config import Config as BotoConfig
from pydantic import BaseModel

from src.config import settings

logger = structlog.get_logger()

BOTO_CONFIG = BotoConfig(
    retries={"max_attempts": 3, "mode": "adaptive"},
)

K8S_TIMEOUT = 5.0

# STS regional endpoint template
_STS_URL = "https://sts.{region}.amazonaws.com/"

# Token validity in seconds (presigned URL expiry)
_TOKEN_EXPIRY = 60


class ClusterConnection(BaseModel):
    """Connection details for a K8s API server."""

    endpoint: str
    ca_data: str
    token: str
    cluster_arn: str
    cluster_name: str
    account_id: str
    region: str


def get_eks_bearer_token(
    session,  # noqa: ANN001
    cluster_name: str,
    region: str,
) -> str:
    """Generate a K8s bearer token via STS presigned URL.

    Constructs a GetCallerIdentity request with X-K8s-Aws-Id
    header, signs it with SigV4QueryAuth (signature in query
    params), and base64-encodes the URL as a bearer token.

    This is the same mechanism used by aws-iam-authenticator
    and ``aws eks get-token``.

    Args:
        session: boto3 Session with credentials for the account.
        cluster_name: Name of the EKS cluster.
        region: AWS region of the cluster.

    Returns:
        Bearer token string prefixed with 'k8s-aws-v1.'.
    """
    endpoint = _STS_URL.format(region=region)
    params = {
        "Action": "GetCallerIdentity",
        "Version": "2011-06-15",
    }
    url = f"{endpoint}?{urlencode(params)}"

    # X-K8s-Aws-Id header identifies the cluster; it gets
    # included in the signed headers by SigV4QueryAuth.
    headers = {
        "x-k8s-aws-id": cluster_name,
    }

    request = AWSRequest(method="GET", url=url, headers=headers)

    credentials = session.get_credentials()
    resolved = credentials.get_frozen_credentials()
    signer = SigV4QueryAuth(
        resolved, "sts", region, expires=_TOKEN_EXPIRY,
    )
    signer.add_auth(request)

    # After signing, request.url contains the full presigned
    # URL with all auth params in the query string.
    signed_url = request.url

    token_bytes = base64.urlsafe_b64encode(
        signed_url.encode("utf-8"),
    ).rstrip(b"=")
    return f"k8s-aws-v1.{token_bytes.decode('utf-8')}"


def get_cluster_connection(
    session,  # noqa: ANN001
    cluster_name: str,
    region: str,
    account_id: str,
) -> ClusterConnection | None:
    """Build a ClusterConnection from EKS describe + token.

    Args:
        session: boto3 Session for the account.
        cluster_name: EKS cluster name.
        region: AWS region.
        account_id: AWS account ID.

    Returns:
        ClusterConnection or None on failure.
    """
    try:
        eks = session.client(
            "eks",
            region_name=region,
            config=BOTO_CONFIG,
            verify=settings.aws.ssl_verify,
        )
        resp = eks.describe_cluster(name=cluster_name)
        cluster = resp["cluster"]
        endpoint = cluster.get("endpoint", "")
        ca_data = (
            cluster.get("certificateAuthority", {})
            .get("data", "")
        )
        if not endpoint:
            logger.warning(
                "k8s_no_endpoint",
                cluster=cluster_name,
            )
            return None

        token = get_eks_bearer_token(
            session, cluster_name, region,
        )
        return ClusterConnection(
            endpoint=endpoint,
            ca_data=ca_data,
            token=token,
            cluster_arn=cluster["arn"],
            cluster_name=cluster_name,
            account_id=account_id,
            region=region,
        )
    except Exception:
        logger.exception(
            "k8s_connection_failed",
            cluster=cluster_name,
            account_id=account_id,
            region=region,
        )
        return None


def k8s_api_get(
    conn: ClusterConnection,
    path: str,
    timeout: float = K8S_TIMEOUT,
) -> dict | None:
    """HTTPS GET against the K8s API server.

    Args:
        conn: ClusterConnection with endpoint and token.
        path: API path (e.g. '/api/v1/namespaces').
        timeout: Request timeout in seconds.

    Returns:
        Parsed JSON dict, or None on error/timeout.
    """
    url = f"{conn.endpoint}{path}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {conn.token}",
            "Accept": "application/json",
        },
    )

    ctx = ssl.create_default_context()
    if conn.ca_data:
        ca_bytes = base64.b64decode(conn.ca_data)
        ctx.load_verify_locations(cadata=ca_bytes.decode())
    if not settings.aws.ssl_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(
            req, timeout=timeout, context=ctx,
        ) as resp:
            return json.loads(resp.read())
    except HTTPError as e:
        logger.warning(
            "k8s_api_http_error",
            path=path,
            cluster=conn.cluster_name,
            status=e.code,
        )
        return None
    except (URLError, TimeoutError, OSError):
        logger.warning(
            "k8s_api_unreachable",
            path=path,
            cluster=conn.cluster_name,
        )
        return None
