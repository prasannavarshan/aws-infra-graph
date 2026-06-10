"""Tests for K8s auth module — token generation and API client."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.credentials import Credentials

from src.collector.k8s.auth import (
    ClusterConnection,
    get_eks_bearer_token,
    k8s_api_get,
)

CLUSTER_NAME = "test-cluster"
REGION = "us-east-1"
ACCOUNT_ID = "123456789012"
CLUSTER_ARN = (
    f"arn:aws:eks:{REGION}:{ACCOUNT_ID}:cluster/{CLUSTER_NAME}"
)


@pytest.fixture()
def mock_session():
    """Create a mock boto3 session with real credentials."""
    session = MagicMock()
    creds = Credentials(
        access_key="AKIAIOSFODNN7EXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        token="FwoGZXIvYXdzEBYaDH...",
    )
    session.get_credentials.return_value = creds
    return session


@pytest.fixture()
def mock_connection():
    """Create a test ClusterConnection."""
    return ClusterConnection(
        endpoint="https://test.eks.amazonaws.com",
        ca_data="",
        token="k8s-aws-v1.dGVzdC10b2tlbg",
        cluster_arn=CLUSTER_ARN,
        cluster_name=CLUSTER_NAME,
        account_id=ACCOUNT_ID,
        region=REGION,
    )


class TestGetEksBearerToken:
    """Tests for get_eks_bearer_token."""

    def test_happy_path_returns_prefixed_token(
        self, mock_session,
    ):
        """Token should start with k8s-aws-v1. prefix."""
        token = get_eks_bearer_token(
            mock_session, CLUSTER_NAME, REGION,
        )
        assert token.startswith("k8s-aws-v1.")
        assert len(token) > len("k8s-aws-v1.")

    def test_token_contains_signed_headers(
        self, mock_session,
    ):
        """Signed URL should include x-k8s-aws-id in signed headers."""
        import base64

        token = get_eks_bearer_token(
            mock_session, CLUSTER_NAME, REGION,
        )

        b64_part = token[len("k8s-aws-v1."):]
        padding = 4 - len(b64_part) % 4
        if padding != 4:
            b64_part += "=" * padding
        url = base64.urlsafe_b64decode(b64_part).decode()

        assert "GetCallerIdentity" in url
        assert "x-k8s-aws-id" in url
        assert "sts" in url

    def test_token_uses_correct_region(self, mock_session):
        """The STS endpoint should use the specified region."""
        import base64

        token = get_eks_bearer_token(
            mock_session, CLUSTER_NAME, "eu-west-1",
        )

        b64_part = token[len("k8s-aws-v1."):]
        padding = 4 - len(b64_part) % 4
        if padding != 4:
            b64_part += "=" * padding
        url = base64.urlsafe_b64decode(b64_part).decode()

        assert "sts.eu-west-1.amazonaws.com" in url


class TestK8sApiGet:
    """Tests for k8s_api_get."""

    @patch("src.collector.k8s.auth.urllib.request.urlopen")
    def test_happy_path_returns_json(
        self, mock_urlopen, mock_connection,
    ):
        """Successful API call returns parsed JSON."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(
            {"items": [{"name": "test"}]},
        ).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = k8s_api_get(
            mock_connection, "/api/v1/namespaces",
        )

        assert result is not None
        assert "items" in result

    @patch("src.collector.k8s.auth.urllib.request.urlopen")
    def test_timeout_returns_none(
        self, mock_urlopen, mock_connection,
    ):
        """Timeout should return None gracefully."""
        mock_urlopen.side_effect = TimeoutError(
            "Connection timed out",
        )

        result = k8s_api_get(
            mock_connection, "/api/v1/nodes", timeout=1.0,
        )

        assert result is None

    @patch("src.collector.k8s.auth.urllib.request.urlopen")
    def test_http_error_returns_none(
        self, mock_urlopen, mock_connection,
    ):
        """HTTP errors (401, 403, etc.) should return None."""
        from urllib.error import HTTPError

        mock_urlopen.side_effect = HTTPError(
            url="https://test.eks.amazonaws.com/api/v1/nodes",
            code=403,
            msg="Forbidden",
            hdrs=None,
            fp=None,
        )

        result = k8s_api_get(
            mock_connection, "/api/v1/nodes",
        )

        assert result is None
