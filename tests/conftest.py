"""Shared test fixtures for AWS infrastructure graph tests."""


import boto3
import pytest
from moto import mock_aws


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch):
    """Set dummy AWS credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture()
def aws_mock():
    """Provide a moto mock_aws context for all AWS services."""
    with mock_aws():
        yield


@pytest.fixture()
def mock_session(aws_mock):
    """Provide a boto3 session within the moto mock."""
    return boto3.Session(region_name="us-east-1")


ACCOUNT_ID = "123456789012"
REGION = "us-east-1"
