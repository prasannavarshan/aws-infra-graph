"""Tests for the S3 collector."""

import boto3
import pytest
from moto import mock_aws

from src.collector.s3 import S3Collector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"


@pytest.fixture()
def s3_env():
    """Set up moto-mocked S3 with buckets."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        s3 = session.client("s3", region_name="us-east-1")

        s3.create_bucket(Bucket="test-bucket-one")
        s3.create_bucket(
            Bucket="test-bucket-two",
            CreateBucketConfiguration={"LocationConstraint": "eu-west-1"},
        )

        # Enable versioning on one bucket
        s3.put_bucket_versioning(
            Bucket="test-bucket-one",
            VersioningConfiguration={"Status": "Enabled"},
        )

        yield {"session": session}


class TestS3CollectorHappyPath:
    """Happy path tests for S3 collector."""

    def test_collects_all_buckets(self, s3_env):
        collector = S3Collector(
            session=s3_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        nodes, edges = collector.collect()

        buckets = [n for n in nodes if n.label == NodeLabel.S3_BUCKET]
        assert len(buckets) == 2

    def test_bucket_properties(self, s3_env):
        collector = S3Collector(
            session=s3_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        nodes, _ = collector.collect()

        bucket_one = next(
            (n for n in nodes if n.name == "test-bucket-one"), None
        )
        assert bucket_one is not None
        assert bucket_one.arn == "arn:aws:s3:::test-bucket-one"
        assert bucket_one.properties["versioning"] == "Enabled"

    def test_bucket_region_detection(self, s3_env):
        collector = S3Collector(
            session=s3_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        nodes, _ = collector.collect()

        bucket_two = next(
            (n for n in nodes if n.name == "test-bucket-two"), None
        )
        assert bucket_two is not None
        assert bucket_two.region == "eu-west-1"

    def test_belongs_to_edge(self, s3_env):
        collector = S3Collector(
            session=s3_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        _, edges = collector.collect()

        belongs = [
            e for e in edges
            if e.relationship == RelationshipType.BELONGS_TO
        ]
        assert len(belongs) == 2


class TestS3CollectorEdgeCases:
    """Edge case tests."""

    def test_collect_in_region_returns_empty(self, s3_env):
        collector = S3Collector(
            session=s3_env["session"],
            account_id=ACCOUNT_ID,
        )
        nodes, edges = collector.collect_in_region("us-east-1")
        assert nodes == []
        assert edges == []

    def test_empty_account_returns_no_buckets(self):
        with mock_aws():
            session = boto3.Session(region_name="us-east-1")
            collector = S3Collector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["us-east-1"],
            )
            nodes, edges = collector.collect()
            assert nodes == []
            assert edges == []


class TestS3CollectorErrors:
    """Error handling tests."""

    def test_handles_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name="us-east-1")
            collector = S3Collector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["us-east-1"],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
