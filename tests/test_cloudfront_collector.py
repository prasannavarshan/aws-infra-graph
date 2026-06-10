"""Tests for the CloudFront collector."""

import boto3
import pytest
from moto import mock_aws

from src.collector.cloudfront import CloudFrontCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"


@pytest.fixture()
def cloudfront_env():
    """Set up moto-mocked CloudFront with a distribution."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        client = session.client(
            "cloudfront", region_name="us-east-1"
        )

        client.create_distribution(
            DistributionConfig={
                "CallerReference": "test-ref",
                "Origins": {
                    "Quantity": 1,
                    "Items": [{
                        "Id": "s3-origin",
                        "DomainName": "my-bucket.s3.amazonaws.com",
                        "S3OriginConfig": {
                            "OriginAccessIdentity": "",
                        },
                    }],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "s3-origin",
                    "ViewerProtocolPolicy": "redirect-to-https",
                    "ForwardedValues": {
                        "QueryString": False,
                        "Cookies": {"Forward": "none"},
                    },
                    "TrustedSigners": {
                        "Enabled": False,
                        "Quantity": 0,
                    },
                    "MinTTL": 0,
                },
                "Comment": "Test distribution",
                "Enabled": True,
            }
        )

        yield {"session": session}


class TestCloudFrontHappyPath:
    def test_collects_distribution(self, cloudfront_env):
        collector = CloudFrontCollector(
            session=cloudfront_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        nodes, edges = collector.collect()

        dists = [
            n for n in nodes
            if n.label == NodeLabel.CLOUDFRONT_DISTRIBUTION
        ]
        assert len(dists) == 1

    def test_distribution_properties(self, cloudfront_env):
        collector = CloudFrontCollector(
            session=cloudfront_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        nodes, _ = collector.collect()
        dist = nodes[0]
        assert dist.region == "global"
        assert dist.properties["enabled"] is True

    def test_distributes_s3_edge(self, cloudfront_env):
        collector = CloudFrontCollector(
            session=cloudfront_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        _, edges = collector.collect()
        distributes = [
            e for e in edges
            if e.relationship == RelationshipType.DISTRIBUTES
        ]
        assert len(distributes) == 1
        assert "my-bucket" in distributes[0].target_arn


class TestCloudFrontEdgeCases:
    def test_collect_in_region_returns_empty(self, cloudfront_env):
        collector = CloudFrontCollector(
            session=cloudfront_env["session"],
            account_id=ACCOUNT_ID,
        )
        nodes, edges = collector.collect_in_region("us-east-1")
        assert nodes == []
        assert edges == []


class TestCloudFrontErrors:
    def test_no_distributions_handles_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name="us-east-1")
            collector = CloudFrontCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["us-east-1"],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
