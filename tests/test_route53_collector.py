"""Tests for the Route53 collector."""

import boto3
import pytest
from moto import mock_aws

from src.collector.route53 import Route53Collector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"


@pytest.fixture()
def route53_env():
    """Set up moto-mocked Route53 with a hosted zone and records."""
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        r53 = session.client("route53", region_name="us-east-1")

        zone = r53.create_hosted_zone(
            Name="example.com",
            CallerReference="test-ref-001",
        )
        zone_id = zone["HostedZone"]["Id"].split("/")[-1]

        r53.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [{
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": "app.example.com",
                        "Type": "A",
                        "TTL": 300,
                        "ResourceRecords": [{"Value": "1.2.3.4"}],
                    },
                }],
            },
        )

        yield {
            "session": session,
            "zone_id": zone_id,
        }


class TestRoute53CollectorHappyPath:
    """Happy path tests for Route53 collector."""

    def test_collects_hosted_zone(self, route53_env):
        collector = Route53Collector(
            session=route53_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        nodes, edges = collector.collect()

        zones = [
            n for n in nodes if n.label == NodeLabel.ROUTE53_ZONE
        ]
        assert len(zones) == 1
        assert "example.com" in zones[0].name

    def test_collects_dns_records(self, route53_env):
        collector = Route53Collector(
            session=route53_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        nodes, _ = collector.collect()

        records = [
            n for n in nodes if n.label == NodeLabel.ROUTE53_RECORD
        ]
        # SOA + NS + our A record
        assert len(records) >= 1

    def test_record_part_of_zone(self, route53_env):
        collector = Route53Collector(
            session=route53_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        _, edges = collector.collect()

        part_of = [
            e for e in edges
            if e.relationship == RelationshipType.PART_OF
        ]
        assert len(part_of) >= 1

    def test_zone_properties(self, route53_env):
        collector = Route53Collector(
            session=route53_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        nodes, _ = collector.collect()

        zone = next(
            (n for n in nodes if n.label == NodeLabel.ROUTE53_ZONE),
            None,
        )
        assert zone is not None
        assert zone.region == "global"
        assert zone.properties["zone_id"] == route53_env["zone_id"]


class TestRoute53VPCAssociation:
    """Tests for private hosted zone VPC associations."""

    def test_private_zone_has_vpc_association(self):
        with mock_aws():
            session = boto3.Session(region_name="us-east-1")
            ec2 = session.client("ec2", region_name="us-east-1")
            r53 = session.client("route53", region_name="us-east-1")

            vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
            vpc_id = vpc["Vpc"]["VpcId"]

            r53.create_hosted_zone(
                Name="internal.example.com",
                CallerReference="test-private-001",
                HostedZoneConfig={"PrivateZone": True, "Comment": "private"},
                VPC={"VPCRegion": "us-east-1", "VPCId": vpc_id},
            )

            collector = Route53Collector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["us-east-1"],
            )
            _, edges = collector.collect()

            assoc_edges = [
                e for e in edges
                if e.relationship == RelationshipType.ASSOCIATED_WITH
            ]
            assert len(assoc_edges) >= 1
            assert vpc_id in assoc_edges[0].target_arn

    def test_private_zone_stores_vpc_in_properties(self):
        with mock_aws():
            session = boto3.Session(region_name="us-east-1")
            ec2 = session.client("ec2", region_name="us-east-1")
            r53 = session.client("route53", region_name="us-east-1")

            vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
            vpc_id = vpc["Vpc"]["VpcId"]

            r53.create_hosted_zone(
                Name="internal.example.com",
                CallerReference="test-private-002",
                HostedZoneConfig={"PrivateZone": True, "Comment": "private"},
                VPC={"VPCRegion": "us-east-1", "VPCId": vpc_id},
            )

            collector = Route53Collector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["us-east-1"],
            )
            nodes, _ = collector.collect()

            private_zones = [
                n for n in nodes
                if n.label == NodeLabel.ROUTE53_ZONE
                and n.properties.get("is_private")
            ]
            assert len(private_zones) == 1
            vpc_assocs = private_zones[0].properties.get(
                "vpc_associations", [],
            )
            assert any(vpc_id in v for v in vpc_assocs)

    def test_public_zone_has_no_vpc_association(self, route53_env):
        collector = Route53Collector(
            session=route53_env["session"],
            account_id=ACCOUNT_ID,
            regions=["us-east-1"],
        )
        _, edges = collector.collect()

        assoc_edges = [
            e for e in edges
            if e.relationship == RelationshipType.ASSOCIATED_WITH
        ]
        assert len(assoc_edges) == 0


class TestRoute53CollectorEdgeCases:
    """Edge case tests."""

    def test_collect_in_region_returns_empty(self, route53_env):
        collector = Route53Collector(
            session=route53_env["session"],
            account_id=ACCOUNT_ID,
        )
        nodes, edges = collector.collect_in_region("us-east-1")
        assert nodes == []
        assert edges == []


class TestRoute53CollectorErrors:
    """Error handling tests."""

    def test_no_zones_handles_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name="us-east-1")
            collector = Route53Collector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["us-east-1"],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
