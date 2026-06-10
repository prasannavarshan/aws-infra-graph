"""Tests for the ELB collector."""

import boto3
import pytest
from moto import mock_aws

from src.collector.elb import ELBCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.fixture()
def elb_env():
    """Set up moto-mocked ELBv2 with ALB and target group."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        elbv2 = session.client("elbv2", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        subnet1 = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.1.0/24",
            AvailabilityZone="us-east-1a",
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.2.0/24",
            AvailabilityZone="us-east-1b",
        )

        sg = ec2.create_security_group(
            GroupName="alb-sg", Description="ALB SG", VpcId=vpc_id
        )

        lb = elbv2.create_load_balancer(
            Name="test-alb",
            Subnets=[
                subnet1["Subnet"]["SubnetId"],
                subnet2["Subnet"]["SubnetId"],
            ],
            SecurityGroups=[sg["GroupId"]],
            Scheme="internet-facing",
            Type="application",
        )
        lb_arn = lb["LoadBalancers"][0]["LoadBalancerArn"]

        tg = elbv2.create_target_group(
            Name="test-tg",
            Protocol="HTTP",
            Port=80,
            VpcId=vpc_id,
            TargetType="instance",
        )
        tg_arn = tg["TargetGroups"][0]["TargetGroupArn"]

        yield {
            "session": session,
            "lb_arn": lb_arn,
            "tg_arn": tg_arn,
            "vpc_id": vpc_id,
        }


class TestELBCollectorHappyPath:
    """Happy path tests for ELB collector."""

    def test_collects_load_balancer(self, elb_env):
        collector = ELBCollector(
            session=elb_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()

        lbs = [
            n for n in nodes if n.label == NodeLabel.LOAD_BALANCER
        ]
        assert len(lbs) == 1
        assert lbs[0].name == "test-alb"

    def test_collects_target_group(self, elb_env):
        collector = ELBCollector(
            session=elb_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        tgs = [
            n for n in nodes if n.label == NodeLabel.TARGET_GROUP
        ]
        assert len(tgs) == 1
        assert tgs[0].name == "test-tg"

    def test_lb_has_sg_edge(self, elb_env):
        collector = ELBCollector(
            session=elb_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        has_sg = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_SG
        ]
        assert len(has_sg) >= 1

    def test_lb_part_of_vpc(self, elb_env):
        collector = ELBCollector(
            session=elb_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        part_of = [
            e for e in edges
            if e.relationship == RelationshipType.PART_OF
            and e.source_arn == elb_env["lb_arn"]
        ]
        assert len(part_of) == 1


class TestELBCollectorEdgeCases:
    """Edge case tests."""

    def test_empty_region(self):
        with mock_aws():
            session = boto3.Session(region_name="eu-west-1")
            collector = ELBCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["eu-west-1"],
            )
            nodes, _ = collector.collect()
            lbs = [
                n for n in nodes
                if n.label == NodeLabel.LOAD_BALANCER
            ]
            assert len(lbs) == 0


class TestELBCollectorErrors:
    """Error handling tests."""

    def test_handles_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = ELBCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
