"""Tests for the RDS collector."""

import boto3
import pytest
from moto import mock_aws

from src.collector.rds import RDSCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.fixture()
def rds_env():
    """Set up moto-mocked RDS with a DB instance."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        rds = session.client("rds", region_name=REGION)

        # Create VPC and subnets for DB subnet group
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

        rds.create_db_subnet_group(
            DBSubnetGroupName="test-subnet-group",
            DBSubnetGroupDescription="Test",
            SubnetIds=[
                subnet1["Subnet"]["SubnetId"],
                subnet2["Subnet"]["SubnetId"],
            ],
        )

        sg = ec2.create_security_group(
            GroupName="rds-sg", Description="RDS SG", VpcId=vpc_id
        )

        rds.create_db_instance(
            DBInstanceIdentifier="test-db",
            DBInstanceClass="db.t3.micro",
            Engine="postgres",
            EngineVersion="15.4",
            MasterUsername="admin",
            MasterUserPassword="password123",
            DBSubnetGroupName="test-subnet-group",
            VpcSecurityGroupIds=[sg["GroupId"]],
            AllocatedStorage=20,
        )

        yield {
            "session": session,
            "sg_id": sg["GroupId"],
            "subnet1_id": subnet1["Subnet"]["SubnetId"],
            "subnet2_id": subnet2["Subnet"]["SubnetId"],
        }


class TestRDSCollectorHappyPath:
    """Happy path tests for RDS collector."""

    def test_collects_rds_instance(self, rds_env):
        collector = RDSCollector(
            session=rds_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()

        rds_nodes = [
            n for n in nodes if n.label == NodeLabel.RDS_INSTANCE
        ]
        assert len(rds_nodes) == 1
        assert rds_nodes[0].name == "test-db"

    def test_rds_instance_properties(self, rds_env):
        collector = RDSCollector(
            session=rds_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        db = next(
            (n for n in nodes if n.name == "test-db"), None
        )
        assert db is not None
        assert db.properties["engine"] == "postgres"
        assert db.properties["instance_class"] == "db.t3.micro"

    def test_rds_has_sg_edge(self, rds_env):
        collector = RDSCollector(
            session=rds_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        has_sg = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_SG
        ]
        assert len(has_sg) >= 1

    def test_rds_runs_in_subnet_edge(self, rds_env):
        collector = RDSCollector(
            session=rds_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        runs_in = [
            e for e in edges
            if e.relationship == RelationshipType.RUNS_IN
        ]
        assert len(runs_in) >= 1


class TestRDSCollectorEdgeCases:
    """Edge case tests."""

    def test_empty_region_returns_nothing(self):
        with mock_aws():
            session = boto3.Session(region_name="eu-west-1")
            collector = RDSCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["eu-west-1"],
            )
            nodes, edges = collector.collect()
            rds_nodes = [
                n for n in nodes if n.label == NodeLabel.RDS_INSTANCE
            ]
            assert len(rds_nodes) == 0


class TestRDSCollectorErrors:
    """Error handling tests."""

    def test_handles_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = RDSCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
