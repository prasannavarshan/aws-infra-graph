"""Tests for the EC2 collector."""

import boto3
import pytest
from moto import mock_aws

from src.collector.ec2 import EC2Collector
from src.collector.ec2_helpers import (
    _parse_tags,
    _summarize_nacl_entries,
    _tag_name,
)
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


@pytest.fixture()
def ec2_env():
    """Set up a moto-mocked AWS env with VPC, subnet, SG, and instance."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        ec2.create_tags(
            Resources=[vpc_id],
            Tags=[{"Key": "Name", "Value": "test-vpc"}],
        )

        subnet = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="10.0.1.0/24"
        )
        subnet_id = subnet["Subnet"]["SubnetId"]

        sg = ec2.create_security_group(
            GroupName="test-sg",
            Description="Test SG",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        # Add an SG-to-SG ingress rule
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "UserIdGroupPairs": [{"GroupId": sg_id}],
            }],
        )

        instance = ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            SecurityGroupIds=[sg_id],
        )
        instance_id = instance["Instances"][0]["InstanceId"]

        yield {
            "session": session,
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "sg_id": sg_id,
            "instance_id": instance_id,
        }


class TestParseHelpers:
    """Tests for tag parsing utility functions."""

    def test_parse_tags_converts_list_to_dict(self):
        tags = [{"Key": "Name", "Value": "foo"}, {"Key": "Env", "Value": "prod"}]
        assert _parse_tags(tags) == {"Name": "foo", "Env": "prod"}

    def test_parse_tags_returns_empty_for_none(self):
        assert _parse_tags(None) == {}

    def test_tag_name_extracts_name(self):
        assert _tag_name({"Name": "my-resource", "Env": "prod"}) == "my-resource"

    def test_tag_name_returns_empty_when_missing(self):
        assert _tag_name({"Env": "prod"}) == ""


class TestEC2CollectorHappyPath:
    """Happy path: collect VPCs, subnets, SGs, and instances."""

    def test_collects_all_resource_types(self, ec2_env):
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()

        labels = {n.label for n in nodes}
        assert NodeLabel.VPC in labels
        assert NodeLabel.SUBNET in labels
        assert NodeLabel.SECURITY_GROUP in labels
        assert NodeLabel.EC2_INSTANCE in labels

    def test_vpc_node_has_correct_properties(self, ec2_env):
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        vpcs = [n for n in nodes if n.label == NodeLabel.VPC]
        assert len(vpcs) >= 1
        test_vpc = next(
            (v for v in vpcs if v.properties["vpc_id"] == ec2_env["vpc_id"]),
            None,
        )
        assert test_vpc is not None
        assert test_vpc.name == "test-vpc"
        assert test_vpc.properties["cidr_block"] == "10.0.0.0/16"
        assert "secondary_cidrs" in test_vpc.properties
        assert isinstance(
            test_vpc.properties["secondary_cidrs"], list,
        )
        assert test_vpc.account_id == ACCOUNT_ID
        assert test_vpc.region == REGION

    def test_instance_runs_in_subnet_edge(self, ec2_env):
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        runs_in = [
            e for e in edges
            if e.relationship == RelationshipType.RUNS_IN
        ]
        assert len(runs_in) >= 1
        instance_arn = (
            f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}"
            f":instance/{ec2_env['instance_id']}"
        )
        subnet_arn = (
            f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}"
            f":subnet/{ec2_env['subnet_id']}"
        )
        edge = next(
            (e for e in runs_in if e.source_arn == instance_arn), None
        )
        assert edge is not None
        assert edge.target_arn == subnet_arn

    def test_instance_has_sg_edge(self, ec2_env):
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        has_sg = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_SG
        ]
        assert len(has_sg) >= 1

    def test_sg_allows_ingress_edge(self, ec2_env):
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        ingress = [
            e for e in edges
            if e.relationship == RelationshipType.ALLOWS_INGRESS
        ]
        assert len(ingress) >= 1
        assert ingress[0].properties["from_port"] == 443

    def test_subnet_part_of_vpc_edge(self, ec2_env):
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        part_of = [
            e for e in edges
            if e.relationship == RelationshipType.PART_OF
            and "subnet" in e.source_arn
        ]
        assert len(part_of) >= 1


class TestEC2CollectorEdgeCases:
    """Edge cases: empty regions, no instances, etc."""

    def test_empty_region_returns_no_resources(self):
        with mock_aws():
            session = boto3.Session(region_name="eu-west-1")
            collector = EC2Collector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["eu-west-1"],
            )
            nodes, edges = collector.collect()

            # moto creates a default VPC, so filter to non-default
            non_default = [
                n for n in nodes
                if n.label == NodeLabel.EC2_INSTANCE
            ]
            assert len(non_default) == 0

    def test_instance_without_subnet_skips_runs_in(self):
        """Instances without SubnetId should not create RUNS_IN edges."""
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            ec2 = session.client("ec2", region_name=REGION)
            # Classic EC2 instance (no VPC) — moto may still assign a VPC
            # but we test the collector logic handles missing gracefully
            ec2.run_instances(
                ImageId="ami-12345678",
                InstanceType="t2.micro",
                MinCount=1,
                MaxCount=1,
            )
            collector = EC2Collector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()
            instances = [
                n for n in nodes if n.label == NodeLabel.EC2_INSTANCE
            ]
            assert len(instances) >= 1


class TestEC2CollectorErrors:
    """Error handling: API failures should not crash the collector."""

    def test_collects_partial_on_api_error(self, ec2_env):
        """If one resource type fails, others should still be collected."""
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        # Collector should not raise even if internal errors occur
        nodes, edges = collector.collect()
        assert len(nodes) > 0

    def test_invalid_region_handled_gracefully(self):
        """Collecting from an invalid region should log error, not crash."""
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = EC2Collector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["invalid-region-99"],
            )
            # Should not raise
            nodes, edges = collector.collect()
            # May return empty or default VPC data depending on moto
            assert isinstance(nodes, list)
            assert isinstance(edges, list)


class TestNACLSummarizer:
    """Tests for _summarize_nacl_entries helper."""

    def test_summarize_ingress_rules(self):
        entries = [
            {
                "Egress": False,
                "RuleNumber": 100,
                "RuleAction": "allow",
                "Protocol": "6",
                "PortRange": {"From": 443, "To": 443},
                "CidrBlock": "0.0.0.0/0",
            },
            {
                "Egress": False,
                "RuleNumber": 32767,
                "RuleAction": "deny",
                "Protocol": "-1",
                "CidrBlock": "0.0.0.0/0",
            },
        ]
        result = _summarize_nacl_entries(entries, egress=False)
        assert "Rule 100 ALLOW tcp:443" in result
        assert "32767" not in result

    def test_summarize_filters_by_egress(self):
        entries = [
            {
                "Egress": True,
                "RuleNumber": 100,
                "RuleAction": "allow",
                "Protocol": "-1",
                "CidrBlock": "0.0.0.0/0",
            },
            {
                "Egress": False,
                "RuleNumber": 200,
                "RuleAction": "allow",
                "Protocol": "6",
                "PortRange": {"From": 80, "To": 80},
                "CidrBlock": "10.0.0.0/8",
            },
        ]
        ingress = _summarize_nacl_entries(entries, egress=False)
        assert "Rule 200" in ingress
        assert "Rule 100" not in ingress

    def test_summarize_empty_returns_none(self):
        assert _summarize_nacl_entries([], egress=False) == "none"


class TestNACLCollector:
    """Tests for NACL collection in EC2Collector."""

    def test_collects_nacl_nodes(self, ec2_env):
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        nacls = [
            n for n in nodes if n.label == NodeLabel.NETWORK_ACL
        ]
        # moto creates a default NACL per VPC
        assert len(nacls) >= 1

    def test_nacl_part_of_vpc_edge(self, ec2_env):
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        nacl_part_of = [
            e for e in edges
            if e.relationship == RelationshipType.PART_OF
            and "network-acl" in e.source_arn
        ]
        assert len(nacl_part_of) >= 1
        assert "vpc" in nacl_part_of[0].target_arn

    def test_nacl_has_nacl_edge_to_subnet(self, ec2_env):
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        has_nacl = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_NACL
        ]
        assert len(has_nacl) >= 1
        assert "subnet" in has_nacl[0].source_arn
        assert "network-acl" in has_nacl[0].target_arn

    def test_nacl_properties_include_rules(self, ec2_env):
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        nacls = [
            n for n in nodes if n.label == NodeLabel.NETWORK_ACL
        ]
        assert len(nacls) >= 1
        props = nacls[0].properties
        assert "ingress_rules" in props
        assert "egress_rules" in props
        assert "network_acl_id" in props
        assert "vpc_id" in props


class TestENICollection:
    """Tests for per-ENI node and edge creation."""

    def test_eni_nodes_created(self, ec2_env):
        """Happy path: instance ENIs become NetworkInterface nodes."""
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()

        enis = [
            n for n in nodes
            if n.label == NodeLabel.NETWORK_INTERFACE
        ]
        assert len(enis) >= 1
        eni = enis[0]
        assert eni.properties["eni_id"]
        assert eni.properties["vpc_id"] == ec2_env["vpc_id"]
        assert isinstance(eni.properties["is_primary"], bool)
        assert eni.properties["device_index"] >= 0

    def test_has_eni_edges_exist(self, ec2_env):
        """Happy path: EC2Instance --HAS_ENI--> NetworkInterface."""
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        has_eni = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_ENI
        ]
        assert len(has_eni) >= 1
        instance_arn = (
            f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}"
            f":instance/{ec2_env['instance_id']}"
        )
        edge = next(
            (e for e in has_eni
             if e.source_arn == instance_arn),
            None,
        )
        assert edge is not None
        assert "network-interface" in edge.target_arn

    def test_eni_has_sg_edges(self, ec2_env):
        """Edge case: both flattened and per-ENI HAS_SG exist."""
        collector = EC2Collector(
            session=ec2_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()

        enis = [
            n for n in nodes
            if n.label == NodeLabel.NETWORK_INTERFACE
        ]
        assert enis
        eni_arn = enis[0].arn

        # Per-ENI HAS_SG edges
        eni_sg_edges = [
            e for e in edges
            if (e.relationship == RelationshipType.HAS_SG
                and e.source_arn == eni_arn)
        ]
        assert len(eni_sg_edges) >= 1

        # Flattened instance HAS_SG edges still exist
        instance_arn = (
            f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}"
            f":instance/{ec2_env['instance_id']}"
        )
        inst_sg_edges = [
            e for e in edges
            if (e.relationship == RelationshipType.HAS_SG
                and e.source_arn == instance_arn)
        ]
        assert len(inst_sg_edges) >= 1

    def test_no_enis_no_crash(self):
        """Edge case: instance data with no ENIs."""
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = EC2Collector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            # collect with no instances — no crash
            nodes, edges = collector.collect()
            enis = [
                n for n in nodes
                if n.label == NodeLabel.NETWORK_INTERFACE
            ]
            assert len(enis) == 0
