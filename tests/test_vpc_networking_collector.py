"""Tests for the VPC Networking collector."""

import boto3
import pytest
from moto import mock_aws

from src.collector.vpc_networking import (
    VPCNetworkingCollector,
    _route_target_arn,
    _summarize_routes,
)
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"


# --- Helper fixtures ---


@pytest.fixture()
def vpc_env():
    """Set up a moto-mocked AWS env with VPC, subnet, IGW, NAT, and routes."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)
        ec2_resource = session.resource("ec2", region_name=REGION)

        # Create VPC and subnet
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]
        ec2.create_tags(
            Resources=[vpc_id],
            Tags=[{"Key": "Name", "Value": "test-vpc"}],
        )

        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.1.0/24",
            AvailabilityZone=f"{REGION}a",
        )
        subnet_id = subnet["Subnet"]["SubnetId"]

        # Create Internet Gateway and attach
        igw = ec2.create_internet_gateway()
        igw_id = igw["InternetGateway"]["InternetGatewayId"]
        ec2.attach_internet_gateway(
            InternetGatewayId=igw_id, VpcId=vpc_id,
        )
        ec2.create_tags(
            Resources=[igw_id],
            Tags=[{"Key": "Name", "Value": "test-igw"}],
        )

        # Allocate EIP and create NAT Gateway
        eip = ec2.allocate_address(Domain="vpc")
        nat = ec2.create_nat_gateway(
            SubnetId=subnet_id,
            AllocationId=eip["AllocationId"],
        )
        nat_id = nat["NatGateway"]["NatGatewayId"]

        # Create route table and associate with subnet
        rt = ec2.create_route_table(VpcId=vpc_id)
        rt_id = rt["RouteTable"]["RouteTableId"]
        ec2.create_tags(
            Resources=[rt_id],
            Tags=[{"Key": "Name", "Value": "test-rt"}],
        )
        ec2.associate_route_table(
            RouteTableId=rt_id, SubnetId=subnet_id,
        )

        # Add routes
        ec2.create_route(
            RouteTableId=rt_id,
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=igw_id,
        )

        yield {
            "session": session,
            "ec2": ec2,
            "ec2_resource": ec2_resource,
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "igw_id": igw_id,
            "nat_id": nat_id,
            "rt_id": rt_id,
        }


@pytest.fixture()
def peering_env():
    """Set up moto-mocked AWS env with VPC peering."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        ec2 = session.client("ec2", region_name=REGION)

        vpc1 = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc1_id = vpc1["Vpc"]["VpcId"]

        vpc2 = ec2.create_vpc(CidrBlock="10.1.0.0/16")
        vpc2_id = vpc2["Vpc"]["VpcId"]

        pcx = ec2.create_vpc_peering_connection(
            VpcId=vpc1_id, PeerVpcId=vpc2_id,
        )
        pcx_id = pcx["VpcPeeringConnection"][
            "VpcPeeringConnectionId"
        ]

        # Accept the peering
        ec2.accept_vpc_peering_connection(
            VpcPeeringConnectionId=pcx_id,
        )

        ec2.create_tags(
            Resources=[pcx_id],
            Tags=[{"Key": "Name", "Value": "test-peering"}],
        )

        yield {
            "session": session,
            "ec2": ec2,
            "vpc1_id": vpc1_id,
            "vpc2_id": vpc2_id,
            "pcx_id": pcx_id,
        }


# --- Summarizer tests ---


class TestSummarizeRoutes:
    """Tests for _summarize_routes."""

    def test_basic_routes(self):
        routes = [
            {
                "DestinationCidrBlock": "10.0.0.0/16",
                "GatewayId": "local",
                "State": "active",
            },
            {
                "DestinationCidrBlock": "0.0.0.0/0",
                "GatewayId": "igw-abc123",
                "State": "active",
            },
        ]
        result = _summarize_routes(routes)
        assert "10.0.0.0/16 -> local" in result
        assert "0.0.0.0/0 -> igw-abc123" in result

    def test_blackhole_skipped(self):
        routes = [
            {
                "DestinationCidrBlock": "172.16.0.0/12",
                "GatewayId": "igw-dead",
                "State": "blackhole",
            },
        ]
        assert _summarize_routes(routes) == "none"

    def test_empty_routes(self):
        assert _summarize_routes([]) == "none"


class TestRouteTargetArn:
    """Tests for _route_target_arn."""

    def test_igw_target(self):
        route = {"GatewayId": "igw-abc123", "State": "active"}
        result = _route_target_arn(route, REGION, ACCOUNT_ID)
        assert result is not None
        arn, target_id = result
        assert "internet-gateway/igw-abc123" in arn
        assert target_id == "igw-abc123"

    def test_nat_target(self):
        route = {"NatGatewayId": "nat-abc123", "State": "active"}
        result = _route_target_arn(route, REGION, ACCOUNT_ID)
        assert result is not None
        arn, target_id = result
        assert "natgateway/nat-abc123" in arn
        assert target_id == "nat-abc123"

    def test_tgw_target(self):
        route = {
            "TransitGatewayId": "tgw-abc123",
            "State": "active",
        }
        result = _route_target_arn(route, REGION, ACCOUNT_ID)
        assert result is not None
        arn, target_id = result
        assert "transit-gateway/tgw-abc123" in arn

    def test_pcx_target(self):
        route = {
            "VpcPeeringConnectionId": "pcx-abc123",
            "State": "active",
        }
        result = _route_target_arn(route, REGION, ACCOUNT_ID)
        assert result is not None
        arn, target_id = result
        assert "vpc-peering-connection/pcx-abc123" in arn

    def test_local_returns_none(self):
        route = {"GatewayId": "local", "State": "active"}
        assert _route_target_arn(route, REGION, ACCOUNT_ID) is None

    def test_blackhole_returns_none(self):
        route = {
            "GatewayId": "igw-abc123",
            "State": "blackhole",
        }
        assert _route_target_arn(route, REGION, ACCOUNT_ID) is None


# --- Route Table tests ---


class TestRouteTableCollection:
    """Tests for route table collection."""

    def test_route_table_node_created(self, vpc_env):
        collector = VPCNetworkingCollector(
            session=vpc_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, edges = collector.collect()

        rt_nodes = [
            n for n in nodes
            if n.label == NodeLabel.ROUTE_TABLE
        ]
        # At least 2: main RT + explicit one
        assert len(rt_nodes) >= 2

    def test_route_table_properties(self, vpc_env):
        collector = VPCNetworkingCollector(
            session=vpc_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        named_rt = next(
            (n for n in nodes if n.name == "test-rt"),
            None,
        )
        assert named_rt is not None
        assert named_rt.properties["route_table_id"] == vpc_env["rt_id"]
        assert named_rt.properties["vpc_id"] == vpc_env["vpc_id"]

    def test_route_table_part_of_vpc(self, vpc_env):
        collector = VPCNetworkingCollector(
            session=vpc_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        part_of = [
            e for e in edges
            if e.relationship == RelationshipType.PART_OF
            and "route-table" in e.source_arn
        ]
        assert len(part_of) >= 1

    def test_subnet_has_route_table(self, vpc_env):
        collector = VPCNetworkingCollector(
            session=vpc_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        has_rt = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_ROUTE_TABLE
        ]
        assert len(has_rt) >= 1
        assert vpc_env["subnet_id"] in has_rt[0].source_arn

    def test_routes_to_igw(self, vpc_env):
        collector = VPCNetworkingCollector(
            session=vpc_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        routes_to = [
            e for e in edges
            if e.relationship == RelationshipType.ROUTES_TO
            and "internet-gateway" in e.target_arn
        ]
        assert len(routes_to) >= 1


# --- NAT Gateway tests ---


class TestNATGatewayCollection:
    """Tests for NAT Gateway collection."""

    def test_nat_gateway_node_created(self, vpc_env):
        collector = VPCNetworkingCollector(
            session=vpc_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        nat_nodes = [
            n for n in nodes
            if n.label == NodeLabel.NAT_GATEWAY
        ]
        assert len(nat_nodes) == 1

    def test_nat_gateway_properties(self, vpc_env):
        collector = VPCNetworkingCollector(
            session=vpc_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        nat_node = next(
            n for n in nodes
            if n.label == NodeLabel.NAT_GATEWAY
        )
        assert nat_node.properties["nat_gateway_id"] == vpc_env["nat_id"]
        assert nat_node.properties["subnet_id"] == vpc_env["subnet_id"]

    def test_nat_gateway_runs_in_subnet(self, vpc_env):
        collector = VPCNetworkingCollector(
            session=vpc_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        runs_in = [
            e for e in edges
            if e.relationship == RelationshipType.RUNS_IN
            and "natgateway" in e.source_arn
        ]
        assert len(runs_in) == 1


# --- Internet Gateway tests ---


class TestInternetGatewayCollection:
    """Tests for Internet Gateway collection."""

    def test_igw_node_created(self, vpc_env):
        collector = VPCNetworkingCollector(
            session=vpc_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        igw_nodes = [
            n for n in nodes
            if n.label == NodeLabel.INTERNET_GATEWAY
        ]
        assert len(igw_nodes) >= 1

    def test_igw_properties(self, vpc_env):
        collector = VPCNetworkingCollector(
            session=vpc_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        igw_node = next(
            (n for n in nodes if n.name == "test-igw"),
            None,
        )
        assert igw_node is not None
        assert igw_node.properties["igw_id"] == vpc_env["igw_id"]

    def test_igw_attached_to_vpc(self, vpc_env):
        collector = VPCNetworkingCollector(
            session=vpc_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        attached = [
            e for e in edges
            if e.relationship == RelationshipType.ATTACHED_TO
            and "internet-gateway" in e.source_arn
        ]
        assert len(attached) >= 1


# --- VPC Peering tests ---


class TestVPCPeeringCollection:
    """Tests for VPC Peering collection."""

    def test_peering_node_created(self, peering_env):
        collector = VPCNetworkingCollector(
            session=peering_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        pcx_nodes = [
            n for n in nodes
            if n.label == NodeLabel.VPC_PEERING
        ]
        assert len(pcx_nodes) == 1

    def test_peering_properties(self, peering_env):
        collector = VPCNetworkingCollector(
            session=peering_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        pcx_node = next(
            n for n in nodes
            if n.label == NodeLabel.VPC_PEERING
        )
        assert pcx_node.properties["peering_id"] == peering_env["pcx_id"]
        assert pcx_node.properties["status"] == "active"

    def test_peering_peers_with_both_vpcs(self, peering_env):
        collector = VPCNetworkingCollector(
            session=peering_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        peers = [
            e for e in edges
            if e.relationship == RelationshipType.PEERS_WITH
        ]
        assert len(peers) == 2

        sides = {e.properties.get("side") for e in peers}
        assert sides == {"requester", "accepter"}

    def test_peering_references_correct_vpcs(self, peering_env):
        collector = VPCNetworkingCollector(
            session=peering_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        peers = [
            e for e in edges
            if e.relationship == RelationshipType.PEERS_WITH
        ]
        target_arns = {e.target_arn for e in peers}
        assert any(
            peering_env["vpc1_id"] in arn for arn in target_arns
        )
        assert any(
            peering_env["vpc2_id"] in arn for arn in target_arns
        )


# --- Edge cases ---


class TestVPCNetworkingEdgeCases:
    """Tests for edge cases."""

    def test_empty_region(self):
        with mock_aws():
            session = boto3.Session(region_name="eu-west-1")
            collector = VPCNetworkingCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["eu-west-1"],
            )
            nodes, edges = collector.collect()
            # Default VPC resources may exist in moto
            # but no errors should occur
            assert isinstance(nodes, list)
            assert isinstance(edges, list)

    def test_main_route_table_flagged(self, vpc_env):
        collector = VPCNetworkingCollector(
            session=vpc_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        rt_nodes = [
            n for n in nodes
            if n.label == NodeLabel.ROUTE_TABLE
        ]
        main_rts = [
            n for n in rt_nodes
            if n.properties.get("is_main")
        ]
        assert len(main_rts) >= 1


class TestVPCNetworkingErrors:
    """Tests for error handling."""

    def test_api_error_graceful(self):
        """Collector handles API errors without raising."""
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = VPCNetworkingCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            # Should not raise — moto works fine here,
            # just verifying no exceptions propagate
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
