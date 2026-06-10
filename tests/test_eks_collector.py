"""Tests for the EKS collector."""

import json

import boto3
import pytest
from moto import mock_aws

from src.collector.eks import EKSCollector
from src.graph.model import NodeLabel, RelationshipType

ACCOUNT_ID = "123456789012"
REGION = "us-east-1"

TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "eks.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})


@pytest.fixture()
def eks_env():
    """Set up moto-mocked EKS with cluster and node group."""
    with mock_aws():
        session = boto3.Session(region_name=REGION)
        iam = session.client("iam", region_name=REGION)
        eks = session.client("eks", region_name=REGION)

        # Create IAM roles
        cluster_role_arn = iam.create_role(
            RoleName="eks-cluster-role",
            AssumeRolePolicyDocument=TRUST_POLICY,
        )["Role"]["Arn"]

        node_role_arn = iam.create_role(
            RoleName="eks-node-role",
            AssumeRolePolicyDocument=TRUST_POLICY,
        )["Role"]["Arn"]

        # Create cluster
        cluster = eks.create_cluster(
            name="test-cluster",
            roleArn=cluster_role_arn,
            resourcesVpcConfig={
                "subnetIds": ["subnet-aaa", "subnet-bbb"],
                "securityGroupIds": ["sg-cluster01"],
            },
        )["cluster"]

        # Create node group
        eks.create_nodegroup(
            clusterName="test-cluster",
            nodegroupName="test-nodegroup",
            nodeRole=node_role_arn,
            subnets=["subnet-aaa", "subnet-bbb"],
            instanceTypes=["m5.large"],
            scalingConfig={
                "minSize": 1,
                "maxSize": 3,
                "desiredSize": 2,
            },
        )

        yield {
            "session": session,
            "cluster_arn": cluster["arn"],
            "cluster_role_arn": cluster_role_arn,
            "node_role_arn": node_role_arn,
        }


class TestEKSCollectorHappyPath:
    """Happy path tests for EKS collector."""

    def test_collects_cluster(self, eks_env):
        collector = EKSCollector(
            session=eks_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        clusters = [
            n for n in nodes
            if n.label == NodeLabel.EKS_CLUSTER
        ]
        assert len(clusters) == 1
        assert clusters[0].name == "test-cluster"

    def test_cluster_properties(self, eks_env):
        collector = EKSCollector(
            session=eks_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        cluster = [
            n for n in nodes
            if n.label == NodeLabel.EKS_CLUSTER
        ][0]
        assert cluster.properties["status"] in (
            "CREATING", "ACTIVE",
        )
        assert "version" in cluster.properties
        assert "service_cidr" in cluster.properties

    def test_collects_nodegroup(self, eks_env):
        collector = EKSCollector(
            session=eks_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        nodegroups = [
            n for n in nodes
            if n.label == NodeLabel.EKS_NODEGROUP
        ]
        assert len(nodegroups) == 1
        assert nodegroups[0].name == "test-nodegroup"

    def test_nodegroup_properties(self, eks_env):
        collector = EKSCollector(
            session=eks_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        nodes, _ = collector.collect()

        ng = [
            n for n in nodes
            if n.label == NodeLabel.EKS_NODEGROUP
        ][0]
        assert ng.properties["desired_size"] == 2
        assert ng.properties["max_size"] == 3
        assert ng.properties["min_size"] == 1

    def test_cluster_belongs_to_account(self, eks_env):
        collector = EKSCollector(
            session=eks_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        belongs = [
            e for e in edges
            if e.relationship == RelationshipType.BELONGS_TO
        ]
        assert len(belongs) >= 1

    def test_cluster_has_role(self, eks_env):
        collector = EKSCollector(
            session=eks_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        has_role = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_ROLE
            and e.target_arn == eks_env["cluster_role_arn"]
        ]
        assert len(has_role) == 1

    def test_cluster_runs_in_subnets(self, eks_env):
        collector = EKSCollector(
            session=eks_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        cluster_arn = eks_env["cluster_arn"]
        runs_in = [
            e for e in edges
            if e.relationship == RelationshipType.RUNS_IN
            and e.source_arn == cluster_arn
        ]
        assert len(runs_in) == 2

    def test_cluster_has_sg(self, eks_env):
        collector = EKSCollector(
            session=eks_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        has_sg = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_SG
        ]
        # At least the user-specified SG
        assert len(has_sg) >= 1

    def test_nodegroup_part_of_cluster(self, eks_env):
        collector = EKSCollector(
            session=eks_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        part_of = [
            e for e in edges
            if e.relationship == RelationshipType.PART_OF
        ]
        assert len(part_of) == 1
        assert part_of[0].target_arn == eks_env["cluster_arn"]

    def test_nodegroup_has_role(self, eks_env):
        collector = EKSCollector(
            session=eks_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        ng_role = [
            e for e in edges
            if e.relationship == RelationshipType.HAS_ROLE
            and e.target_arn == eks_env["node_role_arn"]
        ]
        assert len(ng_role) == 1

    def test_nodegroup_runs_in_subnets(self, eks_env):
        collector = EKSCollector(
            session=eks_env["session"],
            account_id=ACCOUNT_ID,
            regions=[REGION],
        )
        _, edges = collector.collect()

        cluster_arn = eks_env["cluster_arn"]
        ng_runs_in = [
            e for e in edges
            if e.relationship == RelationshipType.RUNS_IN
            and e.source_arn != cluster_arn
        ]
        assert len(ng_runs_in) == 2


class TestEKSCollectorEdgeCases:
    """Edge case tests."""

    def test_empty_region(self):
        with mock_aws():
            session = boto3.Session(region_name="eu-west-1")
            collector = EKSCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["eu-west-1"],
            )
            nodes, edges = collector.collect()
            assert len(nodes) == 0
            assert len(edges) == 0

    def test_cluster_with_no_nodegroups(self):
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            iam = session.client("iam", region_name=REGION)
            eks = session.client("eks", region_name=REGION)

            role_arn = iam.create_role(
                RoleName="eks-role",
                AssumeRolePolicyDocument=TRUST_POLICY,
            )["Role"]["Arn"]

            eks.create_cluster(
                name="lonely-cluster",
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": ["subnet-aaa"],
                    "securityGroupIds": ["sg-aaa"],
                },
            )

            collector = EKSCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()

            clusters = [
                n for n in nodes
                if n.label == NodeLabel.EKS_CLUSTER
            ]
            nodegroups = [
                n for n in nodes
                if n.label == NodeLabel.EKS_NODEGROUP
            ]
            assert len(clusters) == 1
            assert len(nodegroups) == 0


class TestEKSCollectorErrors:
    """Error handling tests."""

    def test_handles_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = EKSCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=[REGION],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
            assert isinstance(edges, list)

    def test_invalid_region_handled_gracefully(self):
        with mock_aws():
            session = boto3.Session(region_name=REGION)
            collector = EKSCollector(
                session=session,
                account_id=ACCOUNT_ID,
                regions=["invalid-region-99"],
            )
            nodes, edges = collector.collect()
            assert isinstance(nodes, list)
