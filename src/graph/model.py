"""Pydantic models for knowledge graph nodes and edges."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class NodeLabel(StrEnum):
    """Node labels matching AWS resource types."""

    ACCOUNT = "Account"
    VPC = "VPC"
    SUBNET = "Subnet"
    SECURITY_GROUP = "SecurityGroup"
    EC2_INSTANCE = "EC2Instance"
    NETWORK_INTERFACE = "NetworkInterface"
    IAM_ROLE = "IAMRole"
    IAM_POLICY = "IAMPolicy"
    IAM_USER = "IAMUser"
    S3_BUCKET = "S3Bucket"
    RDS_INSTANCE = "RDSInstance"
    LAMBDA_FUNCTION = "LambdaFunction"
    ECS_CLUSTER = "ECSCluster"
    ECS_SERVICE = "ECSService"
    EKS_CLUSTER = "EKSCluster"
    EKS_NODEGROUP = "EKSNodegroup"
    NETWORK_ACL = "NetworkACL"
    LOAD_BALANCER = "LoadBalancer"
    TARGET_GROUP = "TargetGroup"
    ROUTE53_ZONE = "Route53Zone"
    ROUTE53_RECORD = "Route53Record"
    DYNAMODB_TABLE = "DynamoDBTable"
    SQS_QUEUE = "SQSQueue"
    SNS_TOPIC = "SNSTopic"
    CLOUDFRONT_DISTRIBUTION = "CloudFrontDistribution"
    API_GATEWAY = "APIGateway"
    VPC_ENDPOINT = "VPCEndpoint"
    TRANSIT_GATEWAY = "TransitGateway"
    TGW_ATTACHMENT = "TGWAttachment"
    TGW_ROUTE_TABLE = "TGWRouteTable"
    CLOUDWAN_CORE_NETWORK = "CloudWANCoreNetwork"
    CLOUDWAN_SEGMENT = "CloudWANSegment"
    CLOUDWAN_ATTACHMENT = "CloudWANAttachment"
    ROUTE_TABLE = "RouteTable"
    NAT_GATEWAY = "NATGateway"
    INTERNET_GATEWAY = "InternetGateway"
    VPC_PEERING = "VPCPeering"
    ELASTICACHE_CLUSTER = "ElastiCacheCluster"
    ELASTICACHE_REPLICATION_GROUP = "ElastiCacheReplicationGroup"
    ELASTICACHE_SERVERLESS_CACHE = "ElastiCacheServerlessCache"
    CLOUDFORMATION_STACK = "CloudFormationStack"
    ORGANIZATIONAL_UNIT = "OrganizationalUnit"
    SERVICE_CONTROL_POLICY = "ServiceControlPolicy"
    OPENSEARCH_DOMAIN = "OpenSearchDomain"
    WAF_WEB_ACL = "WAFWebACL"
    RESOLVER_ENDPOINT = "ResolverEndpoint"
    RESOLVER_RULE = "ResolverRule"
    CODECOMMIT_REPO = "CodeCommitRepo"
    CODEPIPELINE = "CodePipeline"
    CODEBUILD_PROJECT = "CodeBuildProject"
    K8S_NAMESPACE = "K8sNamespace"
    K8S_DEPLOYMENT = "K8sDeployment"
    K8S_SERVICE = "K8sService"
    K8S_SERVICE_ACCOUNT = "K8sServiceAccount"
    K8S_NODE = "K8sNode"
    K8S_INGRESS = "K8sIngress"


class RelationshipType(StrEnum):
    """Edge types describing relationships between resources."""

    RUNS_IN = "RUNS_IN"
    PART_OF = "PART_OF"
    HAS_SG = "HAS_SG"
    HAS_ENI = "HAS_ENI"
    HAS_ROLE = "HAS_ROLE"
    HAS_NACL = "HAS_NACL"
    HAS_POLICY = "HAS_POLICY"
    TARGETS = "TARGETS"
    ROUTES_TO = "ROUTES_TO"
    TRIGGERS_FROM = "TRIGGERS_FROM"
    RESOLVES_TO = "RESOLVES_TO"
    PEERS_WITH = "PEERS_WITH"
    ALLOWS_INGRESS = "ALLOWS_INGRESS"
    BELONGS_TO = "BELONGS_TO"
    MEMBER_OF = "MEMBER_OF"
    PUBLISHES_TO = "PUBLISHES_TO"
    SUBSCRIBES_TO = "SUBSCRIBES_TO"
    DISTRIBUTES = "DISTRIBUTES"
    INVOKES = "INVOKES"
    LAUNCHES = "LAUNCHES"
    CONNECTS_TO = "CONNECTS_TO"
    ATTACHED_TO = "ATTACHED_TO"
    HAS_SEGMENT = "HAS_SEGMENT"
    SHARED_WITH = "SHARED_WITH"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    HAS_ROUTE_TABLE = "HAS_ROUTE_TABLE"
    DENIES = "DENIES"
    MANAGES = "MANAGES"
    GOVERNED_BY = "GOVERNED_BY"
    PROTECTS = "PROTECTS"
    RUNS_IN_NAMESPACE = "RUNS_IN_NAMESPACE"
    HOSTS_ON = "HOSTS_ON"
    ASSUMES_IRSA = "ASSUMES_IRSA"
    SELECTS = "SELECTS"
    EXPOSES_VIA = "EXPOSES_VIA"
    SOURCE_FROM = "SOURCE_FROM"
    BUILDS_WITH = "BUILDS_WITH"
    DEPLOYS_TO = "DEPLOYS_TO"


# Relationship types where the collector produces the COMPLETE set of
# edges per source node each crawl. Old edges not in the new set must
# be deleted to avoid stale data (e.g. removed security groups, subnet
# changes, CloudWAN segment reassignments).
EXCLUSIVE_EDGE_TYPES: frozenset[RelationshipType] = frozenset({
    RelationshipType.HAS_SG,
    RelationshipType.RUNS_IN,
    RelationshipType.HAS_NACL,
    RelationshipType.PART_OF,
    RelationshipType.HOSTS_ON,
})


class ResourceNode(BaseModel):
    """A node in the infrastructure knowledge graph.

    Represents a single AWS resource with its metadata.
    """

    arn: str = Field(description="AWS ARN uniquely identifying this resource")
    name: str = Field(description="Human-readable name or identifier")
    label: NodeLabel = Field(description="Graph node label (resource type)")
    account_id: str = Field(description="AWS account ID that owns this resource")
    region: str = Field(description="AWS region where this resource exists")
    tags: dict[str, str] = Field(default_factory=dict, description="AWS resource tags")
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Service-specific properties (instance_type, cidr_block, etc.)",
    )
    last_crawled: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ResourceEdge(BaseModel):
    """An edge in the infrastructure knowledge graph.

    Represents a relationship between two AWS resources.
    """

    source_arn: str = Field(description="ARN of the source resource")
    target_arn: str = Field(description="ARN of the target resource")
    relationship: RelationshipType = Field(description="Type of relationship")
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Relationship-specific properties (port, protocol, etc.)",
    )
