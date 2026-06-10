"""Maps CloudFormation PhysicalResourceId to ARN.

CloudFormation's `list_stack_resources` returns PhysicalResourceId which
may be an ARN, a name, an ID, or a URL depending on the resource type.
This module converts those to ARNs so we can create MANAGES edges to
existing graph nodes.
"""

from __future__ import annotations

from collections.abc import Callable
from urllib.parse import urlparse

# Type alias for ARN builder functions.
# Each takes (physical_id, region, account_id) and returns an ARN string.
ArnBuilder = Callable[[str, str, str], str]


def _ec2_arn(resource: str) -> ArnBuilder:
    """Build an EC2 ARN builder for a given resource type."""
    return lambda pid, r, a: f"arn:aws:ec2:{r}:{a}:{resource}/{pid}"


def _lambda_fn(pid: str, r: str, a: str) -> str:
    return f"arn:aws:lambda:{r}:{a}:function:{pid}"


def _s3_bucket(pid: str, _r: str, _a: str) -> str:
    return f"arn:aws:s3:::{pid}"


def _rds_instance(pid: str, r: str, a: str) -> str:
    return f"arn:aws:rds:{r}:{a}:db:{pid}"


def _dynamodb_table(pid: str, r: str, a: str) -> str:
    return f"arn:aws:dynamodb:{r}:{a}:table/{pid}"


def _sqs_queue(pid: str, r: str, a: str) -> str:
    """SQS PhysicalResourceId is a URL like https://sqs.region.amazonaws.com/acct/name."""
    parsed = urlparse(pid)
    parts = parsed.path.strip("/").split("/")
    if len(parts) >= 2:
        queue_name = parts[-1]
        queue_account = parts[-2]
        return f"arn:aws:sqs:{r}:{queue_account}:{queue_name}"
    return f"arn:aws:sqs:{r}:{a}:{pid}"


def _sns_topic(pid: str, r: str, a: str) -> str:
    return f"arn:aws:sns:{r}:{a}:{pid}"


def _ecs_cluster(pid: str, r: str, a: str) -> str:
    return f"arn:aws:ecs:{r}:{a}:cluster/{pid}"


def _ecs_service(pid: str, _r: str, _a: str) -> str:
    # PhysicalResourceId for ECS service is the full ARN
    return pid


def _eks_cluster(pid: str, r: str, a: str) -> str:
    return f"arn:aws:eks:{r}:{a}:cluster/{pid}"


def _elb_v2(pid: str, _r: str, _a: str) -> str:
    # ELBv2 PhysicalResourceId is the full ARN
    return pid


def _iam_role(pid: str, _r: str, a: str) -> str:
    return f"arn:aws:iam::{a}:role/{pid}"


def _iam_policy(pid: str, _r: str, _a: str) -> str:
    # IAM policy PhysicalResourceId is the full ARN
    return pid


def _iam_user(pid: str, _r: str, a: str) -> str:
    return f"arn:aws:iam::{a}:user/{pid}"


def _route53_zone(pid: str, _r: str, _a: str) -> str:
    zone_id = pid.split("/")[-1] if "/" in pid else pid
    return f"arn:aws:route53:::hostedzone/{zone_id}"


def _elasticache_cluster(pid: str, r: str, a: str) -> str:
    return (
        f"arn:aws:elasticache:{r}:{a}:"
        f"cluster:{pid}"
    )


def _elasticache_repl_group(pid: str, r: str, a: str) -> str:
    return (
        f"arn:aws:elasticache:{r}:{a}:"
        f"replicationgroup:{pid}"
    )


def _cloudfront_dist(pid: str, _r: str, a: str) -> str:
    return (
        f"arn:aws:cloudfront::{a}:"
        f"distribution/{pid}"
    )


def _apigateway_rest(pid: str, r: str, a: str) -> str:
    return (
        f"arn:aws:apigateway:{r}::"
        f"/restapis/{pid}"
    )


# Map CFN resource types to ARN builder functions.
_ARN_BUILDERS: dict[str, ArnBuilder] = {
    # EC2
    "AWS::EC2::Instance": _ec2_arn("instance"),
    "AWS::EC2::VPC": _ec2_arn("vpc"),
    "AWS::EC2::Subnet": _ec2_arn("subnet"),
    "AWS::EC2::SecurityGroup": _ec2_arn("security-group"),
    "AWS::EC2::InternetGateway": _ec2_arn("internet-gateway"),
    "AWS::EC2::NatGateway": _ec2_arn("natgateway"),
    "AWS::EC2::RouteTable": _ec2_arn("route-table"),
    "AWS::EC2::NetworkAcl": _ec2_arn("network-acl"),
    "AWS::EC2::VPCEndpoint": _ec2_arn("vpc-endpoint"),
    "AWS::EC2::NetworkInterface": _ec2_arn("network-interface"),
    # Lambda
    "AWS::Lambda::Function": _lambda_fn,
    # S3
    "AWS::S3::Bucket": _s3_bucket,
    # RDS
    "AWS::RDS::DBInstance": _rds_instance,
    # DynamoDB
    "AWS::DynamoDB::Table": _dynamodb_table,
    # SQS
    "AWS::SQS::Queue": _sqs_queue,
    # SNS
    "AWS::SNS::Topic": _sns_topic,
    # ECS
    "AWS::ECS::Cluster": _ecs_cluster,
    "AWS::ECS::Service": _ecs_service,
    # EKS
    "AWS::EKS::Cluster": _eks_cluster,
    # ELBv2
    "AWS::ElasticLoadBalancingV2::LoadBalancer": _elb_v2,
    "AWS::ElasticLoadBalancingV2::TargetGroup": _elb_v2,
    # IAM (global — no region)
    "AWS::IAM::Role": _iam_role,
    "AWS::IAM::ManagedPolicy": _iam_policy,
    "AWS::IAM::User": _iam_user,
    # Route53
    "AWS::Route53::HostedZone": _route53_zone,
    # ElastiCache
    "AWS::ElastiCache::CacheCluster": _elasticache_cluster,
    "AWS::ElastiCache::ReplicationGroup": _elasticache_repl_group,
    # CloudFront (global)
    "AWS::CloudFront::Distribution": _cloudfront_dist,
    # API Gateway
    "AWS::ApiGateway::RestApi": _apigateway_rest,
    # CloudFormation nested stack — PhysicalResourceId IS the child ARN
    "AWS::CloudFormation::Stack": lambda pid, _r, _a: pid,
}


def physical_id_to_arn(
    resource_type: str,
    physical_id: str,
    region: str,
    account_id: str,
) -> str | None:
    """Convert a CloudFormation PhysicalResourceId to an ARN.

    Args:
        resource_type: CFN resource type (e.g. "AWS::EC2::Instance").
        physical_id: The PhysicalResourceId from list_stack_resources.
        region: AWS region of the stack.
        account_id: AWS account ID of the stack.

    Returns:
        The ARN string, or None if the resource type is not mapped.
    """
    if not physical_id:
        return None

    # If the physical ID is already an ARN, return as-is.
    if physical_id.startswith("arn:"):
        return physical_id

    builder = _ARN_BUILDERS.get(resource_type)
    if builder is None:
        return None

    return builder(physical_id, region, account_id)
