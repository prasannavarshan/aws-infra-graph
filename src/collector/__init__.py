"""AWS resource collectors."""

from src.collector.apigateway import APIGatewayCollector
from src.collector.cloudformation import CloudFormationCollector
from src.collector.cloudfront import CloudFrontCollector
from src.collector.cloudwan import CloudWANCollector
from src.collector.codebuild import CodeBuildCollector
from src.collector.codecommit import CodeCommitCollector
from src.collector.codepipeline import CodePipelineCollector
from src.collector.dynamodb import DynamoDBCollector
from src.collector.ec2 import EC2Collector
from src.collector.ecs import ECSCollector
from src.collector.eks import EKSCollector
from src.collector.elasticache import ElastiCacheCollector
from src.collector.elb import ELBCollector
from src.collector.iam import IAMCollector
from src.collector.k8s import K8sCollector
from src.collector.lambda_fn import LambdaCollector
from src.collector.opensearch import OpenSearchCollector
from src.collector.organizations import OrganizationsCollector
from src.collector.rds import RDSCollector
from src.collector.route53 import Route53Collector
from src.collector.route53_resolver import Route53ResolverCollector
from src.collector.s3 import S3Collector
from src.collector.sns import SNSCollector
from src.collector.sqs import SQSCollector
from src.collector.transit_gateway import TransitGatewayCollector
from src.collector.vpc_endpoints import VPCEndpointsCollector
from src.collector.vpc_networking import VPCNetworkingCollector
from src.collector.waf import WAFCollector

__all__ = [
    "APIGatewayCollector",
    "CodeBuildCollector",
    "CodeCommitCollector",
    "CodePipelineCollector",
    "K8sCollector",
    "CloudFormationCollector",
    "CloudFrontCollector",
    "CloudWANCollector",
    "DynamoDBCollector",
    "EC2Collector",
    "ECSCollector",
    "ElastiCacheCollector",
    "EKSCollector",
    "ELBCollector",
    "IAMCollector",
    "LambdaCollector",
    "OpenSearchCollector",
    "OrganizationsCollector",
    "RDSCollector",
    "Route53Collector",
    "Route53ResolverCollector",
    "S3Collector",
    "SNSCollector",
    "SQSCollector",
    "TransitGatewayCollector",
    "VPCEndpointsCollector",
    "VPCNetworkingCollector",
    "WAFCollector",
]
