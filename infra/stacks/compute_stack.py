"""ECS cluster, task definition, ALB, and auto-scaling for aws-infra-graph."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import (
    aws_ec2 as ec2,
)
from aws_cdk import (
    aws_ecr_assets as ecr_assets,
)
from aws_cdk import (
    aws_ecs as ecs,
)
from aws_cdk import (
    aws_elasticloadbalancingv2 as elbv2,
)
from aws_cdk import (
    aws_iam as iam,
)
from aws_cdk import (
    aws_logs as logs,
)
from aws_cdk import (
    aws_secretsmanager as secretsmanager,
)
from constructs import Construct


class ComputeStack(cdk.Stack):
    """ECS Fargate — MCP server only. Neo4j runs on a separate EC2 instance."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        vpc_id: str,
        private_subnet_ids: list[str],
        allowed_cidrs: list[str],
        certificate_arn: str | None,
        cross_account_role_name: str,
        neo4j_host: str,
        org_account_id: str = "",
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- Lookup existing VPC ---
        vpc = ec2.Vpc.from_lookup(self, "Vpc", vpc_id=vpc_id)

        # Explicit subnet selection to avoid multiple-subnets-per-AZ error
        private_subnets = ec2.SubnetSelection(
            subnets=[
                ec2.Subnet.from_subnet_id(self, f"Subnet{i}", sid)
                for i, sid in enumerate(private_subnet_ids)
            ],
        )

        # --- Secrets ---
        mcp_token_secret = secretsmanager.Secret(
            self, "McpAuthToken",
            secret_name="aws-infra-graph/mcp-auth-token",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_punctuation=True,
                password_length=48,
            ),
        )
        gchat_webhook_secret = secretsmanager.Secret.from_secret_name_v2(
            self, "GChatWebhook",
            secret_name="aws-infra-graph/gchat-webhook",
        )

        # --- Security Groups ---
        self.alb_sg = ec2.SecurityGroup(
            self, "AlbSg",
            vpc=vpc,
            description="ALB for MCP server",
            allow_all_outbound=False,
        )
        self.ecs_sg = ec2.SecurityGroup(
            self, "EcsSg",
            vpc=vpc,
            description="ECS tasks (MCP server)",
        )

        # ALB ingress from allowed CIDRs (private ALB — corporate network/VPN only)
        for cidr in allowed_cidrs:
            self.alb_sg.add_ingress_rule(
                ec2.Peer.ipv4(cidr),
                ec2.Port.tcp(443 if certificate_arn else 80),
                "MCP clients",
            )
            if certificate_arn:
                self.alb_sg.add_ingress_rule(
                    ec2.Peer.ipv4(cidr),
                    ec2.Port.tcp(80),
                    "HTTP redirect to HTTPS",
                )

        # ALB → ECS on port 8050
        self.alb_sg.add_egress_rule(
            self.ecs_sg, ec2.Port.tcp(8050), "To MCP server",
        )
        self.ecs_sg.add_ingress_rule(
            self.alb_sg, ec2.Port.tcp(8050), "From ALB",
        )

        # --- ECS Cluster (Fargate) ---
        self.cluster = ecs.Cluster(
            self, "Cluster",
            vpc=vpc,
            cluster_name="infra-graph",
        )

        # --- Task Definition (Fargate) ---
        task_role = iam.Role(
            self, "TaskRole",
            role_name="InfraGraphTaskRole",
            assumed_by=iam.ServicePrincipal("ecs-tasks.amazonaws.com"),
        )
        self.task_definition = ecs.FargateTaskDefinition(
            self, "TaskDef",
            task_role=task_role,
            cpu=1024,
            memory_limit_mib=4096,
        )

        # Task role — replaces AWS_PROFILE for cross-account access
        self.task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["sts:AssumeRole"],
                resources=[f"arn:aws:iam::*:role/{cross_account_role_name}"],
            ),
        )
        self.task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "organizations:List*",
                    "organizations:Describe*",
                    "networkmanager:*",
                ],
                resources=["*"],
            ),
        )

        log_group = logs.LogGroup(
            self, "Logs",
            log_group_name="/ecs/infra-graph",
            retention=logs.RetentionDays.TWO_WEEKS,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )

        # --- MCP server container ---
        mcp_image = ecr_assets.DockerImageAsset(
            self, "McpImage",
            directory="..",  # project root (Dockerfile location)
        )
        mcp_container = self.task_definition.add_container(
            "mcp-server",
            image=ecs.ContainerImage.from_docker_image_asset(mcp_image),
            memory_reservation_mib=3072,
            cpu=1024,
            essential=True,
            environment={
                "TRANSPORT": "http",
                "NEO4J_URI": f"bolt://{neo4j_host}:7687",
                "NEO4J_USER": "neo4j",
                "NEO4J_PASSWORD": "changeme",
                "DEPLOY_ENV": "aws",
                "AWS_DEFAULT_REGION": "us-east-1",
                "AWS_CROSS_ACCOUNT_ROLE_NAME": cross_account_role_name,
                "AWS_MGMT_ACCOUNT_ID": "123456789012",
                "AWS_SSL_VERIFY": "true",
                "AWS_REGIONS": '["us-east-1","us-west-2"]',
                **({"AWS_ORG_ACCOUNT_ID": org_account_id} if org_account_id else {}),
            },
            secrets={
                "MCP_AUTH_TOKEN": ecs.Secret.from_secrets_manager(mcp_token_secret),
                "MCP_GCHAT_WEBHOOK_URL": ecs.Secret.from_secrets_manager(gchat_webhook_secret),
            },
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="mcp", log_group=log_group,
            ),
        )
        mcp_container.add_port_mappings(
            ecs.PortMapping(container_port=8050),
        )

        # --- ECS Service (Fargate) ---
        service = ecs.FargateService(
            self, "Service",
            cluster=self.cluster,
            task_definition=self.task_definition,
            desired_count=1,
            min_healthy_percent=100,
            max_healthy_percent=200,
            security_groups=[self.ecs_sg],
            vpc_subnets=private_subnets,
        )

        # --- ALB ---
        alb = elbv2.ApplicationLoadBalancer(
            self, "Alb",
            vpc=vpc,
            internet_facing=False,
            security_group=self.alb_sg,
            vpc_subnets=private_subnets,
        )

        if certificate_arn:
            listener = alb.add_listener(
                "Https",
                port=443,
                open=False,
                certificates=[
                    elbv2.ListenerCertificate.from_arn(certificate_arn),
                ],
                ssl_policy=elbv2.SslPolicy.TLS13_13,
            )
            # HTTP → HTTPS redirect (reuse "Http" logical ID to replace the old listener)
            alb.add_listener(
                "Http",
                port=80,
                open=False,
                default_action=elbv2.ListenerAction.redirect(
                    protocol="HTTPS", port="443", permanent=True,
                ),
            )
        else:
            listener = alb.add_listener("Http", port=80, open=False)

        listener.add_targets(
            "McpTarget",
            port=8050,
            protocol=elbv2.ApplicationProtocol.HTTP,
            targets=[
                service.load_balancer_target(
                    container_name="mcp-server",
                    container_port=8050,
                ),
            ],
            health_check=elbv2.HealthCheck(
                path="/health",
                port="8050",
                interval=cdk.Duration.seconds(30),
                healthy_threshold_count=2,
                unhealthy_threshold_count=5,
            ),
        )

        # Expose for schedule stack
        self.private_subnets = private_subnets
        self.vpc = vpc
        self.alb_dns_name = alb.load_balancer_dns_name
        self.mcp_token_secret_arn = mcp_token_secret.secret_arn
        self.certificate_arn = certificate_arn  # used by ScheduleStack to pick http/https

        # --- Outputs ---
        cdk.CfnOutput(self, "AlbUrl", value=alb.load_balancer_dns_name)
        cdk.CfnOutput(
            self, "McpEndpoint",
            value=f"{'https' if certificate_arn else 'http'}://"
                  f"{alb.load_balancer_dns_name}/mcp",
        )
        cdk.CfnOutput(
            self, "McpTokenSecretArn", value=mcp_token_secret.secret_arn,
        )
