"""EventBridge + Lambda for periodic graph refresh via HTTP POST to /refresh."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import (
    aws_ec2 as ec2,
    aws_events as events,
    aws_events_targets as targets,
    aws_lambda as lambda_,
    aws_secretsmanager as secretsmanager,
)
from constructs import Construct


class ScheduleStack(cdk.Stack):
    """Lambda triggered by EventBridge that POSTs to the MCP server /refresh endpoint."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        alb_dns_name: str,
        mcp_token_secret_arn: str,
        vpc: ec2.IVpc,
        private_subnet_ids: list[str],
        use_https: bool = True,
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        port = 443 if use_https else 80
        scheme = "https" if use_https else "http"

        # The Lambda reads the auth token at runtime from Secrets Manager.
        # This avoids resolving the secret at synth time (unsafe_unwrap) and
        # keeps the plaintext token out of the CloudFormation template.
        # The Lambda code calls:
        #   boto3.client("secretsmanager").get_secret_value(
        #       SecretId=os.environ["MCP_AUTH_TOKEN_SECRET_ARN"]
        #   )["SecretString"]

        # Lambda SG — egress to ALB only (private VPC, no internet/NAT needed)
        lambda_sg = ec2.SecurityGroup(
            self, "LambdaSg",
            vpc=vpc,
            description="Refresh Lambda to internal ALB",
            allow_all_outbound=False,
        )
        lambda_sg.add_egress_rule(
            ec2.Peer.ipv4("10.0.0.0/8"), ec2.Port.tcp(port), "To ALB",
        )
        # Allow egress to Secrets Manager (HTTPS/443) — needed for runtime secret fetch
        lambda_sg.add_egress_rule(
            ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.tcp(443), "To Secrets Manager",
        )

        # Pin Lambda to the same private subnets as the ALB — avoids CDK picking
        # EKS/DB subnets with non-routable CIDRs (e.g. 100.65.x.x RFC 6598 space)
        subnets = ec2.SubnetSelection(
            subnets=[
                ec2.Subnet.from_subnet_id(self, f"Subnet{i}", sid)
                for i, sid in enumerate(private_subnet_ids)
            ],
        )

        refresh_fn = lambda_.Function(
            self, "RefreshFn",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=lambda_.Code.from_inline(f"""
import urllib.request
import urllib.error
import ssl
import os
import json
import boto3

def handler(event, context):
    # Fetch token at runtime — never stored in plaintext env var or template
    secret_arn = os.environ["MCP_AUTH_TOKEN_SECRET_ARN"]
    sm = boto3.client("secretsmanager")
    token = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    alb_dns = os.environ["ALB_DNS_NAME"]

    url = f"{scheme}://{{alb_dns}}/refresh"
    ctx = ssl.create_default_context() if "{scheme}" == "https" else None
    req = urllib.request.Request(
        url,
        method="POST",
        headers={{"Authorization": f"Bearer {{token}}"}},
    )
    try:
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            print(f"refresh triggered: {{resp.status}} {{resp.read().decode()}}")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"refresh http error: {{e.code}} {{body}}")
        raise
"""),
            environment={
                "MCP_AUTH_TOKEN_SECRET_ARN": mcp_token_secret_arn,
                "ALB_DNS_NAME": alb_dns_name,
            },
            timeout=cdk.Duration.seconds(30),
            vpc=vpc,
            vpc_subnets=subnets,
            security_groups=[lambda_sg],
        )

        # Grant Lambda read access to the MCP auth token secret at runtime
        mcp_token_secret = secretsmanager.Secret.from_secret_complete_arn(
            self, "McpTokenSecret", mcp_token_secret_arn,
        )
        mcp_token_secret.grant_read(refresh_fn)

        rule = events.Rule(
            self, "RefreshSchedule",
            schedule=events.Schedule.cron(hour="13", minute="0"),
            description="Periodic graph refresh for aws-infra-graph",
        )
        rule.add_target(targets.LambdaFunction(refresh_fn))
