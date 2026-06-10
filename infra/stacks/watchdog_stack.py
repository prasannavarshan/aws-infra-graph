"""Watchdog stack: detects Neo4j DatabaseUnavailable and notifies GChat."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import (
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_lambda as lambda_,
    aws_logs as logs,
    aws_secretsmanager as secretsmanager,
    aws_sns as sns,
    aws_sns_subscriptions as subs,
)
from constructs import Construct

# Number of log matches in a 5-minute window that triggers the alarm.
_ALARM_THRESHOLD = 1


class WatchdogStack(cdk.Stack):
    """Monitors Neo4j health via log metric filter and notifies GChat.

    Flow:
      mcp-server log → metric filter ("DatabaseUnavailable")
        → CloudWatch Alarm
          → SNS → Lambda
            → GChat webhook  (notify with context)

    ECS restart was removed: Neo4j now runs on a separate EC2 instance, so
    restarting ECS has no effect on Neo4j availability. The right remediation
    is to SSH into the Neo4j EC2 via SSM and run `systemctl restart neo4j`.

    The Lambda runs inside the VPC (private subnets have NAT → internet via
    central network account), so it can reach the public GChat webhook URL.
    The GChat webhook URL is read at runtime from Secrets Manager.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        log_group_name: str,
        vpc: ec2.IVpc,
        private_subnet_ids: list[str],
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # GChat webhook secret — must be pre-created before deploying this stack:
        #   aws secretsmanager create-secret \
        #     --name aws-infra-graph/gchat-webhook \
        #     --secret-string "https://chat.googleapis.com/v1/spaces/..." \
        #     --profile your-aws-profile --region us-east-1
        gchat_secret = secretsmanager.Secret.from_secret_name_v2(
            self, "GChatWebhook",
            secret_name="aws-infra-graph/gchat-webhook",
        )

        # --- Log metric filter on the mcp-server log stream ---
        log_group = logs.LogGroup.from_log_group_name(
            self, "InfraGraphLogs", log_group_name,
        )
        metric = cloudwatch.Metric(
            namespace="InfraGraph",
            metric_name="Neo4jDatabaseUnavailable",
            statistic="Sum",
            period=cdk.Duration.minutes(5),
        )
        logs.MetricFilter(
            self, "DbUnavailableFilter",
            log_group=log_group,
            metric_namespace=metric.namespace,
            metric_name=metric.metric_name,
            filter_pattern=logs.FilterPattern.literal('"DatabaseUnavailable"'),
            metric_value="1",
            default_value=0,
        )

        alarm = cloudwatch.Alarm(
            self, "DbUnavailableAlarm",
            alarm_name="infra-graph-neo4j-unavailable",
            alarm_description="Neo4j DatabaseUnavailable error detected in mcp-server logs",
            metric=metric,
            threshold=_ALARM_THRESHOLD,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        # --- SNS topic ---
        topic = sns.Topic(self, "WatchdogTopic", display_name="infra-graph-watchdog")
        alarm.add_alarm_action(cw_actions.SnsAction(topic))

        # Lambda SG: allow HTTPS out via NAT (GChat + Secrets Manager)
        lambda_sg = ec2.SecurityGroup(
            self, "WatchdogLambdaSg",
            vpc=vpc,
            description="Watchdog Lambda HTTPS egress via NAT",
            allow_all_outbound=False,
        )
        lambda_sg.add_egress_rule(
            ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "HTTPS out",
        )

        subnets = ec2.SubnetSelection(
            subnets=[
                ec2.Subnet.from_subnet_id(self, f"WatchdogSubnet{i}", sid)
                for i, sid in enumerate(private_subnet_ids)
            ],
        )

        watchdog_fn = lambda_.Function(
            self, "WatchdogFn",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.handler",
            timeout=cdk.Duration.seconds(30),
            vpc=vpc,
            vpc_subnets=subnets,
            security_groups=[lambda_sg],
            environment={
                "GCHAT_SECRET_NAME": "aws-infra-graph/gchat-webhook",
            },
            code=lambda_.Code.from_inline(_LAMBDA_CODE),
        )

        watchdog_fn.add_to_role_policy(
            iam.PolicyStatement(
                actions=["secretsmanager:GetSecretValue"],
                resources=[gchat_secret.secret_arn],
            ),
        )

        topic.add_subscription(subs.LambdaSubscription(watchdog_fn))


# Inline Lambda — reads GChat URL from Secrets Manager, posts alert.
# No ECS restart: Neo4j is on EC2, restarting ECS does not fix it.
# Manual remediation: SSM into Neo4j EC2, run `systemctl restart neo4j`.
_LAMBDA_CODE = """
import boto3
import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone

def handler(event, context):
    secret   = os.environ["GCHAT_SECRET_NAME"]
    region   = os.environ.get("AWS_REGION", "us-east-1")
    now_utc  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sm  = boto3.client("secretsmanager", region_name=region)
    url = sm.get_secret_value(SecretId=secret)["SecretString"]

    msg = {
        "text": (
            f"*[infra-graph] Neo4j DatabaseUnavailable* \\U0001f6a8\\n"
            f"Detected at {now_utc}.\\n"
            f"*Action required:* SSM into the Neo4j EC2 instance and run "
            f"`systemctl restart neo4j`.\\n"
            f"Check CloudWatch `/ecs/infra-graph` (mcp-server stream) for context."
        )
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(msg).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        print(f"watchdog: gchat notified at {now_utc}")
    except urllib.error.URLError as e:
        print(f"gchat notify failed: {e}")
"""
