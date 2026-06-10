#!/usr/bin/env python3
"""CDK app entry point for aws-infra-graph deployment."""

import os
import sys

# Use podman instead of docker for container image builds
os.environ.setdefault("CDK_DOCKER", "podman")

import aws_cdk as cdk

from stacks.compute_stack import ComputeStack
from stacks.neo4j_stack import Neo4jStack
from stacks.schedule_stack import ScheduleStack
from stacks.watchdog_stack import WatchdogStack

app = cdk.App()

# --- Safety: require explicit AWS profile ---
aws_profile = app.node.try_get_context("aws_profile")
if not aws_profile:
    print(
        "ERROR: aws_profile is required. Set it in cdk.json or pass "
        "-c aws_profile=your-aws-profile",
        file=sys.stderr,
    )
    sys.exit(1)

# Enforce the profile for all AWS SDK calls (including image builds)
os.environ["AWS_PROFILE"] = aws_profile

account = app.node.try_get_context("account")
region = app.node.try_get_context("region") or "us-east-1"

if not account:
    print(
        f"ERROR: account is required. Pass -c account=<ACCOUNT_ID> "
        f"for profile '{aws_profile}'",
        file=sys.stderr,
    )
    sys.exit(1)

# Verify at synth time: if AWS_PROFILE is set to something else, warn loudly
active_profile = os.environ.get("AWS_PROFILE", "")
if active_profile and active_profile != aws_profile:
    print(
        f"WARNING: AWS_PROFILE={active_profile} overrides cdk.json "
        f"aws_profile={aws_profile}. Deployment may target wrong account!",
        file=sys.stderr,
    )

# Required context parameters — pass via cdk.json or --context
vpc_id = app.node.try_get_context("vpc_id")
if not vpc_id:
    print(
        "ERROR: vpc_id is required. Use -c vpc_id=vpc-xxx",
        file=sys.stderr,
    )
    sys.exit(1)

env = cdk.Environment(account=account, region=region)

private_subnet_ids = app.node.try_get_context("private_subnet_ids") or []
if not private_subnet_ids:
    print("ERROR: private_subnet_ids is required.", file=sys.stderr)
    sys.exit(1)

neo4j = Neo4jStack(
    app, "InfraGraphNeo4j",
    vpc_id=vpc_id,
    private_subnet_ids=private_subnet_ids,
    env=env,
)

compute = ComputeStack(
    app, "InfraGraphCompute",
    vpc_id=vpc_id,
    private_subnet_ids=private_subnet_ids,
    org_account_id=app.node.try_get_context("org_account_id") or "",
    allowed_cidrs=app.node.try_get_context("allowed_cidrs") or [],
    certificate_arn=app.node.try_get_context("certificate_arn"),
    cross_account_role_name=app.node.try_get_context("cross_account_role_name") or "",
    neo4j_host=neo4j.neo4j_host,
    env=env,
)

ScheduleStack(
    app, "InfraGraphSchedule",
    alb_dns_name=compute.alb_dns_name,
    mcp_token_secret_arn=compute.mcp_token_secret_arn,
    vpc=compute.vpc,
    private_subnet_ids=private_subnet_ids,
    use_https=bool(compute.certificate_arn),
    env=env,
)

WatchdogStack(
    app, "InfraGraphWatchdog",
    log_group_name="/ecs/infra-graph",
    vpc=compute.vpc,
    private_subnet_ids=private_subnet_ids,
    env=env,
)

app.synth()
