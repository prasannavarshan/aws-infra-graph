# Sample Queries for AWS Infrastructure Knowledge Graph

These are example queries you can ask Claude Code once the MCP server is connected.

## Architecture Queries

- "What EC2 instances are in the production VPC?"
- "Show me all resources in account 123456789012"
- "What does the web-api Lambda function depend on?"
- "Trace the network path from the ALB to the RDS database"
- "What VPCs are peered together?"

## Guided Connectivity (Natural Language)

Uses `guided_connectivity_check` — fuzzy resource names, auto-resolves types and SGs:

- "Check if lambda my-api-auth can reach eks my-cluster on port 443"
- "Can the redis my-cache talk to lambda api-handler on port 6379?"
- "Check if ec2 web-server can reach rds main-database on port 5432"
- "Can lambda authorizer in account prod-account reach eks cluster in staging-account on port 443?"

## SG-to-SG Connectivity

Uses `check_sg_connectivity` — direct security group evaluation:

- "Can security group eks-node-sg talk to redis-sg on port 6379?"
- "Check connectivity from sg-0abc123 to sg-0def456 on port 443"
- "Can the lambda-sg in account 111111111111 reach eks-worker-sg in account 222222222222 on port 443?"

## CloudWAN & Route Tracing

Uses `check_cloudwan_connectivity`, `get_cloudwan_routes`, `trace_route`:

- "Can CloudWAN segment SegmentDev reach SegmentProd?"
- "Show me the routes in the SharedWAN segment"
- "Trace the route from 10.10.1.5 to 10.20.1.5"
- "Is traffic routable from the OnPrem datacenter to the beta VPC?"

## Cross-Account Connectivity

- "Can ElastiCache my-cache-001 talk to EKS cluster my-eks-cluster on port 6379?"
- "Analyze connectivity from the ALB in account A to the RDS in account B on port 5432"
- "What's the network path between VPC in us-east-1 and VPC in us-west-2 through Transit Gateway?"

## Debugging / Troubleshooting

- "Why can't the web-api Lambda reach the database? Trace the path."
- "What security groups are attached to the production RDS instance?"
- "Which IAM role does the ECS service use, and what policies does it have?"
- "Find all security groups that allow ingress from 0.0.0.0/0"
- "What ElastiCache clusters are in us-west-2?"
- "Show me all replication groups and their member clusters"

## Cost & Optimization

- "What are the largest EC2 instance types across all accounts?"
- "Find all S3 buckets without encryption enabled"
- "Show me RDS instances that are not multi-AZ"

## Overview

- "Give me a summary of all resources in the organization"
- "How many resources does each account have?"
- "What resource types exist in us-west-2?"
- "Show me the account summary for 111111111111"
