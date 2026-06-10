# aws-infra-graph

MCP server that builds a Neo4j knowledge graph of your AWS infrastructure for AI agent context.

## Features

**27 AWS service collectors:**
EC2 (VPCs, Subnets, Security Groups, Instances, NACLs, ENIs), IAM (Roles, Policies, Users), S3, RDS, Lambda, ECS (Clusters, Services), EKS (Clusters, Nodegroups), ElastiCache (Clusters, Replication Groups, Serverless), ELB (ALB/NLB, Target Groups), Route53 (Zones, Records, VPC associations), Route53 Resolver (Endpoints, Rules), DynamoDB, SQS (with DLQ links), SNS (with subscriptions), CloudFront, API Gateway (REST + HTTP), VPC Endpoints, VPC Networking (Route Tables, NAT/Internet Gateways, VPC Peering), Transit Gateway (TGWs, Attachments, Route Tables), Cloud WAN (Core Networks, Segments, Attachments), Organizations (Accounts, OUs, SCPs), CloudFormation (Stacks, MANAGES edges), CodeCommit, CodePipeline, CodeBuild, WAF (WebACLs, PROTECTS edges), OpenSearch, K8s (Namespaces, Deployments, Services, Nodes via EKS API)

**34 MCP tools across 11 categories:**

| Category | Tools |
|----------|-------|
| Search | `find_resources`, `get_resource`, `get_account_summary`, `find_accounts` |
| Topology | `get_dependencies`, `get_network_path` |
| Connectivity | `analyze_connectivity`, `check_sg_connectivity`, `guided_connectivity_check` |
| CloudWAN | `check_cloudwan_connectivity`, `get_cloudwan_routes`, `get_tgw_routes`, `trace_route`, `trace_dns` |
| Security | `find_open_security_groups`, `find_public_resources`, `trace_iam_permissions`, `find_cross_account_roles`, `get_effective_scps`, `get_resource_security_groups` |
| Cost | `get_cost_by_service`, `get_resource_density`, `find_idle_resources` |
| Overview | `get_org_overview`, `get_vpc_topology`, `get_service_map` |
| Org Knowledge | `get_org_knowledge`, `save_org_knowledge`, `review_org_knowledge` |
| Issue Reporting | `report_issue`, `list_issues`, `close_issue` |
| Admin | `refresh_graph` (fire-and-forget), `get_refresh_status` |

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) package manager
- Neo4j 5.x (via Docker/Podman)
- AWS credentials configured (`~/.aws/credentials` or environment variables)

## Quick Start

### 1. Start Neo4j

**Docker:**
```bash
docker compose up -d
```

**Podman** (if you have TLS cert issues with registries):
```bash
podman pull --tls-verify=false docker.io/library/neo4j:5-community
podman run -d --name aws-infra-graph-neo4j --replace \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/changeme \
  -e 'NEO4J_PLUGINS=["apoc"]' \
  neo4j:5-community
```

Verify at http://localhost:7474 (login: `neo4j` / `changeme`).

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your settings (see below)
```

### 3. Install dependencies

```bash
uv sync
```

### 4. Run the MCP server

```bash
# stdio transport (Claude Code local)
uv run python -m src.main

# HTTP transport (remote access)
TRANSPORT=http uv run python -m src.main
```

## Configuration

### Single-account mode (default)

Uses your current AWS CLI credentials. Account ID is auto-detected via STS.

```env
AWS_CROSS_ACCOUNT_ROLE_NAME=
AWS_REGIONS=us-east-1,us-west-2
```

### Multi-account mode (AWS Organizations)

Assumes a cross-account role in each child account.

```env
AWS_CROSS_ACCOUNT_ROLE_NAME=OrganizationAccountAccessRole
AWS_REGIONS=us-east-1,us-west-2
# Optional: limit to specific accounts (empty = auto-discover from Organizations)
AWS_ACCOUNT_IDS=111111111111,222222222222
```

## Claude Code MCP Integration

The project includes `.mcp.json` for automatic Claude Code integration:

```json
{
  "mcpServers": {
    "aws-infra-graph": {
      "command": "uv",
      "args": ["run", "python", "-m", "src.main"],
      "env": {
        "TRANSPORT": "stdio",
        "NEO4J_URI": "bolt://localhost:7687",
        "NEO4J_USER": "neo4j",
        "NEO4J_PASSWORD": "changeme"
      }
    }
  }
}
```

Once connected, ask Claude things like:
- "Refresh the infrastructure graph"
- "What EC2 instances are in us-east-1?"
- "Find all security groups that allow 0.0.0.0/0 ingress"
- "Check if lambda my-api-auth can reach eks prod-cluster on port 443"
- "Can ElastiCache in account A talk to EKS in account B on port 6379?"
- "Trace the route from 10.10.0.10 to 10.20.0.10"
- "Check CloudWAN connectivity between ProdSegment and OnPremWAN"
- "Show me the VPC topology"

See `examples/sample_queries.md` for more.

## AWS Deployment

Run the full stack (MCP server + Neo4j) on AWS instead of your laptop.

### Architecture

```
MCP Clients (Claude Code, Kiro)
         │ HTTPS/443
   ┌─────▼──────┐
   │ Internal   │  (private subnets, 10.0.0.0/8 only)
   │ ALB        │
   └─────┬──────┘
         │ :8050
  ┌──────▼──────────┐        ┌─────────────────────┐
  │  ECS Fargate    │  Bolt  │  EC2 t3.large        │
  │  1 vCPU / 4 GB  │───────▶│  Neo4j 5 Community   │
  │  MCP Server     │ :7687  │  100 GB XFS EBS gp3  │
  └─────────────────┘        └─────────────────────┘
         ▲ POST /refresh
  ┌──────┴──────┐
  │  Lambda     │◄── EventBridge (daily at 7 AM MDT)
  └─────────────┘
```

**Two separate stacks:**

| Stack | Resource | Purpose |
|-------|----------|---------|
| `InfraGraphNeo4j` | EC2 t3.large + EBS gp3 100 GB | Graph database — data survives instance replacement |
| `InfraGraphCompute` | ECS Fargate + ALB | MCP server — stateless, points at Neo4j EC2 |

> **Why EC2 for Neo4j?** The original EFS sidecar architecture caused recurring
> `DatabaseUnavailable` crashes. Under heavy write load during crawls, EFS
> transit encryption (stunnel) drops its TCP connection. Neo4j's page cache
> checkpoint then fails with `java.io.IOException: Stale file handle` (NFS
> ESTALE), marking the database unavailable. Moving Neo4j to a local EBS volume
> eliminates NFS entirely. See `docs/ops-runbook.md` for full details.
>
> **Periodic refresh:** An EventBridge rule fires daily at 7 AM MDT (13:00 UTC) and triggers a
> Lambda that POSTs to the MCP server's `/refresh` endpoint. Use
> `get_refresh_status()` to check if a crawl is in progress.

### Prerequisites

- AWS CDK v2 (`npm install -g aws-cdk`)
- Podman (or Docker)
- AWS CLI profile with access to the deployment account

### Deploy

```bash
# One-time setup
cd infra
uv venv && uv pip install -r requirements.txt
AWS_PROFILE=<your-profile> cdk bootstrap aws://<account-id>/us-east-1
```

**All changes (code or infra) — ~3 minutes:**
```bash
cd infra
AWS_PROFILE=YOUR_AWS_PROFILE \
  CDK_DOCKER=podman \
  JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1 \
  cdk deploy InfraGraphCompute --require-approval never
```

> **Do NOT use `--hotswap`.** CDK hotswap registers a new task definition
> by copying only the container image — it silently drops
> `efsVolumeConfiguration`, causing Neo4j to start with ephemeral storage
> and lose all graph data on the next deploy.

### Configuration

All deployment config is in `infra/cdk.json`:

| Parameter | Description |
|-----------|-------------|
| `aws_profile` | AWS CLI profile name (required) |
| `account` | Target AWS account ID (required) |
| `region` | Deployment region (default: us-east-1) |
| `vpc_id` | Existing VPC to deploy into (required) |
| `private_subnet_ids` | Subnet IDs for ECS tasks and ALB (one per AZ) |
| `allowed_cidrs` | CIDRs allowed to reach the ALB |
| `certificate_arn` | ACM cert for HTTPS (optional, uses HTTP if empty) |
| `cross_account_role_name` | IAM role to assume in child accounts |
| `org_account_id` | Delegated admin account for Organizations API |

### Cross-Account Access

The ECS task role (`InfraGraphTaskRole`) needs to be trusted by the cross-account
role in each member account. A CloudFormation StackSet template is provided at
`infra/iam/cross-account-trust.yaml`.

### Container Testing (local)

```bash
# Start MCP server + Neo4j via containers
podman compose up --build

# Test health endpoint
curl http://localhost:8050/health

# Tear down
podman compose down
```

## Development

```bash
# Install dev dependencies
uv sync --group dev

# Run tests
uv run pytest tests/ -v

# Lint
uv run ruff check src/ tests/

# Format
uv run ruff format src/ tests/
```

## Architecture

```
AWS Org (boto3) ──▶ Neo4j Knowledge Graph ◀── Claude Code (MCP Client)
     │                      ▲                         │
     ▼                      │                         ▼
STS AssumeRole        Graph Builder             MCP Server (FastMCP)
```

1. **Collection** — Collectors enumerate AWS resources via boto3 + STS
2. **Normalization** — Raw API responses become Pydantic `ResourceNode`/`ResourceEdge` models
3. **Graph Construction** — Builder upserts nodes and relationships into Neo4j
4. **Querying** — MCP tools execute Cypher queries and return formatted results
