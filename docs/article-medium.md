# Giving AI Agents a Complete Picture of Your AWS Infrastructure

*How I built an MCP server that turns a multi-account AWS org into a queryable knowledge graph — and the hard problems along the way*

---

<!-- DIAGRAM: docs/diagrams/architecture.excalidraw
     Export to PNG from https://excalidraw.com and insert here.
     Caption: "System architecture: AWS collectors → Neo4j graph → MCP server → AI agents" -->

---

When an AI agent helps you debug a production issue, it's essentially working blind.

It can read your code. It can search your docs. But it has no idea that your Lambda is in the wrong security group, that the RDS it's trying to reach is two VPC hops away through a Transit Gateway, or that a Service Control Policy three levels up the org hierarchy is quietly blocking the IAM call it's about to make.

I hit this wall while working across a large multi-account AWS organization. The questions that took the longest to answer weren't complex — they were spatial. *What can reach what? Why is this connection failing? Which account owns this resource?* These are graph problems, and I was solving them by clicking through the console like it was 2015.

So I built `aws-infra-graph`: an MCP server that crawls your entire AWS org, builds a Neo4j knowledge graph, and exposes it through tools that AI agents can actually use.

This is the story of how it works, what broke spectacularly along the way, and why the hardest problems were the ones I didn't expect.

---

## The Core Idea

The architecture is straightforward on paper:

```
AWS Org (boto3 collectors)
        ↓
   Neo4j graph
        ↓
 MCP server (FastMCP)
        ↓
AI agents (Claude Code, any MCP client)
```

Collectors enumerate every resource across every account. They normalize API responses into typed Pydantic models — `ResourceNode` and `ResourceEdge` — with a consistent schema: every node has an ARN, a name, an account ID, a region, and a `last_crawled` timestamp. The graph builder writes these to Neo4j. The MCP server exposes Cypher-backed tools that agents can call in natural language.

The result: 34 tools across 11 categories — topology queries, connectivity checks, DNS tracing, security audits, cost analysis, org overview. Agents can ask things like:

- *"Can the Lambda in account A reach the EKS cluster in account B on port 443?"*
- *"Trace the DNS path for api.internal.company.org from the production VPC"*
- *"Find all security groups that allow ingress from 0.0.0.0/0 across the whole org"*
- *"What's the network path between these two IPs through the Transit Gateway?"*

And get back actual answers — not "please log in to the console and check."

---

## The Graph Schema

The real work is in the schema. A flat inventory of resources isn't useful — the value is in the edges.

The graph has 27 node types and 35+ relationship types. Some straightforward:

```cypher
(EC2Instance)-[:RUNS_IN]->(Subnet)-[:PART_OF]->(VPC)
(IAMRole)-[:HAS_POLICY]->(IAMPolicy)
(LambdaFunction)-[:HAS_ROLE]->(IAMRole)
```

Some that capture the real complexity of a multi-account org:

```cypher
(VPC)-[:SHARED_WITH]->(VPC)                     // RAM-shared VPCs across accounts
(K8sServiceAccount)-[:ASSUMES_IRSA]->(IAMRole)  // IRSA pod identity bindings
(K8sService)-[:EXPOSES_VIA]->(LoadBalancer)     // cross-boundary K8s edges
(CloudWANAttachment)-[:ATTACHED_TO]->(CoreNetwork)
(Account)-[:GOVERNED_BY]->(ServiceControlPolicy)
```

A typical cross-account network path traverses 13–14 hops through the graph. Without the edges, you have a parts list. With them, you have a map.

---

## The Performance Cliff

<!-- DIAGRAM: docs/diagrams/perf-crawl.excalidraw
     Export to PNG from https://excalidraw.com and insert here.
     Caption: "Crawl time: 528 min → 415 min (+concurrency) → 15 min (+index). One RANGE index caused a 97% reduction." -->

The first production run against 70 accounts took **528 minutes**. That's nearly 9 hours to crawl what turns out to be ~42,000 nodes and ~42,000 edges.

I tried the obvious things first. Added write concurrency (`NEO4J_WRITE_CONCURRENCY=3`). Got it down to 415 minutes. A 20% improvement — still useless for a daily refresh.

The actual problem was invisible until I profiled the Cypher queries. Every edge write was doing a full graph scan.

The pattern used to find a node before creating an edge looks like this:

```cypher
MATCH (n {arn: $arn}) ...
```

With no index on `arn`, that's O(n) against the entire graph for every edge upsert. With 42,000 nodes and a similar number of edges, each crawl was executing tens of millions of individual node lookups.

The fix was a single RANGE index:

```cypher
CREATE INDEX idx_arn_resource FOR (n:Resource) ON (n.arn)
```

And every node gets a secondary `:Resource` label via `apoc.merge.node` so the index is always hit — not just on nodes that happen to have that label natively.

**Result: 528 minutes → 15 minutes. A 97% reduction.**

The write concurrency setting became irrelevant — writes now take under 2 seconds total. Collection is the bottleneck now, and that's just boto3 pagination time which can't be compressed further without hitting rate limits.

The lesson: if your graph operations are slow, check your indexes before you optimize anything else. An `EXPLAIN` on the first edge upsert would have caught this immediately.

---

## The EKS Bearer Token Problem

EKS clusters don't use standard AWS credentials for their Kubernetes API. You generate a short-lived bearer token from a presigned STS URL. This is documented, but the documentation glosses over a detail that cost me an afternoon.

The naive approach:

```python
url = sts.generate_presigned_url("get_caller_identity")
token = "k8s-aws-v1." + base64.b64encode(url.encode()).decode()
```

This fails. `GetCallerIdentity` takes no parameters, so you can't attach a `ClusterName` query parameter to identify which cluster the token is for. And without that parameter, the EKS API server rejects it.

The correct approach is to manually construct a presigned STS URL using botocore's signing primitives:

```python
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
import base64

request = AWSRequest(
    method="GET",
    url="https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
    headers={"x-k8s-aws-id": cluster_name}
)
SigV4QueryAuth(credentials, "sts", region).add_auth(request)

# base64url encode, strip padding
token = "k8s-aws-v1." + base64.urlsafe_b64encode(
    request.url.encode()
).decode().rstrip("=")
```

The `x-k8s-aws-id` header is what tells the EKS API server which cluster this token is for. It gets signed into the presigned URL, so the server can verify it cryptographically.

Worth documenting because `generate_presigned_url("get_caller_identity")` silently ignores extra parameters rather than raising an error. You get a token that looks valid and fails at authentication time with no helpful error message.

---

## DNS Across Account Boundaries

Private Route53 zones in AWS can be associated with VPCs across accounts — but the collector for the zone owner doesn't know about the VPC on the other side. It stores the association as a VPC ARN using the zone owner's account ID, which creates a dangling edge pointing at a node that doesn't exist.

The symptom: queries that should return 15+ zone-VPC associations returned 3. Everything else silently dropped.

The fix is a post-processing reconciliation step in the graph builder. After all accounts are collected, it iterates zone associations, extracts VPC IDs, and repoints edges to the correct VPC nodes regardless of account:

```python
def _link_dns_zone_vpcs(self, zones: list[ResourceNode]) -> None:
    for zone in zones:
        for vpc_assoc in zone.properties.get("vpc_associations", []):
            vpc_id = vpc_assoc["vpc_id"]
            actual_vpc = self._find_vpc_by_id(vpc_id)  # search by ID, not account
            if actual_vpc:
                self._write_edge(zone.arn, actual_vpc.arn, "ASSOCIATED_WITH")
```

After this fix: 15 private zones properly associated, 1,046 edges. Before: 3 zones and silence.

The broader lesson is that cross-account resources require a two-pass collection strategy. First pass: collect everything. Second pass: reconcile cross-account references. Any edge that crosses an account boundary is a potential orphan until the reconciliation step runs. This pattern shows up in several other places in the codebase — shared VPCs, CloudWAN attachments, RAM-shared Transit Gateway route tables.

---

## Union Security Group Evaluation

AWS evaluates security groups on a network interface as a union — if *any* attached SG allows the traffic, it passes. This seems obvious until you try to model it in a connectivity checker.

Consider an EKS worker node with two security groups:
- `sg-node`: restrictive egress to specific CIDRs, referenced by the MongoDB endpoint's ingress rule
- `sg-cluster`: allow-all egress, not referenced by the endpoint's ingress rule

Evaluated individually:
- `sg-node`: egress check → DENIED (no allow-all rule)
- `sg-cluster`: ingress check → DENIED (not referenced by endpoint's ingress)

Evaluated together: `sg-cluster` provides egress, `sg-node` provides the ingress reference → **ALLOWED**

The `check_sg_connectivity` tool accepts comma-separated SG identifiers for exactly this reason:

```
check_sg_connectivity(
    source_sg="sg-cluster,sg-node",
    target_sg="sg-mongodb-vpce",
    port=27017
)
```

This isn't an edge case — it's how EKS pod networking works by default. Every pod has at least two SGs (node SG + cluster SG), and connectivity analysis that evaluates them individually will produce false DENIED results on traffic that actually succeeds.

---

## Don't Put Neo4j on EFS

The original deployment used an EFS volume mounted into the Fargate task sidecar alongside Neo4j. This worked until a TCP connection drop through our SSL inspection proxy caused an NFS ESTALE error, after which the Neo4j data directory was inaccessible until a full replacement.

EFS is NFS under the hood. NFS is a stateful protocol — it maintains file handles that become invalid when the underlying TCP connection drops. When that happens under a proxy that does SSL inspection, you get ESTALE errors that Neo4j cannot recover from gracefully.

The fix: Neo4j on EC2 with an EBS volume attached as a local block device. EBS doesn't care about TCP state. A disconnected EC2 instance doesn't corrupt your data. The graph survives instance replacement because `delete_on_termination=False` on the EBS volume.

Two CDK stacks:
- `InfraGraphNeo4j` — EC2 t3.large + 100 GB EBS gp3 (XFS). Graph data lives here.
- `InfraGraphCompute` — ECS Fargate + internal ALB. Stateless MCP server. Points at Neo4j EC2 via Bolt on port 7687.

Deploying them separately means you can replace the compute stack without touching Neo4j, and replace the Neo4j instance without losing any data (just reattach the EBS volume).

---

## The Architecture in Production

The MCP server exposes a `streamable-http` endpoint on port 8050 behind an internal ALB. Any MCP client with network access and a valid auth token can connect — Claude Code, VS Code extensions, or a chat frontend.

Daily refresh runs on an EventBridge cron at 13:00 UTC. A 15-minute full crawl means the graph is always within 24 hours of reality. A manual `refresh_graph` tool lets agents trigger an update on demand.

Cross-account collection works by assuming a role in each member account from the management account. The collector gets a fresh boto3 session per account, enumerates resources in all regions, normalizes them into the `ResourceNode`/`ResourceEdge` model, and hands them to the graph builder.

The 27 collectors cover: EC2 (instances, VPCs, subnets, security groups, NACLs, ENIs), IAM, S3, RDS, Lambda, ECS, EKS, Kubernetes (via EKS API), ElastiCache, ELB, Route53, Route53 Resolver, DynamoDB, SQS, SNS, CloudFront, API Gateway, VPC Endpoints, VPC Networking (route tables, NAT/IGW, VPC peering), Transit Gateway, CloudWAN, Organizations, CloudFormation, CodeCommit, CodePipeline, CodeBuild, WAF, OpenSearch.

---

## What It's Like to Use

The agents that connect to this server can answer questions that previously required 20 minutes of console clicking:

> "Can the Lambda function `payment-processor` in account A reach the EKS cluster in account B on port 443?"

That question requires: finding the Lambda's VPC and security groups, finding the EKS cluster's VPC and security groups, traversing Transit Gateway route tables to check for a path, evaluating SG rules including cross-SG references, and checking NACLs. The `guided_connectivity_check` tool does this from fuzzy resource names. No account IDs, no region names, no ARNs needed.

> "Trace the DNS path for `api.internal.company.org` from the production VPC"

The `trace_dns` tool walks the Route53 Resolver chain: outbound endpoint → forwarding rule → target IPs → inbound endpoint → private hosted zone → A records. It surfaces split-horizon configurations, cross-account zone associations, and NS delegation chains.

> "Find all security groups that allow ingress from 0.0.0.0/0 across all accounts"

The `find_open_security_groups` tool runs a single Cypher query across the whole graph. No looping through accounts, no paginating through the AWS console.

---

## Going Open Source

This started as an internal tool. I'm releasing it as an open source project — MIT licensed, no org-specific logic hardcoded.

If you have a single AWS account, you connect with your existing credentials and get a queryable graph in minutes. If you have a large multi-account org, point it at your management account with an assume-role ARN and let it crawl.

**What you need:**
- Python 3.12+, `uv`
- Neo4j 5.x (Docker Compose file included)
- AWS credentials (single account or org-level role)

Quick start:

```bash
git clone https://github.com/YOUR_USERNAME/aws-infra-graph
cd aws-infra-graph
cp .env.example .env   # add your AWS profile and Neo4j creds

docker compose up -d   # start Neo4j

uv sync
uv run python -m src.main   # start MCP server on stdio
```

Then add it to your Claude Code or MCP client config and start asking questions.

---

## What I'd Do Differently

**Start with Neo4j indexes.** The 528-minute crawl was entirely self-inflicted. An `EXPLAIN` on the first edge upsert would have caught it immediately. Add indexes before you write a single node.

**Design for cross-account edges from day one.** Several collectors needed a rewrite when I realized they were writing ARNs with the wrong account ID in them. The `ResourceEdge` model should carry a flag for edges that cross account boundaries and need reconciliation.

**Don't use EFS for stateful containers.** Block storage for databases. Always.

**Two-pass collection is the pattern, not the exception.** Any resource that can be shared across accounts (VPCs, TGW route tables, Route53 zones) requires a reconciliation pass after all accounts are collected. Build that into the architecture from the start.

---

The full source, documentation, and getting-started guide are on GitHub at **[YOUR_REPO_URL]**.

27 collectors. 34 MCP tools. 612 tests. MIT licensed. If you're running multiple AWS accounts and find yourself spending more time answering "what can reach what" than building things, this might save you some time.

---

*Stack: Python 3.12+, FastMCP, boto3, Neo4j 5, Pydantic v2, AWS CDK (ECS Fargate + EC2 EBS). 42,000+ nodes and edges from a 70-account org.*
