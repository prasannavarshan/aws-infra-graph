# PLANNING.md — Architecture & Design Decisions

## Architecture Overview

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  AWS Org     │     │   Neo4j      │     │  Claude Code │
│  (boto3)     │────▶│  Knowledge   │◀────│  / Kiro CLI  │
│  Collectors  │     │  Graph       │     │  (MCP Client)│
└──────────────┘     └──────────────┘     └──────────────┘
       │                    ▲                     │
       │                    │                     │
       ▼                    │                     ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  STS         │     │  Graph       │     │  MCP Server  │
│  AssumeRole  │     │  Builder     │     │  (FastMCP)   │
│  (per acct)  │     │              │     │  Tools       │
└──────────────┘     └──────────────┘     └──────────────┘
```

### AWS Deployment Architecture

```
MCP Clients (Claude Code, Kiro)
         │ HTTPS/443
   ┌─────▼──────┐
   │ Internal   │  (private subnets, 10.0.0.0/8 only)
   │ ALB        │
   └─────┬──────┘
         │ :8050
  ┌──────▼──────────┐       ┌─────────────────────┐
  │  ECS Fargate    │ Bolt  │  EC2 t3.large        │
  │  1 vCPU / 4 GB  │──────▶│  Neo4j 5 Community   │
  │  MCP Server     │ :7687 │  100 GB XFS EBS gp3  │
  └─────────────────┘       └─────────────────────┘
```

Two CDK stacks:
- **`InfraGraphNeo4j`**: EC2 t3.large + 100 GB EBS gp3 (XFS) — graph data survives instance replacement (`delete_on_termination=False`)
- **`InfraGraphCompute`**: ECS Fargate + ALB — stateless MCP server, points at Neo4j EC2

Neo4j runs on EC2+EBS (not EFS sidecar) to avoid NFS ESTALE crashes. See `docs/ops-runbook.md`.

## Data Flow

1. **Collection**: Collectors enumerate AWS resources across accounts using boto3 + STS
2. **Normalization**: Raw API responses are normalized into Pydantic `ResourceNode` and `ResourceEdge` models
3. **Graph Construction**: Builder inserts nodes and relationships into Neo4j
4. **Querying**: MCP tools execute Cypher queries and return formatted results

## Key Design Decisions

### Why Neo4j (not NetworkX or SQLite)?
- Native graph traversal for path-finding queries ("can X reach Y?")
- Cypher query language is expressive for relationship patterns
- Scales to large orgs (tens of thousands of resources)
- Persistent storage survives restarts
- Cole Medin uses Neo4j in mcp-crawl4ai-rag for similar patterns

### Why FastMCP lifespan pattern?
- Initializes Neo4j connection and boto3 sessions once at startup
- Shares state across all tool invocations via context
- Clean shutdown handling
- Standard pattern from Cole Medin's MCP servers

### Why streamable-http transport?
- Initially used stdio for direct Claude Code integration
- Switched to `streamable-http` on port 8050 for persistent server mode
- Allows Kiro CLI and other MCP clients to connect over HTTP
- Server stays running between requests (no per-call startup cost)
- Configurable via TRANSPORT env var (`stdio` or `http`)

## Graph Schema

### Node Labels & Properties

All nodes share: `arn`, `name`, `account_id`, `region`, `tags` (JSON), `last_crawled`

| Label | Additional Properties |
|-------|----------------------|
| Account | account_id, account_name, org_unit |
| VPC | cidr_block, secondary_cidrs, is_default |
| Subnet | cidr_block, availability_zone, is_public |
| SecurityGroup | vpc_id, description, ingress_rules, egress_rules |
| EC2Instance | instance_type, state, private_ip, public_ip, ami_id |
| IAMRole | path, assume_role_policy |
| IAMPolicy | policy_type (managed/inline), document |
| IAMUser | user_id, path |
| S3Bucket | creation_date, versioning, encryption |
| RDSInstance | engine, engine_version, instance_class, multi_az |
| LambdaFunction | runtime, handler, memory_size, timeout |
| ECSCluster | status, capacity_providers |
| ECSService | desired_count, launch_type, task_definition |
| EKSCluster | version, status, endpoint, platform_version, service_cidr, endpoint_public_access, endpoint_private_access |
| EKSNodegroup | status, instance_types, ami_type, capacity_type, disk_size, min_size, max_size, desired_size |
| LoadBalancer | lb_type (ALB/NLB), scheme, dns_name |
| TargetGroup | protocol, port, health_check |
| Route53Zone | zone_id, is_private, vpc_associations |
| Route53Record | record_type, ttl, values |
| DynamoDBTable | table_status, billing_mode |
| SQSQueue | queue_type, visibility_timeout |
| SNSTopic | display_name, subscriptions_confirmed |
| CloudFrontDistribution | status, domain_name, origins |
| APIGateway | api_type, endpoint_type |
| VPCEndpoint | endpoint_type, service_name, state, private_dns_enabled |
| TransitGateway | tgw_id, state, owner_id, amazon_side_asn |
| TGWAttachment | attachment_id, resource_type, resource_id, tgw_owner_id |
| TGWRouteTable | route_table_id, tgw_id, default_association |
| CloudWANCoreNetwork | core_network_id, state, segment_count, edge_locations |
| CloudWANSegment | core_network_id, edge_locations, shared_segments |
| CloudWANAttachment | attachment_type, segment_name, resource_arn, edge_location |
| NetworkACL | network_acl_id, vpc_id, is_default, ingress_rules, egress_rules |
| RouteTable | route_table_id, vpc_id, is_main, routes |
| NATGateway | nat_gateway_id, vpc_id, subnet_id, state, connectivity_type, public_ip, private_ip |
| InternetGateway | igw_id, state |
| VPCPeering | peering_id, status, requester_vpc_id, requester_account_id, requester_cidr, accepter_vpc_id, accepter_account_id, accepter_cidr |
| ElastiCacheCluster | engine, engine_version, cache_node_type, num_cache_nodes, status, endpoint, port, preferred_az, snapshot_retention_limit, at_rest_encryption, transit_encryption |
| ElastiCacheReplicationGroup | engine, description, status, cluster_enabled, multi_az, automatic_failover, num_node_groups, snapshot_retention_limit, at_rest_encryption, transit_encryption |
| NetworkInterface | eni_id, subnet_id, vpc_id, private_ip, is_primary, status, device_index |
| CloudFormationStack | status, description, creation_time, last_updated_time, role_arn, parent_id, root_id, drift_status, termination_protection, parameters, outputs |
| OrganizationalUnit | ou_id, ou_name, ou_type (ROOT/ORGANIZATIONAL_UNIT) |
| ServiceControlPolicy | policy_id, policy_name, aws_managed, description, policy_document, policy_summary |
| OpenSearchDomain | domain_id, engine_version, instance_type, instance_count, dedicated_master, zone_awareness, endpoint, vpc_id, encryption_at_rest, node_to_node_encryption, fine_grained_access, access_policies |
| ElastiCacheServerlessCache | engine, status, endpoint, reader_endpoint, max_data_storage_gb, max_ecpu_per_second, kms_key_id, snapshot_retention_limit |
| WAFWebACL | scope, capacity, default_action, rule_count, rules_summary, managed_rule_groups, description, managed_by_firewall_manager |
| K8sNamespace | cluster_name, status |
| K8sDeployment | cluster_name, namespace, kind (deployment/statefulset/daemonset), replicas, ready_replicas |
| K8sService | cluster_name, namespace, type, cluster_ip, ports, external_hostname, selector |
| K8sServiceAccount | cluster_name, namespace, irsa_role_arn |
| K8sNode | cluster_name, instance_type, kubelet_version, os_image, internal_ip, hostname, provider_id, unschedulable |
| K8sIngress | cluster_name, namespace, ingress_class, external_hostname, rules |

### Relationship Types

| Relationship | From | To | Meaning |
|-------------|------|----|---------|
| RUNS_IN | EC2Instance/EKSCluster/EKSNodegroup/NATGateway/ElastiCacheCluster/OpenSearchDomain | Subnet | Resource placed in subnet |
| PART_OF | Subnet/TGWRouteTable/CloudWANAtt/EKSNodegroup/RouteTable/NATGateway/ElastiCacheCluster/OrganizationalUnit | VPC/TGW/Segment/EKSCluster/ElastiCacheReplicationGroup/OrganizationalUnit | Resource belongs to parent |
| HAS_SG | EC2Instance/NetworkInterface/RDS/Lambda/VPCEndpoint/EKSCluster/ElastiCacheCluster/OpenSearchDomain | SecurityGroup | Resource has security group |
| HAS_ROLE | EC2Instance/Lambda/ECS/EKSCluster/EKSNodegroup | IAMRole | Resource assumes role |
| HAS_POLICY | IAMRole | IAMPolicy | Role has attached policy |
| TARGETS | LoadBalancer | TargetGroup | LB forwards to target group |
| ROUTES_TO | TargetGroup/RouteTable | EC2Instance/IGW/NAT/TGW/VPCPeering | TG routes to instance; RT routes to target |
| TRIGGERS_FROM | LambdaFunction | S3Bucket/SQS/etc | Lambda trigger source |
| RESOLVES_TO | Route53Record | LoadBalancer/EC2 | DNS resolves to resource |
| PEERS_WITH | VPCPeering/TGWAttachment | VPC/TGW | Peering connection |
| ALLOWS_INGRESS | SecurityGroup | SecurityGroup | SG rule allows traffic from |
| BELONGS_TO | * | Account | Resource belongs to account |
| MEMBER_OF | Account | Account | Org membership |
| PUBLISHES_TO | * | SNSTopic | Publishes to SNS |
| SUBSCRIBES_TO | SQSQueue | SNSTopic | SQS subscribes to SNS |
| DISTRIBUTES | CloudFrontDistribution | S3Bucket | CDN distributes from origin |
| INVOKES | APIGateway | LambdaFunction | API invokes Lambda |
| CONNECTS_TO | VPCEndpoint/CloudWANSegment | Service/Segment | Connects to service or shared segment |
| ATTACHED_TO | TGWAttachment/CloudWANAttachment/InternetGateway | TGW/VPC/CoreNetwork/TGWRouteTable | Network attachment |
| HAS_SEGMENT | CloudWANCoreNetwork | CloudWANSegment | Core network owns segment |
| SHARED_WITH | VPC | VPC | RAM-shared VPC (same VPC ID, different accounts) |
| HAS_NACL | Subnet | NetworkACL | Subnet associated with NACL |
| LAUNCHES | EKSNodegroup | EC2Instance | Node group manages instance |
| ASSOCIATED_WITH | Route53Zone | VPC | Private hosted zone resolves in VPC |
| HAS_ENI | EC2Instance | NetworkInterface | Instance has network interface |
| HAS_ROUTE_TABLE | Subnet | RouteTable | Subnet associated with route table |
| MANAGES | CloudFormationStack | * | Stack manages/owns this resource |
| GOVERNED_BY | Account/OrganizationalUnit | ServiceControlPolicy | SCP attached to target |
| PROTECTS | WAFWebACL | LoadBalancer/CloudFrontDistribution/APIGateway | WAF protects resource |
| RUNS_IN_NAMESPACE | K8sDeployment/K8sService/K8sServiceAccount/K8sIngress | K8sNamespace | Resource lives in K8s namespace |
| HOSTS_ON | K8sNode | EC2Instance | K8s node runs on EC2 instance (via providerID) |
| ASSUMES_IRSA | K8sServiceAccount | IAMRole | SA assumes IAM role via IRSA annotation |
| SELECTS | K8sService | K8sDeployment | Service selects deployment via label selector |
| EXPOSES_VIA | K8sService/K8sIngress | LoadBalancer | K8s resource exposed via AWS load balancer |

## Collector Pattern

Each collector follows this pattern:
1. Accept a boto3 session (already assumed into target account)
2. Paginate through all resources of its type
3. Return list of `ResourceNode` and `ResourceEdge` Pydantic models
4. Handle region iteration internally
5. Log progress and errors with account/region context

Special patterns:
- **Global services** (IAM, CloudFront, CloudWAN, WAF): Override `collect()` to run once, not per-region (WAF collects REGIONAL per-region + CLOUDFRONT from us-east-1)
- **Management-only** (Organizations): Set `management_only = True` class attribute; builder skips for member accounts
- **Cross-account ARNs** (TGW, CloudWAN): Use owner account ID in edge target ARNs, not collector's account
- **Shared VPCs**: Builder runs `_bridge_shared_vpcs()` post-build to create SHARED_WITH edges

## Network Path Tracing Architecture

Cross-account network paths traverse multiple resource types. A typical path:

```
Instance (Account A)
  └─ RUNS_IN → Subnet
       └─ PART_OF → VPC (Account A)
            └─ SHARED_WITH → VPC (RAM owner, Account B)
                 └─ ←ATTACHED_TO─ CloudWAN VPC Attachment
                      └─ ATTACHED_TO → Core Network
                           └─ ←ATTACHED_TO─ CloudWAN TGW RT Attachment
                                └─ ATTACHED_TO → TGW Route Table
                                     └─ PART_OF → Transit Gateway
                                          └─ ←ATTACHED_TO─ TGW VPC Attachment
                                               └─ ATTACHED_TO → VPC (RAM owner, Account C)
                                                    └─ SHARED_WITH → VPC (Account D)
                                                         └─ ←PART_OF─ Subnet
                                                              └─ ←RUNS_IN─ Instance (Account D)
```

Key considerations:
- Paths are 13-14 hops for cross-account via CloudWAN+TGW (hop limit set to 20)
- Edge upsert order matters: run TGW collector before CloudWAN so target nodes exist
- Shared VPC bridging must run after all accounts are collected
- Legacy accounts outside Control Tower appear as orphan references (no node, edge silently skipped)

## Current Scale (Production)

- **69 accounts** in AWS Organization
- **42,570+ nodes** and **41,996+ edges** (full collection incl. NACLs, VPC networking, and ElastiCache)
- **23 collectors**: Organizations, EC2 (incl. NACLs), IAM, S3, RDS, Lambda, ECS, EKS, K8s (post-build), ElastiCache, ELB, OpenSearch, Route53, DynamoDB, SQS, SNS, CloudFront, APIGateway, VPCEndpoints, VPCNetworking (Route Tables, NAT/IGW, VPC Peering), TransitGateway, CloudWAN, CloudFormation
- **23 MCP tools** across 8 categories: Search, Topology, Connectivity, CloudWAN, Security, Cost, Overview, Admin
- **612 tests**, all passing (3 pre-existing failures in test_org_discovery.py)
- Runs on local Mac Pro with Neo4j Community Edition (trivial at this scale)

## Per-ENI SG Tracking

EC2 instances (especially EKS worker nodes) have multiple ENIs with different security groups. The primary ENI has the node SG, while secondary ENIs (VPC CNI pod networking) have cluster SG + EKS managed SG + additional SGs.

### Graph Model

```
EC2Instance
  ├─ HAS_SG → SecurityGroup  (flattened, backward compat)
  ├─ HAS_ENI → NetworkInterface (primary, device_index=0)
  │     └─ HAS_SG → SecurityGroup (node SG)
  └─ HAS_ENI → NetworkInterface (secondary, device_index=1+)
        └─ HAS_SG → SecurityGroup (cluster SG, managed SG, etc.)
```

Both the flattened `EC2Instance --HAS_SG-->` edges and per-ENI `NetworkInterface --HAS_SG-->` edges coexist. Flattened edges maintain backward compatibility for all existing queries. Per-ENI edges enable precise SG evaluation per interface.

### Data Source

`describe_instances` already returns full ENI data in `NetworkInterfaces[]` — no separate `describe_network_interfaces` API call needed. Each ENI includes attachment info, SGs, subnet, and IPs.

### Key Files

- `src/collector/ec2.py` — `_process_eni()` creates NetworkInterface nodes and per-ENI HAS_SG edges
- `src/graph/model.py` — `NETWORK_INTERFACE` NodeLabel, `HAS_ENI` RelationshipType

## Union SG Evaluation

AWS evaluates all SGs on an ENI as a union — if ANY SG allows, traffic passes. `check_sg_connectivity` supports this via comma-separated SG identifiers.

### How It Works

```
check_sg_connectivity(
  source_sg="sg-cluster,sg-managed",  # comma-separated
  target_sg="sg-mongodb-vpce",
  port=27017
)
```

1. Each comma-separated identifier is resolved independently via `_resolve_multiple_sgs()`
2. All source SG IDs form `src_sg_ids` frozenset, all target SG IDs form `tgt_sg_ids`
3. Egress: iterate source SGs, break on first allow (union semantics)
4. Ingress: iterate target SGs, break on first allow (union semantics)
5. Cross-SG references work: ingress rule `sg:sg-cluster` matches because `sg-cluster` is in `src_sg_ids`

### When Union Matters

Single-SG evaluation gives false DENIED when:
- SG-A has restrictive egress (only specific CIDRs) but is referenced in target's ingress
- SG-B has open egress (0.0.0.0/0) but is NOT referenced in target's ingress
- Together: SG-B provides egress, SG-A provides the ingress reference → ALLOWED

Real example: EKS cluster SG has no broad egress but is referenced by MongoDB VPC endpoint ingress. EKS managed SG has allow-all egress. Union evaluation correctly returns ALLOWED.

### Tool Comparison

| Tool | SG Evaluation | Use Case |
|------|--------------|----------|
| `check_sg_connectivity` | Union (comma-separated) | Precise check with explicit SGs |
| `guided_connectivity_check` | Per-SG iteration | Quick fuzzy check, auto-discovers SGs |

`guided_connectivity_check` iterates all SGs on a resource individually — if any single SG passes both egress and ingress, it reports ALLOWED. This works for ~95% of cases. Union evaluation in `guided_connectivity_check` is a future enhancement for the edge cases where egress and ingress are satisfied by different SGs.

## Live SG Refresh

Connectivity tools (`guided_connectivity_check`, `check_sg_connectivity`) evaluate SG rules from the Neo4j graph, which may be stale. The `live_refresh` parameter (default `False`) fetches fresh SG rules from AWS before evaluating.

### Flow

```
1. Resolve resources / SGs from graph (unchanged)
2. IF live_refresh=True:
   a. Group involved SGs by (account_id, region)
   b. Per group: get_session_for_account → describe_security_groups
   c. Build ResourceNode objects, upsert to Neo4j (graph stays fresh)
   d. Replace stale SG dicts with fresh ones for evaluation
3. Evaluate SG rules (unchanged)
4. Output includes "[SG rules refreshed from AWS]" note
```

### Human-in-the-loop

- Default is `False` — graph data only, no AWS API calls
- Agent sets `True` when user asks for live/current data (e.g., "use live SG data")
- User sees `"live_refresh": true` in the MCP tool call approval prompt and can reject

### Key files

- `src/tools/sg_refresh.py` — `refresh_security_groups()` core function, `_fetch_sgs_from_aws()`, `_build_sg_result()`
- Reuses: `get_session_for_account()` (cross-account), `summarize_rules()` (rule formatting), `neo4j.upsert_nodes()` (graph update)

## VPC CIDRs vs Subnet CIDRs

VPC nodes and Subnet nodes store different CIDR data, and different tools surface them differently:

### Data Model

- **VPC node**: `cidr_block` (primary, e.g. `10.150.32.0/20`) + `secondary_cidrs` (list, e.g. `["100.67.0.0/16"]`)
- **Subnet node**: `cidr_block` (single subnet CIDR, e.g. `100.67.0.0/18`)

Secondary CIDRs are VPC-level associations from `CidrBlockAssociationSet`. Subnets are carved from those CIDRs (e.g. a `/16` VPC CIDR split into three `/18` subnets).

### Tool Behavior

| Tool | Shows | Source |
|------|-------|--------|
| `get_vpc_topology` | Primary VPC CIDR + individual subnet CIDRs | `vpc.cidr_block` + `subnet.cidr_block` |
| `get_resource` (VPC ARN) | Primary + `secondary_cidrs` property | VPC node properties |
| `guided_connectivity_check` (pod CIDR) | VPC secondary CIDRs | `lookup_vpc_cidrs` reads `secondary_cidrs` from VPC node |

### Why This Matters

`get_vpc_topology` does NOT show VPC `secondary_cidrs` — it shows subnet CIDRs. An agent interpreting the topology output may report three `/18` subnets when the actual VPC has two secondary CIDRs (`/17` + `/18`). Both are correct views of the same data at different levels:

```
VPC secondary CIDR: 100.78.0.0/17          → Subnets: 100.78.0.0/18, 100.78.64.0/18
VPC secondary CIDR: 100.78.128.0/18        → Subnet:  100.78.128.0/18
```

For pod CIDR evaluation, `lookup_vpc_cidrs` uses the VPC-level `secondary_cidrs` (not subnet CIDRs), which is the correct granularity for SNAT and ingress rule matching.

## SG Rule Enrichment

### Prefix List Support

SG rules referencing AWS managed prefix lists (`pl-xxx`) are resolved to CIDRs at collection time via `ec2:GetManagedPrefixListEntries`. Stored as `pl:pl-xxx[cidr1,cidr2]` so connectivity evaluation works without extra API calls.

```
# Resolved (ec2_client available):
tcp:443 from pl:pl-abc123[10.0.0.0/8,172.16.0.0/12]

# Unresolved (no client or API error):
tcp:443 from pl:pl-abc123
```

Connectivity tools parse bracket CIDRs and evaluate each with `_cidr_contains`. Unresolved prefix lists are skipped (conservative — no false ALLOW). The `_split_sources` helper ensures commas inside brackets are not treated as source separators.

### SG Name Enrichment

At display time, `sg:sg-xxx` references in rules are enriched to `sg:sg-xxx (my-sg-name)` using a name cache (`load_sg_names`). This makes rules readable without manual SG lookups.

### Deep SG Expansion

`get_resource_security_groups(expand_references=True)` shows the full rules of security groups referenced in `sg:sg-xxx` rules (one level deep). Helps users understand what a referenced SG actually allows.

### Key Files

- `src/collector/ec2_helpers.py` — `summarize_rules`, `_resolve_prefix_list`, tag helpers
- `src/tools/connectivity.py` — `_split_sources`, `_check_sg_allows` with `pl:` handling
- `src/tools/name_cache.py` — `load_sg_names`, `enrich_sg_reference`
- `src/tools/resource_sgs.py` — `expand_references`, `_extract_sg_references`, `_format_referenced_section`

## Future Enhancements

### Connectivity & Resolution
- Union SG evaluation in `guided_connectivity_check` — currently iterates SGs individually (works for ~95% of cases). Add union semantics for the edge case where egress and ingress are satisfied by different SGs on the same ENI. Only worth adding if a real false-DENIED case is encountered.
- Skip VPN inference for VPC IPs in `resolve_source` — when CIDR match finds a VPC with a VPC-type CloudWAN attachment, skip the 4-segment route table scan
- Improve fuzzy matching for truncated names — e.g., `"b-ae1-my-auth"` doesn't match `"b-ae1-my-lambdaAuthorizer"` (prefix-of-suffix, not substring)

### New Collectors
- WAF (WebACLs associated with ALBs, CloudFront, API Gateway)
- Secrets Manager / Parameter Store
- Direct Connect (gateways, virtual interfaces)
- VPN connections (site-to-site VPN details beyond CloudWAN attachments)

### Graph Intelligence
- Blast radius analysis ("if this VPC/TGW goes down, what's affected?")
- Stale resource detection (stopped instances, unused SGs, detached IGWs/NATs)
- Security posture scoring (open SGs, public resources, missing encryption per account)
- Change detection (diff between crawls — "what changed since last refresh?")

### Operational
- Incremental crawling (only update changed resources)
- Cost data integration via AWS Cost Explorer API (actual billing data)
- CloudWatch metrics on graph nodes
- Scheduled refresh via cron or Lambda
- Web UI for graph visualization
- Diagram generation (network topology, architecture diagrams)
