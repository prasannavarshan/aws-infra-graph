# Ops Runbook — Neo4j EC2 + EBS

This runbook covers day-to-day operations for the Neo4j instance backing the aws-infra-graph MCP server.

## Architecture

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
         ▲ POST /refresh
  ┌──────┴──────┐
  │  Lambda     │◄── EventBridge (daily at 7 AM MDT)
  └─────────────┘
```

**Two separate CDK stacks:**

| Stack | AWS Resources | Deploy command |
|-------|---------------|----------------|
| `InfraGraphNeo4j` | EC2 t3.large + 100 GB EBS gp3 + 30 GB root EBS | `cdk deploy InfraGraphNeo4j` |
| `InfraGraphCompute` | ECS Fargate + ALB + Lambda | `cdk deploy InfraGraphCompute` |

### Why EC2 for Neo4j (not EFS sidecar)?

The original architecture ran Neo4j as an ECS Fargate sidecar with its `/data` directory on EFS.
This caused recurring `DatabaseUnavailable` crashes in production.

**Root cause:** EFS transit encryption uses stunnel (an in-process TLS proxy). Under heavy write load
during graph crawls, stunnel's TCP connection to the NFS server drops briefly. When that happens,
Neo4j's page cache checkpoint tries to fsync store files through the NFS mount, which returns
`ESTALE` (stale file handle). Neo4j treats any fsync failure as a fatal database error and marks
the database unavailable — requiring a container restart and a fresh crawl.

**Fix:** Move Neo4j to a dedicated EC2 instance with a locally-attached EBS volume. EBS is a
block device — there is no network filesystem, no stunnel, no ESTALE. The Neo4j process talks
directly to the kernel block layer.

The EBS data volume (`/dev/sdb` → `/dev/nvme1n1` on Nitro instances) is mounted at
`/var/lib/neo4j/data`, formatted XFS with `noatime`. The volume has `delete_on_termination=False`,
so graph data survives instance replacement.

---

## Shell access via SSM

The instance has no SSH key pair. Connect using SSM Session Manager:

```bash
# Get the instance ID from CDK outputs or AWS console
aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=aws-infra-graph-neo4j" \
  --query "Reservations[].Instances[].InstanceId" \
  --output text \
  --profile YOUR_AWS_PROFILE

# Start a session
aws ssm start-session \
  --target i-<instance-id> \
  --profile YOUR_AWS_PROFILE
```

Alternatively, use the AWS Console → EC2 → select instance → Connect → Session Manager.

---

## Check Neo4j health

```bash
# Service status
systemctl status neo4j

# Live logs (last 50 lines)
journalctl -u neo4j -n 50 --no-pager

# Follow logs in real time
journalctl -u neo4j -f

# Bolt connectivity from the instance itself
nc -z localhost 7687 && echo "Bolt OK"

# Query the database (should return version info)
cypher-shell -u neo4j -p changeme "RETURN 1 AS ok"
```

From the ECS task (can also test Bolt from a Fargate task):
```bash
# Check health endpoint (includes neo4j connection status)
curl http://localhost:8050/health
```

---

## Check EBS data volume

```bash
# Confirm the volume is mounted
df -h /var/lib/neo4j/data

# Expected output: ~100G total, mounted on /dev/nvme1n1 (XFS)

# Check filesystem health
xfs_info /var/lib/neo4j/data

# Check inode/space usage
du -sh /var/lib/neo4j/data/databases/
```

---

## Restart Neo4j

```bash
systemctl restart neo4j

# Wait for Bolt
for i in $(seq 1 30); do
  nc -z localhost 7687 && echo "Ready after $((i*5))s" && break
  sleep 5
done
```

The systemd override (`/etc/systemd/system/neo4j.service.d/override.conf`) configures
`Restart=on-failure` with `RestartSec=10` — Neo4j will restart automatically after crashes.

If Neo4j is stuck due to a stale store lock from an unclean shutdown:

```bash
find /var/lib/neo4j/data/databases -name store_lock -delete
systemctl start neo4j
```

The `ExecStartPre` in the systemd override already does this automatically on every start.

---

## Change the Neo4j password

The initial password is `changeme` (set via `neo4j-admin dbms set-initial-password` during
UserData). To change it:

```bash
# Option 1: via cypher-shell (database must be running)
cypher-shell -u neo4j -p changeme -d system \
  "ALTER CURRENT USER SET PASSWORD FROM 'changeme' TO 'new-password'"

# Option 2: stop Neo4j, reset, restart
systemctl stop neo4j
sudo -u neo4j neo4j-admin dbms set-initial-password new-password
systemctl start neo4j
```

After changing the password, update the ECS task definition environment variable `NEO4J_PASSWORD`
(stored in AWS Secrets Manager or as a plaintext env var — check the `InfraGraphCompute` stack)
and force a new ECS deployment.

---

## Replacing the EC2 instance

The EBS data volume (`/dev/sdb`, `delete_on_termination=False`) survives instance replacement.
Procedure:

1. Note the data volume's EBS volume ID from the AWS console (EC2 → Instances → block devices).
2. Stop the instance (or terminate — data volume is safe either way).
3. Re-deploy the `InfraGraphNeo4j` CDK stack. A new instance will be launched.
4. **The new instance will format the data volume fresh** (the UserData runs `mkfs.xfs`).
   - If you want to **preserve graph data**: detach the old volume, attach it to the new instance
     as `/dev/sdb` before launching, and skip the CDK deploy (or modify UserData to skip mkfs if
     the filesystem already exists).
   - If you want a **clean start**: let CDK deploy normally. The graph will be rebuilt on the next
     refresh crawl.
5. After the new instance is running, update the `NEO4J_URI` in the `InfraGraphCompute` stack
   if the private IP changed, then redeploy Compute.

> **Data volume tip:** The current IP is a CDK output (`Neo4jPrivateIp`). If it changes after
> instance replacement, run `cdk deploy InfraGraphCompute` — it reads `neo4j.neo4j_host` from
> the Neo4j stack outputs automatically.

---

## Deploying changes

### Code-only change (MCP server logic)

```bash
cd infra
CDK_DOCKER=podman \
  AWS_PROFILE=YOUR_AWS_PROFILE \
  AWS_DEFAULT_REGION=us-east-1 \
  cdk deploy InfraGraphCompute --require-approval never --force --exclusively
```

`--force` is required — without it, CDK skips deployment when the CloudFormation template hasn't
changed (code-only changes update the Docker image but not the template).

`--exclusively` is required — without it, CDK auto-includes `InfraGraphNeo4j` as a dependency
stack and tries to replace the EC2 instance (because the exported `PrivateIp` output is in use
by `InfraGraphCompute`). This causes a rollback and kills the Neo4j instance. Always use
`--exclusively` when deploying only the Compute stack.

### Infrastructure change (EC2 instance, EBS, security groups)

```bash
cd infra
CDK_DOCKER=podman \
  AWS_PROFILE=YOUR_AWS_PROFILE \
  AWS_DEFAULT_REGION=us-east-1 \
  cdk deploy InfraGraphNeo4j --require-approval never
```

If you change both stacks:

```bash
cdk deploy InfraGraphNeo4j InfraGraphCompute --require-approval never --force
```

**Never use `--hotswap`** for Compute stack changes — CDK hotswap registers a new task definition
by copying only the container image, silently dropping the EFS volume configuration. (Even though
we no longer use EFS for Neo4j, hotswap is still unsafe for task definition changes in general.)

### Verifying the new revision is actually running before triggering a crawl

CDK `deploy` registers a new task definition and updates the service, but the old task keeps
running until ECS replaces it (rolling update). If you trigger a crawl immediately after deploy,
it may run on the old code.

Always confirm the running task is on the expected revision before triggering a validation crawl:

```bash
# Step 1 — get the running task ARN
AWS_PROFILE=YOUR_AWS_PROFILE AWS_DEFAULT_REGION=us-east-1 \
  aws ecs list-tasks --cluster infra-graph --output text --query "taskArns"

# Step 2 — confirm it's on the expected task def revision
AWS_PROFILE=YOUR_AWS_PROFILE AWS_DEFAULT_REGION=us-east-1 \
  aws ecs describe-tasks --cluster infra-graph --tasks <task-arn> \
  --query "tasks[0].{rev:taskDefinitionArn,status:lastStatus}" --output json
```

If the revision is still the old one, either wait (~30s) for ECS to complete the rolling replace,
or force it immediately:

```bash
# Force restart — stop the old task, ECS will start a new one on the latest revision
AWS_PROFILE=YOUR_AWS_PROFILE AWS_DEFAULT_REGION=us-east-1 \
  aws ecs stop-task --cluster infra-graph --task <task-arn> \
  --reason "Forcing restart on new task def revision"
```

Then wait ~15s for the new task to reach RUNNING before triggering the crawl.

---

## Memory and resource tuning

Current allocation on t3.large (8 GB RAM):

| Component | Size | Rationale |
|-----------|------|-----------|
| JVM heap | 3 GB (initial = max) | Avoids resize GC pauses; fixed at max |
| Page cache | 2 GB | Hot graph data in memory |
| OS + JVM overhead | ~3 GB | Buffer, OS page cache, JVM non-heap |

Settings are in `/etc/neo4j/neo4j.conf`:

```
server.memory.heap.initial_size=3g
server.memory.heap.max_size=3g
server.memory.pagecache.size=2g
```

To change memory allocation: edit these values, then `systemctl restart neo4j`. No instance
replacement required.

If you upgrade to a t3.xlarge (16 GB): bump heap to 6g and pagecache to 4g.

### Crawl concurrency tuning

| Env var | Default | Effect |
|---------|---------|--------|
| `AWS_MAX_CONCURRENCY` | 5 | Max accounts crawled in parallel |
| `AWS_COLLECTOR_CONCURRENCY` | 10 | Max collectors running in parallel per account |
| `NEO4J_WRITE_CONCURRENCY` | 3 | Max accounts writing to Neo4j simultaneously |

`NEO4J_WRITE_CONCURRENCY=3` was set after profiling a full-org crawl showing ~5h of serialized
Neo4j write queue (was hardcoded to 1). Increase to 4-5 if write bottlenecks persist; decrease
to 1 if you see Neo4j transaction conflicts under heavy load.

Set these in the ECS task definition environment variables or `.env` for local runs.

### Neo4j indexes

On every `connect()`, the MCP server calls `_ensure_indexes()` which creates a `RANGE` index on
`arn` for each of the 51 node labels (`idx_arn_<label>`). This is idempotent (`IF NOT EXISTS`).

Without these indexes, every `MATCH (n {arn: ...})` during edge upserts performs a full graph
scan — O(55K) per lookup. With indexes, it's O(log n) — roughly 3000-4000x faster per lookup.
At 10K edges per large account, this is the difference between 116 minutes and a few seconds of
write time.

If you ever wipe the database and restore from backup, the indexes are recreated automatically on
next restart. To check indexes manually:
```
cypher-shell -u neo4j -p <password> "SHOW INDEXES YIELD name, type WHERE name STARTS WITH 'idx_arn'"
```

---

## APOC plugin

APOC is installed at `/var/lib/neo4j/plugins/apoc-core.jar`. The version matches Neo4j's version
(pinned via `apt-mark hold neo4j`).

APOC settings live in `/etc/neo4j/apoc.conf` (not `neo4j.conf` — Neo4j 5 requirement):

```
apoc.export.file.enabled=true
apoc.import.file.enabled=true
```

`neo4j.conf` contains the procedure whitelist:
```
dbms.security.procedures.unrestricted=apoc.*
```

---

## Kernel settings (applied once via UserData)

These are applied at launch and persist via `/etc/sysctl.d/99-neo4j.conf` and `/etc/rc.local`:

| Setting | Value | Why |
|---------|-------|-----|
| `vm.swappiness` | 0 | Prevents JVM heap from being swapped to disk (causes GC pauses) |
| Transparent huge pages | disabled | Neo4j explicitly recommends disabling THP |
| File descriptor limit | 60,000 | Neo4j opens many store files simultaneously |

To verify:
```bash
cat /proc/sys/vm/swappiness                              # should be 0
cat /sys/kernel/mm/transparent_hugepage/enabled         # should show [never]
ulimit -n                                               # should be 60000 (check as neo4j user)
```

---

## Known gotchas

### NVMe device naming
On Nitro-based instances (t3), block devices attached as `/dev/sdb` in the AWS console appear as
`/dev/nvme1n1` in the OS. The UserData script detects the correct device at runtime:
```bash
ROOT_DISK=$(lsblk -ndo PKNAME $(findmnt -n -o SOURCE /))
DATA_DEV=$(lsblk -ndo NAME,TYPE | awk '$2=="disk" && $1!="'"$ROOT_DISK"'"' | head -1 | awk '{print "/dev/"$1}')
```

### Org SCP: no public IP
The org SCP (`BlockPublicIp4Ec2s`) denies `ec2:RunInstances` when
`AssociatePublicIpAddress` is absent or true. The CDK stack sets `associate_public_ip_address=False`
explicitly.

### Org tag policy: Environment case
The org tag policy requires `Environment=Dev` (capital D). `dev`, `DEV`, etc. will cause
`ec2:RunInstances` to fail with a tag policy violation.

### gpg no TTY in SSM
When running `gpg --dearmor` in a non-interactive SSM shell, stdin-based dearmor fails.
The UserData writes the key to a temp file first:
```bash
wget -q -O /tmp/neo4j.key https://debian.neo4j.com/neotechnology.gpg.key
gpg --batch --yes --dearmor /tmp/neo4j.key > /etc/apt/keyrings/neo4j.gpg
```

### Neo4j initial password
`neo4j-admin dbms set-initial-password` only works before Neo4j has started for the first time.
If Neo4j has already started once (even briefly), use cypher-shell instead:
```bash
cypher-shell -u neo4j -p neo4j -d system \
  "ALTER CURRENT USER SET PASSWORD FROM 'neo4j' TO 'changeme'"
```

### Neo4j 5 and apoc.conf
In Neo4j 5, `apoc.export.file.enabled` and `apoc.import.file.enabled` must be in
`/etc/neo4j/apoc.conf`, not `neo4j.conf`. Putting them in `neo4j.conf` causes Neo4j to fail
to start with "Unknown config option" errors.

---

## Monitoring

### CloudWatch metrics to watch
- EC2 CPU: `AWS/EC2 CPUUtilization` for `i-<instance-id>` — baseline ~5-15%, spikes to 40-60%
  during crawls are normal
- EBS: `VolumeReadOps`, `VolumeWriteOps`, `VolumeQueueLength` — queue depth >1 sustained indicates
  I/O saturation
- EBS: `VolumeConsumedReadWriteOps` — compare against 3000 provisioned IOPS on gp3

### Log locations
| Log | Location |
|-----|----------|
| UserData (launch script) | `/var/log/user-data.log` |
| Neo4j service | `journalctl -u neo4j` |
| Neo4j debug log | `/var/log/neo4j/debug.log` |
| Neo4j query log | `/var/log/neo4j/query.log` |
| MCP server (ECS) | CloudWatch Logs: `/ecs/infra-graph` |

---

## Troubleshooting

### "DatabaseUnavailable" in MCP server logs
1. SSH into instance via SSM.
2. `systemctl status neo4j` — if inactive/failed: `systemctl start neo4j`
3. `journalctl -u neo4j -n 100` — look for `java.io.IOException` or `StoreCopyException`
4. If store lock is stale: `find /var/lib/neo4j/data/databases -name store_lock -delete && systemctl start neo4j`
5. If disk full: `df -h /var/lib/neo4j/data` — may need to expand the EBS volume

### MCP server returns 503 / health check fails
1. Check ECS task is running: `aws ecs list-tasks --cluster infra-graph --profile YOUR_AWS_PROFILE`
2. Check task logs in CloudWatch: `/ecs/infra-graph`
3. Verify Neo4j is reachable from the ECS task: look for `neo4j_connected` in task startup logs
4. If `AuthError`: password mismatch — see "Change the Neo4j password" above

### Crawl runs but graph is empty after refresh
1. Check MCP server logs for collector errors (account-level failures are logged but don't abort the crawl)
2. Verify STS AssumeRole is working: look for `assuming_role account_id=...` log lines
3. Check that `OrganizationAccessRole` exists in target accounts and trusts `InfraGraphTaskRole`
