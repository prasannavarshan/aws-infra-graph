"""EC2 instance running Neo4j 5 Community Edition on EBS gp3 storage."""

from __future__ import annotations

import aws_cdk as cdk
from aws_cdk import (
    aws_ec2 as ec2,
)
from aws_cdk import (
    aws_iam as iam,
)
from constructs import Construct


class Neo4jStack(cdk.Stack):
    """EC2 t3.large running Neo4j 5 Community on EBS gp3 — no NFS, no stunnel."""

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        vpc_id: str,
        private_subnet_ids: list[str],
        **kwargs,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        vpc = ec2.Vpc.from_lookup(self, "Vpc", vpc_id=vpc_id)

        # Use VPC-level private subnet selection — ec2.Instance needs AZ info,
        # which Subnet.from_subnet_id() cannot provide without full attributes.
        private_subnets = ec2.SubnetSelection(
            subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
        )

        # Security group — Bolt + HTTP from private address space only
        self.neo4j_sg = ec2.SecurityGroup(
            self, "Neo4jSg",
            vpc=vpc,
            description="Neo4j EC2 - Bolt and HTTP browser",
        )
        # 10.0.0.0/8 covers all private subnets; public internet cannot reach this
        self.neo4j_sg.add_ingress_rule(
            ec2.Peer.ipv4("10.0.0.0/8"),
            ec2.Port.tcp(7687),
            "Bolt from VPC",
        )
        self.neo4j_sg.add_ingress_rule(
            ec2.Peer.ipv4("10.0.0.0/8"),
            ec2.Port.tcp(7474),
            "HTTP browser from VPC",
        )

        # IAM role — SSM access so we can shell in without SSH keys
        role = iam.Role(
            self, "Neo4jRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonSSMManagedInstanceCore",
                ),
            ],
        )

        user_data = ec2.UserData.for_linux()
        user_data.add_commands(
            "set -euxo pipefail",
            "exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1",

            # ── OS baseline ───────────────────────────────────────────────────
            "apt-get update -y",
            "apt-get install -y openjdk-17-jdk wget curl gnupg xfsprogs awscli",

            # ── Kernel tuning required by Neo4j ──────────────────────────────
            # vm.swappiness=0: avoid swapping JVM heap to disk (causes GC pauses)
            "sysctl -w vm.swappiness=0",
            "echo 'vm.swappiness=0' >> /etc/sysctl.d/99-neo4j.conf",
            # Disable transparent huge pages — Neo4j explicitly recommends this
            "echo never > /sys/kernel/mm/transparent_hugepage/enabled",
            "echo never > /sys/kernel/mm/transparent_hugepage/defrag",
            "cat >> /etc/rc.local << 'RC'",
            "echo never > /sys/kernel/mm/transparent_hugepage/enabled",
            "echo never > /sys/kernel/mm/transparent_hugepage/defrag",
            "RC",
            "chmod +x /etc/rc.local",
            # File descriptor limits — Neo4j opens many store files simultaneously
            "echo '* soft nofile 60000' >> /etc/security/limits.conf",
            "echo '* hard nofile 60000' >> /etc/security/limits.conf",
            "echo 'neo4j soft nofile 60000' >> /etc/security/limits.conf",
            "echo 'neo4j hard nofile 60000' >> /etc/security/limits.conf",

            # ── EBS data volume: format XFS + mount at /var/lib/neo4j/data ─────
            # On Nitro (t3) instances the block device /dev/sdb maps to the
            # NVMe namespace /dev/nvme1n1 in the OS. Detect it at runtime by
            # finding the disk that is NOT the root disk.
            "ROOT_DISK=$(lsblk -ndo PKNAME $(findmnt -n -o SOURCE /))",
            "DATA_DEV=$(lsblk -ndo NAME,TYPE | awk '$2==\"disk\" && $1!=\"'\"$ROOT_DISK\"'\"' | head -1 | awk '{print \"/dev/\"$1}')",
            "echo \"Detected data device: $DATA_DEV\"",
            "mkfs.xfs $DATA_DEV",
            "mkdir -p /var/lib/neo4j/data",
            "mount -o defaults,noatime $DATA_DEV /var/lib/neo4j/data",
            # Use UUID in fstab so device renaming doesn't break mounts on restart
            "DATA_UUID=$(blkid -s UUID -o value $DATA_DEV)",
            "echo \"UUID=$DATA_UUID /var/lib/neo4j/data xfs defaults,noatime 0 2\" >> /etc/fstab",

            # ── Neo4j apt repo ────────────────────────────────────────────────
            "mkdir -p /etc/apt/keyrings",
            # gpg --dearmor needs a file input (not stdin) when there is no TTY
            "wget -q -O /tmp/neo4j.key https://debian.neo4j.com/neotechnology.gpg.key"
            " && gpg --batch --yes --dearmor /tmp/neo4j.key > /etc/apt/keyrings/neo4j.gpg",
            "echo 'deb [signed-by=/etc/apt/keyrings/neo4j.gpg]"
            " https://debian.neo4j.com stable 5'"
            " | tee /etc/apt/sources.list.d/neo4j.list",
            "apt-get update -y",
            # Pin Neo4j so unattended upgrades don't break a running instance
            "apt-get install -y neo4j",
            "apt-mark hold neo4j",

            # ── Fix data directory ownership after mount ──────────────────────
            "chown -R neo4j:neo4j /var/lib/neo4j/data",
            "chmod 750 /var/lib/neo4j/data",

            # ── APOC plugin ───────────────────────────────────────────────────
            # neo4j --version prints e.g. "neo4j 5.18.0" — extract the semver
            "NEO4J_VERSION=$(neo4j --version | grep -oP '[0-9]+\\.[0-9]+\\.[0-9]+')",
            'wget -q -O /var/lib/neo4j/plugins/apoc-core.jar'
            ' "https://github.com/neo4j/apoc/releases/download/'
            '${NEO4J_VERSION}/apoc-${NEO4J_VERSION}-core.jar"',
            "chown neo4j:neo4j /var/lib/neo4j/plugins/apoc-core.jar",

            # ── neo4j.conf ────────────────────────────────────────────────────
            # Listen on all interfaces so ECS tasks can reach Bolt
            # The line may be commented differently across versions; use a
            # targeted append+comment approach instead of fragile sed.
            "sed -i 's|^#*server.default_listen_address=.*"
            "|server.default_listen_address=0.0.0.0|' /etc/neo4j/neo4j.conf",
            # If the line doesn't exist at all, append it
            "grep -q '^server.default_listen_address' /etc/neo4j/neo4j.conf"
            " || echo 'server.default_listen_address=0.0.0.0' >> /etc/neo4j/neo4j.conf",

            # t3.large = 8 GB RAM. Allocation:
            #   heap:       3 GB  (initial = max avoids resize GC pauses)
            #   pagecache:  2 GB  (graph store hot data)
            #   OS + JVM:   ~3 GB remainder
            "echo 'server.memory.heap.initial_size=3g' >> /etc/neo4j/neo4j.conf",
            "echo 'server.memory.heap.max_size=3g'     >> /etc/neo4j/neo4j.conf",
            "echo 'server.memory.pagecache.size=2g'    >> /etc/neo4j/neo4j.conf",

            # APOC permissions — Neo4j 5 requires apoc.* settings in apoc.conf
            "echo 'dbms.security.procedures.unrestricted=apoc.*' >> /etc/neo4j/neo4j.conf",
            "printf 'apoc.export.file.enabled=true\\napoc.import.file.enabled=true\\n'"
            " > /etc/neo4j/apoc.conf",
            "chown neo4j:neo4j /etc/neo4j/apoc.conf",

            # Bolt connector explicitly on all interfaces
            "echo 'server.bolt.listen_address=0.0.0.0:7687' >> /etc/neo4j/neo4j.conf",

            # ── systemd service hardening ─────────────────────────────────────
            "mkdir -p /etc/systemd/system/neo4j.service.d",
            # Raise fd limit inside the unit (security/limits.conf alone isn't
            # enough for systemd-managed services)
            "cat > /etc/systemd/system/neo4j.service.d/override.conf << 'UNIT'",
            "[Service]",
            "LimitNOFILE=60000",
            # Protect from OOM killer — negative score = less likely to be killed
            "OOMScoreAdjust=-500",
            # Auto-restart on crash with a 10s backoff
            "Restart=on-failure",
            "RestartSec=10",
            # Clean up any stale store lock left by an unclean shutdown
            "ExecStartPre=/bin/bash -c 'find /var/lib/neo4j/data/databases -name store_lock -delete 2>/dev/null || true'",
            "UNIT",
            "systemctl daemon-reload",

            # ── Initial password (must run as neo4j user before first start) ──
            "sudo -u neo4j neo4j-admin dbms set-initial-password changeme",

            # ── Start ─────────────────────────────────────────────────────────
            "systemctl enable neo4j",
            "systemctl start neo4j",

            # Wait for Bolt to be ready before signalling success
            "for i in $(seq 1 30); do"
            "  nc -z localhost 7687 && echo 'Neo4j Bolt ready' && break;"
            "  sleep 5;"
            "done",
        )

        instance = ec2.Instance(
            self, "Neo4jInstance",
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.T3, ec2.InstanceSize.LARGE,
            ),
            machine_image=ec2.MachineImage.from_ssm_parameter(
                "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id",
                os=ec2.OperatingSystemType.LINUX,
            ),
            vpc=vpc,
            vpc_subnets=private_subnets,
            security_group=self.neo4j_sg,
            role=role,
            user_data=user_data,
            require_imdsv2=True,
            # SCP DTCTSCP009 denies ec2:RunInstances when AssociatePublicIpAddress
            # is absent or true. Explicitly set it false via the launch template.
            associate_public_ip_address=False,
            block_devices=[
                # Root OS volume — 30 GB is plenty for Ubuntu + Neo4j binaries
                ec2.BlockDevice(
                    device_name="/dev/sda1",
                    volume=ec2.BlockDeviceVolume.ebs(
                        30,
                        volume_type=ec2.EbsDeviceVolumeType.GP3,
                        encrypted=True,
                        delete_on_termination=True,
                    ),
                ),
                # Dedicated data volume — XFS, separate lifecycle from instance
                ec2.BlockDevice(
                    device_name="/dev/sdb",
                    volume=ec2.BlockDeviceVolume.ebs(
                        100,
                        volume_type=ec2.EbsDeviceVolumeType.GP3,
                        iops=3000,
                        encrypted=True,
                        delete_on_termination=False,
                    ),
                ),
            ],
        )

        cdk.Tags.of(instance).add("Name", "aws-infra-graph-neo4j")
        cdk.Tags.of(instance).add("Application", "aws-infra-graph")
        cdk.Tags.of(instance).add("Environment", "Dev")
        cdk.Tags.of(instance).add("Team", "platform-engineering")
        cdk.Tags.of(instance).add("Owner", "owner@example.com")

        self.neo4j_host = instance.instance_private_ip

        cdk.CfnOutput(self, "Neo4jPrivateIp", value=self.neo4j_host)
        cdk.CfnOutput(
            self, "Neo4jBoltUri",
            value=f"bolt://{self.neo4j_host}:7687",
        )
