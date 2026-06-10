"""EC2 collector — VPCs, Subnets, Security Groups, and EC2 Instances."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.collector.ec2_helpers import (
    _parse_tags,
    _summarize_nacl_entries,
    _tag_name,
    summarize_rules,
)
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


class EC2Collector(BaseCollector):
    """Collects VPCs, Subnets, Security Groups, and EC2 Instances."""

    def collect_in_region(
        self, region: str
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect all EC2-related resources in a single region."""
        ec2 = self.client("ec2", region)
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []

        self._collect_vpcs(ec2, region, nodes, edges)
        self._collect_subnets(ec2, region, nodes, edges)
        self._collect_network_acls(ec2, region, nodes, edges)
        self._collect_security_groups(ec2, region, nodes, edges)
        self._collect_instances(ec2, region, nodes, edges)

        return nodes, edges

    def _vpc_arn(self, region: str, vpc_id: str) -> str:
        return f"arn:aws:ec2:{region}:{self.account_id}:vpc/{vpc_id}"

    def _subnet_arn(self, region: str, subnet_id: str) -> str:
        return f"arn:aws:ec2:{region}:{self.account_id}:subnet/{subnet_id}"

    def _sg_arn(self, region: str, sg_id: str) -> str:
        return f"arn:aws:ec2:{region}:{self.account_id}:security-group/{sg_id}"

    def _instance_arn(self, region: str, instance_id: str) -> str:
        return f"arn:aws:ec2:{region}:{self.account_id}:instance/{instance_id}"

    def _eni_arn(self, region: str, eni_id: str) -> str:
        return (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":network-interface/{eni_id}"
        )

    def _nacl_arn(self, region: str, nacl_id: str) -> str:
        return (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":network-acl/{nacl_id}"
        )

    def _account_arn(self) -> str:
        return f"arn:aws:organizations::{self.account_id}:account"

    def _collect_vpcs(
        self,
        ec2,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect VPCs and create BELONGS_TO edges."""
        try:
            paginator = ec2.get_paginator("describe_vpcs")
            for page in paginator.paginate():
                for vpc in page["Vpcs"]:
                    tags = _parse_tags(vpc.get("Tags"))
                    arn = self._vpc_arn(region, vpc["VpcId"])
                    nodes.append(ResourceNode(
                        arn=arn,
                        name=_tag_name(tags) or vpc["VpcId"],
                        label=NodeLabel.VPC,
                        account_id=self.account_id,
                        region=region,
                        tags=tags,
                        properties={
                            "vpc_id": vpc["VpcId"],
                            "cidr_block": vpc["CidrBlock"],
                            "secondary_cidrs": [
                                a["CidrBlock"]
                                for a in vpc.get(
                                    "CidrBlockAssociationSet", [],
                                )
                                if a.get("CidrBlockState", {}).get(
                                    "State",
                                ) == "associated"
                                and a["CidrBlock"] != vpc["CidrBlock"]
                            ],
                            "is_default": vpc.get("IsDefault", False),
                            "state": vpc.get("State", ""),
                            "owner_id": vpc.get(
                                "OwnerId", self.account_id,
                            ),
                        },
                    ))
                    edges.append(ResourceEdge(
                        source_arn=arn,
                        target_arn=self._account_arn(),
                        relationship=RelationshipType.BELONGS_TO,
                    ))
        except ClientError as e:
            logger.error(
                "vpc_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _collect_subnets(
        self,
        ec2,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect Subnets and create PART_OF edges to VPCs."""
        try:
            paginator = ec2.get_paginator("describe_subnets")
            for page in paginator.paginate():
                for subnet in page["Subnets"]:
                    tags = _parse_tags(subnet.get("Tags"))
                    arn = self._subnet_arn(region, subnet["SubnetId"])
                    nodes.append(ResourceNode(
                        arn=arn,
                        name=_tag_name(tags) or subnet["SubnetId"],
                        label=NodeLabel.SUBNET,
                        account_id=self.account_id,
                        region=region,
                        tags=tags,
                        properties={
                            "subnet_id": subnet["SubnetId"],
                            "vpc_id": subnet["VpcId"],
                            "cidr_block": subnet["CidrBlock"],
                            "availability_zone": subnet["AvailabilityZone"],
                            "is_public": subnet.get(
                                "MapPublicIpOnLaunch", False
                            ),
                            "owner_id": subnet.get(
                                "OwnerId", self.account_id,
                            ),
                        },
                    ))
                    edges.append(ResourceEdge(
                        source_arn=arn,
                        target_arn=self._vpc_arn(region, subnet["VpcId"]),
                        relationship=RelationshipType.PART_OF,
                    ))
        except ClientError as e:
            logger.error(
                "subnet_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _collect_network_acls(
        self,
        ec2,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect Network ACLs with subnet associations."""
        try:
            paginator = ec2.get_paginator(
                "describe_network_acls",
            )
            for page in paginator.paginate():
                for nacl in page["NetworkAcls"]:
                    nacl_id = nacl["NetworkAclId"]
                    arn = self._nacl_arn(region, nacl_id)
                    entries = nacl.get("Entries", [])
                    tags = _parse_tags(nacl.get("Tags"))
                    nodes.append(ResourceNode(
                        arn=arn,
                        name=_tag_name(tags) or nacl_id,
                        label=NodeLabel.NETWORK_ACL,
                        account_id=self.account_id,
                        region=region,
                        tags=tags,
                        properties={
                            "network_acl_id": nacl_id,
                            "vpc_id": nacl.get("VpcId", ""),
                            "is_default": nacl.get(
                                "IsDefault", False,
                            ),
                            "ingress_rules":
                                _summarize_nacl_entries(
                                    entries, egress=False,
                                ),
                            "egress_rules":
                                _summarize_nacl_entries(
                                    entries, egress=True,
                                ),
                        },
                    ))
                    edges.append(ResourceEdge(
                        source_arn=arn,
                        target_arn=self._vpc_arn(
                            region, nacl.get("VpcId", ""),
                        ),
                        relationship=RelationshipType.PART_OF,
                    ))
                    for assoc in nacl.get(
                        "Associations", [],
                    ):
                        subnet_id = assoc.get("SubnetId")
                        if subnet_id:
                            edges.append(ResourceEdge(
                                source_arn=self._subnet_arn(
                                    region, subnet_id,
                                ),
                                target_arn=arn,
                                relationship=(
                                    RelationshipType.HAS_NACL
                                ),
                            ))
        except ClientError as e:
            logger.error(
                "nacl_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _collect_security_groups(
        self,
        ec2,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect Security Groups with ingress rules as ALLOWS_INGRESS edges."""
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    tags = _parse_tags(sg.get("Tags"))
                    sg_arn = self._sg_arn(region, sg["GroupId"])
                    ingress_rules = summarize_rules(
                        sg.get("IpPermissions", []),
                        ec2_client=ec2,
                    )
                    egress_rules = summarize_rules(
                        sg.get("IpPermissionsEgress", []),
                        ec2_client=ec2,
                    )
                    nodes.append(ResourceNode(
                        arn=sg_arn,
                        name=_tag_name(tags) or sg.get("GroupName", sg["GroupId"]),
                        label=NodeLabel.SECURITY_GROUP,
                        account_id=self.account_id,
                        region=region,
                        tags=tags,
                        properties={
                            "group_id": sg["GroupId"],
                            "group_name": sg.get("GroupName", ""),
                            "vpc_id": sg.get("VpcId", ""),
                            "description": sg.get("Description", ""),
                            "ingress_rules": ingress_rules,
                            "egress_rules": egress_rules,
                            "owner_id": sg.get(
                                "OwnerId", self.account_id,
                            ),
                        },
                    ))
                    edges.append(ResourceEdge(
                        source_arn=sg_arn,
                        target_arn=self._vpc_arn(region, sg.get("VpcId", "")),
                        relationship=RelationshipType.PART_OF,
                    ))
                    self._collect_sg_ingress_edges(
                        sg, sg_arn, region, edges
                    )
        except ClientError as e:
            logger.error(
                "sg_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _collect_sg_ingress_edges(
        self,
        sg: dict,
        sg_arn: str,
        region: str,
        edges: list[ResourceEdge],
    ) -> None:
        """Create ALLOWS_INGRESS edges for SG-to-SG ingress rules."""
        for rule in sg.get("IpPermissions", []):
            for pair in rule.get("UserIdGroupPairs", []):
                source_sg_id = pair.get("GroupId", "")
                if source_sg_id:
                    edges.append(ResourceEdge(
                        source_arn=self._sg_arn(region, source_sg_id),
                        target_arn=sg_arn,
                        relationship=RelationshipType.ALLOWS_INGRESS,
                        properties={
                            "protocol": rule.get("IpProtocol", ""),
                            "from_port": rule.get("FromPort", -1),
                            "to_port": rule.get("ToPort", -1),
                        },
                    ))

    def _collect_instances(
        self,
        ec2,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect EC2 instances with RUNS_IN and HAS_SG edges."""
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for inst in reservation["Instances"]:
                        self._process_instance(inst, region, nodes, edges)
        except ClientError as e:
            logger.error(
                "instance_collection_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _process_instance(
        self,
        inst: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single EC2 instance into nodes and edges."""
        tags = _parse_tags(inst.get("Tags"))
        instance_id = inst["InstanceId"]
        arn = self._instance_arn(region, instance_id)

        nodes.append(ResourceNode(
            arn=arn,
            name=_tag_name(tags) or instance_id,
            label=NodeLabel.EC2_INSTANCE,
            account_id=self.account_id,
            region=region,
            tags=tags,
            properties={
                "instance_id": instance_id,
                "instance_type": inst.get("InstanceType", ""),
                "state": inst.get("State", {}).get("Name", ""),
                "private_ip": inst.get("PrivateIpAddress", ""),
                "public_ip": inst.get("PublicIpAddress", ""),
                "ami_id": inst.get("ImageId", ""),
                "launch_time": str(inst.get("LaunchTime", "")),
                "subnet_id": inst.get("SubnetId", ""),
                "vpc_id": inst.get("VpcId", ""),
            },
        ))

        # RUNS_IN subnet
        subnet_id = inst.get("SubnetId")
        if subnet_id:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=self._subnet_arn(region, subnet_id),
                relationship=RelationshipType.RUNS_IN,
            ))

        # HAS_SG for each security group.
        # Collect from instance-level field AND ENI-level Groups
        # to cover both legacy and VPC instances. Deduplicate
        # by group_id since the same SG may appear in both.
        sg_ids: set[str] = set()
        for sg in inst.get("SecurityGroups", []):
            sg_ids.add(sg["GroupId"])
        for eni in inst.get("NetworkInterfaces", []):
            for sg in eni.get("Groups", []):
                sg_ids.add(sg["GroupId"])
        for sg_id in sg_ids:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=self._sg_arn(region, sg_id),
                relationship=RelationshipType.HAS_SG,
            ))

        # Per-ENI nodes and edges for granular SG tracking
        for eni in inst.get("NetworkInterfaces", []):
            self._process_eni(eni, arn, region, nodes, edges)

        # HAS_ROLE if an IAM instance profile is attached
        profile = inst.get("IamInstanceProfile")
        if profile:
            edges.append(ResourceEdge(
                source_arn=arn,
                target_arn=profile["Arn"],
                relationship=RelationshipType.HAS_ROLE,
            ))

    def _process_eni(
        self,
        eni: dict,
        instance_arn: str,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single ENI into a node and edges."""
        eni_id = eni.get("NetworkInterfaceId", "")
        if not eni_id:
            return
        arn = self._eni_arn(region, eni_id)
        attachment = eni.get("Attachment", {})
        device_idx = attachment.get("DeviceIndex", -1)

        nodes.append(ResourceNode(
            arn=arn,
            name=eni.get("Description", "") or eni_id,
            label=NodeLabel.NETWORK_INTERFACE,
            account_id=self.account_id,
            region=region,
            properties={
                "eni_id": eni_id,
                "subnet_id": eni.get("SubnetId", ""),
                "vpc_id": eni.get("VpcId", ""),
                "private_ip": eni.get(
                    "PrivateIpAddress", "",
                ),
                "is_primary": device_idx == 0,
                "status": eni.get("Status", ""),
                "device_index": device_idx,
            },
        ))

        edges.append(ResourceEdge(
            source_arn=instance_arn,
            target_arn=arn,
            relationship=RelationshipType.HAS_ENI,
        ))

        for sg in eni.get("Groups", []):
            group_id = sg.get("GroupId", "")
            if group_id:
                edges.append(ResourceEdge(
                    source_arn=arn,
                    target_arn=self._sg_arn(
                        region, group_id,
                    ),
                    relationship=RelationshipType.HAS_SG,
                ))
