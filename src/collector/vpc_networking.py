"""VPC Networking collector — Route Tables, NAT/Internet Gateways, VPC Peering."""

from __future__ import annotations

import structlog
from botocore.exceptions import ClientError

from src.collector.base import BaseCollector
from src.collector.ec2_helpers import _parse_tags, _tag_name
from src.collector.vpc_helpers import _route_target_arn, _summarize_routes
from src.graph.model import NodeLabel, RelationshipType, ResourceEdge, ResourceNode

logger = structlog.get_logger()


# Re-export for backward compatibility (tests import from here)
__all__ = ["VPCNetworkingCollector", "_summarize_routes", "_route_target_arn"]


class VPCNetworkingCollector(BaseCollector):
    """Collects Route Tables, NAT Gateways, Internet Gateways, VPC Peering."""

    def collect_in_region(
        self, region: str,
    ) -> tuple[list[ResourceNode], list[ResourceEdge]]:
        """Collect VPC networking resources in a region."""
        nodes: list[ResourceNode] = []
        edges: list[ResourceEdge] = []
        client = self.client("ec2", region)

        self._collect_route_tables(client, region, nodes, edges)
        self._collect_nat_gateways(client, region, nodes, edges)
        self._collect_internet_gateways(client, region, nodes, edges)
        self._collect_vpc_peering(client, region, nodes, edges)

        return nodes, edges

    def _collect_route_tables(
        self,
        client,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect route tables and their associations."""
        try:
            paginator = client.get_paginator(
                "describe_route_tables",
            )
            for page in paginator.paginate():
                for rt in page["RouteTables"]:
                    self._process_route_table(
                        rt, region, nodes, edges,
                    )
        except ClientError as e:
            logger.error(
                "route_tables_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _process_route_table(
        self,
        rt: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single route table."""
        rt_id = rt["RouteTableId"]
        vpc_id = rt["VpcId"]
        tags = _parse_tags(rt.get("Tags"))
        name = _tag_name(tags) or rt_id

        associations = rt.get("Associations", [])
        is_main = any(
            a.get("Main", False) for a in associations
        )

        routes = rt.get("Routes", [])
        rt_arn = (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":route-table/{rt_id}"
        )

        nodes.append(ResourceNode(
            arn=rt_arn,
            name=name,
            label=NodeLabel.ROUTE_TABLE,
            account_id=self.account_id,
            region=region,
            tags=tags,
            properties={
                "route_table_id": rt_id,
                "vpc_id": vpc_id,
                "is_main": is_main,
                "routes": _summarize_routes(routes),
            },
        ))

        # PART_OF → VPC
        vpc_arn = (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":vpc/{vpc_id}"
        )
        edges.append(ResourceEdge(
            source_arn=rt_arn,
            target_arn=vpc_arn,
            relationship=RelationshipType.PART_OF,
        ))

        # HAS_ROUTE_TABLE (Subnet → RT) for explicit associations
        for assoc in associations:
            subnet_id = assoc.get("SubnetId")
            if not subnet_id:
                continue
            subnet_arn = (
                f"arn:aws:ec2:{region}:{self.account_id}"
                f":subnet/{subnet_id}"
            )
            edges.append(ResourceEdge(
                source_arn=subnet_arn,
                target_arn=rt_arn,
                relationship=RelationshipType.HAS_ROUTE_TABLE,
            ))

        # ROUTES_TO edges for non-local targets
        for route in routes:
            result = _route_target_arn(
                route, region, self.account_id,
            )
            if not result:
                continue
            target_arn, target_id = result
            dest = (
                route.get("DestinationCidrBlock")
                or route.get("DestinationIpv6CidrBlock")
                or route.get("DestinationPrefixListId", "")
            )
            edges.append(ResourceEdge(
                source_arn=rt_arn,
                target_arn=target_arn,
                relationship=RelationshipType.ROUTES_TO,
                properties={
                    "destination": dest,
                    "target_id": target_id,
                },
            ))

    def _collect_nat_gateways(
        self,
        client,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect NAT Gateways."""
        try:
            paginator = client.get_paginator(
                "describe_nat_gateways",
            )
            for page in paginator.paginate():
                for nat in page["NatGateways"]:
                    state = nat.get("State", "")
                    if state not in ("available", "pending"):
                        continue
                    self._process_nat_gateway(
                        nat, region, nodes, edges,
                    )
        except ClientError as e:
            logger.error(
                "nat_gateways_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _process_nat_gateway(
        self,
        nat: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single NAT Gateway."""
        nat_id = nat["NatGatewayId"]
        vpc_id = nat.get("VpcId", "")
        subnet_id = nat.get("SubnetId", "")
        tags = _parse_tags(nat.get("Tags"))
        name = _tag_name(tags) or nat_id

        # Extract IPs from address list
        public_ip = ""
        private_ip = ""
        for addr in nat.get("NatGatewayAddresses", []):
            if addr.get("PublicIp"):
                public_ip = addr["PublicIp"]
            if addr.get("PrivateIp"):
                private_ip = addr["PrivateIp"]

        nat_arn = (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":natgateway/{nat_id}"
        )

        nodes.append(ResourceNode(
            arn=nat_arn,
            name=name,
            label=NodeLabel.NAT_GATEWAY,
            account_id=self.account_id,
            region=region,
            tags=tags,
            properties={
                "nat_gateway_id": nat_id,
                "vpc_id": vpc_id,
                "subnet_id": subnet_id,
                "state": nat.get("State", ""),
                "connectivity_type": nat.get(
                    "ConnectivityType", "public",
                ),
                "public_ip": public_ip,
                "private_ip": private_ip,
            },
        ))

        # RUNS_IN → Subnet
        if subnet_id:
            subnet_arn = (
                f"arn:aws:ec2:{region}:{self.account_id}"
                f":subnet/{subnet_id}"
            )
            edges.append(ResourceEdge(
                source_arn=nat_arn,
                target_arn=subnet_arn,
                relationship=RelationshipType.RUNS_IN,
            ))

        # PART_OF → VPC
        if vpc_id:
            vpc_arn = (
                f"arn:aws:ec2:{region}:{self.account_id}"
                f":vpc/{vpc_id}"
            )
            edges.append(ResourceEdge(
                source_arn=nat_arn,
                target_arn=vpc_arn,
                relationship=RelationshipType.PART_OF,
            ))

    def _collect_internet_gateways(
        self,
        client,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect Internet Gateways."""
        try:
            paginator = client.get_paginator(
                "describe_internet_gateways",
            )
            for page in paginator.paginate():
                for igw in page["InternetGateways"]:
                    self._process_internet_gateway(
                        igw, region, nodes, edges,
                    )
        except ClientError as e:
            logger.error(
                "internet_gateways_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _process_internet_gateway(
        self,
        igw: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single Internet Gateway."""
        igw_id = igw["InternetGatewayId"]
        tags = _parse_tags(igw.get("Tags"))
        name = _tag_name(tags) or igw_id
        attachments = igw.get("Attachments", [])

        state = "detached"
        if attachments:
            state = attachments[0].get("State", "detached")

        igw_arn = (
            f"arn:aws:ec2:{region}:{self.account_id}"
            f":internet-gateway/{igw_id}"
        )

        nodes.append(ResourceNode(
            arn=igw_arn,
            name=name,
            label=NodeLabel.INTERNET_GATEWAY,
            account_id=self.account_id,
            region=region,
            tags=tags,
            properties={
                "igw_id": igw_id,
                "state": state,
            },
        ))

        # ATTACHED_TO → VPC (per attachment)
        for att in attachments:
            vpc_id = att.get("VpcId")
            if not vpc_id:
                continue
            vpc_arn = (
                f"arn:aws:ec2:{region}:{self.account_id}"
                f":vpc/{vpc_id}"
            )
            edges.append(ResourceEdge(
                source_arn=igw_arn,
                target_arn=vpc_arn,
                relationship=RelationshipType.ATTACHED_TO,
            ))

    def _collect_vpc_peering(
        self,
        client,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Collect VPC Peering Connections."""
        try:
            paginator = client.get_paginator(
                "describe_vpc_peering_connections",
            )
            for page in paginator.paginate():
                for pcx in page["VpcPeeringConnections"]:
                    status = pcx.get(
                        "Status", {},
                    ).get("Code", "")
                    if status != "active":
                        continue
                    self._process_vpc_peering(
                        pcx, region, nodes, edges,
                    )
        except ClientError as e:
            logger.error(
                "vpc_peering_failed",
                error_code=e.response["Error"]["Code"],
                account_id=self.account_id,
                region=region,
            )

    def _process_vpc_peering(
        self,
        pcx: dict,
        region: str,
        nodes: list[ResourceNode],
        edges: list[ResourceEdge],
    ) -> None:
        """Process a single VPC Peering Connection."""
        pcx_id = pcx["VpcPeeringConnectionId"]
        tags = _parse_tags(pcx.get("Tags"))
        name = _tag_name(tags) or pcx_id

        requester = pcx.get("RequesterVpcInfo", {})
        accepter = pcx.get("AccepterVpcInfo", {})

        req_vpc_id = requester.get("VpcId", "")
        req_account = requester.get("OwnerId", "")
        req_cidr = requester.get("CidrBlock", "")
        req_region = requester.get("Region", region)

        acc_vpc_id = accepter.get("VpcId", "")
        acc_account = accepter.get("OwnerId", "")
        acc_cidr = accepter.get("CidrBlock", "")
        acc_region = accepter.get("Region", region)

        # Use requester account in ARN to avoid duplicates
        pcx_arn = (
            f"arn:aws:ec2:{region}:{req_account}"
            f":vpc-peering-connection/{pcx_id}"
        )

        nodes.append(ResourceNode(
            arn=pcx_arn,
            name=name,
            label=NodeLabel.VPC_PEERING,
            account_id=self.account_id,
            region=region,
            tags=tags,
            properties={
                "peering_id": pcx_id,
                "status": pcx.get(
                    "Status", {},
                ).get("Code", ""),
                "requester_vpc_id": req_vpc_id,
                "requester_account_id": req_account,
                "requester_cidr": req_cidr,
                "accepter_vpc_id": acc_vpc_id,
                "accepter_account_id": acc_account,
                "accepter_cidr": acc_cidr,
            },
        ))

        # PEERS_WITH → requester VPC
        if req_vpc_id:
            req_vpc_arn = (
                f"arn:aws:ec2:{req_region}:{req_account}"
                f":vpc/{req_vpc_id}"
            )
            edges.append(ResourceEdge(
                source_arn=pcx_arn,
                target_arn=req_vpc_arn,
                relationship=RelationshipType.PEERS_WITH,
                properties={
                    "side": "requester",
                    "vpc_id": req_vpc_id,
                    "account_id": req_account,
                },
            ))

        # PEERS_WITH → accepter VPC
        if acc_vpc_id:
            acc_vpc_arn = (
                f"arn:aws:ec2:{acc_region}:{acc_account}"
                f":vpc/{acc_vpc_id}"
            )
            edges.append(ResourceEdge(
                source_arn=pcx_arn,
                target_arn=acc_vpc_arn,
                relationship=RelationshipType.PEERS_WITH,
                properties={
                    "side": "accepter",
                    "vpc_id": acc_vpc_id,
                    "account_id": acc_account,
                },
            ))
