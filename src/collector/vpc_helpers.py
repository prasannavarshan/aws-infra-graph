"""VPC networking helper functions — route summarization, target ARN construction."""

from __future__ import annotations


def _summarize_routes(routes: list[dict]) -> str:
    """Summarize route table routes into a readable string.

    Format: '10.0.0.0/16 -> local; 0.0.0.0/0 -> igw-abc123'
    """
    parts: list[str] = []
    for route in routes:
        dest = (
            route.get("DestinationCidrBlock")
            or route.get("DestinationIpv6CidrBlock")
            or route.get("DestinationPrefixListId", "")
        )
        if not dest:
            continue

        state = route.get("State", "active")
        if state == "blackhole":
            continue

        target = (
            route.get("GatewayId")
            or route.get("NatGatewayId")
            or route.get("TransitGatewayId")
            or route.get("VpcPeeringConnectionId")
            or route.get("NetworkInterfaceId")
            or route.get("InstanceId")
            or "local"
        )
        parts.append(f"{dest} -> {target}")

    return "; ".join(parts) if parts else "none"


def _route_target_arn(
    route: dict, region: str, account_id: str,
) -> tuple[str, str] | None:
    """Build ARN for a route target, skipping local routes.

    Returns:
        (target_arn, target_id) or None if local/unsupported.
    """
    if route.get("State") == "blackhole":
        return None

    gw_id = route.get("GatewayId", "")
    if gw_id and gw_id != "local":
        if gw_id.startswith("igw-"):
            arn = (
                f"arn:aws:ec2:{region}:{account_id}"
                f":internet-gateway/{gw_id}"
            )
            return arn, gw_id
        if gw_id.startswith("vpce-"):
            arn = (
                f"arn:aws:ec2:{region}:{account_id}"
                f":vpc-endpoint/{gw_id}"
            )
            return arn, gw_id

    nat_id = route.get("NatGatewayId")
    if nat_id:
        arn = (
            f"arn:aws:ec2:{region}:{account_id}"
            f":natgateway/{nat_id}"
        )
        return arn, nat_id

    tgw_id = route.get("TransitGatewayId")
    if tgw_id:
        arn = (
            f"arn:aws:ec2:{region}:{account_id}"
            f":transit-gateway/{tgw_id}"
        )
        return arn, tgw_id

    pcx_id = route.get("VpcPeeringConnectionId")
    if pcx_id:
        arn = (
            f"arn:aws:ec2:{region}:{account_id}"
            f":vpc-peering-connection/{pcx_id}"
        )
        return arn, pcx_id

    return None
