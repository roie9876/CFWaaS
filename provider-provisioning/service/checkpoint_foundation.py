import ipaddress
from dataclasses import dataclass

from .config import uuid_text
from .models import ConnectionManifest, environment_resource_group_name


@dataclass(frozen=True)
class CheckpointFoundation:
    connection_manifest: ConnectionManifest | None
    security_vnet_id: str
    security_vnet_name: str
    firewall_frontend_subnet_id: str
    firewall_backend_subnet_id: str
    management_subnet_id: str
    automation_subnet_id: str
    automation_nsg_id: str
    automation_nat_gateway_id: str
    automation_public_ip_id: str
    private_endpoints_subnet_id: str
    firewall_nsg_id: str
    management_nsg_id: str
    firewall_frontend_ip: str
    firewall_backend_ip: str
    route_server_asn: int | None
    route_server_peers: tuple[str, str] | None
    firewall_topology: str = "single"
    connectivity_mode: str = "vpn"


def _output(outputs: dict, name: str) -> dict:
    item = outputs.get(name)
    if (not isinstance(item, dict) or set(item) - {"type", "value"}
            or not isinstance(item.get("type"), str) or item["type"].lower() != "object"
            or not isinstance(item.get("value"), dict)):
        raise ValueError("Invalid Check Point deployment output")
    return item["value"]


def validate_checkpoint_route_server_peers(peers: object) -> tuple[str, str]:
    subnet = ipaddress.IPv4Network("172.20.254.0/26")
    if not isinstance(peers, list) or len(peers) != 2 or not all(isinstance(item, str) for item in peers):
        raise ValueError("Invalid Check Point Route Server peers")
    try:
        addresses = tuple(ipaddress.IPv4Address(item) for item in peers)
    except ipaddress.AddressValueError:
        raise ValueError("Invalid Check Point Route Server peers") from None
    reserved = {subnet.network_address + offset for offset in range(4)} | {subnet.broadcast_address}
    if (len(set(addresses)) != 2
            or any(address not in subnet or address in reserved for address in addresses)):
        raise ValueError("Invalid Check Point Route Server peers")
    return str(addresses[0]), str(addresses[1])


def validate_checkpoint_foundation(
        outputs: dict, provider_subscription: str, group_name: str,
        environment_id: str, firewall_topology: str = "single",
        connectivity_mode: str = "vpn") -> CheckpointFoundation:
    try:
        uuid_text(provider_subscription)
        uuid_text(environment_id)
        if (not isinstance(group_name, str) or not group_name.startswith("rg-faas-env-")
                or environment_resource_group_name(group_name.removeprefix("rg-faas-env-")) != group_name
                or firewall_topology not in ("single", "vmss")
                or connectivity_mode not in ("vpn", "peering")
                or connectivity_mode == "peering" and firewall_topology != "vmss"):
            raise ValueError()
    except (TypeError, ValueError, AttributeError):
        raise ValueError("Invalid Check Point provider scope") from None
    if not isinstance(outputs, dict) or set(outputs) != {"connectionManifest", "checkpointFoundation"}:
        raise ValueError("Invalid Check Point deployment outputs")
    connection = _output(outputs, "connectionManifest")
    manifest = None
    if connectivity_mode == "vpn":
        if set(connection) != {"providerIngress", "providerDelivery"}:
            raise ValueError("Invalid Check Point connection manifest")
        try:
            manifest = ConnectionManifest.model_validate(connection)
        except (ValueError, TypeError):
            raise ValueError("Invalid Check Point connection manifest") from None

    foundation = _output(outputs, "checkpointFoundation")
    suffix = environment_id[:8]
    group_id = f"/subscriptions/{provider_subscription}/resourceGroups/{group_name}"
    vnet_name = "vnet-cp-security-" + suffix
    vnet_id = f"{group_id}/providers/Microsoft.Network/virtualNetworks/{vnet_name}"
    nsg_scope = f"{group_id}/providers/Microsoft.Network/networkSecurityGroups"
    expected = {
        "securityVnetId": vnet_id,
        "securityVnetName": vnet_name,
        "firewallFrontendSubnetId": vnet_id + "/subnets/firewall-frontend",
        "firewallBackendSubnetId": vnet_id + "/subnets/firewall-backend",
        "managementSubnetId": vnet_id + "/subnets/management",
        "automationSubnetId": vnet_id + "/subnets/automation",
        "automationNsgId": f"{nsg_scope}/nsg-cp-automation-{suffix}",
        "automationNatGatewayId": f"{group_id}/providers/Microsoft.Network/natGateways/nat-cp-automation-{suffix}",
        "automationPublicIpId": f"{group_id}/providers/Microsoft.Network/publicIPAddresses/pip-cp-automation-{suffix}",
        "privateEndpointsSubnetId": vnet_id + "/subnets/private-endpoints",
        "firewallNsgId": f"{nsg_scope}/nsg-cp-firewall-{suffix}",
        "managementNsgId": f"{nsg_scope}/nsg-cp-management-{suffix}",
        "firewallFrontendPrivateIp": "172.22.10.4",
        "firewallBackendPrivateIp": "172.22.20.4",
    }
    # Outputs from templates before the topology parameter carry no marker and are single-gateway.
    reported = foundation.get("firewallTopology", "single")
    routing_fields = ({"routeServerAsn", "routeServerPeerAddresses"} if connectivity_mode == "vpn"
                      else {"connectivityMode"})
    if (set(foundation) - {"firewallTopology"} != set(expected) | routing_fields
            or reported != firewall_topology
            or any(not isinstance(foundation[key], str)
                   or foundation[key].lower() != value.lower() for key, value in expected.items())):
        raise ValueError("Check Point foundation does not match the provider scope")
    peers, asn = None, None
    if connectivity_mode == "vpn":
        if type(foundation["routeServerAsn"]) is not int or foundation["routeServerAsn"] != 65515:
            raise ValueError("Invalid Check Point Route Server ASN")
        peers, asn = validate_checkpoint_route_server_peers(foundation["routeServerPeerAddresses"]), 65515
    elif (foundation["connectivityMode"] != "peering"
          or connection != {"connectivityMode": "peering", "providerVnetId": vnet_id,
                            "firewallVip": "172.22.20.4"}):
        raise ValueError("Invalid Check Point peering manifest")
    return CheckpointFoundation(
        connection_manifest=manifest,
        security_vnet_id=expected["securityVnetId"],
        security_vnet_name=vnet_name,
        firewall_frontend_subnet_id=expected["firewallFrontendSubnetId"],
        firewall_backend_subnet_id=expected["firewallBackendSubnetId"],
        management_subnet_id=expected["managementSubnetId"],
        automation_subnet_id=expected["automationSubnetId"],
        automation_nsg_id=expected["automationNsgId"],
        automation_nat_gateway_id=expected["automationNatGatewayId"],
        automation_public_ip_id=expected["automationPublicIpId"],
        private_endpoints_subnet_id=expected["privateEndpointsSubnetId"],
        firewall_nsg_id=expected["firewallNsgId"],
        management_nsg_id=expected["managementNsgId"],
        firewall_frontend_ip=expected["firewallFrontendPrivateIp"],
        firewall_backend_ip=expected["firewallBackendPrivateIp"],
        route_server_asn=asn,
        route_server_peers=peers,
        firewall_topology=firewall_topology,
        connectivity_mode=connectivity_mode,
    )
