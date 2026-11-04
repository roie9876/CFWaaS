import copy
from uuid import UUID

import pytest

from service.checkpoint_foundation import validate_checkpoint_foundation
from service.models import environment_resource_group_name

SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"
ENVIRONMENT = "00000000-0000-0000-0000-000000000002"
GROUP = environment_resource_group_name("00000000-0000-0000-0000-000000000003")
PREFIX = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{GROUP}/providers/Microsoft.Network"
VNET_NAME = "vnet-cp-security-00000000"
VNET = f"{PREFIX}/virtualNetworks/{VNET_NAME}"


def outputs():
    endpoint = {"publicIp": "8.8.8.8", "bgpAddress": "172.20.255.30", "asn": 65515}
    foundation = {
        "securityVnetId": VNET,
        "securityVnetName": VNET_NAME,
        "firewallFrontendSubnetId": VNET + "/subnets/firewall-frontend",
        "firewallBackendSubnetId": VNET + "/subnets/firewall-backend",
        "managementSubnetId": VNET + "/subnets/management",
        "automationSubnetId": VNET + "/subnets/automation",
        "automationNsgId": PREFIX + "/networkSecurityGroups/nsg-cp-automation-00000000",
        "automationNatGatewayId": PREFIX + "/natGateways/nat-cp-automation-00000000",
        "automationPublicIpId": PREFIX + "/publicIPAddresses/pip-cp-automation-00000000",
        "privateEndpointsSubnetId": VNET + "/subnets/private-endpoints",
        "firewallNsgId": PREFIX + "/networkSecurityGroups/nsg-cp-firewall-00000000",
        "managementNsgId": PREFIX + "/networkSecurityGroups/nsg-cp-management-00000000",
        "firewallFrontendPrivateIp": "172.22.10.4",
        "firewallBackendPrivateIp": "172.22.20.4",
        "routeServerAsn": 65515,
        "routeServerPeerAddresses": ["172.20.254.4", "172.20.254.5"],
    }
    return {
        "connectionManifest": {"type": "Object", "value": {
            "providerIngress": endpoint,
            "providerDelivery": {**endpoint, "publicIp": "1.1.1.1", "asn": 65031}}},
        "checkpointFoundation": {"type": "Object", "value": foundation},
    }


def validate(value):
    return validate_checkpoint_foundation(value, SUBSCRIPTION, GROUP, ENVIRONMENT)


def test_valid_foundation_is_bound_to_provider_group_and_has_both_peers():
    result = validate(outputs())
    assert result.security_vnet_id == VNET
    assert result.firewall_frontend_ip == "172.22.10.4"
    assert result.firewall_backend_ip == "172.22.20.4"
    assert result.automation_nsg_id == PREFIX + "/networkSecurityGroups/nsg-cp-automation-00000000"
    assert result.automation_nat_gateway_id == PREFIX + "/natGateways/nat-cp-automation-00000000"
    assert result.automation_public_ip_id == PREFIX + "/publicIPAddresses/pip-cp-automation-00000000"
    assert result.route_server_asn == 65515
    assert result.route_server_peers == ("172.20.254.4", "172.20.254.5")
    assert result.connection_manifest.providerDelivery.asn == 65031


@pytest.mark.parametrize("key", [
    "securityVnetId", "securityVnetName", "firewallFrontendSubnetId",
    "firewallBackendSubnetId", "managementSubnetId", "automationSubnetId", "automationNsgId",
    "automationNatGatewayId", "automationPublicIpId", "privateEndpointsSubnetId",
    "firewallNsgId", "managementNsgId", "firewallFrontendPrivateIp", "firewallBackendPrivateIp",
])
def test_rejects_any_foundation_resource_or_ip_outside_expected_scope(key):
    value = outputs()
    value["checkpointFoundation"]["value"][key] = "/untrusted"
    with pytest.raises(ValueError, match="provider scope"):
        validate(value)


@pytest.mark.parametrize("peers", [
    [], ["172.20.254.4"], ["172.20.254.4", "172.20.254.4"],
    ["172.20.254.0", "172.20.254.4"], ["172.20.254.63", "172.20.254.4"],
    ["172.20.254.1", "172.20.254.4"], ["172.20.254.2", "172.20.254.4"],
    ["172.20.254.3", "172.20.254.4"],
    ["172.20.255.4", "172.20.254.4"], ["::1", "172.20.254.4"],
    ["invalid", "172.20.254.4"], [None, "172.20.254.4"],
])
def test_rejects_invalid_route_server_peers(peers):
    value = outputs()
    value["checkpointFoundation"]["value"]["routeServerPeerAddresses"] = peers
    with pytest.raises(ValueError, match="Route Server peers"):
        validate(value)


def test_rejects_cross_subscription_group_and_environment_bindings():
    for subscription, group, environment in (
        ("invalid", GROUP, ENVIRONMENT),
        (SUBSCRIPTION, "shared-provider-group", ENVIRONMENT),
        (SUBSCRIPTION, GROUP, "invalid"),
        ("00000000-0000-0000-0000-000000000004", GROUP, ENVIRONMENT),
        (SUBSCRIPTION, environment_resource_group_name("00000000-0000-0000-0000-000000000004"), ENVIRONMENT),
        (SUBSCRIPTION, GROUP, str(UUID(int=1 << 96))),
    ):
        with pytest.raises(ValueError):
            validate_checkpoint_foundation(outputs(), subscription, group, environment)


@pytest.mark.parametrize("mutation", [
    "extra_output", "missing_output", "wrong_type", "extra_field",
    "wrong_asn", "bool_asn", "extra_connection", "private_endpoint",
])
def test_rejects_malformed_and_unsafe_output_shapes_without_echoing_values(mutation):
    value = copy.deepcopy(outputs())
    if mutation == "extra_output":
        value["unexpected"] = "PRIVATE-VALUE"
    elif mutation == "missing_output":
        del value["checkpointFoundation"]
    elif mutation == "wrong_type":
        value["checkpointFoundation"]["type"] = "String"
    elif mutation == "extra_field":
        value["checkpointFoundation"]["value"]["unexpected"] = "PRIVATE-VALUE"
    elif mutation == "wrong_asn":
        value["checkpointFoundation"]["value"]["routeServerAsn"] = 65000
    elif mutation == "bool_asn":
        value["checkpointFoundation"]["value"]["routeServerAsn"] = True
    elif mutation == "extra_connection":
        value["connectionManifest"]["value"]["firewallVip"] = "PRIVATE-VALUE"
    else:
        value["connectionManifest"]["value"]["providerIngress"]["publicIp"] = "10.0.0.1"
    with pytest.raises(ValueError) as error:
        validate(value)
    assert "PRIVATE-VALUE" not in str(error.value)
