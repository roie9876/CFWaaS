"""Read-only discovery of the fixed two-instance Check Point scale set gateways."""
import ipaddress
import re
from collections.abc import Callable

import httpx

from .checkpoint_gaia import CheckpointGaiaError, CheckpointGateway

ARM = "https://management.azure.com"
NIC_API_VERSION = "2018-10-01"
FRONTEND_PEERS = ("172.22.10.4", "172.22.10.5")
FRONTEND_SUBNET = ipaddress.IPv4Network("172.22.10.0/24")
BACKEND_SUBNET = ipaddress.IPv4Network("172.22.20.0/24")
INTERNAL_LOAD_BALANCER_IP = "172.22.20.4"


def scale_set_interfaces_url(group_id: str, environment_id: str) -> str:
    return (f"{ARM}{group_id}/providers/Microsoft.Compute/virtualMachineScaleSets/cp-vmss-{environment_id[:8]}"
            f"/networkInterfaces?api-version={NIC_API_VERSION}")


def parse_scale_set_gateways(document: object, group_id: str, environment_id: str) -> list[CheckpointGateway]:
    """Require exactly two instances whose frontends match the pre-created Route Server peers."""
    suffix = environment_id[:8]
    scale_set = f"{group_id}/providers/Microsoft.Compute/virtualMachineScaleSets/cp-vmss-{suffix}".lower()
    vnet = f"{group_id}/providers/Microsoft.Network/virtualNetworks/vnet-cp-security-{suffix}".lower()
    if (not isinstance(document, dict) or document.get("nextLink")
            or not isinstance(document.get("value"), list) or len(document["value"]) != 4):
        raise CheckpointGaiaError("Check Point scale set must have exactly two ready instances")
    instances: dict[str, dict[str, str]] = {}
    for nic in document["value"]:
        if not isinstance(nic, dict) or not isinstance(nic.get("id"), str) or not isinstance(nic.get("properties"), dict):
            raise CheckpointGaiaError("Invalid Check Point scale set interface")
        match = re.fullmatch(re.escape(scale_set) + r"/virtualmachines/([0-9]{1,4})/networkinterfaces/(eth[01])",
                             nic["id"].lower())
        configs = nic["properties"].get("ipConfigurations")
        config = configs[0].get("properties") if (isinstance(configs, list) and len(configs) == 1
                                                  and isinstance(configs[0], dict)) else None
        if match is None or not isinstance(config, dict) or not isinstance(config.get("subnet"), dict):
            raise CheckpointGaiaError("Invalid Check Point scale set interface")
        instance, name = match.groups()
        subnet = str(config["subnet"].get("id", "")).lower()
        expected_subnet, network = ((vnet + "/subnets/firewall-frontend", FRONTEND_SUBNET) if name == "eth0"
                                    else (vnet + "/subnets/firewall-backend", BACKEND_SUBNET))
        try:
            address = ipaddress.IPv4Address(config.get("privateIPAddress"))
        except (ipaddress.AddressValueError, ValueError):
            raise CheckpointGaiaError("Invalid Check Point scale set interface") from None
        if (subnet != expected_subnet or address not in network
                or nic["properties"].get("primary") is not (name == "eth0")
                or name in instances.setdefault(instance, {})):
            raise CheckpointGaiaError("Invalid Check Point scale set interface")
        instances[instance][name] = str(address)
    if len(instances) != 2 or any(set(item) != {"eth0", "eth1"} for item in instances.values()):
        raise CheckpointGaiaError("Check Point scale set must have exactly two ready instances")
    gateways = sorted((CheckpointGateway(f"cp-vmss-{suffix}-{instance}", item["eth0"], item["eth1"])
                       for instance, item in instances.items()), key=lambda gateway: gateway.frontend_ip)
    if tuple(gateway.frontend_ip for gateway in gateways) != FRONTEND_PEERS:
        raise CheckpointGaiaError("Check Point scale set frontends do not match the Route Server peers")
    if INTERNAL_LOAD_BALANCER_IP in {gateway.backend_ip for gateway in gateways}:
        raise CheckpointGaiaError("Check Point scale set backend conflicts with the internal load balancer")
    return gateways


def discover_scale_set_gateways(token: Callable[[], str], group_id: str, environment_id: str,
                                client: httpx.Client | None = None) -> list[CheckpointGateway]:
    owned = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=False, trust_env=False)
    try:
        response = client.get(scale_set_interfaces_url(group_id, environment_id),
                              headers={"Authorization": "Bearer " + token()})
        if response.status_code != 200:
            raise CheckpointGaiaError("Check Point scale set interfaces are unavailable")
        try:
            document = response.json()
        except ValueError:
            raise CheckpointGaiaError("Check Point scale set interfaces are unavailable") from None
        return parse_scale_set_gateways(document, group_id, environment_id)
    except httpx.HTTPError:
        raise CheckpointGaiaError("Check Point scale set interfaces are unavailable") from None
    finally:
        if owned:
            client.close()
