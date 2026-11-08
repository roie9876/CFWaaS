"""Specialize the validated Check Point security foundation without VPN transport."""
import copy

from .templates import Templates


def peering_foundation(template: dict) -> dict:
    Templates.validate_checkpoint_foundation(template)
    if "firewallTopology" not in template["parameters"]:
        raise ValueError("Peering requires the VMSS-capable Check Point release")
    result = copy.deepcopy(template)
    result["parameters"] = {
        name: result["parameters"][name]
        for name in ("location", "environmentId", "adminAllowedSources", "firewallTopology")
    }
    allowed = {
        "Microsoft.Network/networkSecurityGroups",
        "Microsoft.Network/networkSecurityGroups/securityRules",
        "Microsoft.Network/natGateways",
    }
    special = {
        "Microsoft.Network/virtualNetworks": {"[variables('securityVnetName')]"},
        "Microsoft.Network/publicIPAddresses": {"[format('pip-cp-automation-{0}', variables('suffix'))]"},
        "Microsoft.Network/routeTables": {
            "[format('rt-cp-security-{0}', variables('suffix'))]",
            "[format('rt-cp-management-{0}', variables('suffix'))]",
        },
    }
    resources = [
        resource for resource in result["resources"]
        if resource["type"] in allowed or resource.get("name") in special.get(resource["type"], set())
    ]
    if (len([item for item in resources if item["type"] == "Microsoft.Network/virtualNetworks"]) != 1
            or any(any(token in dependency for token in (
                "checkpoint-", "vnet-cp-pi", "vnet-cp-pd", "rt-cp-pi"))
                for item in resources for dependency in item.get("dependsOn", []))):
        raise ValueError("Unsupported Check Point security foundation")
    # The specialized template must never retain a dependency on a discarded VPN module.
    result["resources"] = resources
    for resource in resources:
        if resource["type"] == "Microsoft.Network/routeTables":
            resource["properties"]["disableBgpRoutePropagation"] = True
    foundation = result["outputs"]["checkpointFoundation"]["value"]
    del foundation["routeServerAsn"]
    del foundation["routeServerPeerAddresses"]
    foundation["connectivityMode"] = "peering"
    result["outputs"]["connectionManifest"]["value"] = {
        "connectivityMode": "peering",
        "providerVnetId": foundation["securityVnetId"],
        "firewallVip": "172.22.20.4",
    }
    return result
