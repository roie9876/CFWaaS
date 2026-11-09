import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

from .checkpoint_private_data import CHECKPOINT_PRIVATE_DATA_OUTPUTS
from .config import WorkerSettings
from .models import DEFAULT_PROVIDER_VPN_GATEWAY_SKU, PROVIDER_VPN_GATEWAY_SKUS

NETWORK_PARAMETERS = {
    "location": "string", "environmentId": "string",
    "customerIngressPublicIp": "string", "customerIngressBgpAddress": "string",
    "customerIngressAsn": "int", "customerDeliveryPublicIp": "string",
    "customerDeliveryBgpAddress": "string", "customerDeliveryAsn": "int",
    "ingressSharedKey": "secureString", "deliverySharedKey": "secureString",
    "sshPublicKey": "string", "parallelProviderNetworking": "bool",
}
PROOF_PARAMETERS = {"location": "string", "environmentId": "string"}
# Optional: second instance of an active-active customer delivery gateway (four-tunnel BGP mesh).
SECONDARY_DELIVERY_PARAMETERS = {
    "customerDeliverySecondaryPublicIp": "string", "customerDeliverySecondaryBgpAddress": "string",
}
CHECKPOINT_FOUNDATION_PARAMETERS = {
    name: kind for name, kind in NETWORK_PARAMETERS.items()
    if name not in {"sshPublicKey", "parallelProviderNetworking"}
}
CHECKPOINT_FOUNDATION_OUTPUTS = {
    "securityVnetId", "securityVnetName", "firewallFrontendSubnetId",
    "firewallBackendSubnetId", "managementSubnetId", "automationSubnetId", "automationNsgId",
    "automationNatGatewayId", "automationPublicIpId", "privateEndpointsSubnetId",
    "firewallNsgId", "managementNsgId", "firewallFrontendPrivateIp",
    "firewallBackendPrivateIp", "routeServerAsn", "routeServerPeerAddresses",
}
CHECKPOINT_PRIVATE_DATA_RESOURCES = {
    "Microsoft.KeyVault/vaults",
    "Microsoft.Storage/storageAccounts",
    "Microsoft.Storage/storageAccounts/blobServices",
    "Microsoft.Storage/storageAccounts/blobServices/containers",
    "Microsoft.Network/privateDnsZones",
    "Microsoft.Network/privateDnsZones/virtualNetworkLinks",
    "Microsoft.Network/privateEndpoints",
    "Microsoft.Network/privateEndpoints/privateDnsZoneGroups",
}
RESOURCE_TYPES = {
    "Microsoft.Network/routeTables", "Microsoft.Network/virtualNetworks",
    "Microsoft.Network/networkSecurityGroups", "Microsoft.Network/publicIPAddresses",
    "Microsoft.Network/networkInterfaces", "Microsoft.Network/virtualNetworkGateways",
    "Microsoft.Network/localNetworkGateways", "Microsoft.Network/connections",
    "Microsoft.Network/loadBalancers", "Microsoft.Network/virtualNetworks/subnets",
    "Microsoft.Network/virtualNetworks/virtualNetworkPeerings",
    "Microsoft.Network/virtualHubs", "Microsoft.Network/virtualHubs/ipConfigurations",
    "Microsoft.Network/virtualHubs/bgpConnections",
    "Microsoft.Compute/virtualMachines", "Microsoft.Compute/availabilitySets",
}


class Templates:
    def __init__(self, settings: WorkerSettings) -> None:
        self.proof = self.validate(
            json.loads((Path(__file__).parent / "templates/proof.json").read_bytes()), False)
        self.network: dict | None = None
        # Proof remains usable before network onboarding is complete. Once all
        # network inputs are supplied, a bad artifact/key fails closed at startup.
        if settings.template_sha256 and settings.ssh_public_key:
            if not settings.template_path.is_file():
                raise ValueError("Configured provider template is unavailable")
            raw = settings.template_path.read_bytes()
            if (len(raw) > 4 * 1024 * 1024 or len(settings.template_sha256) != 64
                    or hashlib.sha256(raw).hexdigest() != settings.template_sha256.lower()):
                raise ValueError("Provider template hash mismatch")
            self.network = self.validate(json.loads(raw), True)
            key = load_ssh_public_key(settings.ssh_public_key.encode())
            if not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey,
                                    ed25519.Ed25519PublicKey)):
                raise ValueError("Unsupported SSH public key")
            if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
                raise ValueError("SSH RSA key is too small")

    @staticmethod
    def _gateway_sku_parameter(template: dict) -> bool:
        """Optional provider gateway SKU: present only with the exact default and SKU list."""
        parameters = template.get("parameters") if isinstance(template, dict) else None
        if not isinstance(parameters, dict) or "providerVpnGatewaySku" not in parameters:
            return False
        parameter = parameters["providerVpnGatewaySku"]
        if (not isinstance(parameter, dict) or parameter.get("defaultValue") != DEFAULT_PROVIDER_VPN_GATEWAY_SKU
                or parameter.get("allowedValues") != list(PROVIDER_VPN_GATEWAY_SKUS)):
            raise ValueError("Provider VPN gateway SKU must default to VpnGw1AZ")
        return True

    @staticmethod
    def secondary_delivery_parameters(template: dict) -> bool:
        """Optional secondary customer delivery endpoint: both string parameters defaulting to empty, or neither."""
        parameters = template.get("parameters") if isinstance(template, dict) else None
        if not isinstance(parameters, dict):
            return False
        present = [name for name in SECONDARY_DELIVERY_PARAMETERS if name in parameters]
        if not present:
            return False
        if len(present) != len(SECONDARY_DELIVERY_PARAMETERS) or any(
                parameters[name] != {"type": "string", "defaultValue": ""} for name in present):
            raise ValueError("Secondary delivery parameters must be optional strings defaulting to empty")
        return True

    @staticmethod
    def validate(template: dict, network: bool) -> dict:
        root = NETWORK_PARAMETERS if network else PROOF_PARAMETERS
        if network and Templates._gateway_sku_parameter(template):
            root = {**root, "providerVpnGatewaySku": "string"}
        if network and Templates.secondary_delivery_parameters(template):
            root = {**root, **SECONDARY_DELIVERY_PARAMETERS}
        Templates._validate_structure(template, network, 0, root)
        outputs = template.get("outputs", {})
        if network:
            if (not isinstance(outputs, dict) or set(outputs) != {"connectionManifest"}
                    or not isinstance(outputs["connectionManifest"], dict)
                    or outputs["connectionManifest"].get("type") != "object"):
                raise ValueError("Invalid connection manifest output")
        elif outputs or len(template["resources"]) != 1:
            raise ValueError("Proof must contain only one route table and no outputs")
        return template

    @staticmethod
    def validate_checkpoint_foundation(template: dict) -> dict:
        admin_access = (isinstance(template, dict) and isinstance(template.get("parameters"), dict)
                        and "adminAllowedSources" in template["parameters"])
        topology = (isinstance(template, dict) and isinstance(template.get("parameters"), dict)
                    and "firewallTopology" in template["parameters"])
        parameters = {**CHECKPOINT_FOUNDATION_PARAMETERS}
        allowed = (RESOURCE_TYPES - {"Microsoft.Compute/virtualMachines", "Microsoft.Compute/availabilitySets"}
                   | {"Microsoft.Network/natGateways"})
        if admin_access:
            parameters["adminAllowedSources"] = "array"
            allowed.add("Microsoft.Network/networkSecurityGroups/securityRules")
        if topology:
            parameter = template["parameters"]["firewallTopology"]
            if (not admin_access or not isinstance(parameter, dict) or parameter.get("defaultValue") != "single"
                    or parameter.get("allowedValues") != ["single", "vmss"]):
                raise ValueError("Check Point firewall topology must default to the single gateway")
            parameters["firewallTopology"] = "string"
        if Templates._gateway_sku_parameter(template):
            parameters["providerVpnGatewaySku"] = "string"
        if Templates.secondary_delivery_parameters(template):
            parameters.update(SECONDARY_DELIVERY_PARAMETERS)
        Templates._validate_structure(template, True, 0, parameters, allowed)
        if admin_access:
            Templates._validate_checkpoint_admin_access(template, topology)
        outputs = template.get("outputs", {})
        if not isinstance(outputs, dict) or set(outputs) != {"connectionManifest", "checkpointFoundation"}:
            raise ValueError("Invalid Check Point foundation outputs")
        for name, expected in (("connectionManifest", {"providerIngress", "providerDelivery"}),
                               ("checkpointFoundation", CHECKPOINT_FOUNDATION_OUTPUTS
                                | ({"firewallTopology"} if topology else set()))):
            output = outputs[name]
            if (not isinstance(output, dict) or output.get("type") != "object"
                    or not isinstance(output.get("value"), dict) or set(output["value"]) != expected):
                raise ValueError("Invalid Check Point foundation output shape")
        if "sharedkey" in json.dumps(outputs).lower() or "secret" in json.dumps(outputs).lower():
            raise ValueError("Check Point foundation outputs must not contain secrets")

        nat_resources = []
        nat_attachments = []

        def no_vpn_nat(value: object) -> None:
            if isinstance(value, dict):
                if value.get("type") == "Microsoft.Network/natGateways":
                    nat_resources.append(value)
                for key, item in value.items():
                    if not isinstance(key, str):
                        raise ValueError("Invalid Check Point foundation property")
                    if key.lower() in {"ingressnatrules", "egressnatrules",
                                       "enablebgproutetranslationfornat", "natrules"}:
                        raise ValueError("Check Point foundation must not configure VPN NAT")
                    if key.lower() == "natgateway":
                        nat_attachments.append(item)
                    no_vpn_nat(item)
            elif isinstance(value, list):
                for item in value:
                    no_vpn_nat(item)

        no_vpn_nat(template)
        nat_id = ("[resourceId('Microsoft.Network/natGateways', "
                  "format('nat-cp-automation-{0}', variables('suffix')))]")
        nsg_id = ("[resourceId('Microsoft.Network/networkSecurityGroups', "
                  "format('nsg-cp-automation-{0}', variables('suffix')))]")
        route_id = ("[resourceId('Microsoft.Network/routeTables', "
                    "format('rt-cp-security-{0}', variables('suffix')))]")
        public_ip_id = ("[resourceId('Microsoft.Network/publicIPAddresses', "
                        "format('pip-cp-automation-{0}', variables('suffix')))]")
        nat_name = "[format('nat-cp-automation-{0}', variables('suffix'))]"
        nsg_name = "[format('nsg-cp-automation-{0}', variables('suffix'))]"
        public_ip_name = "[format('pip-cp-automation-{0}', variables('suffix'))]"
        resources = template["resources"]
        security_vnets = [item for item in resources
                          if item["type"] == "Microsoft.Network/virtualNetworks"
                          and item.get("name") == "[variables('securityVnetName')]"]
        nsgs = [item for item in resources
                if item["type"] == "Microsoft.Network/networkSecurityGroups" and item.get("name") == nsg_name]
        public_ips = [item for item in resources
                      if item["type"] == "Microsoft.Network/publicIPAddresses"
                      and item.get("name") == public_ip_name]
        routes = [item for item in resources
                  if item["type"] == "Microsoft.Network/routeTables"
                  and item.get("name") == "[format('rt-cp-security-{0}', variables('suffix'))]"]
        subnets = security_vnets[0].get("properties", {}).get("subnets") if len(security_vnets) == 1 else None
        automation = [item for item in subnets
                      if isinstance(item, dict) and item.get("name") == "automation"] if isinstance(subnets, list) else []
        expected_automation = {
            "addressPrefix": "172.22.40.0/23",
            "defaultOutboundAccess": False,
            "networkSecurityGroup": {"id": nsg_id},
            "natGateway": {"id": nat_id},
            "routeTable": {"id": route_id},
            "delegations": [{"name": "container-instances",
                             "properties": {"serviceName": "Microsoft.ContainerInstance/containerGroups"}}],
        }
        expected_rule = {"name": "deny-inbound", "properties": {
            "priority": 100, "direction": "Inbound", "access": "Deny", "protocol": "*",
            "sourceAddressPrefix": "*", "sourcePortRange": "*",
            "destinationAddressPrefix": "*", "destinationPortRange": "*",
        }}
        variables = template.get("variables")
        expected_routes: list[dict] | str = [{"name": "firewall-internet", "properties": {
            "addressPrefix": "0.0.0.0/0", "nextHopType": "Internet"}}]
        if admin_access:
            expected_routes = (
                "[concat(createArray(createObject('name', 'firewall-internet', 'properties', "
                "createObject('addressPrefix', '0.0.0.0/0', 'nextHopType', 'Internet'))), "
                "variables('adminReturnRoutes'))]")
        if (not isinstance(variables, dict)
                or variables.get("suffix") != "[take(parameters('environmentId'), 8)]"
                or variables.get("securityVnetName") != "[format('vnet-cp-security-{0}', variables('suffix'))]"
                or len(nat_resources) != 1 or nat_resources[0].get("name") != nat_name
                or nat_resources[0].get("sku") != {"name": "Standard"}
                or nat_resources[0].get("properties") != {"publicIpAddresses": [{"id": public_ip_id}]}
                or nat_attachments != [{"id": nat_id}]
                or len(automation) != 1 or automation[0].get("properties") != expected_automation
                or type(automation[0]["properties"]["defaultOutboundAccess"]) is not bool
                or len(nsgs) != 1 or nsgs[0].get("properties") != {"securityRules": [expected_rule]}
                or len(public_ips) != 1 or public_ips[0].get("sku") != {"name": "Standard"}
                or public_ips[0].get("properties") != {"publicIPAllocationMethod": "Static"}
                or len(routes) != 1 or routes[0].get("properties") != {
                    "disableBgpRoutePropagation": False, "routes": expected_routes}
                or type(routes[0]["properties"]["disableBgpRoutePropagation"]) is not bool):
            raise ValueError("Check Point automation NAT must be isolated to the runner subnet")
        return template

    @staticmethod
    def _validate_checkpoint_admin_access(template: dict, topology: bool = False) -> None:
        parameter = template["parameters"]["adminAllowedSources"]
        if parameter.get("defaultValue") != [] or parameter.get("maxLength") != 16:
            raise ValueError("Check Point admin sources must be optional and bounded")
        variables = template.get("variables", {})
        copies = variables.get("copy", []) if isinstance(variables, dict) else []
        expected_copy = {
            "name": "adminReturnRoutes", "count": "[length(parameters('adminAllowedSources'))]",
            "input": {"name": "[format('approved-admin-{0}', copyIndex('adminReturnRoutes'))]",
                      "properties": {
                          "addressPrefix": "[parameters('adminAllowedSources')[copyIndex('adminReturnRoutes')]]",
                          "nextHopType": "Internet"}},
        }
        rules = variables.get("adminNsgRules") if isinstance(variables, dict) else None
        expected_rules = [
            {"name": "allow-provider-private", "properties": {
                "priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "*",
                "sourceAddressPrefixes": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
                "sourcePortRange": "*", "destinationAddressPrefix": "*", "destinationPortRange": "*"}},
            {"name": "allow-approved-admin", "properties": {
                "priority": 150, "direction": "Inbound", "access": "Allow", "protocol": "Tcp",
                "sourceAddressPrefixes": "[parameters('adminAllowedSources')]",
                "sourcePortRange": "*", "destinationAddressPrefix": "*", "destinationPortRanges": ["22", "443"]}},
            {"name": "deny-other-inbound", "properties": {
                "priority": 200, "direction": "Inbound", "access": "Deny", "protocol": "*",
                "sourceAddressPrefix": "*", "sourcePortRange": "*",
                "destinationAddressPrefix": "*", "destinationPortRange": "*"}},
        ]
        children = [item for item in template["resources"]
                    if item["type"] == "Microsoft.Network/networkSecurityGroups/securityRules"
                    and "copy" in item]
        probe_rules = [item for item in template["resources"]
                       if item["type"] == "Microsoft.Network/networkSecurityGroups/securityRules"
                       and "copy" not in item]
        expected_probe = [{
            "type": "Microsoft.Network/networkSecurityGroups/securityRules",
            "apiVersion": "2025-05-01",
            "name": "[format('{0}/{1}', format('nsg-cp-firewall-{0}', variables('suffix')), "
                    "'allow-azure-load-balancer')]",
            "condition": "[and(not(empty(parameters('adminAllowedSources'))), "
                         "equals(parameters('firewallTopology'), 'vmss'))]",
            "properties": {"priority": 120, "direction": "Inbound", "access": "Allow", "protocol": "*",
                           "sourceAddressPrefix": "AzureLoadBalancer", "sourcePortRange": "*",
                           "destinationAddressPrefix": "*", "destinationPortRange": "*"},
            "dependsOn": ["[resourceId('Microsoft.Network/networkSecurityGroups', "
                          "format('nsg-cp-firewall-{0}', variables('suffix')))]"],
        }] if topology else []
        gateway_sources = ("'172.22.10.4/32', '172.22.10.5/32', '172.22.20.4/32'" if topology
                           else "'172.22.10.4/32', '172.22.20.4/32'")
        expected_child_properties = {
            "firewallAdminRules": "[variables('adminNsgRules')[copyIndex()].properties]",
            "managementAdminRules": (
                "[union(variables('adminNsgRules')[copyIndex()].properties, if(equals(copyIndex(), 0), "
                f"createObject('sourceAddressPrefixes', createArray({gateway_sources}, "
                "'172.22.30.0/24', '172.22.40.0/23')), createObject()), if(equals(copyIndex(), 1), "
                "createObject('destinationPortRanges', createArray('22', '443', '18190', '19009')), createObject()))]"),
        }
        management_routes = [item for item in template["resources"]
                             if item.get("name") == "[format('rt-cp-management-{0}', variables('suffix'))]"]
        expected_management_copy = {
            "name": "routes", "count": "[length(parameters('adminAllowedSources'))]",
            "input": {"name": "[format('approved-admin-{0}', copyIndex('routes'))]",
                      "properties": {"addressPrefix": "[parameters('adminAllowedSources')[copyIndex('routes')]]",
                                     "nextHopType": "Internet"}},
        }
        if (not isinstance(copies, list) or [item for item in copies
                                           if isinstance(item, dict) and item.get("name") == "adminReturnRoutes"]
                != [expected_copy] or rules != expected_rules or len(children) != 2
                or probe_rules != expected_probe
                or {item.get("copy", {}).get("name") for item in children}
                != {"firewallAdminRules", "managementAdminRules"}
                or any(item.get("condition") != "[not(empty(parameters('adminAllowedSources')))]"
                       or item.get("copy", {}).get("count") != "[length(variables('adminNsgRules'))]"
                       or item.get("properties") != expected_child_properties.get(item.get("copy", {}).get("name"))
                       for item in children)
                or len(management_routes) != 1
                or management_routes[0].get("condition") != "[not(empty(parameters('adminAllowedSources')))]"
                or management_routes[0].get("properties") != {
                    "disableBgpRoutePropagation": False, "copy": [expected_management_copy]}):
            raise ValueError("Check Point admin access must use bounded source-scoped rules and Internet return routes")

    @staticmethod
    def validate_checkpoint_private_data(template: dict) -> dict:
        Templates._validate_structure(
            template, True, 0, {"location": "string", "environmentId": "string"},
            CHECKPOINT_PRIVATE_DATA_RESOURCES, {"kind"})
        resources = template["resources"]
        if (len(resources) != len(CHECKPOINT_PRIVATE_DATA_RESOURCES)
                or {item["type"] for item in resources} != CHECKPOINT_PRIVATE_DATA_RESOURCES):
            raise ValueError("Invalid Check Point private data resources")
        by_type = {item["type"]: item for item in resources}
        vault = by_type["Microsoft.KeyVault/vaults"].get("properties")
        storage = by_type["Microsoft.Storage/storageAccounts"]
        state = storage.get("properties")
        blob = by_type["Microsoft.Storage/storageAccounts/blobServices"].get("properties")
        container = by_type["Microsoft.Storage/storageAccounts/blobServices/containers"].get("properties")
        def exact_json(value: object, expected: object) -> bool:
            return json.dumps(value, sort_keys=True) == json.dumps(expected, sort_keys=True)

        if (not exact_json(vault, {
                "tenantId": "[subscription().tenantId]",
                "sku": {"family": "A", "name": "standard"},
                "enableRbacAuthorization": True,
                "enableSoftDelete": True,
                "enablePurgeProtection": True,
                "softDeleteRetentionInDays": 90,
                "publicNetworkAccess": "Disabled",
                "networkAcls": {"defaultAction": "Deny", "bypass": "None"},
            })
                or storage.get("kind") != "StorageV2"
                or not exact_json(state, {
                    "allowSharedKeyAccess": False,
                    "allowBlobPublicAccess": False,
                    "allowCrossTenantReplication": False,
                    "defaultToOAuthAuthentication": True,
                    "publicNetworkAccess": "Disabled",
                    "minimumTlsVersion": "TLS1_2",
                    "supportsHttpsTrafficOnly": True,
                    "networkAcls": {"defaultAction": "Deny", "bypass": "None"},
                })
                or not exact_json(blob, {
                    "isVersioningEnabled": True,
                    "deleteRetentionPolicy": {"enabled": True, "days": 7},
                    "containerDeleteRetentionPolicy": {"enabled": True, "days": 7},
                })
                or not exact_json(container, {"publicAccess": "None"})):
            raise ValueError("Check Point private data security settings are invalid")
        expected_links = [
            {"name": "vault",
             "target": "[resourceId('Microsoft.KeyVault/vaults', format('kvcp{0}', variables('unique')))]",
             "zone": "privatelink.vaultcore.azure.net"},
            {"name": "blob",
             "target": "[resourceId('Microsoft.Storage/storageAccounts', format('stcp{0}', variables('unique')))]",
             "zone": "[format('privatelink.blob.{0}', environment().suffixes.storage)]"},
        ]
        variables = template.get("variables")
        endpoint = by_type["Microsoft.Network/privateEndpoints"].get("properties")
        dns_link = by_type["Microsoft.Network/privateDnsZones/virtualNetworkLinks"].get("properties")
        zone_group = by_type["Microsoft.Network/privateEndpoints/privateDnsZoneGroups"].get("properties")
        copies = {
            "Microsoft.Network/privateDnsZones": "zones",
            "Microsoft.Network/privateDnsZones/virtualNetworkLinks": "dnsLinks",
            "Microsoft.Network/privateEndpoints": "endpoints",
            "Microsoft.Network/privateEndpoints/privateDnsZoneGroups": "zoneGroups",
        }
        if (not isinstance(variables, dict) or variables.get("privateLinks") != expected_links
                or variables.get("unique") != "[uniqueString(resourceGroup().id, parameters('environmentId'))]"
                or variables.get("suffix") != "[take(parameters('environmentId'), 8)]"
                or any(by_type[kind].get("copy") != {
                    "name": name, "count": "[length(variables('privateLinks'))]"}
                    for kind, name in copies.items())
                or not isinstance(endpoint, dict)
                or endpoint.get("subnet") != {"id": (
                    "[resourceId('Microsoft.Network/virtualNetworks/subnets', "
                    "format('vnet-cp-security-{0}', variables('suffix')), 'private-endpoints')]")}
                or endpoint.get("privateLinkServiceConnections") != [{
                    "name": "[variables('privateLinks')[copyIndex()].name]",
                    "properties": {
                        "privateLinkServiceId": "[variables('privateLinks')[copyIndex()].target]",
                        "groupIds": ["[variables('privateLinks')[copyIndex()].name]"]}}]
                or not isinstance(dns_link, dict) or dns_link.get("registrationEnabled") is not False
                or dns_link.get("virtualNetwork") != {"id": (
                    "[resourceId('Microsoft.Network/virtualNetworks', "
                    "format('vnet-cp-security-{0}', variables('suffix')))]")}
                or zone_group != {"privateDnsZoneConfigs": [{
                    "name": "[variables('privateLinks')[copyIndex()].name]",
                    "properties": {"privateDnsZoneId": (
                        "[resourceId('Microsoft.Network/privateDnsZones', "
                        "variables('privateLinks')[copyIndex()].zone)]")}}]}):
            raise ValueError("Check Point private data networking is invalid")
        vault_id = expected_links[0]["target"]
        storage_id = expected_links[1]["target"]
        endpoint_prefix = (
            "[resourceId('Microsoft.Network/privateEndpoints', "
            "format('pe-cp-{0}-{1}', variables('privateLinks')[")
        expected_outputs = {
            "credentialVaultId": vault_id,
            "credentialVaultUri": f"[reference({vault_id[1:-1]}, '2023-07-01').vaultUri]",
            "stateStorageId": storage_id,
            "stateBlobEndpoint": f"[reference({storage_id[1:-1]}, '2023-05-01').primaryEndpoints.blob]",
            "stateContainerName": "terraform-state",
            "credentialPrivateEndpointId": endpoint_prefix + "0].name, variables('suffix')))]",
            "statePrivateEndpointId": endpoint_prefix + "1].name, variables('suffix')))]",
        }
        outputs = template.get("outputs", {})
        if (not isinstance(outputs, dict) or set(outputs) != CHECKPOINT_PRIVATE_DATA_OUTPUTS
                or any(outputs[name] != {"type": "string", "value": value}
                       for name, value in expected_outputs.items())):
            raise ValueError("Invalid Check Point private data outputs")
        return template

    @staticmethod
    def _validate_structure(template: dict, network: bool, depth: int,
                            root_parameters: dict | None = None,
                            allowed_resources: set | None = None,
                            extra_resource_fields: set | None = None) -> None:
        if depth > 8:
            raise ValueError("ARM module nesting exceeds limit")
        allowed = {"$schema", "contentVersion", "metadata", "parameters",
                   "variables", "resources", "outputs"}
        if (not isinstance(template, dict) or set(template) - allowed
                or template.get("$schema") !=
                "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
                or template.get("contentVersion") != "1.0.0.0"):
            raise ValueError("Unsupported ARM template schema or fields")
        expected = root_parameters if root_parameters is not None else (NETWORK_PARAMETERS if network else PROOF_PARAMETERS)
        allowed_resources = allowed_resources if allowed_resources is not None else RESOURCE_TYPES
        extra_resource_fields = extra_resource_fields or set()
        parameters = template.get("parameters", {})
        if not isinstance(parameters, dict) or (depth == 0 and set(parameters) != set(expected)):
            raise ValueError("Template parameter contract mismatch")
        for name, spec in parameters.items():
            if not isinstance(spec, dict):
                raise ValueError("Invalid template parameter schema")
            kind = expected[name] if depth == 0 else spec.get("type", "")
            if (not isinstance(kind, str)
                    or kind.lower() not in {"string", "securestring", "int", "bool",
                                            "array", "object", "secureobject"}
                    or spec.get("type", "").lower() != kind.lower()
                    or set(spec) - {"type", "metadata", "allowedValues", "minLength",
                                    "maxLength", "minValue", "maxValue", "defaultValue"}):
                raise ValueError("Invalid template parameter schema")
            if kind.lower() in ("securestring", "secureobject") and "defaultValue" in spec:
                raise ValueError("Secret defaults are forbidden")
        resources = template.get("resources")
        if not isinstance(resources, list) or not resources:
            raise ValueError("Expected an ARM resources array")
        for resource in resources:
            resource_type = resource.get("type") if isinstance(resource, dict) else None
            if (not isinstance(resource, dict)
                    or resource_type not in allowed_resources | {"Microsoft.Resources/deployments"}
                    or set(resource) - ({"type", "apiVersion", "name", "location", "tags",
                                         "properties", "dependsOn", "condition", "copy",
                                         "sku", "zones", "plan", "identity"} | extra_resource_fields)
                    or (not network and resource["type"] != "Microsoft.Network/routeTables")):
                raise ValueError("Unsupported or out-of-scope template resource")
            if "identity" in resource and (
                    resource_type != "Microsoft.Compute/virtualMachines"
                    or resource["identity"] != {"type": "SystemAssigned"}):
                raise ValueError("Only system-assigned VM identities are permitted")
            if resource_type == "Microsoft.Resources/deployments":
                properties = resource.get("properties", {})
                if (not isinstance(properties, dict)
                        or set(properties) - {"mode", "template", "parameters",
                                              "expressionEvaluationOptions"}
                        or properties.get("mode") != "Incremental"
                        or properties.get("expressionEvaluationOptions", {"scope": "inner"})
                        != {"scope": "inner"}
                        or not isinstance(properties.get("template"), dict)):
                    raise ValueError("Only embedded same-group Incremental modules are permitted")
                Templates._validate_structure(properties["template"], True, depth + 1,
                                              root_parameters, allowed_resources, extra_resource_fields)
