"""Validate private-data deployment references before fetching live resource evidence."""
import re
from dataclasses import dataclass

from .config import uuid_text
from .models import environment_resource_group_name

CHECKPOINT_PRIVATE_DATA_OUTPUTS = {
    "credentialVaultId", "credentialVaultUri", "stateStorageId", "stateBlobEndpoint",
    "stateContainerName", "credentialPrivateEndpointId", "statePrivateEndpointId",
}


@dataclass(frozen=True)
class CheckpointPrivateDataReferences:
    vault_id: str
    vault_uri: str
    storage_id: str
    blob_endpoint: str
    container_name: str
    vault_endpoint_id: str
    storage_endpoint_id: str


def _equal_id(value: object, expected: str) -> bool:
    return isinstance(value, str) and value.lower() == expected.lower()


def _validate_private_link(properties: dict, endpoint: dict, resource_id: str,
                           endpoint_id: str, subnet_id: str, group: str) -> None:
    links = properties.get("privateEndpointConnections")
    connections = endpoint.get("privateLinkServiceConnections")
    subnet = endpoint.get("subnet")
    if (not isinstance(links, list) or len(links) != 1
            or not isinstance(links[0], dict) or not isinstance(links[0].get("properties"), dict)
            or not isinstance(connections, list) or len(connections) != 1
            or not isinstance(connections[0], dict) or not isinstance(connections[0].get("properties"), dict)
            or endpoint.get("manualPrivateLinkServiceConnections", []) != []
            or endpoint.get("provisioningState") != "Succeeded"
            or not isinstance(subnet, dict) or not _equal_id(subnet.get("id"), subnet_id)):
        raise ValueError("Invalid Check Point private endpoint evidence")
    resource_link = links[0]["properties"]
    endpoint_link = connections[0]["properties"]
    resource_endpoint = resource_link.get("privateEndpoint")
    resource_state = resource_link.get("privateLinkServiceConnectionState")
    endpoint_state = endpoint_link.get("privateLinkServiceConnectionState")
    if (not isinstance(resource_endpoint, dict) or not _equal_id(resource_endpoint.get("id"), endpoint_id)
            or resource_link.get("provisioningState") != "Succeeded"
            or not isinstance(resource_state, dict) or resource_state.get("status") != "Approved"
            or not _equal_id(endpoint_link.get("privateLinkServiceId"), resource_id)
            or endpoint_link.get("groupIds") != [group]
            or not isinstance(endpoint_state, dict) or endpoint_state.get("status") != "Approved"):
        raise ValueError("Invalid Check Point private endpoint evidence")


def _private_subnet_id(provider_subscription: str, group_name: str, environment_id: str) -> str:
    return (f"/subscriptions/{provider_subscription}/resourceGroups/{group_name}"
            f"/providers/Microsoft.Network/virtualNetworks/vnet-cp-security-{environment_id[:8]}"
            "/subnets/private-endpoints")


def validate_checkpoint_private_data_outputs(
        outputs: dict, provider_subscription: str, group_name: str,
        environment_id: str) -> CheckpointPrivateDataReferences:
    try:
        uuid_text(provider_subscription)
        uuid_text(environment_id)
        if (not isinstance(group_name, str) or not group_name.startswith("rg-faas-env-")
                or environment_resource_group_name(group_name.removeprefix("rg-faas-env-")) != group_name):
            raise ValueError()
    except (TypeError, ValueError, AttributeError):
        raise ValueError("Invalid Check Point provider scope") from None
    if not isinstance(outputs, dict) or set(outputs) != CHECKPOINT_PRIVATE_DATA_OUTPUTS:
        raise ValueError("Invalid Check Point private data outputs")
    values = {}
    for name in CHECKPOINT_PRIVATE_DATA_OUTPUTS:
        item = outputs[name]
        if (not isinstance(item, dict) or set(item) != {"type", "value"}
                or not isinstance(item["type"], str) or item["type"].lower() != "string"
                or not isinstance(item["value"], str)):
            raise ValueError("Invalid Check Point private data outputs")
        values[name] = item["value"]

    group_id = f"/subscriptions/{provider_subscription}/resourceGroups/{group_name}"
    vault_prefix = group_id + "/providers/Microsoft.KeyVault/vaults/"
    storage_prefix = group_id + "/providers/Microsoft.Storage/storageAccounts/"
    vault_id = values["credentialVaultId"]
    storage_id = values["stateStorageId"]
    if (not vault_id.lower().startswith(vault_prefix.lower())
            or not storage_id.lower().startswith(storage_prefix.lower())):
        raise ValueError("Check Point private data does not match the provider scope")
    vault_name = vault_id[len(vault_prefix):]
    storage_name = storage_id[len(storage_prefix):]
    suffix = environment_id[:8]
    endpoint_scope = group_id + "/providers/Microsoft.Network/privateEndpoints/"
    expected = {
        "credentialVaultUri": f"https://{vault_name}.vault.azure.net/",
        "stateBlobEndpoint": f"https://{storage_name}.blob.core.windows.net/",
        "stateContainerName": "terraform-state",
        "credentialPrivateEndpointId": endpoint_scope + f"pe-cp-vault-{suffix}",
        "statePrivateEndpointId": endpoint_scope + f"pe-cp-blob-{suffix}",
    }
    if (not re.fullmatch(r"kvcp[a-z0-9]{13}", vault_name)
            or not re.fullmatch(r"stcp[a-z0-9]{13}", storage_name)
            or vault_name[4:] != storage_name[4:]
            or any((values[name] != expected_value if name == "stateContainerName"
                    else values[name].lower() not in (
                        {expected_value.lower(), expected_value[:-1].lower()}
                        if name in {"credentialVaultUri", "stateBlobEndpoint"}
                        else {expected_value.lower()}))
                   for name, expected_value in expected.items())):
        raise ValueError("Check Point private data does not match the provider scope")
    return CheckpointPrivateDataReferences(
        vault_id=vault_id,
        vault_uri=expected["credentialVaultUri"],
        storage_id=storage_id,
        blob_endpoint=expected["stateBlobEndpoint"],
        container_name=values["stateContainerName"],
        vault_endpoint_id=values["credentialPrivateEndpointId"],
        storage_endpoint_id=values["statePrivateEndpointId"],
    )


def validate_checkpoint_vault_evidence(
        outputs: dict, provider_subscription: str, provider_tenant: str, group_name: str,
        environment_id: str, vault: dict, private_endpoint: dict) -> CheckpointPrivateDataReferences:
    """Validate fresh ARM responses; this does not prove DNS connectivity or RBAC."""
    try:
        uuid_text(provider_tenant)
    except (TypeError, ValueError, AttributeError):
        raise ValueError("Invalid Check Point provider tenant") from None
    references = validate_checkpoint_private_data_outputs(
        outputs, provider_subscription, group_name, environment_id)

    if not isinstance(vault, dict) or not isinstance(private_endpoint, dict):
        raise ValueError("Invalid Check Point private vault evidence")
    properties = vault.get("properties")
    endpoint = private_endpoint.get("properties")
    tags = vault.get("tags")
    if (not _equal_id(vault.get("id"), references.vault_id)
            or not _equal_id(private_endpoint.get("id"), references.vault_endpoint_id)
            or not isinstance(tags, dict)
            or tags.get("purpose") != "provider-provisioning-checkpoint-private-data"
            or tags.get("environmentId") != environment_id
            or not isinstance(properties, dict) or not isinstance(endpoint, dict)):
        raise ValueError("Invalid Check Point private vault evidence")
    acl = properties.get("networkAcls")
    vault_uri = properties.get("vaultUri")
    if (not _equal_id(properties.get("tenantId"), provider_tenant)
            or properties.get("provisioningState") != "Succeeded"
            or properties.get("enableRbacAuthorization") is not True
            or properties.get("enableSoftDelete") is not True
            or properties.get("enablePurgeProtection") is not True
            or properties.get("publicNetworkAccess") != "Disabled"
            or not isinstance(acl, dict) or acl.get("defaultAction") != "Deny"
            or acl.get("bypass") != "None"
            or acl.get("ipRules", []) != [] or acl.get("virtualNetworkRules", []) != []
            or any(properties.get(key, False) is not False for key in (
                "enabledForDeployment", "enabledForDiskEncryption", "enabledForTemplateDeployment"))
            or not isinstance(vault_uri, str)
            or vault_uri.lower() not in {references.vault_uri.lower(), references.vault_uri[:-1].lower()}):
        raise ValueError("Check Point vault is not private and provider-owned")

    _validate_private_link(
        properties, endpoint, references.vault_id, references.vault_endpoint_id,
        _private_subnet_id(provider_subscription, group_name, environment_id), "vault")
    return references


def validate_checkpoint_state_evidence(
        outputs: dict, provider_subscription: str, group_name: str, environment_id: str,
        storage: dict, blob_service: dict, container: dict,
        private_endpoint: dict) -> CheckpointPrivateDataReferences:
    """Validate fresh ARM responses; this does not prove DNS connectivity or RBAC."""
    references = validate_checkpoint_private_data_outputs(
        outputs, provider_subscription, group_name, environment_id)
    if not all(isinstance(item, dict) for item in (storage, blob_service, container, private_endpoint)):
        raise ValueError("Invalid Check Point private state evidence")
    properties, tags = storage.get("properties"), storage.get("tags")
    service_properties = blob_service.get("properties")
    container_properties, endpoint = container.get("properties"), private_endpoint.get("properties")
    if (not _equal_id(storage.get("id"), references.storage_id)
            or not _equal_id(blob_service.get("id"), references.storage_id + "/blobServices/default")
            or not _equal_id(container.get("id"), references.storage_id + "/blobServices/default/containers/terraform-state")
            or not _equal_id(private_endpoint.get("id"), references.storage_endpoint_id)
            or not isinstance(tags, dict)
            or tags.get("purpose") != "provider-provisioning-checkpoint-private-data"
            or tags.get("environmentId") != environment_id
            or not isinstance(properties, dict) or not isinstance(service_properties, dict)
            or not isinstance(container_properties, dict) or not isinstance(endpoint, dict)):
        raise ValueError("Invalid Check Point private state evidence")
    acl, endpoints = properties.get("networkAcls"), properties.get("primaryEndpoints")
    if (storage.get("kind") != "StorageV2"
            or properties.get("provisioningState") != "Succeeded"
            or properties.get("allowSharedKeyAccess") is not False
            or properties.get("allowBlobPublicAccess") is not False
            or properties.get("allowCrossTenantReplication") is not False
            or properties.get("defaultToOAuthAuthentication") is not True
            or properties.get("publicNetworkAccess") != "Disabled"
            or properties.get("minimumTlsVersion") != "TLS1_2"
            or properties.get("supportsHttpsTrafficOnly") is not True
            or not isinstance(acl, dict) or acl.get("defaultAction") != "Deny" or acl.get("bypass") != "None"
            or acl.get("ipRules", []) != [] or acl.get("virtualNetworkRules", []) != []
            or not isinstance(endpoints, dict)
            or not isinstance(endpoints.get("blob"), str)
            or endpoints["blob"].lower() not in {references.blob_endpoint.lower(), references.blob_endpoint[:-1].lower()}
            or container_properties.get("publicAccess") != "None"
            or service_properties.get("isVersioningEnabled") is not True):
        raise ValueError("Check Point state storage is not private and provider-owned")
    for key in ("deleteRetentionPolicy", "containerDeleteRetentionPolicy"):
        policy = service_properties.get(key)
        if (not isinstance(policy, dict) or policy.get("enabled") is not True
                or type(policy.get("days")) is not int or policy["days"] < 7):
            raise ValueError("Check Point state retention is not configured")
    _validate_private_link(
        properties, endpoint, references.storage_id, references.storage_endpoint_id,
        _private_subnet_id(provider_subscription, group_name, environment_id), "blob")
    return references
