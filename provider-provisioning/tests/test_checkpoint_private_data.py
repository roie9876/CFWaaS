import copy
import json
import time
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import urlsplit
from uuid import UUID

import pytest
from azure.core.exceptions import HttpResponseError

from service.checkpoint_private_data import (
    validate_checkpoint_private_data_outputs, validate_checkpoint_state_evidence,
    validate_checkpoint_vault_evidence,
)
from service.models import environment_resource_group_name
from service.checkpoint_state import CheckpointStateEvidenceError, verify_checkpoint_state
from service.store import LostLease

SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"
ENVIRONMENT = "00000000-0000-0000-0000-000000000002"
GROUP = environment_resource_group_name("00000000-0000-0000-0000-000000000003")
GROUP_ID = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{GROUP}"
VAULT = "kvcp" + "a" * 13
STORAGE = "stcp" + "a" * 13
TENANT = "00000000-0000-0000-0000-000000000004"


def outputs():
    values = {
        "credentialVaultId": f"{GROUP_ID}/providers/Microsoft.KeyVault/vaults/{VAULT}",
        "credentialVaultUri": f"https://{VAULT}.vault.azure.net/",
        "stateStorageId": f"{GROUP_ID}/providers/Microsoft.Storage/storageAccounts/{STORAGE}",
        "stateBlobEndpoint": f"https://{STORAGE}.blob.core.windows.net/",
        "stateContainerName": "terraform-state",
        "credentialPrivateEndpointId": f"{GROUP_ID}/providers/Microsoft.Network/privateEndpoints/pe-cp-vault-00000000",
        "statePrivateEndpointId": f"{GROUP_ID}/providers/Microsoft.Network/privateEndpoints/pe-cp-blob-00000000",
    }
    return {name: {"type": "String", "value": value} for name, value in values.items()}


def validate(value):
    return validate_checkpoint_private_data_outputs(value, SUBSCRIPTION, GROUP, ENVIRONMENT)


def test_scoped_references_have_expected_private_data_endpoints():
    result = validate(outputs())
    assert result.vault_uri == f"https://{VAULT}.vault.azure.net/"
    assert result.blob_endpoint == f"https://{STORAGE}.blob.core.windows.net/"
    assert result.container_name == "terraform-state"
    assert result.vault_endpoint_id.endswith("/pe-cp-vault-00000000")
    assert result.storage_endpoint_id.endswith("/pe-cp-blob-00000000")


def test_accepts_canonical_service_uris_with_or_without_trailing_slash():
    value = outputs()
    value["credentialVaultUri"]["value"] = value["credentialVaultUri"]["value"].removesuffix("/")
    value["stateBlobEndpoint"]["value"] = value["stateBlobEndpoint"]["value"].removesuffix("/")
    result = validate(value)
    assert result.vault_uri == f"https://{VAULT}.vault.azure.net/"
    assert result.blob_endpoint == f"https://{STORAGE}.blob.core.windows.net/"


@pytest.mark.parametrize("name", [
    "credentialVaultId", "credentialVaultUri", "stateStorageId", "stateBlobEndpoint",
    "stateContainerName", "credentialPrivateEndpointId", "statePrivateEndpointId",
])
def test_rejects_references_outside_expected_provider_scope(name):
    value = outputs()
    value[name]["value"] = "PRIVATE-VALUE"
    with pytest.raises(ValueError) as error:
        validate(value)
    assert "PRIVATE-VALUE" not in str(error.value)


@pytest.mark.parametrize("mutation", ["extra", "missing", "wrong_type", "extra_field",
                                      "bad_host", "foreign_storage", "foreign_endpoint"])
def test_rejects_invalid_or_foreign_outputs(mutation):
    value = copy.deepcopy(outputs())
    if mutation == "extra":
        value["unexpected"] = "PRIVATE-VALUE"
    elif mutation == "missing":
        del value["credentialVaultId"]
    elif mutation == "wrong_type":
        value["credentialVaultId"]["type"] = "Object"
    elif mutation == "extra_field":
        value["credentialVaultId"]["secret"] = "PRIVATE-VALUE"
    elif mutation == "bad_host":
        value["credentialVaultUri"]["value"] = f"https://{VAULT}.vault.azure.net.evil.example/"
    elif mutation == "foreign_storage":
        value["stateStorageId"]["value"] = f"{GROUP_ID}/providers/Microsoft.Storage/storageAccounts/stcp{'b' * 13}"
    else:
        value["statePrivateEndpointId"]["value"] = value["statePrivateEndpointId"]["value"].replace(
            GROUP, environment_resource_group_name("00000000-0000-0000-0000-000000000004"))
    with pytest.raises(ValueError) as error:
        validate(value)
    assert "PRIVATE-VALUE" not in str(error.value)


@pytest.mark.parametrize("subscription,group,environment", [
    ("invalid", GROUP, ENVIRONMENT),
    (SUBSCRIPTION, "shared-group", ENVIRONMENT),
    (SUBSCRIPTION, GROUP, "invalid"),
    ("00000000-0000-0000-0000-000000000004", GROUP, ENVIRONMENT),
    (SUBSCRIPTION, environment_resource_group_name("00000000-0000-0000-0000-000000000004"), ENVIRONMENT),
    (SUBSCRIPTION, GROUP, str(UUID(int=(1 << 120) + 2))),
])
def test_rejects_other_subscriptions_groups_and_environments(subscription, group, environment):
    with pytest.raises(ValueError):
        validate_checkpoint_private_data_outputs(outputs(), subscription, group, environment)


def vault_evidence():
    values = outputs()
    vault_id = values["credentialVaultId"]["value"]
    endpoint_id = values["credentialPrivateEndpointId"]["value"]
    vault = {
        "id": vault_id,
        "tags": {"purpose": "provider-provisioning-checkpoint-private-data", "environmentId": ENVIRONMENT},
        "properties": {
            "tenantId": TENANT, "provisioningState": "Succeeded", "enableRbacAuthorization": True,
            "enableSoftDelete": True,
            "enablePurgeProtection": True, "publicNetworkAccess": "Disabled",
            "networkAcls": {"defaultAction": "Deny", "bypass": "None", "ipRules": [],
                            "virtualNetworkRules": []},
            "vaultUri": f"https://{VAULT}.vault.azure.net",
            "privateEndpointConnections": [{
                "properties": {
                    "privateEndpoint": {"id": endpoint_id},
                    "provisioningState": "Succeeded",
                    "privateLinkServiceConnectionState": {"status": "Approved"},
                }}],
        },
    }
    endpoint = {
        "id": endpoint_id,
        "properties": {
            "provisioningState": "Succeeded",
            "subnet": {"id": (f"{GROUP_ID}/providers/Microsoft.Network/virtualNetworks/"
                              "vnet-cp-security-00000000/subnets/private-endpoints")},
            "privateLinkServiceConnections": [{
                "properties": {
                    "privateLinkServiceId": vault_id, "groupIds": ["vault"],
                    "privateLinkServiceConnectionState": {"status": "Approved"},
                }}],
            "manualPrivateLinkServiceConnections": [],
        },
    }
    return vault, endpoint


def validate_evidence(vault, endpoint):
    return validate_checkpoint_vault_evidence(outputs(), SUBSCRIPTION, TENANT, GROUP, ENVIRONMENT, vault, endpoint)


def test_accepts_matching_private_provider_vault_evidence():
    vault, endpoint = vault_evidence()
    assert validate_evidence(vault, endpoint).vault_id == vault["id"]


@pytest.mark.parametrize("target,key,value", [
    ("vault", "tenantId", SUBSCRIPTION),
    ("vault", "publicNetworkAccess", "Enabled"),
    ("vault", "enableRbacAuthorization", False),
    ("vault", "enableSoftDelete", False),
    ("vault", "enablePurgeProtection", False),
    ("vault", "provisioningState", "Updating"),
    ("vault", "vaultUri", "https://private-value.invalid/"),
    ("vault", "enabledForTemplateDeployment", True),
    ("vault", "privateEndpointConnections", []),
    ("endpoint", "provisioningState", "Updating"),
    ("endpoint", "subnet", {"id": "/untrusted"}),
    ("endpoint", "manualPrivateLinkServiceConnections", [{}]),
    ("endpoint", "privateLinkServiceConnections", []),
])
def test_rejects_wrong_private_vault_evidence_without_echoing_values(target, key, value):
    vault, endpoint = vault_evidence()
    (vault if target == "vault" else endpoint)["properties"][key] = value
    with pytest.raises(ValueError) as error:
        validate_evidence(vault, endpoint)
    assert "private-value" not in str(error.value)


@pytest.mark.parametrize("mutation", [
    "vault_id", "endpoint_id", "tag", "acl_bypass", "acl_ip", "vault_link_target",
    "vault_link_pending", "vault_link_updating", "additional_vault_link",
    "endpoint_target", "endpoint_group", "endpoint_pending",
])
def test_rejects_foreign_or_unapproved_private_connections(mutation):
    vault, endpoint = vault_evidence()
    vault_props, endpoint_props = vault["properties"], endpoint["properties"]
    vault_link = vault_props["privateEndpointConnections"][0]["properties"]
    endpoint_link = endpoint_props["privateLinkServiceConnections"][0]["properties"]
    if mutation == "vault_id":
        vault["id"] = "/foreign"
    elif mutation == "endpoint_id":
        endpoint["id"] = "/foreign"
    elif mutation == "tag":
        vault["tags"]["environmentId"] = SUBSCRIPTION
    elif mutation == "acl_bypass":
        vault_props["networkAcls"]["bypass"] = "AzureServices"
    elif mutation == "acl_ip":
        vault_props["networkAcls"]["ipRules"] = [{"value": "0.0.0.0/0"}]
    elif mutation == "vault_link_target":
        vault_link["privateEndpoint"]["id"] = "/foreign"
    elif mutation == "vault_link_pending":
        vault_link["privateLinkServiceConnectionState"]["status"] = "Pending"
    elif mutation == "vault_link_updating":
        vault_link["provisioningState"] = "Updating"
    elif mutation == "additional_vault_link":
        vault_props["privateEndpointConnections"].append(copy.deepcopy(vault_props["privateEndpointConnections"][0]))
    elif mutation == "endpoint_target":
        endpoint_link["privateLinkServiceId"] = "/foreign"
    elif mutation == "endpoint_group":
        endpoint_link["groupIds"] = ["blob"]
    else:
        endpoint_link["privateLinkServiceConnectionState"]["status"] = "Rejected"
    with pytest.raises(ValueError):
        validate_evidence(vault, endpoint)


def state_evidence():
    values = outputs()
    storage_id = values["stateStorageId"]["value"]
    endpoint_id = values["statePrivateEndpointId"]["value"]
    storage = {
        "id": storage_id, "kind": "StorageV2",
        "tags": {"purpose": "provider-provisioning-checkpoint-private-data", "environmentId": ENVIRONMENT},
        "properties": {
            "provisioningState": "Succeeded", "allowSharedKeyAccess": False,
            "allowBlobPublicAccess": False, "allowCrossTenantReplication": False,
            "defaultToOAuthAuthentication": True, "publicNetworkAccess": "Disabled",
            "minimumTlsVersion": "TLS1_2", "supportsHttpsTrafficOnly": True,
            "networkAcls": {"defaultAction": "Deny", "bypass": "None", "ipRules": [],
                            "virtualNetworkRules": []},
            "primaryEndpoints": {"blob": values["stateBlobEndpoint"]["value"]},
            "privateEndpointConnections": [{"properties": {
                "privateEndpoint": {"id": endpoint_id}, "provisioningState": "Succeeded",
                "privateLinkServiceConnectionState": {"status": "Approved"}}}],
        },
    }
    service = {"id": storage_id + "/blobServices/default", "properties": {
        "isVersioningEnabled": True, "deleteRetentionPolicy": {"enabled": True, "days": 7},
        "containerDeleteRetentionPolicy": {"enabled": True, "days": 7}}}
    container = {"id": storage_id + "/blobServices/default/containers/terraform-state",
                 "properties": {"publicAccess": "None"}}
    endpoint = {"id": endpoint_id, "properties": {
        "provisioningState": "Succeeded",
        "subnet": {"id": (f"{GROUP_ID}/providers/Microsoft.Network/virtualNetworks/"
                          "vnet-cp-security-00000000/subnets/private-endpoints")},
        "privateLinkServiceConnections": [{"properties": {
            "privateLinkServiceId": storage_id, "groupIds": ["blob"],
            "privateLinkServiceConnectionState": {"status": "Approved"}}}],
        "manualPrivateLinkServiceConnections": []}}
    return storage, service, container, endpoint


def validate_state(storage, service, container, endpoint):
    return validate_checkpoint_state_evidence(
        outputs(), SUBSCRIPTION, GROUP, ENVIRONMENT, storage, service, container, endpoint)


def test_accepts_matching_private_terraform_state_evidence():
    storage, service, container, endpoint = state_evidence()
    assert validate_state(storage, service, container, endpoint).storage_id == storage["id"]


@pytest.mark.parametrize("target,key,value", [
    ("storage", "allowSharedKeyAccess", True),
    ("storage", "allowBlobPublicAccess", True),
    ("storage", "allowCrossTenantReplication", True),
    ("storage", "defaultToOAuthAuthentication", False),
    ("storage", "publicNetworkAccess", "Enabled"),
    ("storage", "minimumTlsVersion", "TLS1_0"),
    ("storage", "supportsHttpsTrafficOnly", False),
    ("storage", "provisioningState", "Updating"),
    ("storage", "primaryEndpoints", {"blob": "https://private-value.invalid/"}),
    ("service", "isVersioningEnabled", False),
    ("service", "deleteRetentionPolicy", {"enabled": True, "days": 6}),
    ("service", "containerDeleteRetentionPolicy", {"enabled": True, "days": True}),
    ("container", "publicAccess", "Blob"),
    ("endpoint", "provisioningState", "Updating"),
    ("endpoint", "manualPrivateLinkServiceConnections", [{}]),
])
def test_rejects_insecure_private_state_settings_without_echoing_values(target, key, value):
    storage, service, container, endpoint = state_evidence()
    resources = {"storage": storage, "service": service, "container": container, "endpoint": endpoint}
    resources[target]["properties"][key] = value
    with pytest.raises(ValueError) as error:
        validate_state(storage, service, container, endpoint)
    assert "private-value" not in str(error.value)


@pytest.mark.parametrize("mutation", [
    "storage_id", "service_id", "container_id", "endpoint_id", "tag", "kind", "acl_bypass",
    "acl_ip", "subnet", "storage_link_target", "storage_link_pending", "additional_storage_link",
    "endpoint_target", "endpoint_group", "endpoint_pending",
])
def test_rejects_foreign_or_unapproved_private_state_connections(mutation):
    storage, service, container, endpoint = state_evidence()
    storage_props, endpoint_props = storage["properties"], endpoint["properties"]
    storage_link = storage_props["privateEndpointConnections"][0]["properties"]
    endpoint_link = endpoint_props["privateLinkServiceConnections"][0]["properties"]
    if mutation == "storage_id":
        storage["id"] = "/foreign"
    elif mutation == "service_id":
        service["id"] = "/foreign"
    elif mutation == "container_id":
        container["id"] = "/foreign"
    elif mutation == "endpoint_id":
        endpoint["id"] = "/foreign"
    elif mutation == "tag":
        storage["tags"]["environmentId"] = SUBSCRIPTION
    elif mutation == "kind":
        storage["kind"] = "BlobStorage"
    elif mutation == "acl_bypass":
        storage_props["networkAcls"]["bypass"] = "AzureServices"
    elif mutation == "acl_ip":
        storage_props["networkAcls"]["ipRules"] = [{"value": "0.0.0.0/0"}]
    elif mutation == "subnet":
        endpoint_props["subnet"]["id"] = "/foreign"
    elif mutation == "storage_link_target":
        storage_link["privateEndpoint"]["id"] = "/foreign"
    elif mutation == "storage_link_pending":
        storage_link["privateLinkServiceConnectionState"]["status"] = "Pending"
    elif mutation == "additional_storage_link":
        storage_props["privateEndpointConnections"].append(copy.deepcopy(storage_props["privateEndpointConnections"][0]))
    elif mutation == "endpoint_target":
        endpoint_link["privateLinkServiceId"] = "/foreign"
    elif mutation == "endpoint_group":
        endpoint_link["groupIds"] = ["vault"]
    else:
        endpoint_link["privateLinkServiceConnectionState"]["status"] = "Rejected"
    with pytest.raises(ValueError):
        validate_state(storage, service, container, endpoint)


def test_state_verifier_reads_only_expected_provider_resources():
    resources = Mock()
    fixtures = {item["id"].lower(): item for item in state_evidence()}
    resources.resources.get_by_id.side_effect = lambda resource_id, _api: SimpleNamespace(
        as_dict=lambda: copy.deepcopy(fixtures[resource_id.lower()]))
    check = Mock()
    result = verify_checkpoint_state(outputs(), SUBSCRIPTION, GROUP, ENVIRONMENT, resources, check)
    assert result.container_name == "terraform-state"
    assert resources.resources.get_by_id.call_count == 4
    assert check.call_count == 6
    assert all(GROUP.lower() in call.args[0].lower()
               for call in resources.resources.get_by_id.call_args_list)


def test_state_verifier_fails_closed_before_read_for_foreign_output():
    value = outputs()
    value["stateStorageId"]["value"] = "/foreign"
    resources, check = Mock(), Mock()
    with pytest.raises(ValueError):
        verify_checkpoint_state(value, SUBSCRIPTION, GROUP, ENVIRONMENT, resources, check)
    resources.resources.get_by_id.assert_not_called()


def test_state_verifier_stops_when_lease_is_lost():
    resources = Mock()
    fixture = state_evidence()[0]
    resources.resources.get_by_id.return_value = SimpleNamespace(as_dict=lambda: fixture)
    check = Mock(side_effect=[None, None, LostLease()])
    with pytest.raises(LostLease):
        verify_checkpoint_state(outputs(), SUBSCRIPTION, GROUP, ENVIRONMENT, resources, check)
    assert resources.resources.get_by_id.call_count == 1


def test_state_verifier_redacts_azure_errors():
    resources = Mock()
    resources.resources.get_by_id.side_effect = HttpResponseError("PRIVATE-VALUE")
    with pytest.raises(CheckpointStateEvidenceError) as error:
        verify_checkpoint_state(outputs(), SUBSCRIPTION, GROUP, ENVIRONMENT, resources, lambda: None)
    assert "PRIVATE-VALUE" not in str(error.value)


def test_state_verifier_accepts_real_arm_sdk_response_shapes():
    from azure.core.credentials import AccessToken
    from azure.core.pipeline.transport import HttpResponse, HttpTransport
    from azure.mgmt.resource import ResourceManagementClient

    fixtures = {item["id"].lower(): item for item in state_evidence()}

    class Response(HttpResponse):
        def __init__(self, request, resource):
            super().__init__(request, None)
            self.status_code = 200
            self.headers = {"Content-Type": "application/json"}
            self.content_type = "application/json"
            self.payload = json.dumps(resource).encode()

        def body(self):
            return self.payload

    class Transport(HttpTransport):
        def __init__(self):
            self.requests = []

        def open(self):
            pass

        def close(self):
            pass

        def __exit__(self, *args):
            self.close()

        def send(self, request, **kwargs):
            self.requests.append(request.url)
            return Response(request, fixtures[urlsplit(request.url).path.lower()])

    credential = Mock(spec=["get_token"])
    credential.get_token.return_value = AccessToken("fixture-token", int(time.time()) + 3600)
    transport = Transport()
    arm = ResourceManagementClient(credential, SUBSCRIPTION, transport=transport,
                                   logging_enable=False, retry_total=0)
    try:
        result = verify_checkpoint_state(outputs(), SUBSCRIPTION, GROUP, ENVIRONMENT, arm, lambda: None)
        assert result.container_name == "terraform-state"
        assert len(transport.requests) == 4
    finally:
        arm.close()
