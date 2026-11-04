"""Non-secret runner configuration and runner-owned credentials for one Check Point environment.

The worker cannot reach the environment's private Key Vault or state account, so it passes only
non-secret configuration in the job environment. The runner, inside the environment network,
creates or reuses the credentials in the private vault with its managed identity.
"""
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from azure.core.exceptions import AzureError, ResourceNotFoundError
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from pydantic import ConfigDict, Field, field_validator

from .checkpoint_credentials import CheckpointCredentials, generate_checkpoint_credentials
from .checkpoint_foundation import validate_checkpoint_foundation, validate_checkpoint_route_server_peers
from .checkpoint_plan import CheckpointPlanSummary, validate_checkpoint_plan, validate_checkpoint_public_key
from .checkpoint_private_data import validate_checkpoint_private_data_outputs
from .checkpoint_vault import CONTENT_TYPE, CheckpointVaultError, decode_checkpoint_credential
from .config import endpoint, uuid_text
from .models import StrictModel, environment_resource_group_name
from .admin_access import normalize_admin_sources


MAX_CONFIG_BYTES = 16 * 1024
ENVIRONMENT_KEYS = {"FAAS_CONFIG", "FAAS_RUNNER_CLIENT_ID"}


class CheckpointRunnerConfigError(ValueError):
    pass


class CheckpointRuntimeConfig(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    schemaVersion: int
    environmentId: str
    providerSubscriptionId: str
    providerTenantId: str
    providerGroupId: str
    runnerClientId: str
    gatewayImageVersion: str
    managementImageVersion: str
    gatewayVmSize: str
    managementVmSize: str
    providerSshPublicKey: str
    credentialVaultUri: str
    stateBlobEndpoint: str
    stateContainer: str
    firewallFrontendIp: str
    firewallBackendIp: str
    routeServerAsn: int
    routeServerPeers: tuple[str, str]
    adminAllowedSources: list[str] = Field(default_factory=list, max_length=16)
    managementRelayUrl: str = ""
    managementRelayClientId: str = ""

    @field_validator("adminAllowedSources", mode="before")
    @classmethod
    def admin_sources(cls, value: object) -> list[str]:
        return normalize_admin_sources(value)

    @property
    def group_name(self) -> str:
        return self.providerGroupId.rsplit("/", 1)[-1]

    @property
    def credential_name(self) -> str:
        return "cp-credentials-" + self.environmentId


@dataclass(frozen=True)
class CheckpointRunnerSettings:
    """Provider release settings; never derived from customer input."""
    gateway_image_version: str
    management_image_version: str
    gateway_vm_size: str
    management_vm_size: str
    provider_ssh_public_key: str
    management_relay_url: str = ""
    management_relay_client_id: str = ""


@dataclass(frozen=True, repr=False)
class CheckpointRuntimeInputs:
    config: CheckpointRuntimeConfig
    credentials: CheckpointCredentials = field(repr=False)


def _validate_settings(gateway_image_version: str, management_image_version: str,
                       gateway_vm_size: str, management_vm_size: str) -> None:
    if (any(not isinstance(value, str) or len(value) > 64
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value)
            for value in (gateway_image_version, management_image_version))
            or any(not isinstance(value, str) or len(value) > 64
                   or not re.fullmatch(r"Standard_[A-Za-z0-9_]+", value)
                   for value in (gateway_vm_size, management_vm_size))):
        raise CheckpointRunnerConfigError("Invalid Check Point runner settings")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def build_checkpoint_runner_config(
        foundation_outputs: dict, private_outputs: dict, provider_subscription: str, provider_tenant: str,
        group_name: str, environment_id: str, runner_client_id: str,
        gateway_image_version: str, management_image_version: str, gateway_vm_size: str, management_vm_size: str,
        provider_ssh_public_key: str, admin_allowed_sources: list[str] | None = None,
        management_relay_url: str = "", management_relay_client_id: str = "") -> str:
    """Return compact, secret-free JSON from provider evidence/settings and validated admin sources."""
    foundation = validate_checkpoint_foundation(foundation_outputs, provider_subscription, group_name, environment_id)
    private = validate_checkpoint_private_data_outputs(private_outputs, provider_subscription, group_name, environment_id)
    _validate_settings(gateway_image_version, management_image_version, gateway_vm_size, management_vm_size)
    try:
        uuid_text(provider_tenant)
        uuid_text(runner_client_id)
    except (TypeError, ValueError, AttributeError):
        raise CheckpointRunnerConfigError("Invalid Check Point runner identity") from None
    config = {
        "schemaVersion": 1,
        "environmentId": environment_id,
        "providerSubscriptionId": provider_subscription,
        "providerTenantId": provider_tenant,
        "providerGroupId": f"/subscriptions/{provider_subscription}/resourceGroups/{group_name}",
        "runnerClientId": runner_client_id,
        "gatewayImageVersion": gateway_image_version,
        "managementImageVersion": management_image_version,
        "gatewayVmSize": gateway_vm_size,
        "managementVmSize": management_vm_size,
        "providerSshPublicKey": validate_checkpoint_public_key(provider_ssh_public_key).decode("ascii"),
        "credentialVaultUri": private.vault_uri,
        "stateBlobEndpoint": private.blob_endpoint,
        "stateContainer": private.container_name,
        "firewallFrontendIp": foundation.firewall_frontend_ip,
        "firewallBackendIp": foundation.firewall_backend_ip,
        "routeServerAsn": foundation.route_server_asn,
        "routeServerPeers": list(foundation.route_server_peers),
    }
    sources = normalize_admin_sources([] if admin_allowed_sources is None else admin_allowed_sources)
    if sources:
        config.update(schemaVersion=2, adminAllowedSources=sources)
    if management_relay_url or management_relay_client_id:
        config.update(schemaVersion=3, managementRelayUrl=management_relay_url,
                      managementRelayClientId=management_relay_client_id)
    text = json.dumps(config, sort_keys=True, separators=(",", ":"))
    load_checkpoint_runner_config({"FAAS_CONFIG": text, "FAAS_RUNNER_CLIENT_ID": runner_client_id})
    return text


def load_checkpoint_runner_config(environment: Mapping[str, str]) -> CheckpointRuntimeConfig:
    """Validate the job's configuration and its internal provider bindings before use."""
    try:
        text, client = environment["FAAS_CONFIG"], uuid_text(environment["FAAS_RUNNER_CLIENT_ID"])
        if (not isinstance(text, str) or not 1 <= len(text.encode("utf-8")) <= MAX_CONFIG_BYTES
                or client == "00000000-0000-0000-0000-000000000000"):
            raise ValueError()
        raw = json.loads(text, object_pairs_hook=_unique_pairs)
        if isinstance(raw, dict) and isinstance(raw.get("routeServerPeers"), list):
            raw["routeServerPeers"] = tuple(raw["routeServerPeers"])
        config = CheckpointRuntimeConfig.model_validate(raw)
        uuid_text(config.environmentId)
        subscription = uuid_text(config.providerSubscriptionId)
        uuid_text(config.providerTenantId)
        _validate_settings(config.gatewayImageVersion, config.managementImageVersion,
                           config.gatewayVmSize, config.managementVmSize)
        validate_checkpoint_public_key(config.providerSshPublicKey)
        validate_checkpoint_route_server_peers(list(config.routeServerPeers))
        relay = bool(config.managementRelayUrl or config.managementRelayClientId)
        if relay:
            if endpoint(config.managementRelayUrl, ".azurewebsites.net") != config.managementRelayUrl:
                raise ValueError()
            uuid_text(config.managementRelayClientId)
        group = config.group_name
        storage = re.fullmatch(r"https://(stcp[a-z0-9]{13})\.blob\.core\.windows\.net/", config.stateBlobEndpoint)
        if (config.schemaVersion not in (1, 2, 3)
                or config.schemaVersion != (3 if relay else 2 if config.adminAllowedSources else 1)
                or config.runnerClientId != client
                or not group.startswith("rg-faas-env-")
                or environment_resource_group_name(group.removeprefix("rg-faas-env-")) != group
                or config.providerGroupId != f"/subscriptions/{subscription}/resourceGroups/{group}"
                or storage is None
                or config.credentialVaultUri != f"https://kvcp{storage.group(1)[4:]}.vault.azure.net/"
                or config.stateContainer != "terraform-state"
                or config.firewallFrontendIp != "172.22.10.4" or config.firewallBackendIp != "172.22.20.4"
                or config.routeServerAsn != 65515):
            raise ValueError()
        return config
    except (KeyError, TypeError, ValueError, AttributeError):
        raise CheckpointRunnerConfigError("Invalid Check Point runner configuration") from None


def ensure_checkpoint_runner_credentials(config: CheckpointRuntimeConfig,
                                         client: SecretClient) -> CheckpointCredentials:
    """Reuse the environment's single credential version, or create it once; never rotate implicitly."""
    name, tags = config.credential_name, {"purpose": "checkpoint-management-credentials",
                                          "environmentId": config.environmentId}
    options = {"logging_enable": False, "retry_total": 0, "tracing_options": {"enabled": False}}
    try:
        versions = list(client.list_properties_of_secret_versions(name, **options))
    except ResourceNotFoundError:
        versions = []
    if len(versions) > 1:
        raise CheckpointVaultError("Multiple Check Point credential versions require review")
    if not versions:
        generated = generate_checkpoint_credentials()
        value = json.dumps({"managementPassword": generated.management_password, "sicKey": generated.sic_key},
                           separators=(",", ":"))
        client.set_secret(name, value, enabled=True, content_type=CONTENT_TYPE, tags=tags, **options)
        versions = list(client.list_properties_of_secret_versions(name, **options))
        if len(versions) != 1:
            raise CheckpointVaultError("Check Point credential write is unconfirmed")
    version = versions[0].version
    if not isinstance(version, str) or not re.fullmatch(r"[0-9a-f]{32}", version):
        raise CheckpointVaultError("Invalid Check Point credential version")
    secret = client.get_secret(name, version, **options)
    value = getattr(secret, "value", None)
    if not isinstance(value, str):
        raise CheckpointVaultError("Invalid Check Point credential version")
    return decode_checkpoint_credential(secret, name, version, config.environmentId,
                                        hashlib.sha256(value.encode("utf-8")).hexdigest())


def read_checkpoint_runner_inputs(environment: Mapping[str, str]) -> CheckpointRuntimeInputs:
    """Load configuration and the private credential using only the runner's managed identity."""
    config = load_checkpoint_runner_config(environment)
    identity = ManagedIdentityCredential(client_id=config.runnerClientId)
    try:
        client = SecretClient(config.credentialVaultUri, identity, logging_enable=False,
                              retry_total=0, connection_timeout=5, read_timeout=20)
        try:
            return CheckpointRuntimeInputs(config, ensure_checkpoint_runner_credentials(config, client))
        finally:
            client.close()
    except AzureError:
        raise CheckpointRunnerConfigError("Check Point runner credential operation failed") from None
    finally:
        identity.close()


def validate_checkpoint_runner_plan(inputs: CheckpointRuntimeInputs, plan: dict) -> CheckpointPlanSummary:
    """Apply the existing plan guard to the runner's verified configuration and credentials."""
    config = inputs.config
    return validate_checkpoint_plan(
        plan, config.providerSubscriptionId, config.providerTenantId, config.runnerClientId,
        config.group_name, config.environmentId,
        config.gatewayImageVersion, config.managementImageVersion,
        config.gatewayVmSize, config.managementVmSize, config.providerSshPublicKey, inputs.credentials)
