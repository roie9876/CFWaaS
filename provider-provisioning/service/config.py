import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID
from urllib.parse import urlsplit

logger = logging.getLogger("faas.config")


def uuid_text(value: str) -> str:
    if str(UUID(value)) != value:
        raise ValueError("Identity must be a canonical UUID")
    return value


def endpoint(value: str, suffix: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.hostname.endswith(suffix)
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Invalid service endpoint")
    return value.rstrip("/")


@dataclass(frozen=True)
class Customer:
    """Business customer tenant bound to the enrolled API caller's object/client IDs."""

    tenant: str
    principal: str
    client: str

    def __post_init__(self) -> None:
        for value in (self.tenant, self.principal, self.client):
            uuid_text(value)


@dataclass(frozen=True)
class Settings:
    audience: str
    customer: Customer | None
    table_endpoint: str
    vault_url: str
    required_role: str = "FirewallDeployment.Request"
    max_caller_active: int = 2
    max_caller_running: int = 1
    lease_seconds: int = 90
    poll_seconds: float = 5
    max_attempts: int = 5
    auth_mode: str = "customer-managed-identity"
    authority_tenant: str | None = None
    customer_allocation_key: str | None = None
    provider_group_mode: str = "shared"
    parallel_provider_networking: bool = False
    checkpoint_enabled: bool = False

    def __post_init__(self) -> None:
        if self.auth_mode not in ("customer-managed-identity", "provider-api-client",
                                  "provider-api-registry"):
            raise ValueError("Invalid authentication mode")
        if self.provider_group_mode not in ("shared", "isolated"):
            raise ValueError("Invalid provider group mode")
        if type(self.parallel_provider_networking) is not bool:
            raise ValueError("Invalid provider networking mode")
        if type(self.checkpoint_enabled) is not bool or (
                self.checkpoint_enabled and self.provider_group_mode != "isolated"):
            raise ValueError("Check Point deployments require isolated provider groups")
        if self.auth_mode != "provider-api-registry" and self.customer is None:
            raise ValueError("A bound customer is required")
        if self.authority_tenant is None:
            if self.auth_mode in ("provider-api-client", "provider-api-registry"):
                raise ValueError("Provider API client mode requires an authority tenant")
            if self.customer is None:
                raise ValueError("A bound customer is required")
            object.__setattr__(self, "authority_tenant", self.customer.tenant)
        uuid_text(self.authority_tenant)
        uuid_text(self.audience)
    @classmethod
    def from_env(cls) -> "Settings":
        mode = os.getenv("FAAS_AUTH_MODE", "customer-managed-identity")
        provider_group_mode = os.getenv("FAAS_PROVIDER_GROUP_MODE", "shared")
        isolated_lab_risk = os.getenv("FAAS_ALLOW_ISOLATED_LAB_RISK", "false").strip().lower()
        if isolated_lab_risk not in ("true", "false"):
            raise ValueError("Invalid isolated lab risk setting")
        if (provider_group_mode == "isolated"
                and (isolated_lab_risk != "true" or mode != "provider-api-registry")):
            raise ValueError("Isolated provider groups require explicit registry-mode lab risk approval")
        parallel = os.getenv("FAAS_PROVIDER_PARALLEL_NETWORKING", "false").strip().lower()
        if parallel not in ("true", "false"):
            raise ValueError("Invalid provider networking mode")
        checkpoint = os.getenv("FAAS_CHECKPOINT_ENABLED", "false").strip().lower()
        if checkpoint not in ("true", "false"):
            raise ValueError("Invalid Check Point enablement setting")
        customer = None if mode == "provider-api-registry" else Customer(
            os.environ["FAAS_TRUSTED_TENANT_ID"],
            os.environ["FAAS_TRUSTED_PRINCIPAL_ID"],
            os.environ["FAAS_TRUSTED_CLIENT_ID"],
        )
        # The PoC deliberately admits one bound record, not an unbounded tenant list.
        if os.environ.get("FAAS_CUSTOMERS_JSON"):
            if customer is None:
                raise ValueError("Registry customers must be managed through onboarding")
            records = json.loads(os.environ["FAAS_CUSTOMERS_JSON"])
            if records != [{"tenantId": customer.tenant, "principalId": customer.principal,
                            "clientId": customer.client}]:
                raise ValueError("Customer configuration must match the bound PoC customer")
        if "FAAS_MAX_ENVIRONMENTS" in os.environ or "FAAS_MAX_INSTANCES" in os.environ:
            logger.warning("Legacy environment allocation limits are ignored")
        settings = cls(
            audience=os.environ["FAAS_API_AUDIENCE"],
            customer=customer,
            table_endpoint=endpoint(os.environ["FAAS_TABLE_ENDPOINT"], ".table.core.windows.net"),
            vault_url=endpoint(os.environ["FAAS_VAULT_URL"], ".vault.azure.net"),
            required_role=os.getenv("FAAS_REQUIRED_ROLE", "FirewallDeployment.Request"),
            max_caller_active=int(os.getenv("FAAS_MAX_CALLER_ACTIVE", "2")),
            max_caller_running=int(os.getenv("FAAS_MAX_CALLER_RUNNING", "1")),
            lease_seconds=int(os.getenv("FAAS_LEASE_SECONDS", "90")),
            poll_seconds=float(os.getenv("FAAS_POLL_SECONDS", "5")),
            max_attempts=int(os.getenv("FAAS_MAX_ATTEMPTS", "5")),
            auth_mode=mode,
            authority_tenant=os.getenv("FAAS_AUTHORITY_TENANT_ID"),
            provider_group_mode=provider_group_mode,
            parallel_provider_networking=parallel == "true",
            checkpoint_enabled=checkpoint == "true",
        )
        if (not settings.audience or settings.required_role != "FirewallDeployment.Request"
                  or min(settings.max_caller_active, settings.max_caller_running,
                      settings.max_attempts) < 1
                or settings.lease_seconds < 30 or settings.poll_seconds < 0.1):
            raise ValueError("Invalid service limits")
        return settings


@dataclass(frozen=True)
class WorkerSettings:
    subscription: str
    resource_group: str
    template_path: Path
    template_sha256: str
    ssh_public_key: str
    group_subscription: str = ""
    group_provisioner_client_id: str = ""
    group_deployer_client_id: str = ""
    group_deployer_principal_id: str = ""
    managed_host_group: str = ""
    managed_host_parent_group: str = ""
    managed_host_application: str = ""
    managed_host_definition: str = ""
    managed_host_allow_azure_condition: bool = False

    @classmethod
    def from_env(cls) -> "WorkerSettings":
        import re

        group = os.environ["FAAS_PROVIDER_RESOURCE_GROUP"]
        if not re.fullmatch(r"[a-zA-Z0-9_.()-]{1,90}", group) or group.endswith("."):
            raise ValueError("Invalid provider resource group")
        isolated = tuple(os.getenv(name, "") for name in (
            "FAAS_GROUP_SUBSCRIPTION_ID", "FAAS_GROUP_PROVISIONER_CLIENT_ID",
            "FAAS_GROUP_DEPLOYER_CLIENT_ID", "FAAS_GROUP_DEPLOYER_PRINCIPAL_ID"))
        if any(isolated) and not all(isolated):
            raise ValueError("Incomplete isolated provisioning configuration")
        if all(isolated):
            isolated = tuple(uuid_text(value) for value in isolated)
        host = tuple(os.getenv(name, "") for name in (
            "FAAS_MANAGED_HOST_GROUP", "FAAS_MANAGED_HOST_PARENT_GROUP",
            "FAAS_MANAGED_HOST_APPLICATION", "FAAS_MANAGED_HOST_DEFINITION"))
        allow_condition = os.getenv("FAAS_MANAGED_HOST_ALLOW_AZURE_CONDITION", "false").strip().lower()
        if allow_condition not in ("true", "false"):
            raise ValueError("Invalid managed deny condition setting")
        if any(host) and (not all(host) or not all(isolated)):
            raise ValueError("Incomplete managed host configuration")
        if allow_condition == "true" and not all(host):
            raise ValueError("Managed deny condition requires a complete host configuration")
        if all(host):
            if isolated[1] != isolated[2]:
                raise ValueError("Managed host requires one publisher identity")
            if any(not re.fullmatch(r"[a-zA-Z0-9_.()-]{1,90}", name) or name.endswith(".")
                   for name in host):
                raise ValueError("Invalid managed host resource name")
            if host[0].lower() == host[1].lower():
                raise ValueError("Managed host must use a separate parent group")
        return cls(
            uuid_text(os.environ["FAAS_PROVIDER_SUBSCRIPTION_ID"]),
            group,
            Path(os.getenv("FAAS_PROVIDER_TEMPLATE_PATH",
                           str(Path(__file__).parent / "templates/provider.json"))),
            os.getenv("FAAS_PROVIDER_TEMPLATE_SHA256", ""),
            os.getenv("FAAS_NVA_SSH_PUBLIC_KEY", ""),
            *isolated,
            *host,
            allow_condition == "true",
        )


@dataclass(frozen=True)
class CheckpointWorkerSettings:
    """Explicit, provider-only configuration; absent unless FAAS_CHECKPOINT_ENABLED=true."""
    client_id: str
    principal_id: str
    identity_id: str
    control_group: str
    definition: str
    registry_server: str
    image_sha256: str
    gateway_image_version: str
    management_image_version: str
    gateway_vm_size: str
    management_vm_size: str
    ssh_public_key: str
    foundation_template_path: Path
    foundation_template_sha256: str
    private_template_path: Path
    private_template_sha256: str
    management_relay_url: str = ""
    management_relay_client_id: str = ""

    @classmethod
    def from_env(cls, worker: WorkerSettings) -> "CheckpointWorkerSettings | None":
        import re

        enabled = os.getenv("FAAS_CHECKPOINT_ENABLED", "false").strip().lower()
        if enabled not in ("true", "false"):
            raise ValueError("Invalid Check Point enablement setting")
        if enabled == "false":
            return None
        if not worker.managed_host_group or not worker.managed_host_allow_azure_condition:
            raise ValueError("Check Point requires the approved managed host configuration")
        values = {name: os.environ[f"FAAS_CHECKPOINT_{name.upper()}"].strip() for name in (
            "client_id", "principal_id", "control_group", "identity_name", "definition", "registry_server",
            "image_sha256", "gateway_image_version", "management_image_version",
            "gateway_vm_size", "management_vm_size")}
        templates = Path(__file__).parent / "templates"
        control = values["control_group"]
        if (not control.startswith("rg-faas-cp-control-")
                or "rg-faas-cp-control-" + uuid_text(control.removeprefix("rg-faas-cp-control-")) != control
                or not re.fullmatch(r"faas-cp-publisher-[a-z0-9]{8}", values["identity_name"])
                or not re.fullmatch(r"[a-zA-Z0-9_.()-]{1,64}", values["definition"])
                or not re.fullmatch(r"[a-z0-9][a-z0-9-]{3,77}[a-z0-9]\.azurecr\.io", values["registry_server"])
                or not re.fullmatch(r"[0-9a-f]{64}", values["image_sha256"])
                or any(not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", values[name])
                       for name in ("gateway_image_version", "management_image_version"))
                or any(not re.fullmatch(r"Standard_[A-Za-z0-9_]{1,48}", values[name])
                       for name in ("gateway_vm_size", "management_vm_size"))):
            raise ValueError("Invalid Check Point worker configuration")
        hashes = {name: os.environ[f"FAAS_CHECKPOINT_{name.upper()}_TEMPLATE_SHA256"].strip().lower()
                  for name in ("foundation", "private")}
        if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values()):
            raise ValueError("Invalid Check Point template pin")
        relay_url = os.getenv("FAAS_CHECKPOINT_MANAGEMENT_RELAY_URL", "").strip()
        relay_client = os.getenv("FAAS_CHECKPOINT_MANAGEMENT_RELAY_CLIENT_ID", "").strip()
        if relay_url or relay_client:
            relay_url = endpoint(relay_url, ".azurewebsites.net")
            relay_client = uuid_text(relay_client)
        return cls(
            uuid_text(values["client_id"]), uuid_text(values["principal_id"]),
            f"/subscriptions/{worker.group_subscription}/resourceGroups/{control}"
            f"/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{values['identity_name']}",
            control, values["definition"], values["registry_server"], values["image_sha256"],
            values["gateway_image_version"], values["management_image_version"],
            values["gateway_vm_size"], values["management_vm_size"],
            worker.ssh_public_key,
            Path(os.getenv("FAAS_CHECKPOINT_FOUNDATION_TEMPLATE_PATH", str(templates / "checkpoint-foundation.json"))),
            hashes["foundation"],
            Path(os.getenv("FAAS_CHECKPOINT_PRIVATE_TEMPLATE_PATH", str(templates / "checkpoint-private-data.json"))),
            hashes["private"],
            relay_url, relay_client,
        )
