"""Provider-only container-job request preparation and read-only reconciliation."""
import hashlib
import hmac
import ipaddress
import json
import re
from dataclasses import dataclass, field

from azure.core.exceptions import AzureError, ResourceNotFoundError
from azure.mgmt.resource import ResourceManagementClient

from .checkpoint_apply_journal import checkpoint_runner_resource_id
from .checkpoint_foundation import validate_checkpoint_foundation
from .checkpoint_runner_config import CheckpointRunnerSettings, build_checkpoint_runner_config
from .checkpoint_runner_journal import CheckpointRunnerJournal
from .config import uuid_text
from .store import Lease


RUNNER_API_VERSION = "2023-05-01"
DNS_SERVER = "168.63.129.16"


class CheckpointRunnerError(ValueError):
    pass


@dataclass(frozen=True)
class CheckpointRunnerSpec:
    job_id: str
    identity_id: str
    identity_client_id: str
    identity_principal_id: str
    image: str
    subnet_id: str
    environment_id: str
    environment: tuple[tuple[str, str], ...] = field(repr=False)

    @property
    def sha256(self) -> str:
        value = {
            "jobId": self.job_id.lower(), "identityId": self.identity_id.lower(),
            "identityClientId": self.identity_client_id, "identityPrincipalId": self.identity_principal_id,
            "request": _checkpoint_runner_request(self),
        }
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class CheckpointRunnerObservation:
    state: str
    exit_code: int | None = None


def build_checkpoint_runner_spec(
        foundation_outputs: dict, private_outputs: dict, provider_subscription: str, provider_tenant: str,
        group_name: str, environment_id: str, control_group: str, identity: dict,
        registry_server: str, image_sha256: str, settings: CheckpointRunnerSettings,
        admin_allowed_sources: list[str] | None = None, firewall_topology: str = "single") -> CheckpointRunnerSpec:
    """Bind provider release/identity evidence and narrowly validated public admin sources."""
    try:
        uuid_text(provider_subscription)
        uuid_text(provider_tenant)
        uuid_text(environment_id)
        if (not isinstance(control_group, str) or not control_group.startswith("rg-faas-cp-control-")
                or "rg-faas-cp-control-" + uuid_text(control_group.removeprefix("rg-faas-cp-control-")) != control_group
                or not isinstance(registry_server, str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9-]{3,77}[a-z0-9]\.azurecr\.io", registry_server)
                or not isinstance(image_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", image_sha256)
                or not isinstance(settings, CheckpointRunnerSettings)):
            raise ValueError()
    except (TypeError, ValueError, AttributeError):
        raise CheckpointRunnerError("Invalid Check Point runner configuration") from None
    foundation = validate_checkpoint_foundation(foundation_outputs, provider_subscription, group_name, environment_id,
                                                firewall_topology)
    group_id = f"/subscriptions/{provider_subscription}/resourceGroups/{group_name}"
    if not isinstance(identity, dict) or not isinstance(identity.get("properties"), dict):
        raise CheckpointRunnerError("Invalid Check Point runner identity")
    # The managed-application deny admits only the Check Point definition's publisher identity.
    prefix = (f"/subscriptions/{provider_subscription}/resourceGroups/{control_group}"
              "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/")
    raw_id = identity.get("id")
    name = raw_id[len(prefix):] if isinstance(raw_id, str) and raw_id.lower().startswith(prefix.lower()) else ""
    if not re.fullmatch(r"faas-cp-publisher-[a-z0-9]{8}", name):
        raise CheckpointRunnerError("Invalid Check Point runner identity")
    identity_id = prefix + name
    properties, tags = identity["properties"], identity.get("tags")
    if (str(identity.get("location", "")).lower() != "eastus2"
            or not isinstance(tags, dict) or tags.get("purpose") != "provider-provisioning-checkpoint-publisher"
            or properties.get("tenantId") != provider_tenant
            or properties.get("isolationScope") not in (None, "None", "Regional")):
        raise CheckpointRunnerError("Invalid Check Point runner identity")
    try:
        client_id = uuid_text(properties["clientId"])
        principal_id = uuid_text(properties["principalId"])
        if any(value == "00000000-0000-0000-0000-000000000000" for value in (client_id, principal_id)):
            raise ValueError()
    except (KeyError, TypeError, ValueError, AttributeError):
        raise CheckpointRunnerError("Invalid Check Point runner identity") from None
    config = build_checkpoint_runner_config(
        foundation_outputs, private_outputs, provider_subscription, provider_tenant, group_name, environment_id,
        client_id, settings.gateway_image_version, settings.management_image_version,
        settings.gateway_vm_size, settings.management_vm_size, settings.provider_ssh_public_key,
        admin_allowed_sources, settings.management_relay_url, settings.management_relay_client_id,
        firewall_topology)
    environment = (("FAAS_CONFIG", config), ("FAAS_RUNNER_CLIENT_ID", client_id))
    return CheckpointRunnerSpec(
        job_id=checkpoint_runner_resource_id(group_id, environment_id),
        identity_id=identity_id, identity_client_id=client_id, identity_principal_id=principal_id,
        image=f"{registry_server}/faas-checkpoint-runner@sha256:{image_sha256}",
        subnet_id=foundation.automation_subnet_id, environment_id=environment_id, environment=environment,
    )


def _checkpoint_runner_request(spec: CheckpointRunnerSpec) -> dict:
    return {
        "location": "eastus2",
        "tags": {"purpose": "provider-provisioning-checkpoint-runner", "environmentId": spec.environment_id},
        "identity": {"type": "UserAssigned", "userAssignedIdentities": {spec.identity_id: {}}},
        "properties": {
            "osType": "Linux", "sku": "Standard", "restartPolicy": "Never",
            "subnetIds": [{"id": spec.subnet_id}], "dnsConfig": {"nameServers": [DNS_SERVER]},
            "imageRegistryCredentials": [{"server": spec.image.split("/", 1)[0], "identity": spec.identity_id}],
            "containers": [{
                "name": "runner",
                "properties": {
                    "image": spec.image,
                    "environmentVariables": [{"name": name, "value": value} for name, value in spec.environment],
                    "resources": {"requests": {"cpu": 2, "memoryInGB": 4}},
                    # ACI accepts only "privileged" here; the image's USER and the runner's
                    # root refusal enforce non-root execution.
                    "securityContext": {"privileged": False},
                },
            }],
        },
    }


def build_checkpoint_runner_request(
        foundation_outputs: dict, private_outputs: dict, provider_subscription: str, provider_tenant: str,
        group_name: str, environment_id: str, control_group: str, identity: dict,
        registry_server: str, image_sha256: str, settings: CheckpointRunnerSettings,
        admin_allowed_sources: list[str] | None = None,
        firewall_topology: str = "single") -> tuple[CheckpointRunnerSpec, bytes]:
    """Prepare a secret-free request from validated provider inputs; do not launch or authorize it."""
    spec = build_checkpoint_runner_spec(
        foundation_outputs, private_outputs, provider_subscription, provider_tenant, group_name, environment_id,
        control_group, identity, registry_server, image_sha256, settings, admin_allowed_sources, firewall_topology)
    body = json.dumps(_checkpoint_runner_request(spec), sort_keys=True, separators=(",", ":")).encode()
    return spec, body


def validate_checkpoint_runner_request(spec: CheckpointRunnerSpec, body: bytes) -> None:
    """Reject changes to the prepared request before a future launch attempt."""
    expected = json.dumps(_checkpoint_runner_request(spec), sort_keys=True, separators=(",", ":")).encode()
    if not isinstance(body, bytes) or not hmac.compare_digest(body, expected):
        raise CheckpointRunnerError("Check Point runner request does not match the specification")


def validate_checkpoint_runner_observation(resource: dict, spec: CheckpointRunnerSpec) -> CheckpointRunnerObservation:
    """Validate ARM evidence before interpreting job status; not a registry or role authorization check."""
    if not isinstance(resource, dict) or not isinstance(resource.get("properties"), dict):
        raise CheckpointRunnerError("Invalid Check Point runner evidence")
    props, identity, tags = resource["properties"], resource.get("identity"), resource.get("tags")
    if (not isinstance(resource.get("id"), str) or resource["id"].lower() != spec.job_id.lower()
            or not isinstance(resource.get("location"), str) or resource["location"].lower() != "eastus2"
            or not isinstance(tags, dict) or tags.get("purpose") != "provider-provisioning-checkpoint-runner"
            or tags.get("environmentId") != spec.environment_id
            or not isinstance(identity, dict) or identity.get("type") != "UserAssigned"
            or not isinstance(identity.get("userAssignedIdentities"), dict)):
        raise CheckpointRunnerError("Invalid Check Point runner evidence")
    identities = identity["userAssignedIdentities"]
    if len(identities) != 1:
        raise CheckpointRunnerError("Invalid Check Point runner identity")
    identity_key, identity_value = next(iter(identities.items()))
    if (not isinstance(identity_key, str) or identity_key.lower() != spec.identity_id.lower()
            or not isinstance(identity_value, dict)
            or identity_value.get("clientId") != spec.identity_client_id
            or identity_value.get("principalId") != spec.identity_principal_id):
        raise CheckpointRunnerError("Invalid Check Point runner identity")
    subnets, dns, containers = props.get("subnetIds"), props.get("dnsConfig"), props.get("containers")
    registries = props.get("imageRegistryCredentials")
    if (props.get("osType") != "Linux" or props.get("restartPolicy") != "Never"
            or props.get("sku") != "Standard"
            or not isinstance(subnets, list) or len(subnets) != 1 or not isinstance(subnets[0], dict)
            or not isinstance(subnets[0].get("id"), str) or subnets[0]["id"].lower() != spec.subnet_id.lower()
            or not isinstance(dns, dict) or dns.get("nameServers") != [DNS_SERVER]
            or dns.get("searchDomains") not in (None, "") or dns.get("options") not in (None, "")
            or props.get("initContainers") not in (None, [])
            or props.get("volumes") not in (None, []) or props.get("diagnostics") not in (None, {})
            or props.get("secretReferences") not in (None, []) or props.get("extensions") not in (None, [])
            or not isinstance(containers, list) or len(containers) != 1 or not isinstance(containers[0], dict)
            or containers[0].get("name") != "runner" or not isinstance(containers[0].get("properties"), dict)
            or not isinstance(registries, list) or len(registries) != 1 or not isinstance(registries[0], dict)):
        raise CheckpointRunnerError("Invalid Check Point runner configuration")
    registry = registries[0]
    if (registry.get("server") != spec.image.split("/", 1)[0]
            or not isinstance(registry.get("identity"), str) or registry["identity"].lower() != spec.identity_id.lower()
            or registry.get("username") not in (None, "") or registry.get("password") not in (None, "")):
        raise CheckpointRunnerError("Invalid Check Point runner registry")
    container = containers[0]["properties"]
    environment, security, requests = (container.get("environmentVariables"), container.get("securityContext"),
                                       container.get("resources", {}).get("requests")
                                       if isinstance(container.get("resources"), dict) else None)
    if (container.get("image") != spec.image or container.get("command") not in (None, [])
            or container.get("ports") not in (None, []) or container.get("volumeMounts") not in (None, [])
            or container.get("configMap") not in (None, {}, {"keyValuePairs": {}})
            or container.get("livenessProbe") is not None or container.get("readinessProbe") is not None
            or not isinstance(security, dict) or security.get("privileged") is not False
            or any(security.get(key) is not None and security.get(key) is not False for key in (
                "allowPrivilegeEscalation", "runAsUser", "runAsGroup", "capabilities", "seccompProfile"))
            or not isinstance(requests, dict) or type(requests.get("cpu")) not in (int, float)
            or requests["cpu"] != 2 or type(requests.get("memoryInGB")) not in (int, float)
            or requests["memoryInGB"] != 4 or not isinstance(environment, list)):
        raise CheckpointRunnerError("Invalid Check Point runner container")
    values = {}
    for item in environment:
        if (not isinstance(item, dict) or not isinstance(item.get("name"), str)
                or not isinstance(item.get("value"), str) or item["name"] in values
                or item.get("secureValue") is not None or item.get("secureValueReference") is not None):
            raise CheckpointRunnerError("Invalid Check Point runner environment")
        values[item["name"]] = item["value"]
    if values != dict(spec.environment):
        raise CheckpointRunnerError("Invalid Check Point runner environment")

    address = props.get("ipAddress")
    has_private_ip = False
    if address is not None:
        if not isinstance(address, dict) or address.get("type") != "Private" or address.get("ports") not in (None, []):
            raise CheckpointRunnerError("Invalid Check Point runner network")
        try:
            ip = ipaddress.IPv4Address(address["ip"])
        except (KeyError, TypeError, ipaddress.AddressValueError):
            raise CheckpointRunnerError("Invalid Check Point runner network") from None
        subnet = ipaddress.IPv4Network("172.22.40.0/23")
        reserved = {subnet.network_address + offset for offset in range(4)} | {subnet.broadcast_address}
        if ip not in subnet or ip in reserved:
            raise CheckpointRunnerError("Invalid Check Point runner network")
        has_private_ip = True
    provisioning = props.get("provisioningState")
    # ACI reports Pending for the first seconds after creation.
    if provisioning in ("Pending", "Creating", "Updating"):
        return CheckpointRunnerObservation("pending")
    if provisioning == "Failed":
        return CheckpointRunnerObservation("provisioning_failed")
    if provisioning != "Succeeded":
        raise CheckpointRunnerError("Invalid Check Point runner status")
    view = container.get("instanceView")
    if view is None:
        return CheckpointRunnerObservation("pending")
    if not isinstance(view, dict) or not isinstance(view.get("currentState"), dict):
        raise CheckpointRunnerError("Invalid Check Point runner status")
    current = view["currentState"]
    if current.get("state") in ("Waiting", "Pending"):
        return CheckpointRunnerObservation("pending")
    if type(view.get("restartCount")) is not int or view["restartCount"] != 0:
        raise CheckpointRunnerError("Invalid Check Point runner status")
    if current.get("state") == "Running":
        if not has_private_ip:
            raise CheckpointRunnerError("Invalid Check Point runner status")
        return CheckpointRunnerObservation("running")
    # ACI releases the private IP after a Never-restart container terminates.
    # Its subnet, identity, pinned image and configuration are still checked above.
    if (current.get("state") != "Terminated" or type(current.get("exitCode")) is not int
            or not 0 <= current["exitCode"] <= 255):
        raise CheckpointRunnerError("Invalid Check Point runner status")
    return CheckpointRunnerObservation("completed", current["exitCode"])


class CheckpointRunnerObserver:
    def __init__(self, journal: CheckpointRunnerJournal, resources: ResourceManagementClient) -> None:
        self.journal, self.resources = journal, resources

    def observe(self, lease: Lease, spec: CheckpointRunnerSpec) -> CheckpointRunnerObservation:
        reservation = self.journal.read(lease, spec.job_id, spec.sha256)
        self.journal.store.checked_job(lease)
        missing = False
        resource = None
        try:
            resource = self.resources.resources.get_by_id(spec.job_id, RUNNER_API_VERSION)
        except ResourceNotFoundError:
            missing = True
        except AzureError:
            raise CheckpointRunnerError("Check Point runner evidence is unavailable") from None
        if missing:
            self.journal.store.checked_job(lease)
            if reservation.state == "reserved":
                return CheckpointRunnerObservation("not_started")
            if reservation.state in {"launching", "running"}:
                return CheckpointRunnerObservation("unconfirmed")
            raise CheckpointRunnerError("Completed Check Point runner is unavailable")
        if resource is None:
            raise CheckpointRunnerError("Invalid Check Point runner evidence")
        try:
            document = resource.serialize(keep_readonly=True)
        except (AzureError, TypeError, ValueError, AttributeError):
            raise CheckpointRunnerError("Invalid Check Point runner evidence") from None
        observation = validate_checkpoint_runner_observation(document, spec)
        self.journal.store.checked_job(lease)
        if reservation.state == "reserved":
            raise CheckpointRunnerError("Unexpected existing Check Point runner")
        if reservation.state in {"succeeded", "failed"}:
            expected_exit = reservation.exit_code
            if not ((observation.state == "completed" and observation.exit_code == expected_exit)
                    or (observation.state == "provisioning_failed" and reservation.state == "failed"
                        and expected_exit is None)):
                raise CheckpointRunnerError("Check Point runner result changed")
            return observation
        if observation.state == "running":
            self.journal.observe_running(lease, spec.job_id, spec.sha256)
        elif observation.state == "completed":
            if observation.exit_code is None:
                raise CheckpointRunnerError("Invalid Check Point runner status")
            self.journal.finish(lease, spec.job_id, spec.sha256, observation.exit_code)
        elif observation.state == "provisioning_failed":
            self.journal.fail_provisioning(lease, spec.job_id, spec.sha256)
        return observation
