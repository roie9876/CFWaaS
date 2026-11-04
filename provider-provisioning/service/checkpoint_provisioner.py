"""Worker-side orchestration for an optional Check Point environment; disabled unless explicitly configured.

Stages are idempotent and reconciled after restarts: isolated group, network foundation, private
data, then exactly one runner job. The worker never reaches the environment's private vault or state;
the runner does that inside the environment network.
"""
import io
import time
from collections.abc import Callable
from dataclasses import dataclass

from azure.core.exceptions import AzureError, HttpResponseError
from azure.mgmt.resource import ResourceManagementClient

from .azure_data import Vault, secret_names
from .checkpoint_credential_journal import CheckpointCredentialJournal
from .checkpoint_foundation import validate_checkpoint_foundation
from .checkpoint_private_data import validate_checkpoint_private_data_outputs
from .checkpoint_runner import (
    RUNNER_API_VERSION, CheckpointRunnerError, CheckpointRunnerObserver, build_checkpoint_runner_request,
    validate_checkpoint_runner_request,
)
from .checkpoint_runner_config import CheckpointRunnerSettings
from .checkpoint_runner_journal import CheckpointRunnerJournal, CheckpointRunnerStateError
from .config import CheckpointWorkerSettings
from .models import ConnectionManifest, EnvironmentRequest
from .provisioner import Arm, ProvisionError
from .store import Lease, Store


IDENTITY_API_VERSION = "2023-01-31"
ROUTE_SERVER_API_VERSION = "2024-05-01"
DEPLOYMENT_TIMEOUT = 3 * 3600
RUNNER_TIMEOUT = 3 * 3600


@dataclass(frozen=True)
class CheckpointSettings:
    foundation_template: dict
    private_template: dict
    control_group: str
    identity_id: str
    registry_server: str
    image_sha256: str
    runner: CheckpointRunnerSettings


def load_checkpoint_settings(config: CheckpointWorkerSettings) -> CheckpointSettings:
    """Load only the exact pinned, validated templates; fail closed at worker startup otherwise."""
    import hashlib
    import json
    from .templates import Templates

    def pinned(path, digest: str) -> dict:
        raw = path.read_bytes()
        if len(raw) > 4 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("Check Point template hash mismatch")
        return json.loads(raw)

    return CheckpointSettings(
        Templates.validate_checkpoint_foundation(
            pinned(config.foundation_template_path, config.foundation_template_sha256)),
        Templates.validate_checkpoint_private_data(
            pinned(config.private_template_path, config.private_template_sha256)),
        config.control_group, config.identity_id, config.registry_server, config.image_sha256,
        CheckpointRunnerSettings(config.gateway_image_version, config.management_image_version,
                                 config.gateway_vm_size, config.management_vm_size, config.ssh_public_key,
                                 config.management_relay_url, config.management_relay_client_id))


class CheckpointProvisioner:
    def __init__(self, settings: CheckpointSettings, groups, arm_factory: Callable[[str], Arm],
                 resources: ResourceManagementClient, vault: Vault, subscription: str, tenant: str,
                 wait: Callable[[float], None] = time.sleep) -> None:
        self.settings, self.groups, self.arm_factory = settings, groups, arm_factory
        self.resources, self.vault = resources, vault
        self.subscription, self.tenant, self.wait = subscription, tenant, wait

    def _deploy(self, arm: Arm, name: str, template: dict, parameters: dict,
                check: Callable[[], None]) -> dict:
        check()
        if arm.get(name) is None:
            check()
            arm.start(name, template, parameters)
        deadline = time.monotonic() + DEPLOYMENT_TIMEOUT
        while True:
            check()
            state = arm.get(name)
            if state is not None:
                provisioning_state, outputs = state
                if provisioning_state == "Succeeded":
                    return outputs
                if provisioning_state in ("Failed", "Canceled", "Cancelled"):
                    raise ProvisionError("CheckpointDeploymentFailed", False)
            if time.monotonic() >= deadline:
                raise ProvisionError("DeploymentStillRunning")
            self.wait(15)

    def _current_route_server_peers(self, outputs: dict, group: str, environment_id: str) -> dict:
        """ARM captures the Route Server before its IP configuration assigns peer addresses, so an
        empty output list is replaced with the provisioned addresses read from the same resource."""
        import copy
        foundation = outputs.get("checkpointFoundation") if isinstance(outputs, dict) else None
        value = foundation.get("value") if isinstance(foundation, dict) else None
        if not isinstance(value, dict) or value.get("routeServerPeerAddresses") != []:
            return outputs
        hub_id = (f"/subscriptions/{self.subscription}/resourceGroups/{group}/providers/Microsoft.Network"
                  f"/virtualHubs/rs-cp-pi-{environment_id[:8]}")
        try:
            hub = self.resources.resources.get_by_id(hub_id, ROUTE_SERVER_API_VERSION)
        except AzureError:
            raise ProvisionError("ProviderTemporarilyUnavailable") from None
        properties = hub.properties if isinstance(getattr(hub, "properties", None), dict) else {}
        peers = properties.get("virtualRouterIps")
        if (properties.get("provisioningState") != "Succeeded" or properties.get("routingState") != "Provisioned"
                or not isinstance(peers, list)):
            raise ProvisionError("ProviderTemporarilyUnavailable")
        refreshed = copy.deepcopy(outputs)
        refreshed["checkpointFoundation"]["value"]["routeServerPeerAddresses"] = list(peers)
        return refreshed

    def _shared_keys(self, environment_id: str, operation: dict, check: Callable[[], None],
                     bind: Callable[[dict[str, str]], None]) -> tuple[str, str]:
        import json
        ingress, delivery = secret_names(environment_id)
        versions = json.loads(str(operation.get("secretVersions") or "{}"))
        if versions:
            if set(versions) != {"ingress", "delivery"}:
                raise ProvisionError("InvalidSecretReferences", False)
            return self.vault.read(ingress, versions["ingress"]), self.vault.read(delivery, versions["delivery"])
        first, second = self.vault.ensure(ingress, check), self.vault.ensure(delivery, check)
        bind({"ingress": first.version, "delivery": second.version})
        return first.value, second.value

    def _run_job(self, lease: Lease, store: Store, journal: CheckpointRunnerJournal, spec, body: bytes,
                 check: Callable[[], None]) -> None:
        observer = CheckpointRunnerObserver(journal, self.resources)
        reservation = journal.reserve(lease, spec.job_id, spec.sha256)
        if reservation.state == "reserved":
            if observer.observe(lease, spec).state != "not_started":
                raise ProvisionError("CheckpointRunnerConflict", False)
            if journal.begin_launch(lease, spec.job_id, spec.sha256):
                validate_checkpoint_runner_request(spec, body)
                check()
                # Launched only once: a later ambiguous state is reconciled, never relaunched.
                self.resources.resources.begin_create_or_update_by_id(
                    spec.job_id, RUNNER_API_VERSION, io.BytesIO(body), polling=False)
        deadline = time.monotonic() + RUNNER_TIMEOUT
        while True:
            check()
            observation = observer.observe(lease, spec)
            if observation.state == "completed":
                if observation.exit_code != 0:
                    raise ProvisionError("CheckpointRunnerFailed", False)
                return
            if observation.state == "provisioning_failed":
                raise ProvisionError("CheckpointRunnerFailed", False)
            if time.monotonic() >= deadline:
                raise ProvisionError("CheckpointRunnerUnconfirmed", False)
            self.wait(30)

    def provision(self, lease: Lease, store: Store, operation: dict, request: EnvironmentRequest,
                  check: Callable[[], None]) -> dict:
        if (request.firewallType != "checkpoint-byol" or request.mode != "network"
                or request.region != "eastus2" or operation.get("providerGroupMode") != "isolated"):
            raise ProvisionError("CheckpointDeploymentUnavailable", False)
        if request.adminAllowedSources:
            parameter = self.settings.foundation_template.get("parameters", {}).get("adminAllowedSources", {})
            if parameter.get("type") != "array" or parameter.get("maxLength") != 16:
                raise ProvisionError("CheckpointAdminAccessUnavailable", False)
        environment_id = lease.environment_id
        group = self.groups.ensure(
            operation, request.region, check, lambda: store.begin_provider_group(lease),
            lambda scope: store.bind_provider_group(lease, self.subscription, scope))
        arm = self.arm_factory(group)
        try:
            ingress_key, delivery_key = self._shared_keys(
                environment_id, store.operation(lease), check, lambda v: store.bind_secret_versions(lease, v))
            first, second = request.customerIngress, request.customerDelivery
            if first is None or second is None:
                raise ProvisionError("InvalidNetworkRequest", False, True)
            parameters = {key: {"value": value} for key, value in {
                "location": "eastus2", "environmentId": environment_id,
                "customerIngressPublicIp": first.publicIp, "customerIngressBgpAddress": first.bgpAddress,
                "customerIngressAsn": first.asn, "customerDeliveryPublicIp": second.publicIp,
                "customerDeliveryBgpAddress": second.bgpAddress, "customerDeliveryAsn": second.asn,
                "ingressSharedKey": ingress_key, "deliverySharedKey": delivery_key,
            }.items()}
            if request.adminAllowedSources:
                parameters["adminAllowedSources"] = {"value": request.adminAllowedSources}
            foundation_outputs = self._deploy(arm, "faas-cp-foundation-" + environment_id,
                                              self.settings.foundation_template, parameters, check)
            foundation_outputs = self._current_route_server_peers(foundation_outputs, group, environment_id)
            try:
                foundation = validate_checkpoint_foundation(foundation_outputs, self.subscription, group, environment_id)
            except ValueError:
                raise ProvisionError("InvalidCheckpointFoundation", False) from None
            private_outputs = self._deploy(arm, "faas-cp-private-" + environment_id, self.settings.private_template,
                                           {"location": {"value": "eastus2"},
                                            "environmentId": {"value": environment_id}}, check)
            try:
                validate_checkpoint_private_data_outputs(private_outputs, self.subscription, group, environment_id)
                identity = self.resources.resources.get_by_id(
                    self.settings.identity_id, IDENTITY_API_VERSION).serialize(keep_readonly=True)
                spec, body = build_checkpoint_runner_request(
                    foundation_outputs, private_outputs, self.subscription, self.tenant, group, environment_id,
                    self.settings.control_group, identity, self.settings.registry_server,
                    self.settings.image_sha256, self.settings.runner, request.adminAllowedSources)
            except (ValueError, CheckpointRunnerError):
                raise ProvisionError("InvalidCheckpointRunner", False) from None
            journal = CheckpointRunnerJournal(CheckpointCredentialJournal(store, self.subscription))
            try:
                self._run_job(lease, store, journal, spec, body, check)
            except (CheckpointRunnerError, CheckpointRunnerStateError):
                raise ProvisionError("CheckpointRunnerUnconfirmed", False) from None
            return foundation.connection_manifest.model_dump(exclude_none=True)
        except HttpResponseError as exc:
            if exc.status_code in (401, 403):
                raise ProvisionError("ProviderAuthorizationNotReady") from None
            if exc.status_code in (408, 409, 429, 500, 502, 503, 504):
                raise ProvisionError("ProviderTemporarilyUnavailable") from None
            raise ProvisionError("ProviderDeploymentRejected", False) from None
        except AzureError:
            raise ProvisionError("ProviderTemporarilyUnavailable") from None
        finally:
            close = getattr(arm, "close", None)
            if close is not None:
                close()
