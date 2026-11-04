import time
from typing import Callable, Protocol

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.identity import ManagedIdentityCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.resources.models import Deployment, DeploymentProperties

from .azure_data import Vault, secret_names
from .config import WorkerSettings
from .models import ConnectionManifest, EnvironmentRequest, environment_resource_group_name
from .templates import Templates


class ProvisionError(Exception):
    def __init__(self, code: str, retryable: bool = True, release: bool = False) -> None:
        self.code, self.retryable, self.release = code, retryable, release


class Arm(Protocol):
    def get(self, name: str) -> tuple[str, dict] | None: ...
    def start(self, name: str, template: dict, parameters: dict) -> None: ...
    def proof_absent(self, environment_id: str) -> bool: ...


class AzureArm:
    """Only the worker constructs this client, for its fixed provider RG."""

    def __init__(self, settings: WorkerSettings, credential: ManagedIdentityCredential) -> None:
        self.group = settings.resource_group
        self.client = ResourceManagementClient(
            credential, settings.subscription, logging_enable=False,
            retry_total=2, connection_timeout=5, read_timeout=30)

    def get(self, name: str) -> tuple[str, dict] | None:
        try:
            deployment = self.client.deployments.get(self.group, name)
        except ResourceNotFoundError:
            return None
        properties = deployment.properties
        if properties is None:
            raise ProvisionError("InvalidDeploymentResponse")
        return str(properties.provisioning_state), properties.outputs or {}

    def start(self, name: str, template: dict, parameters: dict) -> None:
        deployment = Deployment(properties=DeploymentProperties(
            mode="Incremental", template=template, parameters=parameters))
        # Do not keep an in-process long-running poller as the durable state.
        # The deterministic deployment name is reconciled by GET after every restart.
        self.client.deployments.begin_create_or_update(
            self.group, name, deployment, polling=False)

    def proof_absent(self, environment_id: str) -> bool:
        try:
            self.client.resources.get(
                self.group, "Microsoft.Network", "", "routeTables",
                "faas-proof-" + environment_id, "2024-05-01")
            return False
        except ResourceNotFoundError:
            return True

    def close(self) -> None:
        self.client.close()


class Provisioner:
    def __init__(self, arm: Arm, vault: Vault, templates: Templates,
                 settings: WorkerSettings, wait: Callable[[float], None] = time.sleep) -> None:
        self.arm, self.vault, self.templates = arm, vault, templates
        self.settings, self.wait = settings, wait

    def provision(self, environment_id: str, request: EnvironmentRequest,
                  check: Callable[[], None], secret_versions: dict[str, str] | None = None,
                  bind_versions: Callable[[dict[str, str]], None] | None = None,
                  arm: Arm | None = None, parallel_networking: bool = False) -> dict:
        from uuid import UUID
        if str(UUID(environment_id)) != environment_id:
            raise ProvisionError("InvalidEnvironmentId", False)
        if request.firewallType != "ubuntu":
            raise ProvisionError("CheckpointDeploymentUnavailable", False)
        if type(parallel_networking) is not bool or (parallel_networking and request.mode != "network"):
            raise ProvisionError("InvalidProviderNetworkingMode", False)
        name = "faas-" + environment_id
        arm = arm if arm is not None else self.arm
        try:
            check()
            existing = arm.get(name)
            if existing is None:
                template = self.templates.proof
                parameters: dict = {
                    "location": {"value": request.region},
                    "environmentId": {"value": environment_id},
                }
                if request.mode == "network":
                    if self.templates.network is None:
                        raise ProvisionError("NetworkTemplateNotConfigured", False, True)
                    template = self.templates.network
                    ingress, delivery = secret_names(environment_id)
                    if secret_versions:
                        if set(secret_versions) != {"ingress", "delivery"}:
                            raise ProvisionError("InvalidSecretReferences", False)
                        ingress_key = self.vault.read(ingress, secret_versions["ingress"])
                        delivery_key = self.vault.read(delivery, secret_versions["delivery"])
                    else:
                        if bind_versions is None:
                            raise ProvisionError("SecretBindingRequired", False)
                        first_secret = self.vault.ensure(ingress, check)
                        second_secret = self.vault.ensure(delivery, check)
                        bind_versions({"ingress": first_secret.version,
                                       "delivery": second_secret.version})
                        ingress_key, delivery_key = first_secret.value, second_secret.value
                    check()
                    first, second = request.customerIngress, request.customerDelivery
                    if first is None or second is None:
                        raise ProvisionError("InvalidNetworkRequest", False, True)
                    values = {
                        "customerIngressPublicIp": first.publicIp,
                        "customerIngressBgpAddress": first.bgpAddress,
                        "customerIngressAsn": first.asn,
                        "customerDeliveryPublicIp": second.publicIp,
                        "customerDeliveryBgpAddress": second.bgpAddress,
                        "customerDeliveryAsn": second.asn,
                        "ingressSharedKey": ingress_key, "deliverySharedKey": delivery_key,
                        "sshPublicKey": self.settings.ssh_public_key,
                        "parallelProviderNetworking": parallel_networking,
                    }
                    parameters.update({key: {"value": value} for key, value in values.items()})
                check()
                arm.start(name, template, parameters)
                check()
            deadline = time.monotonic() + 3600
            while True:
                check()
                state = arm.get(name)
                if state is not None:
                    provisioning_state, outputs = state
                    if provisioning_state == "Succeeded":
                        if request.mode == "proof":
                            if outputs:
                                raise ProvisionError("UnexpectedProofOutput", False)
                            return {}
                        # Outputs are treated as untrusted data, never returned verbatim.
                        try:
                            if set(outputs) != {"connectionManifest"}:
                                raise ValueError("Unexpected output")
                            manifest = outputs["connectionManifest"]
                            if (not isinstance(manifest, dict)
                                    or set(manifest) - {"type", "value"}
                                    or manifest.get("type", "").lower() != "object"):
                                raise ValueError("Invalid manifest")
                            return ConnectionManifest.model_validate(
                                manifest["value"]).model_dump(exclude_none=True)
                        except (ValueError, KeyError, TypeError):
                            raise ProvisionError("InvalidConnectionManifest", False) from None
                    if provisioning_state in ("Failed", "Canceled", "Cancelled"):
                        release = request.mode == "proof" and arm.proof_absent(environment_id)
                        raise ProvisionError("DeploymentFailed", False, release)
                if time.monotonic() >= deadline:
                    raise ProvisionError("DeploymentStillRunning")
                self.wait(5)
        except HttpResponseError as exc:
            if exc.status_code in (401, 403):
                raise ProvisionError("ProviderAuthorizationNotReady") from None
            if exc.status_code in (408, 409, 429, 500, 502, 503, 504):
                raise ProvisionError("ProviderTemporarilyUnavailable") from None
            raise ProvisionError("ProviderDeploymentRejected", False) from None
