"""Container entrypoint for one provider-only Check Point Terraform apply and post-boot configuration."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path

from azure.core.exceptions import AzureError, ResourceNotFoundError
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

from .checkpoint_dependencies import (
    CheckpointDependencyError, verify_checkpoint_artifact, verify_checkpoint_provider_runtime,
)
from .checkpoint_gaia import CheckpointConfigurator, CheckpointGaiaError, ManagementApi, TlsPin
from .checkpoint_plan import CheckpointPlanError
from .checkpoint_runner_config import (
    CheckpointRunnerConfigError, CheckpointRuntimeInputs, read_checkpoint_runner_inputs,
    validate_checkpoint_runner_plan,
)
from .checkpoint_saved_plan import CheckpointPlanStorageError, CheckpointPlanWorkspace
from .checkpoint_terraform import CheckpointTerraformError, verify_terraform_runtime
from .checkpoint_vault import CheckpointVaultError


ARTIFACT = Path("/opt/faas/checkpoint")
ARTIFACTS = {"single": ARTIFACT, "vmss": Path("/opt/faas/checkpoint-vmss")}
TERRAFORM = Path("/opt/faas/bin/terraform")
EXIT_OK, EXIT_INPUTS, EXIT_RUNTIME, EXIT_TERRAFORM, EXIT_PLAN, EXIT_CONFIGURE = 0, 10, 20, 30, 40, 50
TIMEOUT_SECONDS = {"init": 600, "plan": 1800, "show": 300, "apply": 5400}
MAX_PLAN_JSON_BYTES = 64 * 1024 * 1024


class _Failure(Exception):
    def __init__(self, code: int, reason: str = "") -> None:
        super().__init__(code)
        self.code, self.reason = code, reason


def _reason(error: Exception) -> str:
    # Plan-guard messages contain only constants, expected addresses, action verbs and schema key names.
    message = str(error)
    return (message if isinstance(error, (CheckpointPlanError, CheckpointGaiaError))
            and message.isascii() and len(message) <= 320 else "")


def _log(label: str) -> None:
    print("checkpoint-runner " + label, file=sys.stderr, flush=True)


def configure_checkpoint(inputs: CheckpointRuntimeInputs) -> None:
    """Pin the management certificate in the private vault and apply the post-boot configuration."""
    config = inputs.config
    name = "cp-management-tls-" + config.environmentId
    options = {"logging_enable": False, "retry_total": 2, "tracing_options": {"enabled": False}}
    identity = ManagedIdentityCredential(client_id=config.runnerClientId)
    client = SecretClient(config.credentialVaultUri, identity, logging_enable=False,
                          connection_timeout=5, read_timeout=20)

    def load() -> str | None:
        try:
            value = client.get_secret(name, **options).value
        except ResourceNotFoundError:
            return None
        if not isinstance(value, str) or len(value) != 64:
            raise CheckpointGaiaError("Invalid management certificate pin")
        return value

    def store(fingerprint: str) -> None:
        client.set_secret(name, fingerprint, content_type="sha256-fingerprint",
                          tags={"purpose": "checkpoint-management-tls-pin",
                                "environmentId": config.environmentId}, **options)

    try:
        gateways, next_hop = None, None
        if config.firewallTopology == "vmss":
            from .checkpoint_scale_set import INTERNAL_LOAD_BALANCER_IP, discover_scale_set_gateways
            gateways = discover_scale_set_gateways(
                lambda: identity.get_token("https://management.azure.com/.default").token,
                config.providerGroupId, config.environmentId)
            next_hop = INTERNAL_LOAD_BALANCER_IP
            _log("scale-set-gateways-discovered")
        CheckpointConfigurator(
            ManagementApi(TlsPin(load, store)), config.environmentId, inputs.credentials.sic_key,
            inputs.credentials.management_password, config.routeServerPeers, config.routeServerAsn, _log,
            admin_allowed_sources=config.adminAllowedSources, gateways=gateways,
            internal_load_balancer_ip=next_hop,
        ).run()
        if config.managementRelayUrl:
            from .checkpoint_access_relay import publish_checkpoint_access
            publish_checkpoint_access(inputs, identity)
            _log("management-access-published")
    except AzureError:
        raise CheckpointGaiaError("Management certificate pin storage failed") from None
    finally:
        client.close()
        identity.close()


def _variables(inputs: CheckpointRuntimeInputs) -> dict[str, str]:
    config = inputs.config
    return {
        "provider_subscription_id": config.providerSubscriptionId,
        "provider_tenant_id": config.providerTenantId,
        "provider_managed_identity_client_id": config.runnerClientId,
        "provider_group_id": config.providerGroupId,
        "environment_id": config.environmentId,
        "provider_admin_ssh_public_key": config.providerSshPublicKey,
        "sic_key": inputs.credentials.sic_key,
        "management_admin_password": inputs.credentials.management_password,
        "gateway_image_version": config.gatewayImageVersion,
        "management_image_version": config.managementImageVersion,
        "gateway_vm_size": config.gatewayVmSize,
        "management_vm_size": config.managementVmSize,
    }


def run_checkpoint_runner(
        environment: Mapping[str, str], artifact: Path | None = None, terraform: Path = TERRAFORM,
        work_parent: Path | None = None, execute: Callable[..., subprocess.CompletedProcess] = subprocess.run,
        read_inputs: Callable[[Mapping[str, str]], CheckpointRuntimeInputs] = read_checkpoint_runner_inputs,
        workspace_factory: Callable[[Path], CheckpointPlanWorkspace] = CheckpointPlanWorkspace,
        configure: Callable[[CheckpointRuntimeInputs], None] = configure_checkpoint) -> int:
    """Return an exit code only; Terraform output is captured and discarded because it can contain secrets."""
    try:
        try:
            inputs = read_inputs(environment)
        except (CheckpointRunnerConfigError, CheckpointVaultError, ValueError):
            raise _Failure(EXIT_INPUTS) from None
        topology = inputs.config.firewallTopology
        artifact = artifact or ARTIFACTS[topology]
        try:
            verify_terraform_runtime(terraform)
            verify_checkpoint_artifact(artifact, topology)
            verify_checkpoint_provider_runtime(artifact, topology)
        except (CheckpointTerraformError, CheckpointDependencyError, OSError):
            raise _Failure(EXIT_RUNTIME) from None
        config = inputs.config
        storage = config.stateBlobEndpoint.removeprefix("https://").split(".", 1)[0]
        with tempfile.TemporaryDirectory(prefix="checkpoint-run-", dir=work_parent) as temporary:
            work = Path(temporary)
            work.chmod(0o700)
            data, home = work / "data", work / "home"
            home.mkdir(mode=0o700)
            data.mkdir(mode=0o700)
            try:
                shutil.copytree(artifact / ".terraform/modules", data / "modules", symlinks=True)
                if any(path.is_symlink() for path in (data / "modules").rglob("*")):
                    raise OSError()
            except OSError:
                raise _Failure(EXIT_RUNTIME) from None
            base = {
                "HOME": str(home), "PATH": "/usr/bin:/bin", "TF_IN_AUTOMATION": "true",
                "TF_DATA_DIR": str(data), "TF_INPUT": "0", "CHECKPOINT_DISABLE": "1",
                "TF_CLI_CONFIG_FILE": os.devnull, "ARM_USE_MSI": "true",
                "ARM_CLIENT_ID": config.runnerClientId, "ARM_TENANT_ID": config.providerTenantId,
                "ARM_SUBSCRIPTION_ID": config.providerSubscriptionId,
            }
            with_variables = {**base, **{"TF_VAR_" + name: value for name, value in _variables(inputs).items()}}

            def terraform_command(stage: str, arguments: list[str], env: dict[str, str],
                                  pass_fds: tuple[int, ...] = ()) -> bytes:
                try:
                    result = execute([str(terraform), f"-chdir={artifact}", *arguments], env=env,
                                     capture_output=True, timeout=TIMEOUT_SECONDS[stage], check=False,
                                     pass_fds=pass_fds, umask=0o077, close_fds=True)
                except (OSError, subprocess.SubprocessError):
                    raise _Failure(EXIT_TERRAFORM) from None
                if result.returncode != 0:
                    raise _Failure(EXIT_TERRAFORM)
                return result.stdout

            terraform_command("init", [
                "init", "-input=false", "-no-color", "-lockfile=readonly", "-get=false",
                f"-plugin-dir={artifact / '.terraform/providers'}",
                f"-backend-config=storage_account_name={storage}",
                f"-backend-config=container_name={config.stateContainer}",
                f"-backend-config=key=checkpoint/{config.environmentId}.tfstate",
                "-backend-config=use_azuread_auth=true", "-backend-config=use_msi=true",
                f"-backend-config=client_id={config.runnerClientId}",
                f"-backend-config=tenant_id={config.providerTenantId}",
                f"-backend-config=subscription_id={config.providerSubscriptionId}",
            ], base)
            try:
                with workspace_factory(work) as workspace:
                    terraform_command("plan", [
                        "plan", "-input=false", "-no-color", "-lock-timeout=120s", f"-out={workspace.plan_file}",
                    ], with_variables)
                    with workspace.seal() as sealed:
                        output = terraform_command(
                            "show", ["show", "-json", "-no-color", sealed.path()], base, (sealed.fileno(),))
                        if not isinstance(output, bytes) or len(output) > MAX_PLAN_JSON_BYTES:
                            raise _Failure(EXIT_PLAN)
                        try:
                            summary = validate_checkpoint_runner_plan(inputs, json.loads(output))
                        except (CheckpointPlanError, ValueError, TypeError) as error:
                            raise _Failure(EXIT_PLAN, _reason(error)) from None
                        if summary.needs_apply:
                            terraform_command("apply", [
                                "apply", "-input=false", "-no-color", "-lock-timeout=120s", sealed.path(),
                            ], with_variables, (sealed.fileno(),))
            except CheckpointPlanStorageError:
                raise _Failure(EXIT_RUNTIME) from None
        _log("infrastructure-ready")
        try:
            configure(inputs)
        except (CheckpointGaiaError, OSError) as error:
            raise _Failure(EXIT_CONFIGURE, _reason(error)) from None
        _log("configured")
        return EXIT_OK
    except _Failure as failure:
        print(f"checkpoint-runner exit={failure.code}" + (f" reason={failure.reason}" if failure.reason else ""),
              file=sys.stderr)
        return failure.code


def main() -> None:
    sys.exit(run_checkpoint_runner(dict(os.environ), work_parent=Path(tempfile.gettempdir())))


if __name__ == "__main__":
    main()
