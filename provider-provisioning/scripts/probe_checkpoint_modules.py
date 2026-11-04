#!/usr/bin/env python3
"""Run a Terraform mock plan of the pinned Check Point modules without Azure credentials."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from common import ROOT
import prepare_checkpoint_modules

sys.path.insert(0, str(ROOT))
from service.checkpoint_credentials import generate_checkpoint_credentials
from service.checkpoint_dependencies import (
    CheckpointDependencyError, verify_checkpoint_artifact, verify_checkpoint_dependencies,
)
from service.checkpoint_plan import (
    EXPECTED, NETWORK_INTERFACES, CheckpointPlanError, validate_checkpoint_destroy_plan, validate_checkpoint_plan,
)
from service.checkpoint_terraform import CheckpointTerraformError, verify_terraform_release

FIXTURE = ROOT / "tests" / "checkpoint_probe"
GROUP = "rg-faas-env-00000000-0000-0000-0000-000000000003"
SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"
SCOPE = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{GROUP}/providers/Microsoft.Network"
FIXTURE_CREDENTIALS = generate_checkpoint_credentials()
FIXTURE_VARIABLES = {
    "provider_subscription_id": SUBSCRIPTION,
    "provider_tenant_id": "00000000-0000-0000-0000-000000000002",
    "provider_managed_identity_client_id": "00000000-0000-0000-0000-000000000005",
    "provider_group_id": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{GROUP}",
    "environment_id": "00000000-0000-0000-0000-000000000004",
    "provider_admin_ssh_public_key": Ed25519PublicKey.from_public_bytes(bytes(range(32))).public_bytes(
        Encoding.OpenSSH, PublicFormat.OpenSSH).decode(),
    "sic_key": FIXTURE_CREDENTIALS.sic_key,
    "management_admin_password": FIXTURE_CREDENTIALS.management_password,
    "gateway_image_version": "1.2.3",
    "management_image_version": "1.2.3",
    "gateway_vm_size": "Standard_D4ds_v5",
    "management_vm_size": "Standard_D4ds_v5",
}
class ProbeError(ValueError):
    pass


def validate_plan(plan: dict, terraform_version: str) -> None:
    if not isinstance(plan, dict):
        raise ProbeError("Terraform mock plan has an unexpected shape")
    test_plan = {**plan, "format_version": plan.get("plan_format_version"),
                 "terraform_version": terraform_version, "complete": True, "errored": False, "applyable": True,
                 "variables": {name: {"value": value} for name, value in FIXTURE_VARIABLES.items()}}
    try:
        summary = validate_checkpoint_plan(
            test_plan, SUBSCRIPTION, FIXTURE_VARIABLES["provider_tenant_id"],
            FIXTURE_VARIABLES["provider_managed_identity_client_id"], GROUP,
            FIXTURE_VARIABLES["environment_id"],
            FIXTURE_VARIABLES["gateway_image_version"], FIXTURE_VARIABLES["management_image_version"],
            FIXTURE_VARIABLES["gateway_vm_size"], FIXTURE_VARIABLES["management_vm_size"],
            FIXTURE_VARIABLES["provider_admin_ssh_public_key"], FIXTURE_CREDENTIALS)
    except CheckpointPlanError:
        raise ProbeError("Terraform mock plan does not match the isolated Check Point configuration") from None
    if summary.creates != len(EXPECTED):
        raise ProbeError("Terraform mock plan must create the expected fixture resources")


def validate_mock_cleanup_state(state: dict, terraform_version: str) -> None:
    if not isinstance(state, dict) or not isinstance(state.get("root_module"), dict):
        raise ProbeError("Terraform mock state has an unexpected shape")
    resources, module_count, item_count = [], 0, 0
    pending = [state["root_module"]]
    while pending:
        module = pending.pop()
        module_count += 1
        if module_count > 32:
            raise ProbeError("Terraform mock state exceeds the expected scope")
        if not isinstance(module, dict) or not isinstance(module.get("resources", []), list) \
                or not isinstance(module.get("child_modules", []), list):
            raise ProbeError("Terraform mock state has an unexpected shape")
        for item in module.get("resources", []):
            item_count += 1
            if (item_count > 100 or not isinstance(item, dict) or not isinstance(item.get("mode"), str)
                    or item["mode"] not in {"managed", "data"}):
                raise ProbeError("Terraform mock state has an unexpected resource")
            if item["mode"] == "managed":
                resources.append({
                    "address": item.get("address"), "mode": "managed", "type": item.get("type"),
                    "provider_name": item.get("provider_name"),
                    "change": {"actions": ["delete"], "before": item.get("values"),
                               "before_sensitive": item.get("sensitive_values"),
                               "after": None, "after_unknown": {}},
                })
        pending.extend(module.get("child_modules", []))
        if len(resources) > len(EXPECTED) or len(pending) > 32:
            raise ProbeError("Terraform mock state exceeds the expected scope")
    outputs = state.get("outputs")
    if not isinstance(outputs, dict) or any(not isinstance(item, dict) for item in outputs.values()):
        raise ProbeError("Terraform mock state has unexpected outputs")
    mock_plan = {
        "format_version": "1.2", "terraform_version": terraform_version,
        "complete": True, "errored": False, "applyable": True,
        "variables": {name: {"value": value} for name, value in FIXTURE_VARIABLES.items()},
        "resource_changes": resources,
        "output_changes": {name: {"actions": ["delete"], "before": item.get("value"),
                                  "before_sensitive": item.get("sensitive"),
                                  "after": None, "after_unknown": False}
                           for name, item in outputs.items()},
    }
    try:
        summary = validate_checkpoint_destroy_plan(
            mock_plan, SUBSCRIPTION, FIXTURE_VARIABLES["provider_tenant_id"],
            FIXTURE_VARIABLES["provider_managed_identity_client_id"], GROUP,
            FIXTURE_VARIABLES["environment_id"],
            FIXTURE_VARIABLES["gateway_image_version"], FIXTURE_VARIABLES["management_image_version"],
            FIXTURE_VARIABLES["gateway_vm_size"], FIXTURE_VARIABLES["management_vm_size"],
            FIXTURE_VARIABLES["provider_admin_ssh_public_key"], FIXTURE_CREDENTIALS)
    except CheckpointPlanError:
        raise ProbeError("Terraform mock cleanup does not match the isolated Check Point configuration") from None
    if summary.deletes != len(EXPECTED):
        raise ProbeError("Terraform mock cleanup has an unexpected resource count")


def _terraform(binary: str, directory: Path, home: Path, arguments: list[str],
               variables: dict[str, str] | None = None,
               expected_errors: tuple[str, ...] | None = None) -> str:
    env = {"HOME": str(home), "PATH": os.defpath, "TF_IN_AUTOMATION": "true", "TF_LOG": "off",
           "TF_CLI_CONFIG_FILE": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "CHECKPOINT_DISABLE": "1"}
    for name, value in (variables or {}).items():
        if name not in FIXTURE_VARIABLES:
            raise ProbeError("Unexpected Terraform mock fixture variable")
        env["TF_VAR_" + name] = value
    try:
        result = subprocess.run([binary, f"-chdir={directory}", *arguments], env=env,
                                capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProbeError("Terraform mock probe could not run") from exc
    if expected_errors is not None:
        if result.returncode == 0:
            raise ProbeError("Terraform mock probe accepted invalid fixture input")
        try:
            events = [json.loads(line) for line in result.stdout.splitlines()]
        except json.JSONDecodeError as exc:
            raise ProbeError("Terraform mock rejection returned invalid JSON") from exc
        errors = [event.get("diagnostic", {}) for event in events
                  if event.get("type") == "diagnostic"
                  and event.get("diagnostic", {}).get("severity") == "error"]
        if (not errors or not any(expected_errors[0] in error.get("detail", "") for error in errors)
                or any(not any(message in error.get("detail", "") for message in expected_errors)
                       for error in errors)):
            raise ProbeError("Terraform mock probe failed for an unexpected reason")
        return result.stdout
    if result.returncode:
        raise ProbeError(f"Terraform {arguments[0]} failed with exit code {result.returncode}")
    return result.stdout


def run(source: Path) -> None:
    executable = shutil.which("terraform")
    if not executable:
        raise ProbeError("Terraform is required for the mock probe")
    local = prepare_checkpoint_modules.LOCAL_ROOT.resolve(strict=True)
    prepared = local / ("checkpoint-probe-" + uuid4().hex)
    prepare_checkpoint_modules.prepare(source, prepared)
    try:
        try:
            verify_checkpoint_artifact(prepared)
        except (OSError, CheckpointDependencyError):
            raise ProbeError("Terraform mock artifact did not match its pin") from None
        with tempfile.TemporaryDirectory(prefix="checkpoint-test-", dir=local) as temporary:
            root = Path(temporary)
            home = root / "home"
            home.mkdir(mode=0o700)
            tests = prepared / "tests"
            tests.mkdir(mode=0o700)
            shutil.copyfile(FIXTURE / "group.tftest.hcl", tests / "group.tftest.hcl")
            shutil.copyfile(FIXTURE / "cleanup.tftest.hcl", tests / "cleanup.tftest.hcl")
            binary = str(Path(executable).resolve(strict=True))
            try:
                verify_terraform_release(Path(binary))
            except CheckpointTerraformError:
                raise ProbeError("Terraform executable did not match the pinned release") from None
            try:
                version = json.loads(_terraform(binary, prepared, home, ["version", "-json"]))
            except json.JSONDecodeError:
                raise ProbeError("Terraform version response is invalid") from None
            if not isinstance(version, dict) or not isinstance(version.get("terraform_version"), str):
                raise ProbeError("Terraform version response is invalid")
            _terraform(binary, prepared, home,
                       ["init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color"])
            try:
                verify_checkpoint_dependencies(prepared)
            except (OSError, CheckpointDependencyError):
                raise ProbeError("Terraform mock dependencies did not match their pins") from None
            _terraform(binary, prepared, home, ["validate", "-no-color"])
            result = _terraform(binary, prepared, home, ["test", "-json", "-verbose"], FIXTURE_VARIABLES)
            try:
                events = [json.loads(line) for line in result.splitlines()]
            except json.JSONDecodeError as exc:
                raise ProbeError("Terraform mock probe returned invalid JSON") from exc
            plans = [event["test_plan"] for event in events if event.get("type") == "test_plan"]
            states = [event["test_state"] for event in events if event.get("type") == "test_state"]
            summaries = [event["test_summary"] for event in events if event.get("type") == "test_summary"]
            if len(plans) != 1 or len(states) != 1 or len(summaries) != 1 or summaries[0].get("status") != "pass":
                raise ProbeError("Terraform mock probe did not complete successfully")
            validate_plan(plans[0], version["terraform_version"])
            validate_mock_cleanup_state(states[0], version["terraform_version"])
            for name in ("management_image_version", "gateway_image_version"):
                _terraform(binary, prepared, home, ["test", "-json"],
                           {**FIXTURE_VARIABLES, name: "latest"},
                           ("Use an explicit Marketplace image version.",))
            _terraform(binary, prepared, home, ["test", "-json"],
                       {**FIXTURE_VARIABLES,
                        "provider_group_id": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/other-group"},
                       ("Use an isolated environment group in the provider subscription.",
                        "Use an isolated FaaS environment resource group ID."))
            _terraform(binary, prepared, home, ["test", "-json"],
                       {**FIXTURE_VARIABLES,
                        "provider_group_id": f"/subscriptions/00000000-0000-0000-0000-000000000006/resourceGroups/{GROUP}"},
                       ("Use an isolated environment group in the provider subscription.",))
            _terraform(binary, prepared, home, ["test", "-json"],
                       {**FIXTURE_VARIABLES, "provider_admin_ssh_public_key": "invalid"},
                       ("A supported provider administrator SSH public key is required.",))
            _terraform(binary, prepared, home, ["test", "-json"],
                       {**FIXTURE_VARIABLES, "management_admin_password": "short"},
                       ("Use an ASCII management password with uppercase, lowercase, a digit and a supported special character.",))
            _terraform(binary, prepared, home, ["test", "-json"],
                       {**FIXTURE_VARIABLES, "sic_key": "short"},
                       ("A Check Point SIC key of at least 12 characters is required.",
                        "Variable [sic_key] must be at least 12 characters long."))
    finally:
        shutil.rmtree(prepared)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="Local Git checkout of the pinned upstream release")
    args = parser.parse_args()
    try:
        run(args.source)
    except (OSError, prepare_checkpoint_modules.PreparationError, ProbeError) as exc:
        raise SystemExit(f"Checkpoint mock probe failed: {type(exc).__name__}: {exc}") from None
    print("Mock plan passed: BYOL VMs use the existing group and network with pinned fixture image versions.")
    print("Mock-state-derived cleanup checks passed; no actual destroy plan was generated.")
    print("No Azure credentials or deployment were used; this does not qualify the real firewall path.")


if __name__ == "__main__":
    main()
