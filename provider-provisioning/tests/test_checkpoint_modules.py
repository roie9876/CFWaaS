import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import prepare_checkpoint_modules as modules
import probe_checkpoint_modules as probe
import package_apps
from service.checkpoint_credentials import generate_checkpoint_credentials
from service.checkpoint_dependencies import ARTIFACT_SHA256, PROVIDER_LOCK_SHA256, REGIONS_COMMIT, REGIONS_SOURCE
from service import checkpoint_plan
from service.checkpoint_plan import CheckpointPlanError, validate_checkpoint_destroy_plan, validate_checkpoint_plan
from service.checkpoint_runner_config import (
    CheckpointRuntimeInputs, load_checkpoint_runner_config, validate_checkpoint_runner_plan,
)
from service.checkpoint_terraform import (
    TERRAFORM_RELEASES, TERRAFORM_VERSION, CheckpointTerraformError, verify_terraform_release,
)


def git(source, *arguments):
    return subprocess.run(["git", "-C", str(source), *arguments], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def upstream(tmp_path, monkeypatch):
    source = tmp_path / "upstream"
    source.mkdir()
    git(source, "init", "-q")
    (source / "LICENSE").write_text("Fixture license\n")
    common = source / "modules" / "common" / "common"
    common.mkdir(parents=True)
    common_main = (b'module "regions" {\n  source  = "Azure/avm-utl-regions/azurerm"\n'
                   b'  version = "0.5.1"\n  enable_telemetry          = false\n}\n')
    (common / "main.tf").write_bytes(common_main)
    monkeypatch.setattr(modules, "COMMON_MAIN_SHA256", hashlib.sha256(common_main).hexdigest())
    digests = {}
    for name in ("management", "single-gateway"):
        directory = source / "modules" / name
        directory.mkdir(parents=True)
        original = (f'terraform {{ required_version = ">= 1.9" }}\n'
                    f'provider "azapi" {{}}\nprovider "azurerm" {{}}\n').encode()
        (directory / "versions.tf").write_bytes(original)
        (directory / "main.tf").write_text('module "common" { source = "../common/common" }\n')
        digests[name] = hashlib.sha256(original).hexdigest()
    git(source, "add", ".")
    git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com",
        "commit", "-qm", "Fixture")
    monkeypatch.setattr(modules, "UPSTREAM_COMMIT", git(source, "rev-parse", "HEAD"))
    monkeypatch.setattr(modules, "UPSTREAM_TREE", git(source, "rev-parse", "HEAD^{tree}"))
    monkeypatch.setattr(modules, "VERSION_FILES", digests)
    monkeypatch.setattr(package_apps, "verify_checkpoint_artifact", lambda _path: None)
    local = tmp_path / "local"
    local.mkdir()
    monkeypatch.setattr(modules, "LOCAL_ROOT", local)
    return source, local


def test_pinned_preparation_uses_committed_files_and_preserves_input(upstream):
    source, local = upstream
    dirty = source / "modules" / "management" / "main.tf"
    dirty.write_text("uncommitted source must not be copied\n")

    output = local / "prepared"
    modules.prepare(source, output)

    assert dirty.read_text() == "uncommitted source must not be copied\n"
    assert "uncommitted source" not in (output / "modules/management/main.tf").read_text()
    assert (output / "LICENSE").read_text() == "Fixture license\n"
    assert (output / "FAAS-UPSTREAM-NOTICE.txt").is_file()
    assert (output / "main.tf").read_text() == (ROOT / "infra/checkpoint/main.tf").read_text()
    assert (output / "variables.tf").read_text() == (ROOT / "infra/checkpoint/variables.tf").read_text()
    assert (output / ".terraform.lock.hcl").read_bytes() == (ROOT / "infra/checkpoint/.terraform.lock.hcl").read_bytes()
    common_main = (output / "modules/common/common/main.tf").read_text()
    assert REGIONS_SOURCE in common_main and "enable_telemetry          = false" in common_main
    for name in ("management", "single-gateway"):
        directory = output / "modules" / name
        versions = (directory / "versions.tf").read_text()
        assert "FaaS modification" in versions
        assert 'provider "azapi"' not in versions
        assert 'provider "azurerm"' not in versions
        assert 'required_version = ">= 1.9"' in versions
        assert "create_resource_group = false" in (directory / "faas_override.tf").read_text()
        assert "vm_os_version         = var.faas_image_version" in (directory / "faas_override.tf").read_text()
        assert "ignore_changes = [ip_tags]" in (directory / "faas_override.tf").read_text()
        assert "explicit Marketplace image version" in (directory / "faas_variables.tf").read_text()


def test_generated_checkpoint_credentials_meet_candidate_constraints_and_stay_out_of_repr():
    credentials = [generate_checkpoint_credentials() for _ in range(32)]
    assert len({item.management_password for item in credentials}) == len(credentials)
    assert len({item.sic_key for item in credentials}) == len(credentials)
    for item in credentials:
        assert 16 <= len(item.management_password) <= 72
        assert re.fullmatch(r"[A-Za-z0-9!@#%_+-]+", item.management_password)
        assert all(re.search(pattern, item.management_password)
                   for pattern in (r"[A-Z]", r"[a-z]", r"[0-9]", r"[!@#%_+-]"))
        assert re.fullmatch(r"[0-9a-f]{48}", item.sic_key)
        assert item.management_password not in repr(item)
        assert item.sic_key not in repr(item)


def test_candidate_disables_uploads_and_optional_gateway_metrics():
    source = (ROOT / "infra/checkpoint/main.tf").read_text()
    management = source.split('module "management" {', 1)[1].split('module "gateway" {', 1)[0]
    gateway = source.split('module "gateway" {', 1)[1].split('output "managementPrivateIp"', 1)[0]
    assert "allow_upload_download           = false" in management
    assert "allow_upload_download           = false" in gateway
    assert "enable_custom_metrics           = false" in gateway
    assert 'zone                            = ""' in management
    assert 'zone                            = ""' in gateway
    assert "enable_ipv6                     = false" in management
    assert "enable_ipv6                     = false" in gateway
    assert re.search(r'provider "modtm"\s*\{\s*enabled\s*=\s*false\s*\}', source)
    azurerm = source.split('provider "azurerm" {', 1)[1].split('provider "azapi" {', 1)[0]
    assert 'resource_provider_registrations = "none"' in azurerm


def test_preparation_refuses_mismatched_pin_and_existing_output(upstream, monkeypatch):
    source, local = upstream
    output = local / "prepared"
    output.mkdir()
    marker = output / "keep"
    marker.write_text("preserve")
    with pytest.raises(modules.PreparationError, match="already exists"):
        modules.prepare(source, output)
    assert marker.read_text() == "preserve"

    monkeypatch.setattr(modules, "UPSTREAM_COMMIT", "0" * 40)
    with pytest.raises(modules.PreparationError, match="pinned release"):
        modules.prepare(source, local / "other")
    assert not (local / "other").exists()
    with pytest.raises(modules.PreparationError, match="direct child"):
        modules.prepare(source, local.parent / "outside")


@pytest.mark.parametrize("kind", ["traversal", "absolute", "symlink", "hardlink"])
def test_archive_refuses_unsafe_entries(tmp_path, kind):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        info = tarfile.TarInfo("../outside" if kind == "traversal"
                               else "/outside" if kind == "absolute" else "modules/link")
        if kind == "symlink":
            info.type, info.linkname = tarfile.SYMTYPE, "../../outside"
        elif kind == "hardlink":
            info.type, info.linkname = tarfile.LNKTYPE, "../../outside"
        else:
            info.size = 0
        tar.addfile(info, io.BytesIO(b"") if info.isfile() else None)
    destination = tmp_path / "prepared"
    destination.mkdir()
    with pytest.raises(modules.PreparationError):
        modules._extract(archive.getvalue(), destination)
    assert not (tmp_path / "outside").exists()


def test_adapter_failure_removes_only_its_new_output(upstream, monkeypatch):
    source, local = upstream
    keep = local / "unrelated"
    keep.write_text("preserve")
    monkeypatch.setattr(modules, "VERSION_FILES", {"management": "0" * 64})
    output = local / "prepared"
    with pytest.raises(modules.PreparationError, match="provider configuration"):
        modules.prepare(source, output)
    assert not output.exists()
    assert keep.read_text() == "preserve"


def test_preparation_refuses_mismatched_provider_lock(upstream, monkeypatch):
    source, local = upstream
    monkeypatch.setattr(modules, "PROVIDER_LOCK_SHA256", "0" * 64)
    with pytest.raises(modules.PreparationError, match="provider lock mismatch"):
        modules.prepare(source, local / "prepared")
    assert not (local / "prepared").exists()


def test_optional_checkpoint_package_includes_pinned_preview_only(upstream, monkeypatch):
    source, local = upstream
    compiled = {
        "provider-dataplane.bicep": b'{"fixture":"ubuntu"}',
        "customer-connections.bicep": b'{}',
        "customer-deployment.bicep": b'{}',
        "provider-guided-installation.bicep": b'{}',
        "provider-checkpoint-foundation.bicep": b'{"fixture":"checkpoint"}',
        "provider-checkpoint-private-data.bicep": b'{"fixture":"checkpoint-private"}',
    }
    monkeypatch.setattr(package_apps, "compile_bicep", lambda name: compiled[name])
    monkeypatch.setattr(package_apps, "validate_runtime_template", lambda *args: None)
    monkeypatch.setattr(package_apps, "validate_checkpoint_template", lambda *args: None)
    monkeypatch.setattr(package_apps, "validate_checkpoint_private_data_template", lambda *args: None)
    with tempfile.TemporaryDirectory(dir=ROOT / ".local") as directory:
        output = Path(directory) / "preview.zip"
        metadata = package_apps.package(output, source)
        with zipfile.ZipFile(output) as archive:
            names = set(archive.namelist())
            assert archive.read("service/templates/checkpoint-foundation.json") == compiled["provider-checkpoint-foundation.bicep"]
            assert archive.read("service/templates/checkpoint-private-data.json") == compiled["provider-checkpoint-private-data.bicep"]
            assert {"service/checkpoint_foundation.py",
                    "checkpoint/LICENSE", "checkpoint/FAAS-UPSTREAM-NOTICE.txt",
                    "checkpoint/main.tf", "checkpoint/variables.tf", "checkpoint/.terraform.lock.hcl",
                    "checkpoint/modules/management/faas_override.tf",
                    "checkpoint/modules/single-gateway/faas_override.tf"} <= names
            assert not any("/.git/" in name or "/.terraform/" in name for name in names)
        assert metadata["includesCheckpointPreview"] is True
        assert metadata["checkpointModuleCommit"] == modules.UPSTREAM_COMMIT
        assert metadata["checkpointRegionsCommit"] == REGIONS_COMMIT
        assert metadata["checkpointProviderLockSha256"] == PROVIDER_LOCK_SHA256
        assert metadata["checkpointArtifactSha256"] == ARTIFACT_SHA256
        assert metadata["checkpointTerraformVersion"] == TERRAFORM_VERSION
        assert metadata["checkpointTerraformLinuxSha256"] == TERRAFORM_RELEASES[("Linux", "x86_64")]["binary_sha256"]
        assert metadata["checkpointPrivateDataSha256"] == hashlib.sha256(
            compiled["provider-checkpoint-private-data.bicep"]).hexdigest()
        assert metadata["checkpointFoundationSha256"] == hashlib.sha256(
            compiled["provider-checkpoint-foundation.bicep"]).hexdigest()
    assert list(local.iterdir()) == []


def test_optional_package_does_not_remove_existing_collision(upstream, monkeypatch):
    source, local = upstream
    collision = local / "checkpoint-package-collision"
    collision.mkdir()
    marker = collision / "keep"
    marker.write_text("preserve")
    monkeypatch.setattr(package_apps, "compile_bicep",
                        lambda name: b"{}")
    monkeypatch.setattr(package_apps, "validate_runtime_template", lambda *args: None)
    monkeypatch.setattr(package_apps, "validate_checkpoint_template", lambda *args: None)
    monkeypatch.setattr(package_apps, "validate_checkpoint_private_data_template", lambda *args: None)
    monkeypatch.setattr(package_apps, "uuid4", lambda: SimpleNamespace(hex="collision"))
    with tempfile.TemporaryDirectory(dir=ROOT / ".local") as directory:
        with pytest.raises(modules.PreparationError, match="already exists"):
            package_apps.package(Path(directory) / "preview.zip", source)
    assert marker.read_text() == "preserve"


def test_optional_checkpoint_package_validates_compiled_private_templates(upstream):
    source, local = upstream
    with tempfile.TemporaryDirectory(dir=ROOT / ".local") as directory:
        output = Path(directory) / "preview.zip"
        metadata = package_apps.package(output, source)
        with zipfile.ZipFile(output) as archive:
            foundation = archive.read("service/templates/checkpoint-foundation.json")
            private_data = archive.read("service/templates/checkpoint-private-data.json")
            assert archive.testzip() is None
        assert metadata["checkpointFoundationSha256"] == hashlib.sha256(foundation).hexdigest()
        assert metadata["checkpointPrivateDataSha256"] == hashlib.sha256(private_data).hexdigest()
        assert metadata["packageSha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert list(local.iterdir()) == []


def fixture_plan():
    resources = []
    for address, kind in probe.EXPECTED.items():
        after, unknown = {}, {}
        gateway = address.startswith("module.gateway.")
        name = "cp-gateway-00000000" if gateway else "cp-management-00000000"
        if kind in {"azurerm_network_interface", "azurerm_public_ip", "azurerm_virtual_machine"}:
            after.update(resource_group_name=probe.GROUP, location="eastus2", id=None)
            unknown["id"] = True
        if address in probe.NETWORK_INTERFACES:
            subnet, forwarding = probe.NETWORK_INTERFACES[address]
            backend = subnet == "firewall-backend"
            after.update(name=name + ("-eth1" if backend else "-eth0"), ip_forwarding_enabled=forwarding)
            after["ip_configuration"] = [{
                "name": "ipconfig2" if backend else "ipconfig1",
                "subnet_id": f"{probe.SCOPE}/virtualNetworks/vnet-cp-security-00000000/subnets/{subnet}",
                "private_ip_address": {"firewall-frontend": "172.22.10.4",
                                       "firewall-backend": "172.22.20.4", "management": "172.22.30.4"}[subnet],
                "private_ip_address_allocation": "Static", "primary": True, "public_ip_address_id": None}]
            unknown["ip_configuration"] = [{} if backend else {"public_ip_address_id": True}]
        if kind == "azurerm_network_interface_security_group_association":
            nsg = "nsg-cp-firewall-00000000" if gateway else "nsg-cp-management-00000000"
            after["network_security_group_id"] = f"{probe.SCOPE}/networkSecurityGroups/{nsg}"
            after["network_interface_id"] = None
            after["id"] = None
            unknown["network_interface_id"] = True
            unknown["id"] = True
        if kind == "azurerm_public_ip":
            after.update(name=name, sku="Standard", allocation_method="Static")
        if kind == "azurerm_virtual_machine":
            sku = "sg-byol" if gateway else "mgmt-byol-blink"
            after.update(name=name, vm_size="Standard_D4ds_v5",
                         network_interface_ids=[None, None] if gateway else [None])
            unknown["network_interface_ids"] = [True, True] if gateway else [True]
            after["identity"] = [{"type": "SystemAssigned", "identity_ids": None, "tenant_id": None}]
            unknown["identity"] = [{"principal_id": True, "tenant_id": True}]
            after["boot_diagnostics"] = [{"enabled": False, "storage_uri": ""}]
            after["delete_os_disk_on_termination"] = True
            after["storage_data_disk"] = []
            after["storage_os_disk"] = [{"name": name, "create_option": "FromImage", "caching": "ReadWrite",
                                          "managed_disk_type": "StandardSSD_LRS", "disk_size_gb": 200,
                                          "managed_disk_id": None}]
            unknown["storage_os_disk"] = [{"managed_disk_id": True}]
            after["storage_image_reference"] = [{"id": None, "publisher": "checkpoint", "offer": "check-point-cg-r82",
                                                 "sku": sku, "version": "1.2.3"}]
            after["plan"] = [{"name": sku, "product": "check-point-cg-r82", "publisher": "checkpoint"}]
            after["os_profile"] = [{
                "computer_name": name, "admin_username": "notused",
                "admin_password": "" if gateway else probe.FIXTURE_CREDENTIALS.management_password,
                "custom_data": (f'synthetic-gateway\nsicKey="{probe.FIXTURE_CREDENTIALS.sic_key}"\n'
                                if gateway else "synthetic-management\n"),
            }]
            after["os_profile_linux_config"] = [{
                "disable_password_authentication": gateway,
                "ssh_keys": ([{"path": "/home/notused/.ssh/authorized_keys",
                               "key_data": probe.FIXTURE_VARIABLES["provider_admin_ssh_public_key"]}]
                             if gateway else []),
            }]
        if kind == "random_id":
            after.update(keepers={"resource_group": probe.GROUP}, byte_length=8)
        change = {"actions": ["create"], "after": after, "after_unknown": unknown}
        if kind == "azurerm_virtual_machine":
            change["after_sensitive"] = {"os_profile": True}
        provider = ("registry.terraform.io/hashicorp/random" if kind == "random_id"
                    else "registry.terraform.io/hashicorp/azurerm")
        resources.append({"address": address, "mode": "managed", "type": kind,
                          "provider_name": provider, "change": change})
    output_values = {"gatewayFrontendPrivateIp": "172.22.10.4", "managementPrivateIp": "172.22.30.4",
                     "gatewayVmId": None, "managementVmId": None}
    outputs = {key: {"actions": ["create"], "after": value, "after_unknown": value is None,
                     "after_sensitive": False} for key, value in output_values.items()}
    return {"plan_format_version": "1.2", "resource_changes": resources, "output_changes": outputs}


@pytest.fixture
def plan_bootstrap_pins(monkeypatch):
    gateway = b'synthetic-gateway\nsicKey="<REDACTED>"\n'
    management = b"synthetic-management\n"
    monkeypatch.setattr(checkpoint_plan, "GATEWAY_BOOTSTRAP_SHA256", hashlib.sha256(gateway).hexdigest())
    monkeypatch.setattr(checkpoint_plan, "MANAGEMENT_BOOTSTRAP_SHA256", hashlib.sha256(management).hexdigest())
    monkeypatch.setattr(checkpoint_plan, "GATEWAY_BOOTSTRAP_TEMPLATE", gateway.decode())
    monkeypatch.setattr(checkpoint_plan, "MANAGEMENT_BOOTSTRAP_TEMPLATE", management.decode())


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_mock_plan_accepts_only_expected_pinned_existing_group_resources():
    probe.validate_plan(fixture_plan(), "1.15.7")


def live_fixture_plan():
    return {**fixture_plan(), "format_version": "1.2", "terraform_version": "1.15.7",
            "complete": True, "errored": False, "applyable": True,
            "variables": {name: {"value": value} for name, value in probe.FIXTURE_VARIABLES.items()}}


def validate_live_fixture(plan):
    return validate_checkpoint_plan(
        plan, probe.SUBSCRIPTION, probe.FIXTURE_VARIABLES["provider_tenant_id"],
        probe.FIXTURE_VARIABLES["provider_managed_identity_client_id"],
        probe.GROUP, probe.FIXTURE_VARIABLES["environment_id"],
        "1.2.3", "1.2.3", "Standard_D4ds_v5", "Standard_D4ds_v5",
        probe.FIXTURE_VARIABLES["provider_admin_ssh_public_key"], probe.FIXTURE_CREDENTIALS)


def fixture_runner_inputs():
    variables = probe.FIXTURE_VARIABLES
    storage = "stcp" + "a" * 13
    config = {
        "schemaVersion": 1, "environmentId": variables["environment_id"],
        "providerSubscriptionId": probe.SUBSCRIPTION, "providerTenantId": variables["provider_tenant_id"],
        "providerGroupId": variables["provider_group_id"], "runnerClientId": variables["provider_managed_identity_client_id"],
        "gatewayImageVersion": variables["gateway_image_version"],
        "managementImageVersion": variables["management_image_version"],
        "gatewayVmSize": variables["gateway_vm_size"], "managementVmSize": variables["management_vm_size"],
        "providerSshPublicKey": variables["provider_admin_ssh_public_key"],
        "credentialVaultUri": f"https://kvcp{'a' * 13}.vault.azure.net/",
        "stateBlobEndpoint": f"https://{storage}.blob.core.windows.net/", "stateContainer": "terraform-state",
        "firewallFrontendIp": "172.22.10.4", "firewallBackendIp": "172.22.20.4",
        "routeServerAsn": 65515, "routeServerPeers": ["172.20.254.4", "172.20.254.5"],
    }
    environment = {"FAAS_CONFIG": json.dumps(config),
                   "FAAS_RUNNER_CLIENT_ID": variables["provider_managed_identity_client_id"]}
    return CheckpointRuntimeInputs(load_checkpoint_runner_config(environment), probe.FIXTURE_CREDENTIALS)


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_runner_plan_guard_uses_verified_inputs_for_exact_scope_and_credentials():
    inputs = fixture_runner_inputs()
    assert validate_checkpoint_runner_plan(inputs, live_fixture_plan()).needs_apply
    other_identity = inputs.config.model_copy(update={"runnerClientId": "00000000-0000-0000-0000-000000000006"})
    with pytest.raises(CheckpointPlanError):
        validate_checkpoint_runner_plan(CheckpointRuntimeInputs(other_identity, inputs.credentials), live_fixture_plan())
    with pytest.raises(CheckpointPlanError):
        validate_checkpoint_runner_plan(
            CheckpointRuntimeInputs(inputs.config, generate_checkpoint_credentials()), live_fixture_plan())


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_live_plan_guard_accepts_only_the_expected_create_plan():
    result = validate_live_fixture(live_fixture_plan())
    assert result.creates == len(probe.EXPECTED)
    assert result.unchanged == 0 and result.output_creates == 4 and result.needs_apply


def azurerm_shaped_fixture_plan(tamper: str = ""):
    plan = live_fixture_plan()
    for item in plan["resource_changes"]:
        if item["type"] != "azurerm_virtual_machine":
            continue
        after, unknown = item["change"]["after"], item["change"]["after_unknown"]
        after["storage_image_reference"][0]["id"] = ""
        after["storage_data_disk"], unknown["storage_data_disk"] = None, True
        after["network_interface_ids"], unknown["network_interface_ids"] = None, True
        rendered = after["os_profile"][0]["custom_data"]
        if tamper == "bootstrap":
            rendered += "x"
        after["os_profile"][0]["custom_data"] = hashlib.sha1(
            base64.b64encode(rendered.encode())).hexdigest()
        if tamper == "image-id":
            after["storage_image_reference"][0]["id"] = "/subscriptions/x/images/y"
    return plan


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_live_plan_guard_accepts_azurerm_computed_create_shape():
    result = validate_live_fixture(azurerm_shaped_fixture_plan())
    assert result.creates == len(probe.EXPECTED) and result.needs_apply


@pytest.mark.usefixtures("plan_bootstrap_pins")
@pytest.mark.parametrize(("tamper", "reason"), [
    ("bootstrap", "Invalid Check Point virtual machine bootstrap"),
    ("image-id", "Invalid Check Point virtual machine: image"),
])
def test_live_plan_guard_rejects_tampered_azurerm_create_shape(tamper, reason):
    with pytest.raises(CheckpointPlanError, match=reason):
        validate_live_fixture(azurerm_shaped_fixture_plan(tamper))


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_live_plan_guard_bounds_refresh_drift_to_expected_resources():
    address = "module.gateway.azurerm_public_ip.public_ip"
    plan = live_fixture_plan()
    plan["resource_drift"] = [{"address": address, "mode": "managed", "type": "azurerm_public_ip",
                               "change": {"actions": ["update"]}}]
    assert validate_live_fixture(plan).needs_apply
    for drift in ({"address": "azurerm_resource_group.other", "mode": "managed",
                   "type": "azurerm_resource_group", "change": {"actions": ["update"]}},
                  {"address": address, "mode": "managed", "type": "azurerm_public_ip",
                   "change": {"actions": ["delete"]}}):
        plan["resource_drift"] = [drift]
        with pytest.raises(CheckpointPlanError, match="drift"):
            validate_live_fixture(plan)


def noop_fixture_plan():
    plan = live_fixture_plan()
    network = probe.SCOPE
    compute = (f"/subscriptions/{probe.SUBSCRIPTION}/resourceGroups/{probe.GROUP}"
               "/providers/Microsoft.Compute")
    for item in plan["resource_changes"]:
        address, kind, change = item["address"], item["type"], item["change"]
        gateway = address.startswith("module.gateway.")
        name = "cp-gateway-00000000" if gateway else "cp-management-00000000"
        after = change["after"]
        change["actions"], change["after_unknown"] = ["no-op"], {}
        if kind == "azurerm_network_interface":
            subnet, _ = probe.NETWORK_INTERFACES[address]
            backend = subnet == "firewall-backend"
            after["id"] = network + "/networkInterfaces/" + name + ("-eth1" if backend else "-eth0")
            after["ip_configuration"][0]["public_ip_address_id"] = (
                None if backend else network + "/publicIPAddresses/" + name)
        elif kind == "azurerm_network_interface_security_group_association":
            after["network_interface_id"] = network + "/networkInterfaces/" + name + "-eth0"
            nsg = network + "/networkSecurityGroups/nsg-cp-" + ("firewall-" if gateway else "management-") + "00000000"
            after["id"] = after["network_interface_id"] + "|" + nsg
        elif kind == "azurerm_public_ip":
            after["id"] = network + "/publicIPAddresses/" + name
        elif kind == "azurerm_virtual_machine":
            change["before_sensitive"] = {"os_profile": True}
            after["id"] = compute + "/virtualMachines/" + name
            after["identity"][0]["tenant_id"] = probe.FIXTURE_VARIABLES["provider_tenant_id"]
            after["storage_os_disk"][0]["managed_disk_id"] = compute + "/disks/" + name
            after["network_interface_ids"] = [network + "/networkInterfaces/" + name + "-eth0"]
            if gateway:
                after["network_interface_ids"].append(network + "/networkInterfaces/" + name + "-eth1")
    for key, output in plan["output_changes"].items():
        output.update(actions=["no-op"], after_unknown=False)
        if key == "gatewayVmId":
            output["after"] = compute + "/virtualMachines/cp-gateway-00000000"
        elif key == "managementVmId":
            output["after"] = compute + "/virtualMachines/cp-management-00000000"
    plan["applyable"] = False
    return plan


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_live_plan_guard_accepts_resume_after_partial_apply():
    plan, fresh = noop_fixture_plan(), live_fixture_plan()
    created = {item["address"]: item for item in fresh["resource_changes"]
               if item["type"] == "azurerm_virtual_machine"}
    plan["resource_changes"] = [created.get(item["address"], item) for item in plan["resource_changes"]]
    for key in ("gatewayVmId", "managementVmId"):
        plan["output_changes"][key] = {"actions": ["update"], "before": None, "after": None,
                                       "after_unknown": True, "before_sensitive": False,
                                       "after_sensitive": False}
    plan["applyable"] = True
    result = validate_live_fixture(plan)
    assert (result.creates, result.output_creates) == (2, 2) and result.needs_apply
    del plan["resource_changes"][[item["type"] for item in plan["resource_changes"]].index(
        "azurerm_virtual_machine")]
    with pytest.raises(CheckpointPlanError):
        validate_live_fixture(plan)


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_live_plan_guard_accepts_unreadable_create_only_fields_only_for_existing_vms():
    plan = noop_fixture_plan()
    for item in plan["resource_changes"]:
        if item["type"] == "azurerm_virtual_machine":
            item["change"]["after"]["os_profile"][0].update(custom_data="", admin_password="")
    assert not validate_live_fixture(plan).needs_apply
    fresh = live_fixture_plan()
    for item in fresh["resource_changes"]:
        if item["type"] == "azurerm_virtual_machine":
            item["change"]["after"]["os_profile"][0]["custom_data"] = ""
    with pytest.raises(CheckpointPlanError):
        validate_live_fixture(fresh)


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_live_plan_guard_accepts_scoped_noop_plan_without_apply():
    plan = noop_fixture_plan()
    result = validate_live_fixture(plan)
    assert result.creates == 0 and result.unchanged == len(probe.EXPECTED)
    assert result.output_creates == 0 and not result.needs_apply


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_live_plan_guard_counts_output_only_changes_as_apply():
    plan = noop_fixture_plan()
    plan["output_changes"]["gatewayVmId"]["actions"] = ["create"]
    with pytest.raises(CheckpointPlanError, match="not applyable"):
        validate_live_fixture(plan)
    plan["applyable"] = True
    result = validate_live_fixture(plan)
    assert result.creates == 0 and result.output_creates == 1 and result.needs_apply


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_live_plan_guard_accepts_only_the_same_approved_ssh_key_with_optional_comment():
    plan = live_fixture_plan()
    plan["variables"]["provider_admin_ssh_public_key"]["value"] += " fixture-comment"
    vm = next(item for item in plan["resource_changes"] if item["address"].startswith(
        "module.gateway.azurerm_virtual_machine."))
    vm["change"]["after"]["os_profile_linux_config"][0]["ssh_keys"][0]["key_data"] += " another-comment"
    assert validate_live_fixture(plan).needs_apply


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_live_plan_guard_rejects_unmarked_existing_credentials():
    plan = noop_fixture_plan()
    vm = next(item for item in plan["resource_changes"] if item["type"] == "azurerm_virtual_machine")
    vm["change"]["before_sensitive"]["os_profile"] = False
    with pytest.raises(CheckpointPlanError):
        validate_live_fixture(plan)


def destroy_fixture_plan():
    plan = noop_fixture_plan()
    plan["applyable"] = True
    for item in plan["resource_changes"]:
        previous = item["change"]
        item["change"] = {
            "actions": ["delete"], "before": previous["after"], "after": None,
            "before_sensitive": previous.get("before_sensitive", {}), "after_unknown": {},
        }
    for name, output in plan["output_changes"].items():
        plan["output_changes"][name] = {
            "actions": ["delete"], "before": output["after"], "after": None,
            "before_sensitive": False, "after_unknown": False,
        }
    return plan


def validate_destroy_fixture(plan):
    return validate_checkpoint_destroy_plan(
        plan, probe.SUBSCRIPTION, probe.FIXTURE_VARIABLES["provider_tenant_id"],
        probe.FIXTURE_VARIABLES["provider_managed_identity_client_id"],
        probe.GROUP, probe.FIXTURE_VARIABLES["environment_id"],
        "1.2.3", "1.2.3", "Standard_D4ds_v5", "Standard_D4ds_v5",
        probe.FIXTURE_VARIABLES["provider_admin_ssh_public_key"], probe.FIXTURE_CREDENTIALS)


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_destroy_guard_accepts_only_the_existing_checkpoint_terraform_resources():
    summary = validate_destroy_fixture(destroy_fixture_plan())
    assert summary.deletes == len(probe.EXPECTED)
    assert summary.output_deletes == 4


def test_pinned_terraform_emits_expected_local_destroy_plan_shape(tmp_path):
    executable = shutil.which("terraform")
    if not executable:
        pytest.skip("Pinned Terraform executable is unavailable")
    binary = Path(executable).resolve(strict=True)
    try:
        verify_terraform_release(binary)
    except CheckpointTerraformError:
        pytest.skip("Pinned Terraform executable is unavailable")
    root = tmp_path / "terraform"
    root.mkdir(mode=0o700)
    (root / "main.tf").write_text(
        'resource "terraform_data" "fixture" { input = "fixture" }\n'
        'output "fixture" { value = terraform_data.fixture.id }\n')
    env = {"HOME": str(root), "PATH": os.defpath, "CHECKPOINT_DISABLE": "1",
           "TF_IN_AUTOMATION": "true", "TF_LOG": "off", "TF_CLI_CONFIG_FILE": os.devnull}
    for arguments in (
        ["init", "-backend=false", "-input=false", "-no-color"],
        ["validate", "-no-color"],
        ["apply", "-auto-approve", "-input=false", "-no-color"],
        ["plan", "-destroy", "-input=false", "-no-color", "-out=destroy.plan"],
    ):
        subprocess.run([str(binary), f"-chdir={root}", *arguments], env=env,
                       capture_output=True, check=True, timeout=60)
    result = subprocess.run([str(binary), f"-chdir={root}", "show", "-json", "destroy.plan"],
                            env=env, capture_output=True, check=True, timeout=30)
    plan = json.loads(result.stdout)
    assert plan["terraform_version"] == TERRAFORM_VERSION
    assert plan["complete"] is True and plan["errored"] is False and plan["applyable"] is True
    resource = plan["resource_changes"][0]["change"]
    output = plan["output_changes"]["fixture"]
    assert resource["actions"] == ["delete"] and resource["after"] is None
    assert resource["after_unknown"] == {}
    assert output["actions"] == ["delete"] and output["after"] is None
    assert output["before_sensitive"] is False and output["after_unknown"] is False


def mock_cleanup_state():
    plan = noop_fixture_plan()
    resources = [{
        "address": item["address"], "mode": item["mode"], "type": item["type"],
        "provider_name": item["provider_name"], "values": item["change"]["after"],
        "sensitive_values": item["change"].get("after_sensitive", {}),
    } for item in plan["resource_changes"]]
    return {"root_module": {"resources": resources},
            "outputs": {name: {"value": output["after"], "sensitive": False}
                        for name, output in plan["output_changes"].items()}}


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_mock_cleanup_checks_realistic_state_shape_without_azure_operations():
    state = mock_cleanup_state()
    state["root_module"]["resources"].append({"mode": "data"})
    probe.validate_mock_cleanup_state(state, "1.15.7")


@pytest.mark.usefixtures("plan_bootstrap_pins")
@pytest.mark.parametrize("mutation", ["invalid_root", "invalid_mode", "unexpected_resource",
                                      "foreign_disk", "sensitive_output", "invalid_child"])
def test_mock_cleanup_rejects_bad_state_without_echoing_values(mutation):
    state = mock_cleanup_state()
    items = state["root_module"]["resources"]
    if mutation == "invalid_root":
        state["root_module"] = "PRIVATE-VALUE"
    elif mutation == "invalid_mode":
        items[0]["mode"] = ["PRIVATE-VALUE"]
    elif mutation == "unexpected_resource":
        items.append({"mode": "managed", "address": "PRIVATE-VALUE"})
    elif mutation == "foreign_disk":
        vm = next(item for item in items if item["type"] == "azurerm_virtual_machine")
        vm["values"]["storage_os_disk"][0]["managed_disk_id"] = "PRIVATE-VALUE"
    elif mutation == "sensitive_output":
        state["outputs"]["gatewayVmId"]["sensitive"] = True
    else:
        state["root_module"]["child_modules"] = ["PRIVATE-VALUE"]
    with pytest.raises(probe.ProbeError) as error:
        probe.validate_mock_cleanup_state(state, "1.15.7")
    assert "PRIVATE-VALUE" not in str(error.value)


@pytest.mark.usefixtures("plan_bootstrap_pins")
@pytest.mark.parametrize("mutation", [
    "not_applyable", "incomplete", "drift", "update", "replace", "noop", "import", "extra_resource",
    "group_delete", "managed_application_delete", "missing_resource", "ubuntu_resource", "foreign_group",
    "foreign_vm_id", "foreign_disk_id", "attached_disk", "data_disk", "foreign_association_id",
    "foreign_nic", "foreign_nsg", "unmarked_secret", "foreign_provider", "wrong_identity", "wrong_ssh",
    "wrong_password", "modified_bootstrap", "sensitive_output", "foreign_output", "output_not_deleted",
])
def test_destroy_guard_rejects_unsafe_scope_or_actions_without_echoing_values(mutation):
    plan = destroy_fixture_plan()
    items = plan["resource_changes"]
    nic = next(item for item in items if item["address"] == "module.gateway.azurerm_network_interface.nic")
    association = next(item for item in items if item["type"] == "azurerm_network_interface_security_group_association")
    vm = next(item for item in items if item["address"].startswith("module.gateway.azurerm_virtual_machine."))
    if mutation == "not_applyable":
        plan["applyable"] = False
    elif mutation == "incomplete":
        plan["complete"] = False
    elif mutation == "drift":
        plan["resource_drift"] = [{"PRIVATE-VALUE": True}]
    elif mutation in ("update", "replace", "noop"):
        vm["change"]["actions"] = {"update": ["update"], "replace": ["delete", "create"],
                                    "noop": ["no-op"]}[mutation]
    elif mutation == "import":
        vm["change"]["importing"] = {"id": "PRIVATE-VALUE"}
    elif mutation in ("extra_resource", "group_delete", "managed_application_delete"):
        kind = {"extra_resource": "azurerm_virtual_network", "group_delete": "azurerm_resource_group",
                "managed_application_delete": "azurerm_managed_application"}[mutation]
        items.append({"address": "PRIVATE-VALUE", "mode": "managed", "type": kind,
                      "change": {"actions": ["delete"], "before": {}, "after": None}})
    elif mutation == "missing_resource":
        items.remove(nic)
    elif mutation == "ubuntu_resource":
        vm["type"] = "azurerm_linux_virtual_machine"
    elif mutation == "foreign_group":
        vm["change"]["before"]["resource_group_name"] = "PRIVATE-VALUE"
    elif mutation == "foreign_vm_id":
        vm["change"]["before"]["id"] = "PRIVATE-VALUE"
    elif mutation == "foreign_disk_id":
        vm["change"]["before"]["storage_os_disk"][0]["managed_disk_id"] = "PRIVATE-VALUE"
    elif mutation == "attached_disk":
        vm["change"]["before"]["storage_os_disk"][0]["create_option"] = "Attach"
    elif mutation == "data_disk":
        vm["change"]["before"]["storage_data_disk"] = [{"managed_disk_id": "PRIVATE-VALUE"}]
    elif mutation == "foreign_association_id":
        association["change"]["before"]["id"] = "PRIVATE-VALUE"
    elif mutation == "foreign_nic":
        association["change"]["before"]["network_interface_id"] = "PRIVATE-VALUE"
    elif mutation == "foreign_nsg":
        association["change"]["before"]["network_security_group_id"] = "PRIVATE-VALUE"
    elif mutation == "unmarked_secret":
        vm["change"]["before_sensitive"]["os_profile"] = False
    elif mutation == "foreign_provider":
        vm["provider_name"] = "PRIVATE-VALUE"
    elif mutation == "wrong_identity":
        plan["variables"]["provider_managed_identity_client_id"]["value"] = "PRIVATE-VALUE"
    elif mutation == "wrong_ssh":
        plan["variables"]["provider_admin_ssh_public_key"]["value"] = "PRIVATE-VALUE"
    elif mutation == "wrong_password":
        plan["variables"]["management_admin_password"]["value"] = "PRIVATE-VALUE"
    elif mutation == "modified_bootstrap":
        vm["change"]["before"]["os_profile"][0]["custom_data"] += "PRIVATE-VALUE"
    elif mutation == "sensitive_output":
        plan["output_changes"]["gatewayVmId"]["before_sensitive"] = True
    elif mutation == "foreign_output":
        plan["output_changes"]["gatewayVmId"]["before"] = "PRIVATE-VALUE"
    else:
        plan["output_changes"]["gatewayVmId"]["actions"] = ["no-op"]
    with pytest.raises(CheckpointPlanError) as error:
        validate_destroy_fixture(plan)
    assert "PRIVATE-VALUE" not in str(error.value)


@pytest.mark.usefixtures("plan_bootstrap_pins")
@pytest.mark.parametrize("mutation", [
    "incomplete", "errored", "not_applyable", "unsupported_version", "drift", "deferred", "action_invocation",
    "failed_check", "unknown_check",
    "update", "replace", "import", "moved", "deposed", "create_existing", "extra_resource", "foreign_group",
    "wrong_region", "foreign_resource_id", "wrong_nic_name", "wrong_private_ip", "wrong_allocation", "wrong_subnet",
    "backend_public_ip", "foreign_association", "foreign_nsg", "wrong_ip_sku", "dynamic_public_ip",
    "wrong_vm_size", "wrong_vm_image", "custom_vm_image", "wrong_marketplace_plan", "unmarked_secret",
    "foreign_vm_nic", "random_keeper", "output_sensitive", "unknown_private_output", "foreign_vm_output",
    "extra_output", "unknown_noop", "unknown_group", "unknown_subnet", "unknown_forwarding", "unknown_nsg",
    "unknown_image", "unknown_marketplace", "unknown_keeper", "excessive_unknown_depth", "foreign_provider",
    "foreign_vm_identity", "foreign_vm_tenant", "unknown_identity_type", "vm_boot_diagnostics",
    "unknown_vm_diagnostics", "vm_zones", "unknown_vm_zones", "missing_variable", "foreign_identity_variable",
    "foreign_subscription_variable", "foreign_ssh_variable", "foreign_sic_variable", "foreign_password_variable",
    "gateway_sic", "gateway_script", "gateway_ssh_key", "gateway_ssh_path", "gateway_password_auth",
    "management_password", "management_script", "management_username", "unknown_profile", "unknown_ssh",
    "foreign_association_id", "foreign_disk_id", "foreign_disk_name", "attached_disk", "data_disk",
    "disk_not_deleted", "unknown_disk_name", "unknown_data_disk",
])
def test_live_plan_guard_rejects_unsafe_changes_without_echoing_values(mutation):
    plan = live_fixture_plan()
    items = plan["resource_changes"]
    nic = next(item for item in items if item["address"] == "module.gateway.azurerm_network_interface.nic")
    backend = next(item for item in items if item["address"] == "module.gateway.azurerm_network_interface.nic1")
    association = next(item for item in items if item["type"] == "azurerm_network_interface_security_group_association")
    public_ip = next(item for item in items if item["type"] == "azurerm_public_ip")
    vm = next(item for item in items if item["type"] == "azurerm_virtual_machine")
    management_vm = next(item for item in items if item["address"] == "module.management.azurerm_virtual_machine.mgmt_vm_instance")
    random = next(item for item in items if item["type"] == "random_id")
    if mutation == "incomplete":
        plan["complete"] = False
    elif mutation == "errored":
        plan["errored"] = True
    elif mutation == "not_applyable":
        plan["applyable"] = False
    elif mutation == "unsupported_version":
        plan["terraform_version"] = "1.8.9"
    elif mutation == "drift":
        plan["resource_drift"] = [{"PRIVATE-VALUE": True}]
    elif mutation == "deferred":
        plan["deferred_changes"] = [{}]
    elif mutation == "action_invocation":
        plan["action_invocations"] = [{"PRIVATE-VALUE": True}]
    elif mutation in ("failed_check", "unknown_check"):
        plan["checks"] = [{"status": "fail" if mutation == "failed_check" else "unknown"}]
    elif mutation in ("update", "replace"):
        nic["change"]["actions"] = ["update"] if mutation == "update" else ["delete", "create"]
    elif mutation == "import":
        nic["change"]["importing"] = {"id": "PRIVATE-VALUE"}
    elif mutation == "moved":
        nic["previous_address"] = "PRIVATE-VALUE"
    elif mutation == "deposed":
        nic["deposed"] = "PRIVATE-VALUE"
    elif mutation == "create_existing":
        nic["change"]["before"] = {"id": "PRIVATE-VALUE"}
    elif mutation == "extra_resource":
        items.append({"address": "PRIVATE-VALUE"})
    elif mutation == "foreign_group":
        nic["change"]["after"]["resource_group_name"] = "PRIVATE-VALUE"
    elif mutation == "wrong_region":
        nic["change"]["after"]["location"] = "PRIVATE-VALUE"
    elif mutation == "foreign_resource_id":
        nic["change"]["after"]["id"] = "PRIVATE-VALUE"
        nic["change"]["after_unknown"]["id"] = False
    elif mutation == "wrong_nic_name":
        nic["change"]["after"]["name"] = "PRIVATE-VALUE"
    elif mutation == "wrong_private_ip":
        nic["change"]["after"]["ip_configuration"][0]["private_ip_address"] = "PRIVATE-VALUE"
    elif mutation == "wrong_allocation":
        nic["change"]["after"]["ip_configuration"][0]["private_ip_address_allocation"] = "Dynamic"
    elif mutation == "wrong_subnet":
        nic["change"]["after"]["ip_configuration"][0]["subnet_id"] = "PRIVATE-VALUE"
    elif mutation == "backend_public_ip":
        backend["change"]["after_unknown"]["ip_configuration"][0]["public_ip_address_id"] = True
    elif mutation == "foreign_association":
        association["change"]["after"]["network_interface_id"] = "PRIVATE-VALUE"
        association["change"]["after_unknown"]["network_interface_id"] = False
    elif mutation == "foreign_nsg":
        association["change"]["after"]["network_security_group_id"] = "PRIVATE-VALUE"
    elif mutation == "wrong_ip_sku":
        public_ip["change"]["after"]["sku"] = "Basic"
    elif mutation == "dynamic_public_ip":
        public_ip["change"]["after"]["allocation_method"] = "Dynamic"
    elif mutation == "wrong_vm_size":
        vm["change"]["after"]["vm_size"] = "PRIVATE-VALUE"
    elif mutation == "wrong_vm_image":
        vm["change"]["after"]["storage_image_reference"][0]["version"] = "latest"
    elif mutation == "custom_vm_image":
        vm["change"]["after"]["storage_image_reference"][0]["id"] = "PRIVATE-VALUE"
    elif mutation == "wrong_marketplace_plan":
        vm["change"]["after"]["plan"][0]["name"] = "PRIVATE-VALUE"
    elif mutation == "unmarked_secret":
        vm["change"]["after_sensitive"]["os_profile"] = False
    elif mutation == "foreign_vm_nic":
        vm["change"]["after"]["network_interface_ids"][0] = "PRIVATE-VALUE"
        vm["change"]["after_unknown"]["network_interface_ids"][0] = False
    elif mutation == "random_keeper":
        random["change"]["after"]["keepers"]["resource_group"] = "PRIVATE-VALUE"
    elif mutation == "output_sensitive":
        plan["output_changes"]["gatewayVmId"]["after_sensitive"] = True
    elif mutation == "unknown_private_output":
        output = plan["output_changes"]["gatewayFrontendPrivateIp"]
        output.update(after=None, after_unknown=True)
    elif mutation == "foreign_vm_output":
        output = plan["output_changes"]["gatewayVmId"]
        output.update(after="PRIVATE-VALUE", after_unknown=False)
    elif mutation == "extra_output":
        plan["output_changes"]["PRIVATE-VALUE"] = {}
    elif mutation == "unknown_group":
        nic["change"]["after_unknown"]["resource_group_name"] = True
    elif mutation == "unknown_subnet":
        nic["change"]["after_unknown"]["ip_configuration"][0]["subnet_id"] = True
    elif mutation == "unknown_forwarding":
        nic["change"]["after_unknown"]["ip_forwarding_enabled"] = True
    elif mutation == "unknown_nsg":
        association["change"]["after_unknown"]["network_security_group_id"] = True
    elif mutation == "unknown_image":
        vm["change"]["after_unknown"]["storage_image_reference"] = [{"version": True}]
    elif mutation == "unknown_marketplace":
        vm["change"]["after_unknown"]["plan"] = [{"name": True}]
    elif mutation == "unknown_keeper":
        random["change"]["after_unknown"]["keepers"] = {"resource_group": True}
    elif mutation == "excessive_unknown_depth":
        marker = False
        for _ in range(20):
            marker = {"nested": marker}
        vm["change"]["after_unknown"]["plan"] = marker
    elif mutation == "foreign_provider":
        vm["provider_name"] = "PRIVATE-VALUE"
    elif mutation == "foreign_vm_identity":
        vm["change"]["after"]["identity"][0]["identity_ids"] = ["PRIVATE-VALUE"]
    elif mutation == "foreign_vm_tenant":
        vm["change"]["after"]["identity"][0]["tenant_id"] = "PRIVATE-VALUE"
        vm["change"]["after_unknown"]["identity"][0]["tenant_id"] = False
    elif mutation == "unknown_identity_type":
        vm["change"]["after_unknown"]["identity"][0]["type"] = True
    elif mutation == "vm_boot_diagnostics":
        vm["change"]["after"]["boot_diagnostics"][0]["enabled"] = True
    elif mutation == "unknown_vm_diagnostics":
        vm["change"]["after_unknown"]["boot_diagnostics"] = [{"storage_uri": True}]
    elif mutation == "vm_zones":
        vm["change"]["after"]["zones"] = ["1"]
    elif mutation == "unknown_vm_zones":
        vm["change"]["after_unknown"]["zones"] = True
    elif mutation == "missing_variable":
        del plan["variables"]["provider_tenant_id"]
    elif mutation == "foreign_identity_variable":
        plan["variables"]["provider_managed_identity_client_id"]["value"] = "PRIVATE-VALUE"
    elif mutation == "foreign_subscription_variable":
        plan["variables"]["provider_subscription_id"]["value"] = "PRIVATE-VALUE"
    elif mutation == "foreign_ssh_variable":
        plan["variables"]["provider_admin_ssh_public_key"]["value"] = "PRIVATE-VALUE"
    elif mutation == "foreign_sic_variable":
        plan["variables"]["sic_key"]["value"] = "PRIVATE-VALUE"
    elif mutation == "foreign_password_variable":
        plan["variables"]["management_admin_password"]["value"] = "PRIVATE-VALUE"
    elif mutation == "gateway_sic":
        vm["change"]["after"]["os_profile"][0]["custom_data"] = 'synthetic-gateway\nsicKey="PRIVATE-VALUE"\n'
    elif mutation == "gateway_script":
        vm["change"]["after"]["os_profile"][0]["custom_data"] += "PRIVATE-VALUE"
    elif mutation == "gateway_ssh_key":
        vm["change"]["after"]["os_profile_linux_config"][0]["ssh_keys"][0]["key_data"] = "PRIVATE-VALUE"
    elif mutation == "gateway_ssh_path":
        vm["change"]["after"]["os_profile_linux_config"][0]["ssh_keys"][0]["path"] = "PRIVATE-VALUE"
    elif mutation == "gateway_password_auth":
        vm["change"]["after"]["os_profile_linux_config"][0]["disable_password_authentication"] = False
    elif mutation == "management_password":
        management_vm["change"]["after"]["os_profile"][0]["admin_password"] = "PRIVATE-VALUE"
    elif mutation == "management_script":
        management_vm["change"]["after"]["os_profile"][0]["custom_data"] += "PRIVATE-VALUE"
    elif mutation == "management_username":
        management_vm["change"]["after"]["os_profile"][0]["admin_username"] = "PRIVATE-VALUE"
    elif mutation == "unknown_profile":
        vm["change"]["after_unknown"]["os_profile"] = [{"custom_data": True}]
    elif mutation == "unknown_ssh":
        vm["change"]["after_unknown"]["os_profile_linux_config"] = [{"ssh_keys": [{"key_data": True}]}]
    elif mutation == "foreign_association_id":
        association["change"]["after"]["id"] = "PRIVATE-VALUE"
        association["change"]["after_unknown"]["id"] = False
    elif mutation == "foreign_disk_id":
        vm["change"]["after"]["storage_os_disk"][0]["managed_disk_id"] = "PRIVATE-VALUE"
        vm["change"]["after_unknown"]["storage_os_disk"][0]["managed_disk_id"] = False
    elif mutation == "foreign_disk_name":
        vm["change"]["after"]["storage_os_disk"][0]["name"] = "PRIVATE-VALUE"
    elif mutation == "attached_disk":
        vm["change"]["after"]["storage_os_disk"][0]["create_option"] = "Attach"
    elif mutation == "data_disk":
        vm["change"]["after"]["storage_data_disk"] = [{"managed_disk_id": "PRIVATE-VALUE"}]
    elif mutation == "disk_not_deleted":
        vm["change"]["after"]["delete_os_disk_on_termination"] = False
    elif mutation == "unknown_disk_name":
        vm["change"]["after_unknown"]["storage_os_disk"][0]["name"] = True
    elif mutation == "unknown_data_disk":
        vm["change"]["after_unknown"]["storage_data_disk"] = True
    else:
        nic["change"]["actions"] = ["no-op"]
    with pytest.raises(CheckpointPlanError) as error:
        validate_live_fixture(plan)
    assert "PRIVATE-VALUE" not in str(error.value)


@pytest.mark.usefixtures("plan_bootstrap_pins")
@pytest.mark.parametrize("change", ["group_resource", "network_resource", "replacement", "wrong_group",
                                     "wrong_subnet", "wrong_nsg", "latest_image", "unmarked_secret",
                                     "duplicate", "malformed"])
def test_mock_plan_rejects_unsafe_or_unexpected_changes(change):
    plan = fixture_plan()
    items = plan["resource_changes"]
    if change == "group_resource":
        items.append({"address": "module.management.azurerm_resource_group.group",
                      "mode": "managed", "type": "azurerm_resource_group",
                      "change": {"actions": ["create"], "after": {}}})
    elif change == "network_resource":
        items[0]["type"] = "azurerm_virtual_network"
    elif change == "replacement":
        items[0]["change"]["actions"] = ["delete", "create"]
    elif change == "wrong_group":
        items[0]["change"]["after"]["resource_group_name"] = "other-group"
    elif change == "wrong_subnet":
        items[0]["change"]["after"]["ip_configuration"][0]["subnet_id"] = "/outside"
    elif change == "wrong_nsg":
        association = next(item for item in items if item["type"] == "azurerm_network_interface_security_group_association")
        association["change"]["after"]["network_security_group_id"] = "/outside"
    elif change == "latest_image":
        vm = next(item for item in items if item["type"] == "azurerm_virtual_machine")
        vm["change"]["after"]["storage_image_reference"][0]["version"] = "latest"
    elif change == "unmarked_secret":
        vm = next(item for item in items if item["type"] == "azurerm_virtual_machine")
        vm["change"]["after_sensitive"] = {"os_profile": False}
    elif change == "duplicate":
        items[-1] = items[0]
    else:
        items[0]["address"] = []
    with pytest.raises(probe.ProbeError):
        probe.validate_plan(plan, "1.15.7")


def test_mock_terraform_never_inherits_azure_credentials(tmp_path, monkeypatch):
    calls = []

    def run(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout="fixture")

    monkeypatch.setenv("ARM_CLIENT_SECRET", "fixture-must-not-be-inherited")
    monkeypatch.setattr(probe.subprocess, "run", run)
    assert probe._terraform("/fixture/terraform", tmp_path, tmp_path, ["test", "-json"]) == "fixture"
    env = calls[0][1]["env"]
    assert set(env) == {"HOME", "PATH", "TF_IN_AUTOMATION", "TF_LOG", "TF_CLI_CONFIG_FILE",
                        "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT",
                        "CHECKPOINT_DISABLE"}
    assert env["GIT_CONFIG_NOSYSTEM"] == "1" and env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["CHECKPOINT_DISABLE"] == "1"
    assert "ARM_CLIENT_SECRET" not in env


def test_mock_rejection_requires_expected_validation_error(tmp_path, monkeypatch):
    detail = "Use an explicit Marketplace image version."
    event = {"type": "diagnostic", "diagnostic": {"severity": "error", "detail": detail}}
    monkeypatch.setattr(probe.subprocess, "run",
                        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=json.dumps(event)))
    probe._terraform("/fixture/terraform", tmp_path, tmp_path, ["test", "-json"],
                     {"management_image_version": "latest"}, (detail,))
    with pytest.raises(probe.ProbeError, match="unexpected reason"):
        probe._terraform("/fixture/terraform", tmp_path, tmp_path, ["test", "-json"],
                         {"management_image_version": "latest"}, ("another error",))
    with pytest.raises(probe.ProbeError, match="Unexpected Terraform"):
        probe._terraform("/fixture/terraform", tmp_path, tmp_path, ["test"], {"other": "value"})


def test_mock_probe_cleans_only_its_own_files_on_failure(tmp_path, monkeypatch):
    local = tmp_path / "local"
    local.mkdir()
    keep = local / "unrelated"
    keep.write_text("preserve")
    monkeypatch.setattr(modules, "LOCAL_ROOT", local)
    monkeypatch.setattr(probe.shutil, "which", lambda _: sys.executable)
    monkeypatch.setattr(modules, "prepare", lambda source, output: output.mkdir())
    monkeypatch.setattr(probe, "verify_checkpoint_artifact", lambda _path: None)
    monkeypatch.setattr(probe, "verify_terraform_release", lambda _path: None)
    monkeypatch.setattr(probe, "_terraform", lambda *args: (_ for _ in ()).throw(probe.ProbeError("fixture failure")))
    with pytest.raises(probe.ProbeError, match="fixture failure"):
        probe.run(tmp_path)
    assert [path.name for path in local.iterdir()] == ["unrelated"]
    assert keep.read_text() == "preserve"
