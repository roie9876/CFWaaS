"""Fail-closed checks for an isolated Check Point Terraform plan.

The plan contains secrets. Callers must keep it private and apply the exact
validated plan only after independent dependency, identity and lifecycle checks.
"""
import base64
import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_ssh_public_key

from .checkpoint_credentials import CheckpointCredentials
from .config import uuid_text
from .models import environment_resource_group_name
from .checkpoint_terraform import TERRAFORM_VERSION


EXPECTED = {
    "module.gateway.azurerm_network_interface.nic": "azurerm_network_interface",
    "module.gateway.azurerm_network_interface.nic1": "azurerm_network_interface",
    "module.gateway.azurerm_network_interface_security_group_association.security_group_association":
        "azurerm_network_interface_security_group_association",
    "module.gateway.azurerm_public_ip.public_ip": "azurerm_public_ip",
    "module.gateway.azurerm_virtual_machine.single_gateway_vm_instance[0]": "azurerm_virtual_machine",
    "module.gateway.random_id.public_ip_suffix": "random_id",
    "module.management.azurerm_network_interface.nic": "azurerm_network_interface",
    "module.management.azurerm_network_interface_security_group_association.security_group_association":
        "azurerm_network_interface_security_group_association",
    "module.management.azurerm_public_ip.public_ip": "azurerm_public_ip",
    "module.management.azurerm_virtual_machine.mgmt_vm_instance": "azurerm_virtual_machine",
    "module.management.random_id.public_ip_suffix": "random_id",
}
NETWORK_INTERFACES = {
    "module.gateway.azurerm_network_interface.nic": ("firewall-frontend", True),
    "module.gateway.azurerm_network_interface.nic1": ("firewall-backend", True),
    "module.management.azurerm_network_interface.nic": ("management", False),
}
OUTPUTS = {"gatewayFrontendPrivateIp", "gatewayVmId", "managementPrivateIp", "managementVmId"}
GATEWAY_BOOTSTRAP_SHA256 = "c573fc1b0e4282b1d018175fe5adb451536ab526db5f50dd4d67def482148220"
MANAGEMENT_BOOTSTRAP_SHA256 = "63859b9a417e997fffe5ccf48639cd3bec21702acb0b6b68093dc6225439e9a5"
# Redacted cloud-init rendered by the pinned modules. AzureRM plans store custom_data as
# sha1(base64(rendered)), so the guard re-renders these to compare digests.
GATEWAY_BOOTSTRAP_TEMPLATE = '#!/usr/bin/python3 /etc/cloud_config.py\n\ninstallationType="gateway"\nallowUploadDownload="false"\nosVersion="R82"\ntemplateName="single_terraform_registry"\ntemplateVersion="1.0.9"\ntemplateType="terraform"\nisBlink="true"\nbootstrapScript64=""\nlocation="eastus2"\nadminShell="/etc/cli.sh"\nsicKey="<REDACTED>"\nmanagementGUIClientNetwork="172.22.40.0/23"\ncustomMetrics="no"\npasswordHash=""\nMaintenanceModePassword=""'
MANAGEMENT_BOOTSTRAP_TEMPLATE = '#!/usr/bin/python3 /etc/cloud_config.py\n\ninstallationType="management"\nallowUploadDownload="false"\nosVersion="R82"\ntemplateName="management_terraform_registry"\ntemplateVersion="1.0.9"\ntemplateType="terraform"\nisBlink="true"\nbootstrapScript64=""\nlocation="eastus2"\nmanagementGUIClientNetwork="172.22.40.0/23"\nenableApi="gui_clients"\nadminShell="/etc/cli.sh"\npasswordHash=""\nMaintenanceModePassword=""\n'
_SIC_PLACEHOLDER = 'sicKey="<REDACTED>"'

_MANAGEMENT_EXPECTED = {address: kind for address, kind in EXPECTED.items() if address.startswith("module.management.")}
VMSS_EXPECTED = {
    **_MANAGEMENT_EXPECTED,
    "module.gateway.azurerm_lb.backend_lb[0]": "azurerm_lb",
    "module.gateway.azurerm_lb.frontend_lb[0]": "azurerm_lb",
    "module.gateway.azurerm_lb_backend_address_pool.backend_lb_pool[0]": "azurerm_lb_backend_address_pool",
    "module.gateway.azurerm_lb_backend_address_pool.frontend_lb_pool[0]": "azurerm_lb_backend_address_pool",
    "module.gateway.azurerm_lb_probe.azure_lb_healprob[0]": "azurerm_lb_probe",
    "module.gateway.azurerm_lb_probe.azure_lb_healprob[1]": "azurerm_lb_probe",
    "module.gateway.azurerm_lb_rule.lbnatrule_standard[0]": "azurerm_lb_rule",
    "module.gateway.azurerm_lb_rule.lbnatrule_standard[1]": "azurerm_lb_rule",
    "module.gateway.azurerm_linux_virtual_machine_scale_set.vmss[0]": "azurerm_linux_virtual_machine_scale_set",
    "module.gateway.azurerm_public_ip.public_ip_lb[0]": "azurerm_public_ip",
    "module.gateway.random_id.random_id": "random_id",
}
VMSS_OUTPUTS = {"gatewayScaleSetId", "internalLoadBalancerIp", "managementPrivateIp", "managementVmId",
                "publicLoadBalancerIp"}
VMSS_INSTANCES = 2
VMSS_SKU = "sg-byol"
VMSS_INTERNAL_LB_IP = "172.22.20.4"
VMSS_BOOTSTRAP_SHA256 = "0d7066622c0e93da84b0f7111ab068215cb569fd10fbd51eeb63cedb6a708eff"
VMSS_BOOTSTRAP_TEMPLATE = '#!/usr/bin/python3 /etc/cloud_config.py\n\ninstallationType="vmss"\nallowUploadDownload="false"\nosVersion="R82"\ntemplateName="vmss_terraform_registry"\ntemplateVersion="1.0.9"\ntemplateType="terraform"\nisBlink="true"\nbootstrapScript64=""\nlocation="eastus2"\nsicKey="<REDACTED>"\nvnet="172.22.10.0/24"\ncustomMetrics="no"\nadminShell="/etc/cli.sh"\npasswordHash=""\nMaintenanceModePassword=""\nsetHealthProbe="false"\n'
TOPOLOGIES = ("single", "vmss")


class CheckpointPlanError(ValueError):
    pass


@dataclass(frozen=True)
class CheckpointPlanSummary:
    creates: int
    unchanged: int
    output_creates: int

    @property
    def needs_apply(self) -> bool:
        return self.creates > 0 or self.output_creates > 0


@dataclass(frozen=True)
class CheckpointDestroySummary:
    deletes: int
    output_deletes: int


def _same_id(value: object, expected: str) -> bool:
    return isinstance(value, str) and value.lower() == expected.lower()


def _reference(value: object, unknown: object, expected: str, creating: bool) -> bool:
    if unknown is True:
        return creating and value is None
    return (unknown is None or unknown is False) and _same_id(value, expected)


def _single_pool(values: object, unknown: object, expected: str, creating: bool) -> bool:
    # AzureRM plans a conditionally selected pool list as wholly unknown on create.
    if unknown is True:
        return creating and values is None
    return (isinstance(values, list) and len(values) == 1
            and _reference(values[0], unknown[0] if isinstance(unknown, list) and len(unknown) == 1 else None,
                           expected, creating))


def _known(value: object, depth: int = 0) -> bool:
    if depth > 16:
        return False
    if value is None or value is False:
        return True
    if isinstance(value, dict):
        return all(_known(item, depth + 1) for item in value.values())
    if isinstance(value, list):
        return all(_known(item, depth + 1) for item in value)
    return False


def validate_checkpoint_public_key(value: str) -> bytes:
    try:
        key = load_ssh_public_key(value.encode("ascii"))
        if (not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey))
                or isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048
                or isinstance(key, ec.EllipticCurvePublicKey) and not isinstance(key.curve, ec.SECP256R1)):
            raise ValueError()
        return key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    except (TypeError, ValueError, AttributeError, UnicodeEncodeError, UnsupportedAlgorithm):
        raise CheckpointPlanError("Invalid Check Point provider SSH key") from None


_ACTIONS = {"create", "delete", "update", "no-op", "read", "forget"}


def _action_detail(address: str, change: object) -> str:
    """Describe a rejected action using only expected addresses, action verbs and schema key names."""
    if not isinstance(change, dict) or not isinstance(change.get("actions"), list):
        return ": " + address
    actions = [item for item in change["actions"] if item in _ACTIONS]
    before, after = change.get("before"), change.get("after")
    keys = []
    if isinstance(before, dict) and isinstance(after, dict):
        keys = sorted(key for key in set(before) | set(after)
                      if isinstance(key, str) and re.fullmatch(r"[a-z0-9_]{1,64}", key)
                      and before.get(key) != after.get(key))[:8]
    return ": " + address + " " + "+".join(actions) + (" " + ",".join(keys) if keys else "")


def _secret_equal(value: object, expected: str) -> bool:
    return isinstance(value, str) and value.isascii() and hmac.compare_digest(value, expected)


def _single(value: object) -> dict | None:
    return value[0] if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict) else None


def _validate_vmss_gateway(address: str, kind: str, change: dict, creating: bool, group_name: str, group_id: str,
                           suffix: str, gateway_image_version: str, gateway_vm_size: str, expected_key: bytes,
                           credentials: CheckpointCredentials) -> None:
    after, unknown = change["after"], change.get("after_unknown", {})
    network = group_id + "/providers/Microsoft.Network"
    vnet = network + "/virtualNetworks/vnet-cp-security-" + suffix
    scale_set, app = "cp-vmss-" + suffix, "cp-vmss-" + suffix + "-app-1"
    lbs = {"backend": network + "/loadBalancers/backend-lb", "frontend": network + "/loadBalancers/frontend-lb"}
    pools = {"backend": lbs["backend"] + "/backendAddressPools/backend-lb-pool",
             "frontend": lbs["frontend"] + "/backendAddressPools/" + app}
    side = "backend" if address.endswith(("backend_lb[0]", "backend_lb_pool[0]", "healprob[1]", "standard[1]")) \
        else "frontend"
    if kind in {"azurerm_lb", "azurerm_public_ip", "azurerm_linux_virtual_machine_scale_set"}:
        if (not _same_id(after.get("resource_group_name"), group_name) or after.get("location") != "eastus2"
                or not all(_known(unknown.get(key)) for key in ("resource_group_name", "location", "name"))
                or after.get("zones") not in (None, []) or not _known(unknown.get("zones"))):
            raise CheckpointPlanError("Check Point plan targets an unexpected group or region")
    if kind == "azurerm_lb":
        config, config_unknown = _single(after.get("frontend_ip_configuration")), \
            _single(unknown.get("frontend_ip_configuration")) or {}
        if (after.get("name") != side + "-lb" or after.get("sku") != "Standard" or config is None
                or not _known(unknown.get("sku"))
                or not _reference(after.get("id"), unknown.get("id"), lbs[side], creating)):
            raise CheckpointPlanError("Invalid Check Point load balancer")
        if side == "backend":
            valid = (config.get("name") == "backend-lb" and config.get("private_ip_address") == VMSS_INTERNAL_LB_IP
                     and config.get("private_ip_address_allocation") == "Static"
                     and _same_id(config.get("subnet_id"), vnet + "/subnets/firewall-backend")
                     and config.get("public_ip_address_id") in (None, "")
                     and all(_known(config_unknown.get(key)) for key in (
                         "name", "private_ip_address", "private_ip_address_allocation", "subnet_id")))
        else:
            valid = (config.get("name") == app and config.get("subnet_id") in (None, "")
                     and _known(config_unknown.get("subnet_id"))
                     and _reference(config.get("public_ip_address_id"), config_unknown.get("public_ip_address_id"),
                                    network + "/publicIPAddresses/" + app, creating))
        if not valid:
            raise CheckpointPlanError("Invalid Check Point load balancer frontend")
    elif kind == "azurerm_lb_backend_address_pool":
        name = "backend-lb-pool" if side == "backend" else app
        if (after.get("name") != name or after.get("virtual_network_id") not in (None, "")
                or after.get("tunnel_interface") not in (None, [])
                or not _reference(after.get("loadbalancer_id"), unknown.get("loadbalancer_id"), lbs[side], creating)
                or not _reference(after.get("id"), unknown.get("id"), pools[side], creating)):
            raise CheckpointPlanError("Invalid Check Point load balancer pool")
    elif kind == "azurerm_lb_probe":
        name = "backend-lb" if side == "backend" else app
        if (after.get("name") != name or after.get("protocol") != "Tcp" or after.get("port") != 8117
                or after.get("interval_in_seconds") != 5 or after.get("number_of_probes") != 2
                or after.get("request_path") not in (None, "")
                or not _reference(after.get("loadbalancer_id"), unknown.get("loadbalancer_id"), lbs[side], creating)
                or not _reference(after.get("id"), unknown.get("id"), lbs[side] + "/probes/" + name, creating)):
            raise CheckpointPlanError("Invalid Check Point load balancer probe")
    elif kind == "azurerm_lb_rule":
        backend = side == "backend"
        name = "backend-lb" if backend else app
        pool_ids, pool_unknown = after.get("backend_address_pool_ids"), unknown.get("backend_address_pool_ids")
        if (after.get("name") != name or after.get("frontend_ip_configuration_name") != name
                or after.get("protocol") != ("All" if backend else "Tcp")
                or after.get("frontend_port") != (0 if backend else 80)
                or after.get("backend_port") != (0 if backend else 80)
                or after.get("floating_ip_enabled") is not True
                or after.get("disable_outbound_snat") not in (None, False)
                or not _single_pool(pool_ids, pool_unknown, pools[side], creating)
                or not _reference(after.get("loadbalancer_id"), unknown.get("loadbalancer_id"), lbs[side], creating)
                or not _reference(after.get("probe_id"), unknown.get("probe_id"),
                                  lbs[side] + "/probes/" + name, creating)):
            raise CheckpointPlanError("Invalid Check Point load balancer rule")
    elif kind == "azurerm_public_ip":
        if (after.get("name") != app or after.get("sku") != "Standard" or after.get("allocation_method") != "Static"
                or not _known(unknown.get("sku")) or not _known(unknown.get("allocation_method"))
                or not _reference(after.get("id"), unknown.get("id"), network + "/publicIPAddresses/" + app, creating)):
            raise CheckpointPlanError("Invalid Check Point public IP")
    elif kind == "random_id":
        if (after.get("keepers") != {"rg_id": group_id} or after.get("byte_length") != 13
                or not _known(unknown.get("keepers")) or not _known(unknown.get("byte_length"))):
            raise CheckpointPlanError("Invalid Check Point plan identity")
    elif kind == "azurerm_linux_virtual_machine_scale_set":
        compute = group_id + "/providers/Microsoft.Compute"
        image, marketplace = _single(after.get("source_image_reference")), _single(after.get("plan"))
        disk, ssh = _single(after.get("os_disk")), _single(after.get("admin_ssh_key"))
        sensitive = change.get("after_sensitive")
        nics = after.get("network_interface")
        checks = (
            ("name", lambda: after.get("name") != scale_set or after.get("computer_name_prefix") != scale_set),
            ("size", lambda: after.get("sku") != gateway_vm_size or not _known(unknown.get("sku"))),
            ("capacity", lambda: after.get("instances") != VMSS_INSTANCES or after.get("overprovision") is not False
                or after.get("upgrade_mode") != "Manual" or not _known(unknown.get("instances"))),
            ("id", lambda: not _reference(after.get("id"), unknown.get("id"),
                                          compute + "/virtualMachineScaleSets/" + scale_set, creating)),
            ("image", lambda: image is None or after.get("source_image_id") not in (None, "")
                or image != {"publisher": "checkpoint", "offer": "check-point-cg-r82",
                             "sku": VMSS_SKU, "version": gateway_image_version}),
            ("plan", lambda: marketplace != {"name": VMSS_SKU, "product": "check-point-cg-r82",
                                             "publisher": "checkpoint"}),
            ("identity", lambda: after.get("identity") not in (None, []) or not _known(unknown.get("identity"))),
            ("extensions", lambda: after.get("extension") not in (None, []) or after.get("data_disk") not in (None, [])
                or not (_known(unknown.get("extension")) or creating and unknown.get("extension") is True)
                or not _known(unknown.get("data_disk"))),
            ("diagnostics", lambda: _single(after.get("boot_diagnostics")) is None
                or after["boot_diagnostics"][0].get("storage_account_uri") not in (None, "")),
            ("os-disk", lambda: disk is None or disk.get("caching") != "ReadWrite"
                or disk.get("storage_account_type") != "StandardSSD_LRS" or disk.get("disk_size_gb") != 100),
            ("sensitive", lambda: not isinstance(sensitive, dict) or sensitive.get("custom_data") is not True
                or sensitive.get("admin_password") is not True),
            ("authentication", lambda: after.get("admin_username") != "notused"
                or after.get("disable_password_authentication") is not True
                or ssh is None or ssh.get("username") != "notused" or not isinstance(ssh.get("public_key"), str)),
            ("network", lambda: not isinstance(nics, list) or len(nics) != 2
                or any(not isinstance(nic, dict) for nic in nics)),
        )
        for label, failed in checks:
            if failed():
                raise CheckpointPlanError("Invalid Check Point scale set: " + label)
        try:
            if validate_checkpoint_public_key(ssh["public_key"]) != expected_key:
                raise ValueError()
        except (ValueError, CheckpointPlanError):
            raise CheckpointPlanError("Invalid Check Point gateway authentication") from None
        unknown_nics = unknown.get("network_interface")
        unknown_nics = unknown_nics if isinstance(unknown_nics, list) and len(unknown_nics) == 2 else [{}, {}]
        for index, (nic, nic_unknown) in enumerate(zip(nics, unknown_nics)):
            backend = index == 1
            config = _single(nic.get("ip_configuration"))
            config_unknown = _single(nic_unknown.get("ip_configuration") if isinstance(nic_unknown, dict) else None) \
                or {}
            if (config is None or nic.get("name") != ("eth1" if backend else "eth0")
                    or nic.get("primary") is not (not backend) or nic.get("enable_ip_forwarding") is not True
                    or nic.get("network_security_group_id") not in (None, "")
                    or config.get("name") != ("ipconfig2" if backend else "ipconfig1")
                    or config.get("primary") is not True
                    or not _same_id(config.get("subnet_id"),
                                    vnet + "/subnets/" + ("firewall-backend" if backend else "firewall-frontend"))):
                raise CheckpointPlanError("Invalid Check Point scale set network")
            pool_ids, pool_unknown = config.get("load_balancer_backend_address_pool_ids"), \
                config_unknown.get("load_balancer_backend_address_pool_ids")
            public = config.get("public_ip_address")
            if (not _single_pool(pool_ids, pool_unknown, pools["backend" if backend else "frontend"], creating)
                    or (backend and public not in (None, []))
                    or (not backend and (_single(public) is None
                                         or public[0].get("name") != scale_set + "-public-ip"
                                         or public[0].get("public_ip_prefix_id") not in (None, "")))):
                raise CheckpointPlanError("Invalid Check Point scale set network")
        bootstrap = after.get("custom_data")
        rendered = VMSS_BOOTSTRAP_TEMPLATE.replace(_SIC_PLACEHOLDER, f'sicKey="{credentials.sic_key}"', 1)
        encoded = base64.b64encode(rendered.encode("ascii")).decode("ascii")
        if (hashlib.sha256(VMSS_BOOTSTRAP_TEMPLATE.encode("ascii")).hexdigest() != VMSS_BOOTSTRAP_SHA256
                or not (_secret_equal(bootstrap, encoded) or (not creating and bootstrap in ("", None)))):
            raise CheckpointPlanError("Invalid Check Point scale set bootstrap")
        tags = after.get("tags")
        if tags != {
                "LegacyVMNVA": "", "x-chkp-anti-spoofing": "eth0:false,eth1:false",
                "x-chkp-ip-address": "private", "x-chkp-ip-version": "ipv4-only",
                "x-chkp-management": "cp-management-" + suffix, "x-chkp-management-address": "172.22.30.4",
                "x-chkp-management-interface": "eth0", "x-chkp-orchestration-mode": "Uniform",
                "x-chkp-srcImageUri": "noCustomUri", "x-chkp-template": "faas-vmss-" + suffix,
                "x-chkp-topology": "eth0:external,eth1:internal"}:
            raise CheckpointPlanError("Invalid Check Point scale set tags")
    else:
        raise CheckpointPlanError("Unexpected Check Point plan resources")


def validate_checkpoint_plan(
        plan: dict, provider_subscription: str, provider_tenant: str, provider_managed_identity_client_id: str,
        group_name: str, environment_id: str,
        gateway_image_version: str, management_image_version: str,
        gateway_vm_size: str, management_vm_size: str, provider_ssh_public_key: str,
        credentials: CheckpointCredentials, topology: str = "single") -> CheckpointPlanSummary:
    if topology not in TOPOLOGIES:
        raise CheckpointPlanError("Invalid Check Point plan scope or configuration")
    vmss = topology == "vmss"
    expected_resources = VMSS_EXPECTED if vmss else EXPECTED
    try:
        uuid_text(provider_subscription)
        uuid_text(provider_tenant)
        uuid_text(provider_managed_identity_client_id)
        uuid_text(environment_id)
        if (not isinstance(group_name, str) or not group_name.startswith("rg-faas-env-")
                or environment_resource_group_name(group_name.removeprefix("rg-faas-env-")) != group_name
                or any(not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value)
                       for value in (gateway_image_version, management_image_version))
                or any(not isinstance(value, str) or not re.fullmatch(r"Standard_[A-Za-z0-9_]+", value)
                       for value in (gateway_vm_size, management_vm_size))
                or not isinstance(credentials, CheckpointCredentials)
                or not isinstance(credentials.sic_key, str) or not re.fullmatch(r"[0-9a-f]{48}", credentials.sic_key)
                or not isinstance(credentials.management_password, str)
                or not re.fullmatch(r"[A-Za-z0-9!@#%_+-]{16,72}", credentials.management_password)
                or not all(re.search(pattern, credentials.management_password)
                           for pattern in (r"[A-Z]", r"[a-z]", r"[0-9]", r"[!@#%_+-]"))):
            raise ValueError()
    except (TypeError, ValueError, AttributeError):
        raise CheckpointPlanError("Invalid Check Point plan scope or configuration") from None
    expected_key = validate_checkpoint_public_key(provider_ssh_public_key)
    if (not isinstance(plan, dict)
            or not isinstance(plan.get("format_version"), str)
            or not re.fullmatch(r"1\.[0-9]+", plan["format_version"])
            or plan.get("terraform_version") != TERRAFORM_VERSION):
        raise CheckpointPlanError("Incomplete or unsupported Check Point plan")
    if plan.get("complete") is not True or plan.get("errored") is not False:
        raise CheckpointPlanError("Incomplete or unsupported Check Point plan: incomplete")
    if plan.get("deferred_changes", []) != [] or plan.get("action_invocations", []) != []:
        raise CheckpointPlanError("Incomplete or unsupported Check Point plan: deferred")
    # Refresh drift on already-created Check Point resources is informational: the planned
    # resource_changes below are still validated against the exact expected configuration.
    drift = plan.get("resource_drift", [])
    if not isinstance(drift, list) or any(
            not isinstance(item, dict) or item.get("mode") != "managed"
            or expected_resources.get(item.get("address")) is None
            or item.get("type") != expected_resources[item["address"]]
            or not isinstance(item.get("change"), dict)
            or item["change"].get("actions") not in (["update"], ["no-op"])
            for item in drift):
        raise CheckpointPlanError("Incomplete or unsupported Check Point plan: drift")
    checks = plan.get("checks", [])
    if not isinstance(checks, list) or any(
            not isinstance(item, dict) or item.get("status") != "pass" for item in checks):
        raise CheckpointPlanError("Check Point plan checks are not complete")
    group_id = f"/subscriptions/{provider_subscription}/resourceGroups/{group_name}"
    expected_variables = {
        "provider_subscription_id": provider_subscription,
        "provider_tenant_id": provider_tenant,
        "provider_managed_identity_client_id": provider_managed_identity_client_id,
        "provider_group_id": group_id,
        "environment_id": environment_id,
        "gateway_image_version": gateway_image_version,
        "management_image_version": management_image_version,
        "gateway_vm_size": gateway_vm_size,
        "management_vm_size": management_vm_size,
    }
    variable_names = set(expected_variables) | {
        "provider_admin_ssh_public_key", "sic_key", "management_admin_password",
    }
    variables = plan.get("variables")
    if (not isinstance(variables, dict) or set(variables) != variable_names
            or any(not isinstance(item, dict) or "value" not in item for item in variables.values())
            or any(not _same_id(variables[name]["value"], value)
                   for name, value in expected_variables.items())):
        raise CheckpointPlanError("Invalid Check Point plan variables")
    try:
        if (validate_checkpoint_public_key(variables["provider_admin_ssh_public_key"]["value"]) != expected_key
                or not _secret_equal(variables["sic_key"]["value"], credentials.sic_key)
                or not _secret_equal(variables["management_admin_password"]["value"], credentials.management_password)):
            raise ValueError()
    except (TypeError, ValueError, AttributeError, CheckpointPlanError):
        raise CheckpointPlanError("Check Point plan variables do not match approved credentials") from None
    resources = plan.get("resource_changes")
    if not isinstance(resources, list) or any(not isinstance(item, dict) for item in resources):
        raise CheckpointPlanError("Invalid Check Point plan resources")
    addresses = [item.get("address") for item in resources]
    if (len(addresses) != len(expected_resources) or not all(isinstance(item, str) for item in addresses)
            or set(addresses) != set(expected_resources)):
        raise CheckpointPlanError("Unexpected Check Point plan resources")

    suffix = environment_id[:8]
    network = group_id + "/providers/Microsoft.Network"
    compute = group_id + "/providers/Microsoft.Compute"
    vnet = network + "/virtualNetworks/vnet-cp-security-" + suffix
    gateway, management = "cp-gateway-" + suffix, "cp-management-" + suffix
    creates = 0
    created: set[str] = set()
    for item in resources:
        address = item["address"]
        kind = expected_resources[address]
        change = item.get("change")
        provider = ("registry.terraform.io/hashicorp/random" if kind == "random_id"
                    else "registry.terraform.io/hashicorp/azurerm")
        if (item.get("mode") != "managed" or item.get("type") != kind
                or item.get("provider_name") != provider
                or "previous_address" in item or "deposed" in item
                or not isinstance(change, dict)
                or change.get("actions") not in (["create"], ["no-op"])
                or change.get("importing") is not None
                or not isinstance(change.get("after"), dict)
                or not isinstance(change.get("after_unknown", {}), dict)):
            raise CheckpointPlanError("Unsafe Check Point resource action" + _action_detail(address, change))
        creating = change["actions"] == ["create"]
        if creating and change.get("before") is not None:
            raise CheckpointPlanError("Unsafe Check Point resource action")
        creates += int(creating)
        if creating:
            created.add(address)
        after, unknown = change["after"], change.get("after_unknown", {})
        is_gateway = address.startswith("module.gateway.")
        if vmss and is_gateway:
            _validate_vmss_gateway(address, kind, change, creating, group_name, group_id, suffix,
                                   gateway_image_version, gateway_vm_size, expected_key, credentials)
            continue
        name = gateway if is_gateway else management
        if kind in {"azurerm_network_interface", "azurerm_public_ip", "azurerm_virtual_machine"}:
            if (not _same_id(after.get("resource_group_name"), group_name) or after.get("location") != "eastus2"
                    or not all(_known(unknown.get(key)) for key in ("resource_group_name", "location", "name"))):
                raise CheckpointPlanError("Check Point plan targets an unexpected group or region")
        if kind == "azurerm_network_interface":
            subnet, forwarding = NETWORK_INTERFACES[address]
            is_backend = subnet == "firewall-backend"
            nic_name = name + ("-eth1" if is_backend else "-eth0")
            nic_id = network + "/networkInterfaces/" + nic_name
            configs, unknown_configs = after.get("ip_configuration"), unknown.get("ip_configuration", [])
            if (after.get("name") != nic_name or after.get("ip_forwarding_enabled") is not forwarding
                    or not _known(unknown.get("ip_forwarding_enabled"))
                    or not _reference(after.get("id"), unknown.get("id"), nic_id, creating)
                    or not isinstance(configs, list) or len(configs) != 1
                    or not isinstance(configs[0], dict) or not isinstance(unknown_configs, list)
                    or len(unknown_configs) not in (0, 1)
                    or (unknown_configs and not isinstance(unknown_configs[0], dict))):
                raise CheckpointPlanError("Invalid Check Point network interface")
            config = configs[0]
            config_unknown = unknown_configs[0] if unknown_configs else {}
            expected_ip = {"firewall-frontend": "172.22.10.4",
                           "firewall-backend": "172.22.20.4", "management": "172.22.30.4"}[subnet]
            if (config.get("name") != ("ipconfig2" if is_backend else "ipconfig1")
                    or not _same_id(config.get("subnet_id"), vnet + "/subnets/" + subnet)
                    or config.get("private_ip_address") != expected_ip
                    or config.get("private_ip_address_allocation") != "Static" or config.get("primary") is not True
                    or not all(_known(config_unknown.get(key)) for key in (
                        "name", "subnet_id", "private_ip_address", "private_ip_address_allocation", "primary"))):
                raise CheckpointPlanError("Invalid Check Point network interface")
            public_id = config.get("public_ip_address_id")
            public_unknown = config_unknown.get("public_ip_address_id")
            if (is_backend and (public_id not in (None, "")
                                or (public_unknown is not None and public_unknown is not False))
                    or not is_backend and not _reference(
                        public_id, public_unknown, network + "/publicIPAddresses/" + name, creating)):
                raise CheckpointPlanError("Invalid Check Point network interface")
        elif kind == "azurerm_network_interface_security_group_association":
            expected_nic = network + "/networkInterfaces/" + name + "-eth0"
            expected_nsg = network + "/networkSecurityGroups/nsg-cp-" + (
                "firewall-" if is_gateway else "management-") + suffix
            if (not _same_id(after.get("network_security_group_id"), expected_nsg)
                    or not _known(unknown.get("network_security_group_id"))
                    or not _reference(after.get("network_interface_id"), unknown.get("network_interface_id"),
                                      expected_nic, creating)
                    or not _reference(after.get("id"), unknown.get("id"),
                                      expected_nic + "|" + expected_nsg, creating)):
                raise CheckpointPlanError("Invalid Check Point network security association")
        elif kind == "azurerm_public_ip":
            if (after.get("name") != name or after.get("sku") != "Standard"
                    or after.get("allocation_method") != "Static"
                    or not _known(unknown.get("sku")) or not _known(unknown.get("allocation_method"))
                    or not _reference(after.get("id"), unknown.get("id"),
                                      network + "/publicIPAddresses/" + name, creating)):
                raise CheckpointPlanError("Invalid Check Point public IP")
        elif kind == "azurerm_virtual_machine":
            sku = "sg-byol" if is_gateway else "mgmt-byol-blink"
            image_version = gateway_image_version if is_gateway else management_image_version
            vm_size = gateway_vm_size if is_gateway else management_vm_size
            image, marketplace = after.get("storage_image_reference"), after.get("plan")
            sensitive = change.get("after_sensitive")
            before_sensitive = change.get("before_sensitive")
            identity, unknown_identity = after.get("identity"), unknown.get("identity", [])
            diagnostics = after.get("boot_diagnostics")
            profile, linux = after.get("os_profile"), after.get("os_profile_linux_config")
            os_disks, unknown_disks = after.get("storage_os_disk"), unknown.get("storage_os_disk", [])
            nic_ids, unknown_nics = after.get("network_interface_ids"), unknown.get("network_interface_ids", [])
            expected_nics = [network + "/networkInterfaces/" + name + "-eth0"]
            if is_gateway:
                expected_nics.append(network + "/networkInterfaces/" + name + "-eth1")
            # Evaluated in order; each label is a constant so the reason never contains plan values.
            checks = (
                ("name", lambda: after.get("name") != name),
                ("size", lambda: after.get("vm_size") != vm_size),
                ("known", lambda: not all(_known(unknown.get(key)) for key in (
                    "vm_size", "storage_image_reference", "plan"))
                    or not _known(unknown.get("os_profile")) or not _known(unknown.get("os_profile_linux_config"))),
                ("zones", lambda: after.get("zones") not in (None, []) or not _known(unknown.get("zones"))),
                ("id", lambda: not _reference(after.get("id"), unknown.get("id"),
                                              compute + "/virtualMachines/" + name, creating)),
                ("image", lambda: not isinstance(image, list) or len(image) != 1 or not isinstance(image[0], dict)
                    or image[0].get("id") not in (None, "")
                    or any(image[0].get(key) != value for key, value in {
                        "publisher": "checkpoint", "offer": "check-point-cg-r82",
                        "sku": sku, "version": image_version}.items())),
                ("plan", lambda: not isinstance(marketplace, list) or len(marketplace) != 1
                    or marketplace[0] != {"name": sku, "product": "check-point-cg-r82", "publisher": "checkpoint"}),
                ("sensitive", lambda: not isinstance(sensitive, dict) or sensitive.get("os_profile") is not True
                    or (not creating and (not isinstance(before_sensitive, dict)
                                          or before_sensitive.get("os_profile") is not True))),
                ("identity", lambda: not isinstance(identity, list) or len(identity) != 1
                    or not isinstance(identity[0], dict)
                    or identity[0].get("type") != "SystemAssigned"
                    or identity[0].get("identity_ids") not in (None, [])
                    or not isinstance(unknown_identity, list) or len(unknown_identity) not in (0, 1)
                    or (unknown_identity and not isinstance(unknown_identity[0], dict))),
                ("diagnostics", lambda: diagnostics != [{"enabled": False, "storage_uri": ""}]
                    or not _known(unknown.get("boot_diagnostics"))),
                ("disk-deletion", lambda: after.get("delete_os_disk_on_termination") is not True
                    or not _known(unknown.get("delete_os_disk_on_termination"))),
                # AzureRM computes data disks when none are configured; existing VMs must report none.
                ("data-disks", lambda: not ((creating and after.get("storage_data_disk") is None
                                             and unknown.get("storage_data_disk") is True)
                                            or (after.get("storage_data_disk") == []
                                                and _known(unknown.get("storage_data_disk"))))),
                ("os-disk", lambda: not isinstance(os_disks, list) or len(os_disks) != 1
                    or not isinstance(os_disks[0], dict)
                    or not isinstance(unknown_disks, list) or len(unknown_disks) not in (0, 1)
                    or (unknown_disks and not isinstance(unknown_disks[0], dict))),
                ("profile", lambda: not isinstance(profile, list) or len(profile) != 1
                    or not isinstance(profile[0], dict)
                    or not isinstance(linux, list) or len(linux) != 1 or not isinstance(linux[0], dict)),
                # A new VM's NIC list is wholly computed; the NIC resources themselves are validated separately.
                ("nics", lambda: not (creating and nic_ids is None and unknown_nics is True)
                    and (not isinstance(nic_ids, list) or len(nic_ids) != len(expected_nics)
                         or not isinstance(unknown_nics, list)
                         or len(unknown_nics) not in (0, len(expected_nics)))),
            )
            for label, failed in checks:
                if failed():
                    raise CheckpointPlanError("Invalid Check Point virtual machine: " + label)
            disk, disk_unknown = os_disks[0], unknown_disks[0] if unknown_disks else {}
            if (disk.get("name") != name or disk.get("create_option") != "FromImage"
                    or disk.get("caching") != "ReadWrite" or disk.get("managed_disk_type") != "StandardSSD_LRS"
                    or type(disk.get("disk_size_gb")) is not int or disk["disk_size_gb"] != 200
                    or not all(_known(disk_unknown.get(key)) for key in
                               ("name", "create_option", "caching", "managed_disk_type", "disk_size_gb"))
                    or not _reference(disk.get("managed_disk_id"), disk_unknown.get("managed_disk_id"),
                                      compute + "/disks/" + name, creating)):
                raise CheckpointPlanError("Invalid Check Point virtual machine disk")
            identity_markers = unknown_identity[0] if unknown_identity else {}
            if (not _known(identity_markers.get("type")) or not _known(identity_markers.get("identity_ids"))
                    or not _reference(identity[0].get("tenant_id"), identity_markers.get("tenant_id"),
                                      provider_tenant, creating)):
                raise CheckpointPlanError("Invalid Check Point virtual machine identity")
            profile_value, linux_value = profile[0], linux[0]
            bootstrap = profile_value.get("custom_data")
            if (profile_value.get("computer_name") != name or profile_value.get("admin_username") != "notused"
                    or not isinstance(bootstrap, str) or not bootstrap.isascii() or len(bootstrap) > 16384):
                raise CheckpointPlanError("Invalid Check Point virtual machine bootstrap")
            if is_gateway:
                marker = f'sicKey="{credentials.sic_key}"'
                keys = linux_value.get("ssh_keys")
                if (profile_value.get("admin_password") != ""
                        or linux_value.get("disable_password_authentication") is not True
                        or not isinstance(keys, list) or len(keys) != 1 or not isinstance(keys[0], dict)
                        or keys[0].get("path") != "/home/notused/.ssh/authorized_keys"
                        or not isinstance(keys[0].get("key_data"), str)):
                    raise CheckpointPlanError("Invalid Check Point gateway authentication")
                try:
                    if validate_checkpoint_public_key(keys[0]["key_data"]) != expected_key:
                        raise ValueError()
                except (ValueError, CheckpointPlanError):
                    raise CheckpointPlanError("Invalid Check Point gateway authentication") from None
                template, bootstrap_hash = GATEWAY_BOOTSTRAP_TEMPLATE, GATEWAY_BOOTSTRAP_SHA256
                rendered = template.replace(_SIC_PLACEHOLDER, marker, 1)
            else:
                # AzureRM cannot read create-only secrets back, so unchanged VMs report them as empty.
                password = profile_value.get("admin_password")
                if (not (_secret_equal(password, credentials.management_password)
                         or (not creating and password == ""))
                        or linux_value.get("disable_password_authentication") is not False
                        or linux_value.get("ssh_keys") != []):
                    raise CheckpointPlanError("Invalid Check Point management authentication")
                template, bootstrap_hash = MANAGEMENT_BOOTSTRAP_TEMPLATE, MANAGEMENT_BOOTSTRAP_SHA256
                rendered = template
            digest = hashlib.sha1(base64.b64encode(rendered.encode("ascii"))).hexdigest()
            if (hashlib.sha256(template.encode("ascii")).hexdigest() != bootstrap_hash
                    or not (_secret_equal(bootstrap, rendered) or _secret_equal(bootstrap, digest)
                            or (not creating and bootstrap == ""))):
                raise CheckpointPlanError("Invalid Check Point virtual machine bootstrap")
            markers = unknown_nics if isinstance(unknown_nics, list) and unknown_nics else [False] * len(expected_nics)
            if isinstance(nic_ids, list) and any(not _reference(value, marker, expected_id, creating)
                   for value, marker, expected_id in zip(nic_ids, markers, expected_nics)):
                raise CheckpointPlanError("Invalid Check Point virtual machine network")
        elif kind == "random_id":
            if (after.get("keepers") != {"resource_group": group_name} or after.get("byte_length") != 8
                    or not _known(unknown.get("keepers")) or not _known(unknown.get("byte_length"))):
                raise CheckpointPlanError("Invalid Check Point plan identity")

    outputs = plan.get("output_changes")
    if not isinstance(outputs, dict) or set(outputs) != (VMSS_OUTPUTS if vmss else OUTPUTS):
        raise CheckpointPlanError("Invalid Check Point plan outputs")
    expected_outputs = {
        "managementPrivateIp": "172.22.30.4",
        "managementVmId": compute + "/virtualMachines/" + management,
    }
    if vmss:
        expected_outputs.update({
            "internalLoadBalancerIp": VMSS_INTERNAL_LB_IP,
            "gatewayScaleSetId": compute + "/virtualMachineScaleSets/cp-vmss-" + suffix,
        })
        public = outputs["publicLoadBalancerIp"]
        public_creating = isinstance(public, dict) and public.get("actions") == ["create"]
        try:
            known_public = (isinstance(public, dict) and public.get("actions") == ["no-op"]
                            and public.get("after_unknown") in (None, False)
                            and ipaddress.IPv4Address(public.get("after")).is_global)
        except (TypeError, ValueError):
            known_public = False
        if (not isinstance(public, dict) or public.get("after_sensitive") is not False
                or not ((public_creating and public.get("after") is None and public.get("after_unknown") is True)
                        or known_public)):
            raise CheckpointPlanError("Invalid Check Point plan outputs")
    else:
        expected_outputs.update({
            "gatewayFrontendPrivateIp": "172.22.10.4",
            "gatewayVmId": compute + "/virtualMachines/" + gateway,
        })
    output_creates = int(vmss and public_creating)
    for key, expected_value in expected_outputs.items():
        output = outputs[key]
        # After a partial apply the VM-id outputs exist as null and update to unknown with the VM create.
        vm_address = {"gatewayVmId": "module.gateway.azurerm_virtual_machine.single_gateway_vm_instance[0]",
                      "gatewayScaleSetId": "module.gateway.azurerm_linux_virtual_machine_scale_set.vmss[0]",
                      "managementVmId": "module.management.azurerm_virtual_machine.mgmt_vm_instance"}.get(key)
        if (isinstance(output, dict) and output.get("actions") == ["update"] and vm_address in created
                and output.get("before") is None and output.get("before_sensitive") is False
                and output.get("after") is None and output.get("after_unknown") is True):
            output = dict(output, actions=["create"])
        if (not isinstance(output, dict) or output.get("actions") not in (["create"], ["no-op"])
                or output.get("after_sensitive") is not False
                or not _reference(output.get("after"), output.get("after_unknown"),
                                  expected_value, output["actions"] == ["create"])
                or (key.endswith("Ip") and output.get("after_unknown") is True)):
            raise CheckpointPlanError("Invalid Check Point plan outputs")
        output_creates += int(output["actions"] == ["create"])
    if type(plan.get("applyable")) is not bool or ((creates or output_creates) and plan["applyable"] is not True):
        raise CheckpointPlanError("Check Point plan is not applyable")
    return CheckpointPlanSummary(
        creates=creates, unchanged=len(resources) - creates, output_creates=output_creates)


def validate_checkpoint_destroy_plan(
        plan: dict, provider_subscription: str, provider_tenant: str, provider_managed_identity_client_id: str,
        group_name: str, environment_id: str, gateway_image_version: str, management_image_version: str,
        gateway_vm_size: str, management_vm_size: str, provider_ssh_public_key: str,
        credentials: CheckpointCredentials, topology: str = "single") -> CheckpointDestroySummary:
    """Validate only the CP Terraform-owned resources, never a resource group or managed application."""
    if topology not in TOPOLOGIES:
        raise CheckpointPlanError("Incomplete or unsupported Check Point destroy plan")
    if not isinstance(plan, dict) or plan.get("applyable") is not True:
        raise CheckpointPlanError("Incomplete or unsupported Check Point destroy plan")
    resources, outputs = plan.get("resource_changes"), plan.get("output_changes")
    if (not isinstance(resources, list) or not isinstance(outputs, dict)
            or any(not isinstance(item, dict) for item in resources)
            or set(outputs) != (VMSS_OUTPUTS if topology == "vmss" else OUTPUTS)):
        raise CheckpointPlanError("Invalid Check Point destroy plan")
    normalized_resources = []
    for item in resources:
        change = item.get("change")
        if (not isinstance(change, dict) or change.get("actions") != ["delete"]
                or not isinstance(change.get("before"), dict) or change.get("after") is not None
                or change.get("importing") is not None or not _known(change.get("after_unknown"))):
            raise CheckpointPlanError("Unsafe Check Point destroy action")
        normalized_resources.append({
            **item, "change": {
                "actions": ["no-op"], "after": change["before"], "after_unknown": {},
                "after_sensitive": change.get("before_sensitive"),
                "before_sensitive": change.get("before_sensitive"),
            },
        })
    normalized_outputs = {}
    for name, output in outputs.items():
        if (not isinstance(output, dict) or output.get("actions") != ["delete"]
                or output.get("after") is not None or output.get("before_sensitive") is not False
                or not _known(output.get("after_unknown"))):
            raise CheckpointPlanError("Invalid Check Point destroy outputs")
        normalized_outputs[name] = {
            "actions": ["no-op"], "after": output.get("before"),
            "after_unknown": False, "after_sensitive": False,
        }
    normalized = {**plan, "resource_changes": normalized_resources, "output_changes": normalized_outputs}
    summary = validate_checkpoint_plan(
        normalized, provider_subscription, provider_tenant, provider_managed_identity_client_id,
        group_name, environment_id, gateway_image_version, management_image_version,
        gateway_vm_size, management_vm_size, provider_ssh_public_key, credentials, topology)
    if (summary.creates != 0
            or summary.unchanged != len(VMSS_EXPECTED if topology == "vmss" else EXPECTED)
            or summary.output_creates != 0):
        raise CheckpointPlanError("Invalid Check Point destroy plan")
    return CheckpointDestroySummary(deletes=len(resources), output_deletes=len(outputs))
