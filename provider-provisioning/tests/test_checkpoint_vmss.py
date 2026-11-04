import base64
import copy
import hashlib
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare_checkpoint_modules as modules
import probe_checkpoint_modules as probe
import test_checkpoint_gaia as gaia_tests
import test_checkpoint_modules as single
from service import checkpoint_dependencies, checkpoint_gaia as gaia, checkpoint_plan, checkpoint_scale_set as scale_set
from service.checkpoint_plan import (
    VMSS_BOOTSTRAP_TEMPLATE, VMSS_EXPECTED, CheckpointPlanError, validate_checkpoint_destroy_plan,
    validate_checkpoint_plan,
)

SCOPE = probe.SCOPE
GROUP_ID = f"/subscriptions/{probe.SUBSCRIPTION}/resourceGroups/{probe.GROUP}"
VNET = f"{SCOPE}/virtualNetworks/vnet-cp-security-00000000"
APP = "cp-vmss-00000000-app-1"


@pytest.fixture
def upstream_vmss(upstream, monkeypatch):
    source, local = upstream
    directory = source / "modules" / "vmss"
    directory.mkdir(parents=True)
    original = b'terraform { required_version = ">= 1.9" }\nprovider "azapi" {}\nprovider "azurerm" {}\n'
    (directory / "versions.tf").write_bytes(original)
    (directory / "main.tf").write_text('module "common" { source = "../common/common" }\n')
    single.git(source, "add", ".")
    single.git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com", "commit", "-qm", "vmss")
    monkeypatch.setattr(modules, "UPSTREAM_COMMIT", single.git(source, "rev-parse", "HEAD"))
    monkeypatch.setattr(modules, "UPSTREAM_TREE", single.git(source, "rev-parse", "HEAD^{tree}"))
    monkeypatch.setattr(modules, "VMSS_VERSION_FILES", {
        "management": modules.VERSION_FILES["management"], "vmss": hashlib.sha256(original).hexdigest()})
    return source, local


upstream = single.upstream


def test_vmss_preparation_uses_vmss_root_and_fixed_capacity_override(upstream_vmss):
    source, local = upstream_vmss
    output = local / "prepared-vmss"
    modules.prepare(source, output, "vmss")

    assert not (output / "modules/single-gateway").exists()
    assert (output / "main.tf").read_text() == (ROOT / "infra/checkpoint-vmss/main.tf").read_text()
    assert (output / "variables.tf").read_bytes() == (ROOT / "infra/checkpoint/variables.tf").read_bytes()
    assert (output / ".terraform.lock.hcl").read_bytes() == (ROOT / "infra/checkpoint/.terraform.lock.hcl").read_bytes()
    override = (output / "modules/vmss/faas_override.tf").read_text()
    assert 'resource "azurerm_monitor_autoscale_setting" "vmss_settings"' in override and "count = 0" in override
    assert 'vmss_principal_id = ""' in override and "ignore_changes = [ip_tags]" in override
    assert (output / "modules/management/faas_override.tf").read_text() == modules.OVERRIDE
    assert "vmss versions.tf" in (output / "FAAS-UPSTREAM-NOTICE.txt").read_text()


def test_preparation_rejects_unknown_topology(upstream_vmss):
    source, local = upstream_vmss
    with pytest.raises(modules.PreparationError, match="topology"):
        modules.prepare(source, local / "other", "ha")
    assert not (local / "other").exists()


def test_vmss_root_pins_paygo_two_instance_standard_load_balancers():
    main = (ROOT / "infra/checkpoint-vmss/main.tf").read_text()
    for line in ('vm_os_sku                       = "sg-ngtp"', 'deployment_mode                 = "Standard"',
                 'number_of_vm_instances          = "2"', 'minimum_number_of_vm_instances  = "2"',
                 'maximum_number_of_vm_instances  = "2"', "backend_lb_IP_address           = 4",
                 "enable_custom_metrics           = false", 'storage_account_deployment_mode = "None"'):
        assert line in main


def test_dependency_pins_are_topology_specific():
    assert checkpoint_dependencies.VMSS_EXPECTED_MODULES["gateway"] == ("./modules/vmss", "modules/vmss")
    assert checkpoint_dependencies.EXPECTED_MODULES["gateway"] == ("./modules/single-gateway", "modules/single-gateway")
    assert checkpoint_dependencies.VMSS_ARTIFACT_SHA256 != checkpoint_dependencies.ARTIFACT_SHA256
    with pytest.raises(checkpoint_dependencies.CheckpointDependencyError, match="topology"):
        checkpoint_dependencies.verify_checkpoint_artifact(ROOT, "ha")


def _resource(address, kind, after, unknown, sensitive=None):
    change = {"actions": ["create"], "after": after, "after_unknown": unknown}
    if sensitive is not None:
        change["after_sensitive"] = sensitive
    provider = ("registry.terraform.io/hashicorp/random" if kind == "random_id"
                else "registry.terraform.io/hashicorp/azurerm")
    return {"address": address, "mode": "managed", "type": kind, "provider_name": provider, "change": change}


def vmss_plan():
    base = {"resource_group_name": probe.GROUP, "location": "eastus2", "zones": None}
    gateway = "module.gateway."
    bootstrap = VMSS_BOOTSTRAP_TEMPLATE.replace(
        'sicKey="<REDACTED>"', f'sicKey="{probe.FIXTURE_CREDENTIALS.sic_key}"')
    nic = lambda backend: {  # noqa: E731
        "name": "eth1" if backend else "eth0", "primary": not backend, "enable_ip_forwarding": True,
        "network_security_group_id": None,
        "ip_configuration": [{
            "name": "ipconfig2" if backend else "ipconfig1", "primary": True,
            "subnet_id": f"{VNET}/subnets/" + ("firewall-backend" if backend else "firewall-frontend"),
            "load_balancer_backend_address_pool_ids": [None],
            "public_ip_address": [] if backend else [
                {"name": "cp-vmss-00000000-public-ip", "public_ip_prefix_id": None}],
        }],
    }
    nic_unknown = {"ip_configuration": [{"load_balancer_backend_address_pool_ids": [True]}]}
    resources = [
        _resource(gateway + "azurerm_lb.backend_lb[0]", "azurerm_lb", {**base, "name": "backend-lb", "sku": "Standard",
            "frontend_ip_configuration": [{"name": "backend-lb", "private_ip_address": "172.22.20.4",
                                           "private_ip_address_allocation": "Static", "public_ip_address_id": None,
                                           "subnet_id": f"{VNET}/subnets/firewall-backend"}]},
            {"id": True, "frontend_ip_configuration": [{"id": True}]}),
        _resource(gateway + "azurerm_lb.frontend_lb[0]", "azurerm_lb", {**base, "name": "frontend-lb", "sku": "Standard",
            "frontend_ip_configuration": [{"name": APP, "subnet_id": None}]},
            {"id": True, "frontend_ip_configuration": [{"public_ip_address_id": True}]}),
        _resource(gateway + "azurerm_lb_backend_address_pool.backend_lb_pool[0]", "azurerm_lb_backend_address_pool",
                  {"name": "backend-lb-pool", "virtual_network_id": None, "tunnel_interface": []},
                  {"id": True, "loadbalancer_id": True}),
        _resource(gateway + "azurerm_lb_backend_address_pool.frontend_lb_pool[0]", "azurerm_lb_backend_address_pool",
                  {"name": APP, "virtual_network_id": None, "tunnel_interface": []},
                  {"id": True, "loadbalancer_id": True}),
    ]
    for index, name in enumerate((APP, "backend-lb")):
        resources.append(_resource(f"{gateway}azurerm_lb_probe.azure_lb_healprob[{index}]", "azurerm_lb_probe",
            {"name": name, "protocol": "Tcp", "port": 8117, "interval_in_seconds": 5, "number_of_probes": 2,
             "request_path": None}, {"id": True, "loadbalancer_id": True}))
        resources.append(_resource(f"{gateway}azurerm_lb_rule.lbnatrule_standard[{index}]", "azurerm_lb_rule",
            {"name": name, "frontend_ip_configuration_name": name, "protocol": "Tcp" if index == 0 else "All",
             "frontend_port": 80 if index == 0 else 0, "backend_port": 80 if index == 0 else 0,
             "floating_ip_enabled": True, "disable_outbound_snat": None, "backend_address_pool_ids": [None]},
            {"id": True, "loadbalancer_id": True, "probe_id": True, "backend_address_pool_ids": [True]}))
    resources += [
        _resource(gateway + "azurerm_public_ip.public_ip_lb[0]", "azurerm_public_ip",
                  {**base, "name": APP, "sku": "Standard", "allocation_method": "Static"}, {"id": True}),
        _resource(gateway + "random_id.random_id", "random_id",
                  {"byte_length": 13, "keepers": {"rg_id": GROUP_ID}}, {"id": True}),
        _resource(gateway + "azurerm_linux_virtual_machine_scale_set.vmss[0]",
                  "azurerm_linux_virtual_machine_scale_set", {
                      **base, "name": "cp-vmss-00000000", "computer_name_prefix": "cp-vmss-00000000",
                      "sku": "Standard_D4ds_v5", "instances": 2, "overprovision": False, "upgrade_mode": "Manual",
                      "source_image_id": None, "identity": [], "extension": [], "data_disk": [],
                      "source_image_reference": [{"publisher": "checkpoint", "offer": "check-point-cg-r82",
                                                  "sku": "sg-ngtp", "version": "1.2.3"}],
                      "plan": [{"name": "sg-ngtp", "product": "check-point-cg-r82", "publisher": "checkpoint"}],
                      "boot_diagnostics": [{"storage_account_uri": ""}],
                      "os_disk": [{"caching": "ReadWrite", "storage_account_type": "StandardSSD_LRS",
                                   "disk_size_gb": 100}],
                      "admin_username": "notused", "disable_password_authentication": True,
                      "admin_ssh_key": [{"username": "notused",
                                         "public_key": probe.FIXTURE_VARIABLES["provider_admin_ssh_public_key"]}],
                      "custom_data": base64.b64encode(bootstrap.encode()).decode(),
                      "network_interface": [nic(False), nic(True)],
                      "tags": {"LegacyVMNVA": "", "x-chkp-anti-spoofing": "eth0:false,eth1:false",
                               "x-chkp-ip-address": "private", "x-chkp-ip-version": "ipv4-only",
                               "x-chkp-management": "cp-management-00000000",
                               "x-chkp-management-address": "172.22.30.4", "x-chkp-management-interface": "eth0",
                               "x-chkp-orchestration-mode": "Uniform", "x-chkp-srcImageUri": "noCustomUri",
                               "x-chkp-template": "faas-vmss-00000000",
                               "x-chkp-topology": "eth0:external,eth1:internal"},
                  }, {"id": True, "admin_password": True, "network_interface": [nic_unknown, nic_unknown]},
                  {"custom_data": True, "admin_password": True}),
    ]
    management = [item for item in single.fixture_plan()["resource_changes"]
                  if item["address"].startswith("module.management.")]
    values = {"managementPrivateIp": "172.22.30.4", "internalLoadBalancerIp": "172.22.20.4",
              "managementVmId": None, "gatewayScaleSetId": None, "publicLoadBalancerIp": None}
    outputs = {key: {"actions": ["create"], "after": value, "after_unknown": value is None, "after_sensitive": False}
               for key, value in values.items()}
    return {"format_version": "1.2", "terraform_version": "1.15.7", "complete": True, "errored": False,
            "applyable": True, "variables": {name: {"value": value} for name, value in probe.FIXTURE_VARIABLES.items()},
            "resource_changes": management + resources, "output_changes": outputs}


def validate(plan, topology="vmss"):
    return validate_checkpoint_plan(
        plan, probe.SUBSCRIPTION, probe.FIXTURE_VARIABLES["provider_tenant_id"],
        probe.FIXTURE_VARIABLES["provider_managed_identity_client_id"], probe.GROUP,
        probe.FIXTURE_VARIABLES["environment_id"], "1.2.3", "1.2.3", "Standard_D4ds_v5", "Standard_D4ds_v5",
        probe.FIXTURE_VARIABLES["provider_admin_ssh_public_key"], probe.FIXTURE_CREDENTIALS, topology=topology)


def _find(plan, suffix):
    return next(item for item in plan["resource_changes"] if item["address"].endswith(suffix))


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_vmss_plan_guard_accepts_the_expected_create_plan():
    summary = validate(vmss_plan())
    assert summary.creates == len(VMSS_EXPECTED) == 16 and summary.output_creates == 5


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_topologies_do_not_accept_each_others_plans():
    with pytest.raises(CheckpointPlanError, match="Unexpected Check Point plan resources"):
        validate(vmss_plan(), "single")
    with pytest.raises(CheckpointPlanError, match="Unexpected Check Point plan resources"):
        validate(single.live_fixture_plan())
    with pytest.raises(CheckpointPlanError):
        validate(vmss_plan(), "ha")


@pytest.mark.usefixtures("plan_bootstrap_pins")
@pytest.mark.parametrize("path, value, reason", [
    (("vmss[0]", "instances"), 3, "scale set"),
    (("vmss[0]", "sku"), "Standard_D2s_v5", "scale set"),
    (("vmss[0]", "plan"), [{"name": "sg-byol", "product": "check-point-cg-r82", "publisher": "checkpoint"}],
     "scale set"),
    (("vmss[0]", "identity"), [{"type": "SystemAssigned"}], "scale set"),
    (("vmss[0]", "custom_data"), base64.b64encode(b"other").decode(), "bootstrap"),
    (("vmss[0]", "network_interface", 0, "ip_configuration", 0, "subnet_id"), f"{VNET}/subnets/management",
     "network"),
    (("vmss[0]", "network_interface", 1, "ip_configuration", 0, "public_ip_address"), [{"name": "x"}], "network"),
    (("vmss[0]", "tags"), {}, "tags"),
    (("backend_lb[0]", "frontend_ip_configuration", 0, "private_ip_address"), "172.22.20.9", "frontend"),
    (("standard[1]", "protocol"), "Tcp", "rule"),
    (("standard[1]", "disable_outbound_snat"), True, "rule"),
    (("healprob[1]", "port"), 22, "probe"),
    (("public_ip_lb[0]", "sku"), "Basic", "public IP"),
])
def test_vmss_plan_guard_rejects_unsafe_changes(path, value, reason):
    plan = vmss_plan()
    target = _find(plan, path[0])["change"]["after"]
    for key in path[1:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(CheckpointPlanError, match=reason):
        validate(plan)


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_vmss_plan_guard_rejects_other_ssh_key_and_wrong_ilb_output():
    plan = vmss_plan()
    other = probe.Ed25519PublicKey.from_public_bytes(bytes(range(1, 33))).public_bytes(
        probe.Encoding.OpenSSH, probe.PublicFormat.OpenSSH).decode()
    _find(plan, "vmss[0]")["change"]["after"]["admin_ssh_key"][0]["public_key"] = other
    with pytest.raises(CheckpointPlanError, match="authentication"):
        validate(plan)
    plan = vmss_plan()
    plan["output_changes"]["internalLoadBalancerIp"]["after"] = "172.22.20.5"
    with pytest.raises(CheckpointPlanError, match="outputs"):
        validate(plan)


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_vmss_plan_guard_accepts_noop_with_known_public_ip_and_destroy():
    plan = vmss_plan()
    for item in plan["resource_changes"]:
        change = item["change"]
        change["actions"], change["before"] = ["no-op"], copy.deepcopy(change["after"])
        change["after_unknown"] = {}
    values = {"managementVmId": f"{GROUP_ID}/providers/Microsoft.Compute/virtualMachines/cp-management-00000000",
              "gatewayScaleSetId": f"{GROUP_ID}/providers/Microsoft.Compute/virtualMachineScaleSets/cp-vmss-00000000",
              "publicLoadBalancerIp": "8.8.8.8"}
    _ids(plan)
    for key, item in plan["output_changes"].items():
        item.update(actions=["no-op"], after=values.get(key, item["after"]), after_unknown=False)
    summary = validate(plan)
    assert summary.creates == 0 and not summary.needs_apply
    plan["output_changes"]["publicLoadBalancerIp"]["after"] = "10.0.0.1"
    with pytest.raises(CheckpointPlanError, match="outputs"):
        validate(plan)


def _ids(plan):
    network, compute = GROUP_ID + "/providers/Microsoft.Network", GROUP_ID + "/providers/Microsoft.Compute"
    backend, frontend = network + "/loadBalancers/backend-lb", network + "/loadBalancers/frontend-lb"
    pools = {"backend": backend + "/backendAddressPools/backend-lb-pool",
             "frontend": frontend + "/backendAddressPools/" + APP}
    ids = {
        "backend_lb[0]": backend, "frontend_lb[0]": frontend,
        "backend_lb_pool[0]": pools["backend"], "frontend_lb_pool[0]": pools["frontend"],
        "healprob[0]": frontend + "/probes/" + APP, "healprob[1]": backend + "/probes/backend-lb",
        "public_ip_lb[0]": network + "/publicIPAddresses/" + APP,
        "vmss[0]": compute + "/virtualMachineScaleSets/cp-vmss-00000000",
    }
    for suffix, value in ids.items():
        after = _find(plan, suffix)["change"]["after"]
        after["id"] = value
        if "pool" in suffix or "healprob" in suffix:
            after["loadbalancer_id"] = backend if "backend" in suffix or suffix == "healprob[1]" else frontend
    _find(plan, "frontend_lb[0]")["change"]["after"]["frontend_ip_configuration"][0]["public_ip_address_id"] = \
        ids["public_ip_lb[0]"]
    for index, side in enumerate(("frontend", "backend")):
        rule = _find(plan, f"standard[{index}]")["change"]["after"]
        rule.update(loadbalancer_id=backend if index else frontend, backend_address_pool_ids=[pools[side]],
                    probe_id=ids[f"healprob[{index}]"])
        nic = _find(plan, "vmss[0]")["change"]["after"]["network_interface"][index]
        nic["ip_configuration"][0]["load_balancer_backend_address_pool_ids"] = [pools[side]]
    for item in plan["resource_changes"]:
        if item["address"].startswith("module.management."):
            single_ids = single.noop_fixture_plan()["resource_changes"]
            match = next(other for other in single_ids if other["address"] == item["address"])
            item["change"] = copy.deepcopy(match["change"])


@pytest.mark.usefixtures("plan_bootstrap_pins")
def test_vmss_destroy_guard_requires_the_full_vmss_resource_set():
    plan = vmss_plan()
    _ids(plan)
    resources = []
    for item in plan["resource_changes"]:
        before = item["change"]["after"]
        resources.append({**item, "change": {"actions": ["delete"], "before": before, "after": None,
                                             "after_unknown": {}, "before_sensitive": item["change"].get(
                                                 "after_sensitive", {})}})
    values = {"managementPrivateIp": "172.22.30.4", "internalLoadBalancerIp": "172.22.20.4",
              "managementVmId": f"{GROUP_ID}/providers/Microsoft.Compute/virtualMachines/cp-management-00000000",
              "gatewayScaleSetId": f"{GROUP_ID}/providers/Microsoft.Compute/virtualMachineScaleSets/cp-vmss-00000000",
              "publicLoadBalancerIp": "8.8.8.8"}
    destroy = {**plan, "resource_changes": resources, "output_changes": {
        key: {"actions": ["delete"], "before": value, "after": None, "after_unknown": False,
              "before_sensitive": False} for key, value in values.items()}}
    summary = validate_checkpoint_destroy_plan(
        destroy, probe.SUBSCRIPTION, probe.FIXTURE_VARIABLES["provider_tenant_id"],
        probe.FIXTURE_VARIABLES["provider_managed_identity_client_id"], probe.GROUP,
        probe.FIXTURE_VARIABLES["environment_id"], "1.2.3", "1.2.3", "Standard_D4ds_v5", "Standard_D4ds_v5",
        probe.FIXTURE_VARIABLES["provider_admin_ssh_public_key"], probe.FIXTURE_CREDENTIALS, topology="vmss")
    assert summary.deletes == 16
    destroy["resource_changes"] = destroy["resource_changes"][1:]
    with pytest.raises(CheckpointPlanError):
        validate_checkpoint_destroy_plan(
            destroy, probe.SUBSCRIPTION, probe.FIXTURE_VARIABLES["provider_tenant_id"],
            probe.FIXTURE_VARIABLES["provider_managed_identity_client_id"], probe.GROUP,
            probe.FIXTURE_VARIABLES["environment_id"], "1.2.3", "1.2.3", "Standard_D4ds_v5", "Standard_D4ds_v5",
            probe.FIXTURE_VARIABLES["provider_admin_ssh_public_key"], probe.FIXTURE_CREDENTIALS, topology="vmss")


plan_bootstrap_pins = single.plan_bootstrap_pins


def test_foundation_outputs_must_match_the_requested_topology():
    import test_checkpoint_foundation as foundation_fixture
    from service.checkpoint_foundation import validate_checkpoint_foundation

    def run(value, topology):
        return validate_checkpoint_foundation(value, foundation_fixture.SUBSCRIPTION, foundation_fixture.GROUP,
                                              foundation_fixture.ENVIRONMENT, topology)

    legacy = foundation_fixture.outputs()
    assert run(legacy, "single").firewall_topology == "single"
    with pytest.raises(ValueError):
        run(legacy, "vmss")
    marked = foundation_fixture.outputs()
    marked["checkpointFoundation"]["value"]["firewallTopology"] = "vmss"
    assert run(marked, "vmss").firewall_topology == "vmss"
    with pytest.raises(ValueError):
        run(marked, "single")
    with pytest.raises(ValueError):
        run(marked, "ha")


def test_foundation_template_requires_exact_vmss_probe_rule_and_single_default():
    import json
    import subprocess
    from service.templates import Templates

    result = subprocess.run(["az", "bicep", "build", "--file",
                             str(ROOT / "infra/provider-checkpoint-foundation.bicep"), "--stdout"],
                            capture_output=True, text=True, check=False)
    if result.returncode:
        pytest.skip("Bicep CLI unavailable")
    template = json.loads(result.stdout)
    Templates.validate_checkpoint_foundation(copy.deepcopy(template))
    probe_rule = next(item for item in template["resources"]
                      if item["type"].endswith("/securityRules") and "copy" not in item)
    for key, value in (("sourceAddressPrefix", "*"), ("priority", 4000)):
        tampered = copy.deepcopy(template)
        next(item for item in tampered["resources"] if item.get("name") == probe_rule["name"])[
            "properties"][key] = value
        with pytest.raises(ValueError):
            Templates.validate_checkpoint_foundation(tampered)
    tampered = copy.deepcopy(template)
    tampered["parameters"]["firewallTopology"]["defaultValue"] = "vmss"
    with pytest.raises(ValueError, match="single gateway"):
        Templates.validate_checkpoint_foundation(tampered)


GATEWAYS = [gaia.CheckpointGateway("cp-vmss-00000000-0", "172.22.10.4", "172.22.20.5"),
            gaia.CheckpointGateway("cp-vmss-00000000-1", "172.22.10.5", "172.22.20.6")]


class ScaleSetApi(gaia_tests.FakeApi):
    """Track gateway objects by name so each scale set member is created and configured separately."""

    def __init__(self):
        super().__init__([])
        self.gateways, self.script_targets = set(), []

    def call(self, command, body, allowed=()):
        if command == "run-script":
            self.script_targets.append((body["script-name"], tuple(body["targets"])))
        if command == "show-simple-gateway":
            self.calls.append((command, body.get("name")))
            self.requests.append((command, body))
            if body["name"] not in self.gateways:
                return {"code": "generic_err_object_not_found"}
            return {"sic-state": "communicating", "logs-settings": {"send-logs-to-server": list(self.log_servers)}}
        if command == "add-simple-gateway":
            self.gateways.add(body["name"])
        return super().call(command, body, allowed)


def scale_set_configurator(api, logs):
    return gaia.CheckpointConfigurator(api, "00000000-0000-0000-0000-000000000004", "s" * 48, "P" * 16,
                                       gaia_tests.PEERS, 65515, logs.append, sleep=lambda _seconds: None,
                                       gateways=GATEWAYS, internal_load_balancer_ip="172.22.20.4")


def test_bgp_script_for_scale_set_sets_internal_load_balancer_next_hop_without_redistribution():
    script = gaia.bgp_script(gaia_tests.PEERS, 65515, "172.22.10.5", "172.22.20.4")
    assert "set router-id 172.22.10.5" in script
    assert "set routemap faas-out id 10 action nexthop ip 172.22.20.4" in script
    assert "export-routemap faas-out" in script and "match network 0.0.0.0/0 exact" in script
    assert "route-redistribution" not in script and "nat" not in script.lower()
    assert gaia.bgp_script(gaia_tests.PEERS, 65515) == gaia.bgp_script(gaia_tests.PEERS, 65515, "172.22.10.4")
    with pytest.raises(gaia.CheckpointGaiaError):
        gaia.bgp_script(gaia_tests.PEERS, 65515, "172.22.10.5", "8.8.8.8")


def test_scale_set_configurator_registers_each_member_and_targets_all():
    api, logs = ScaleSetApi(), []
    status = scale_set_configurator(api, logs).run()
    assert status == gaia.BgpStatus(4, 4)
    adds = [body for command, body in api.requests if command == "add-simple-gateway"]
    assert [body["name"] for body in adds] == [item.name for item in GATEWAYS]
    assert [body["ip-address"] for body in adds] == ["172.22.10.4", "172.22.10.5"]
    assert all(not interface["anti-spoofing"] for body in adds for interface in body["interfaces"])
    install = next(body for command, body in api.requests if command == "install-policy")
    assert install["targets"] == [item.name for item in GATEWAYS]
    rules = {body["name"]: body for command, body in api.requests if command == "add-access-rule"}
    assert rules[gaia.EAST_WEST_RULE]["install-on"] == [item.name for item in GATEWAYS]
    probe_rule = rules[gaia.HEALTH_PROBE_RULE]
    assert probe_rule["source"] == [gaia.AZURE_PROBE_HOST] and probe_rule["service"] == [gaia.AZURE_PROBE_SERVICE]
    hosts = [body for command, body in api.requests if command == "add-host"]
    assert hosts == [{"name": gaia.AZURE_PROBE_HOST, "ip-address": "168.63.129.16"}]
    networks = [body for command, body in api.requests if command == "add-network"]
    assert all(body["nat-settings"]["install-on"] == "All" for body in networks)
    for script in ("faas-bgp", "faas-bgp-status", "faas-management-route"):
        assert {targets for name, targets in api.script_targets if name == script} == {
            (item.name,) for item in GATEWAYS}


def test_single_gateway_configurator_rejects_unexpected_gateway_sets():
    with pytest.raises(gaia.CheckpointGaiaError):
        gaia.CheckpointConfigurator(ScaleSetApi(), "00000000-0000-0000-0000-000000000004", "s" * 48, "P" * 16,
                                    gaia_tests.PEERS, 65515, print, gateways=GATEWAYS)
    with pytest.raises(gaia.CheckpointGaiaError):
        gaia.CheckpointConfigurator(ScaleSetApi(), "00000000-0000-0000-0000-000000000004", "s" * 48, "P" * 16,
                                    gaia_tests.PEERS, 65515, print, gateways=GATEWAYS[:1],
                                    internal_load_balancer_ip="172.22.20.4")


def interfaces_document(addresses=(("0", "172.22.10.4", "172.22.20.5"), ("1", "172.22.10.5", "172.22.20.6"))):
    scale_set = f"{GROUP_ID}/providers/Microsoft.Compute/virtualMachineScaleSets/cp-vmss-00000000"
    value = []
    for instance, front, back in addresses:
        for name, address, subnet in (("eth0", front, "firewall-frontend"), ("eth1", back, "firewall-backend")):
            value.append({"id": f"{scale_set}/virtualMachines/{instance}/networkInterfaces/{name}",
                          "properties": {"primary": name == "eth0", "ipConfigurations": [{"properties": {
                              "privateIPAddress": address, "subnet": {"id": f"{VNET}/subnets/{subnet}"}}}]}})
    return {"value": value}


def test_scale_set_discovery_requires_two_members_on_route_server_peer_addresses():
    gateways = scale_set.parse_scale_set_gateways(interfaces_document(), GROUP_ID,
                                                  probe.FIXTURE_VARIABLES["environment_id"])
    assert gateways == GATEWAYS
    bad = [interfaces_document((("0", "172.22.10.4", "172.22.20.5"),)),
           interfaces_document((("0", "172.22.10.4", "172.22.20.5"), ("1", "172.22.10.6", "172.22.20.6"))),
           interfaces_document((("0", "172.22.10.4", "172.22.20.4"), ("1", "172.22.10.5", "172.22.20.6"))),
           {**interfaces_document(), "nextLink": "https://management.azure.com/next"}]
    swapped = interfaces_document()
    swapped["value"][1]["properties"]["ipConfigurations"][0]["properties"]["subnet"]["id"] = \
        f"{VNET}/subnets/firewall-frontend"
    other = interfaces_document()
    other["value"][0]["id"] = other["value"][0]["id"].replace("cp-vmss-00000000", "cp-vmss-ffffffff")
    for document in (*bad, swapped, other):
        with pytest.raises(gaia.CheckpointGaiaError):
            scale_set.parse_scale_set_gateways(document, GROUP_ID, probe.FIXTURE_VARIABLES["environment_id"])


def test_runner_config_schema4_selects_vmss_and_keeps_single_unchanged():
    import json
    from service.checkpoint_runner_config import CheckpointRunnerConfigError, load_checkpoint_runner_config

    single_config = single.fixture_runner_inputs().config
    assert single_config.firewallTopology == "single" and single_config.schemaVersion == 1
    value = single_config.model_dump()
    value.update(schemaVersion=4, firewallTopology="vmss")
    environment = {"FAAS_CONFIG": json.dumps(value), "FAAS_RUNNER_CLIENT_ID": value["runnerClientId"]}
    assert load_checkpoint_runner_config(environment).firewallTopology == "vmss"
    for update in ({"schemaVersion": 1}, {"firewallTopology": "single"}, {"firewallTopology": "ha"}):
        environment["FAAS_CONFIG"] = json.dumps({**value, **update})
        with pytest.raises(CheckpointRunnerConfigError):
            load_checkpoint_runner_config(environment)
