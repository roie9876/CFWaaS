"""Offline public-admin contracts. The addresses below are examples, not operator defaults."""
import base64
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock, patch

import pytest

from service.admin_access import normalize_admin_sources
from service import checkpoint_gaia as gaia
from service.models import EnvironmentRequest, parse_stored_environment_request, stored_environment_request
from service.profiles import ProfilePublisher
from service.management import ManagementSettings
from service.templates import Templates
from test_checkpoint_gaia import FakeApi, PEERS
from test_management import binding, CLIENT, TENANT

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import customer_connector
from common import compile_bicep


@pytest.mark.parametrize("value", [
    None, "", "8.8.8.8", [None], [8], [""], ["8.8.8.8;true"], ["8.8.8.8\ntrue"],
    ["0.0.0.0/0"], ["::1"], ["2001:4860:4860::8888"], ["10.0.0.1"], ["172.16.0.0/12"],
    ["192.168.1.1"], ["100.64.0.0"], ["169.254.169.254"], ["127.0.0.1"], ["224.0.0.0"],
    ["240.0.0.0"], ["192.0.2.1"], ["198.51.100.0/24"], ["203.0.113.1"], ["198.18.0.0"],
    [str(ipaddress.IPv4Network((2**31, 2)))], ["8.8.8.8/24"],
    ["8.8.8.8/255.255.255.255"], ["8.8.8.8"] * 17,
])
def test_invalid_sources_fail_in_api_and_standalone_connector(value):
    for validate in (normalize_admin_sources, customer_connector.admin_sources):
        with pytest.raises(ValueError):
            validate(value)
    with pytest.raises(ValueError):
        EnvironmentRequest(firewallType="checkpoint-byol", adminAllowedSources=value)


def test_normalization_and_persistence_are_deterministic_without_mutating_input():
    raw = ["8.8.8.8", " 1.1.1.0/24 ", "8.8.8.8/32"]
    expected = ["1.1.1.0/24", "8.8.8.8/32"]
    assert normalize_admin_sources(raw) == customer_connector.admin_sources(raw) == expected
    request = EnvironmentRequest(firewallType="checkpoint-byol", adminAllowedSources=raw)
    stored = stored_environment_request(request, False)
    restored, parallel, isolated = parse_stored_environment_request(stored)
    assert restored.adminAllowedSources == expected and not parallel and not isolated
    assert request.digest() == restored.digest()
    assert raw[0] == "8.8.8.8"
    assert len(normalize_admin_sources([f"8.8.8.{i}" for i in range(1, 17)])) == 16


def test_empty_list_preserves_exact_legacy_ubuntu_and_checkpoint_digests():
    for firewall in ("ubuntu", "checkpoint-byol"):
        legacy = {"region": "eastus2", "tier": "lab", "mode": "proof",
                  "customerIngress": None, "customerDelivery": None}
        if firewall != "ubuntu":
            legacy["firewallType"] = firewall
        canonical = json.dumps(legacy, sort_keys=True, separators=(",", ":"))
        for value in ({}, {"adminAllowedSources": []}):
            request = EnvironmentRequest(firewallType=firewall, **value)
            assert request.canonical() == canonical
            assert request.digest() == hashlib.sha256(canonical.encode()).hexdigest()
            assert "adminAllowedSources" not in request.stored_fields()
    with pytest.raises(ValueError, match="require Check Point"):
        EnvironmentRequest(adminAllowedSources=["8.8.8.8"])


def test_connector_proof_validates_before_network_and_network_propagates_only_explicit_sources():
    endpoints = {"customerIngress": {"publicIp": "8.8.8.8", "bgpAddress": "172.18.255.30", "asn": 65020},
                 "customerDelivery": {"publicIp": "1.1.1.1", "bgpAddress": "172.19.255.30", "asn": 65021}}
    old = customer_connector.request_body("network", endpoints)
    assert old == customer_connector.request_body("network", endpoints, "ubuntu", [])
    assert "adminAllowedSources" not in old and "firewallType" not in old
    request = customer_connector.request_body("network", endpoints, "checkpoint-byol", ["8.8.8.8"])
    assert request["adminAllowedSources"] == ["8.8.8.8/32"]
    assert EnvironmentRequest.model_validate(request).adminAllowedSources == ["8.8.8.8/32"]
    with pytest.raises(ValueError):
        customer_connector.request_body("proof", None, "checkpoint-byol", ["10.0.0.1"])
    with pytest.raises(ValueError):
        customer_connector.request_body("proof", None, "ubuntu", ["8.8.8.8"])


class AdminApi(FakeApi):
    def __init__(self):
        super().__init__(["communicating"])
        self.saved = {}
        self.rules[-1]["action"] = {"name": "Drop"}

    def call(self, command, body, allowed=()):
        if command == "run-script" and body["script-name"] == "faas-admin-clients":
            self.requests.append((command, body))
            return {"tasks": [{"task-id": "admin"}]}
        if command.startswith("show-") and body.get("name") in self.saved:
            return copy.deepcopy(self.saved[body["name"]])
        if command.startswith("add-") and (body.get("name", "").startswith("faas-admin")
                                           or body.get("name") == gaia.ADMIN_RULE):
            saved = copy.deepcopy(body)
            if command == "add-access-rule":
                saved.update(enabled=True, **{key: False for key in
                                              ("source-negate", "destination-negate", "service-negate")})
            self.saved[body["name"]] = saved
        return super().call(command, body, allowed)

    def wait_task(self, task_id, deadline, sleep=None):
        if task_id == "admin":
            return {"task-details": [{"responseMessage": base64.b64encode(
                b"faas-admin-clients-configured\n").decode()}]}
        return super().wait_task(task_id, deadline, sleep)


def configurator(api, sources):
    return gaia.CheckpointConfigurator(api, "00000000-0000-0000-0000-000000000004",
                                      "s" * 48, "P" * 16, PEERS, 65515, lambda _: None,
                                      sleep=lambda _: None, admin_allowed_sources=sources)


def test_admin_policy_is_bounded_additive_idempotent_and_keeps_private_management():
    api = AdminApi()
    runner = configurator(api, ["8.8.8.8", "1.1.1.0/24"])
    assert runner.run() == gaia.BgpStatus(2, 2)
    before = len([command for command, _ in api.requests if command.startswith("add-")])
    runner.ensure_admin_access()
    assert len([command for command, _ in api.requests if command.startswith("add-")]) == before
    admin = api.saved[gaia.ADMIN_RULE]
    assert len(admin["source"]) == 2 and admin["destination"] == [runner.gateway]
    assert admin["service"] == ["ssh", "https"]
    assert not any(command == "add-service-tcp" for command, _ in api.requests)
    assert not any(command in ("delete-simple-gateway", "set-access-rule") for command, _ in api.requests)
    assert api.host["ipv4-address"] == gaia.MANAGEMENT_IP
    script = next(body for command, body in api.requests
                  if command == "run-script" and body["script-name"] == "faas-admin-clients")
    assert script["targets"] == [runner.management]
    assert "cp_conf client add" in script["script"]
    assert not any(word in script["script"] for word in ("createlist", "client del", "Any", "cpstop", "cprestart"))
    api.saved[gaia.ADMIN_RULE]["source-negate"] = True
    with pytest.raises(gaia.CheckpointGaiaError, match="conflicts"):
        runner.ensure_admin_access()


def test_admin_client_failures_and_sic_do_not_silently_succeed_or_reset_gateway():
    api = AdminApi()
    runner = configurator(api, ["8.8.8.8"])
    api.wait_task = Mock(return_value={})
    with pytest.raises(gaia.CheckpointGaiaError, match="did not persist"):
        runner.ensure_admin_access()
    api.objects.add("gateway")
    api.sic_states = ["uninitialized"]
    with pytest.raises(gaia.CheckpointGaiaError, match="will not reset"):
        runner.ensure_gateway()
    assert not any(command == "delete-simple-gateway" for command, _ in api.requests)


def test_documented_gui_client_add_preserves_automation_and_does_not_confuse_suffix_hosts():
    script = gaia.management_clients_script(["8.8.8.8", "1.1.1.0/24"])
    wrong_host = str(ipaddress.IPv4Address("8.8.8.8") + 80)
    mock = (
        f"clients='172.22.40.0/255.255.254.0\n{wrong_host}'\n"
        "cp_conf() {\n"
        "  if [ \"$2\" = get ]; then printf '%s\\n' \"$clients\"; return; fi\n"
        "  if [ \"$2\" = add ]; then clients=\"$clients\n$3\"; return; fi\n"
        "  return 1\n}\n"
    )
    result = subprocess.run(["bash"], input=mock + script + "printf '%s\\n' \"$clients\"\n",
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "faas-admin-clients-configured" in result.stdout.splitlines()
    assert {"172.22.40.0/255.255.254.0", wrong_host, "8.8.8.8",
            "1.1.1.0/255.255.255.0"} <= set(result.stdout.splitlines())
    failed = subprocess.run(["bash"], input="cp_conf() { return 1; }\n" + script,
                            capture_output=True, text=True, check=False)
    assert failed.returncode != 0 and "faas-admin-clients-configured" not in failed.stdout


@pytest.fixture(scope="module")
def templates():
    return {name: json.loads(compile_bicep(name + ".bicep")) for name in
            ("customer-deployment", "provider-checkpoint-foundation", "provider-management")}


def test_compiled_form_contract_propagates_sources_and_preserves_legacy_defaults(templates):
    template = templates["customer-deployment"]
    form = json.loads((ROOT / "portal/customer-form.json").read_text())
    assert template["parameters"]["adminAllowedSources"] == {"type": "array", "defaultValue": [],
                                                            "maxLength": 16, "metadata": {
        "description": "Up to 16 public IPv4 admin hosts/CIDRs. Bare hosts are normalized to /32. Check Point only."}}
    assert template["parameters"]["firewallType"]["defaultValue"] == "ubuntu"
    assert "adminAllowedSources" in form["view"]["outputs"]["parameters"]
    for resource in template["resources"]:
        if resource.get("name") not in ("customer-authorization-proof", "customer-provider-connection"):
            continue
        properties = resource["properties"]
        assert properties["parameters"]["adminAllowedSources"]["value"] == "[parameters('adminAllowedSources')]"
        nested = properties["template"]
        script = next(item for item in nested["resources"] if item["type"] == "Microsoft.Resources/deploymentScripts")
        assert {"name": "FAAS_ADMIN_ALLOWED_SOURCES", "value": "[string(parameters('adminAllowedSources'))]"} in (
            script["properties"]["environmentVariables"])


def test_customer_public_ips_return_routes_and_scoped_nsgs_are_conditional(templates):
    module = next(item for item in templates["customer-deployment"]["resources"] if item.get("name") == "customer-foundation")
    foundation = module["properties"]["template"]
    assert "not(equals(parameters('firewallType'), 'ubuntu'))" in module["properties"]["parameters"]["adminAllowedSources"]
    pips = [item for item in foundation["resources"] if item["type"] == "Microsoft.Network/publicIPAddresses"]
    assert len(pips) == 1 and pips[0]["condition"] == "[not(empty(variables('adminSources')))]"
    assert "adminReturnRoutes" in json.dumps(foundation)
    assert foundation["variables"]["adminSources"] == (
        "[union(variables('normalizedAdminSources'), variables('normalizedAdminSources'))]")
    routes = next(item for item in foundation["variables"]["copy"] if item["name"] == "adminReturnRoutes")
    assert routes["input"]["properties"]["nextHopType"] == "Internet"
    nsg = next(item for item in foundation["resources"] if item["type"] == "Microsoft.Network/networkSecurityGroups")
    assert nsg["properties"].endswith(", createObject())]")
    rules = foundation["variables"]["workloadAdminRules"]
    assert len(rules) == 3 and rules[1]["properties"]["destinationPortRange"] == "22"
    assert rules[1]["properties"]["sourceAddressPrefixes"] == "[variables('adminSources')]"


def test_provider_admin_management_routes_and_automation_allow_are_fixed_per_environment(templates):
    foundation = templates["provider-checkpoint-foundation"]
    routes = next(item for item in foundation["resources"] if item.get("name") == "[format('rt-cp-management-{0}', variables('suffix'))]")
    assert routes["condition"] == "[not(empty(parameters('adminAllowedSources')))]"
    assert routes["properties"]["copy"][0]["input"]["properties"]["nextHopType"] == "Internet"
    rules = foundation["variables"]["adminNsgRules"]
    assert len(rules) == 3 and rules[1]["properties"]["destinationPortRanges"] == ["22", "443"]
    management = next(item for item in foundation["resources"]
                      if item["type"] == "Microsoft.Network/networkSecurityGroups/securityRules"
                      and "nsg-cp-management" in item["name"])
    assert "172.22.40.0/23" in management["properties"]
    assert "19009" in management["properties"]
    source = (ROOT / "infra/checkpoint/main.tf").read_text()
    assert source.count('management_GUI_client_network   = "172.22.40.0/23"') == 2
    assert gaia.MANAGEMENT_IP == "172.22.30.4"


def test_profile_defaults_are_provider_injected_not_secret_defaults(templates, tmp_path):
    for name, value in (("customer.json", templates["customer-deployment"]),
                        ("customer-form.json", json.loads((ROOT / "portal/customer-form.json").read_text())),
                        ("customer-connections.json", json.loads(compile_bicep("customer-connections.bicep")))):
        (tmp_path / name).write_text(json.dumps(value))
    with patch("service.profiles.BlobServiceClient"):
        publisher = ProfilePublisher(Mock(), "https://unit.blob.core.windows.net",
                                     "https://unit-api.azurewebsites.net", "api://" + CLIENT,
                                     TENANT, tmp_path, admin_allowed_sources=["8.8.8.8", "1.1.1.1"])
    template, form = publisher.documents(binding(4))
    assert template["parameters"]["adminAllowedSources"]["defaultValue"] == ["1.1.1.1/32", "8.8.8.8/32"]
    fields = {item["name"]: item for step in form["view"]["properties"]["steps"] for item in step["elements"]}
    assert fields["adminAllowedSources"]["defaultValue"] == "1.1.1.1/32, 8.8.8.8/32"
    assert "defaultValue" not in template["parameters"]["apiClientSecret"]
    assert "defaultValue" not in fields["apiClientSecret"]
    stale = copy.deepcopy(templates["customer-deployment"])
    network = next(item for item in stale["resources"] if item.get("name") == "customer-provider-connection")
    nested_script = next(item for item in network["properties"]["template"]["resources"]
                         if item["type"] == "Microsoft.Resources/deploymentScripts")
    environment = nested_script["properties"]["environmentVariables"]
    nested_script["properties"]["environmentVariables"] = [
        item for item in environment if item["name"] != "FAAS_ADMIN_ALLOWED_SOURCES"]
    (tmp_path / "customer.json").write_text(json.dumps(stale))
    with pytest.raises(ValueError, match="admin access release is incomplete"):
        publisher.documents(binding(4))


@pytest.mark.parametrize("surface", ["bound", "defaults", "sources", "client-subnet", "return-route"])
def test_pinned_foundation_guard_rejects_unbounded_or_unscoped_admin_changes(templates, surface):
    template = copy.deepcopy(templates["provider-checkpoint-foundation"])
    if surface == "bound":
        template["parameters"]["adminAllowedSources"]["maxLength"] = 17
    elif surface == "defaults":
        template["parameters"]["adminAllowedSources"]["defaultValue"] = ["8.8.8.8"]
    elif surface == "sources":
        template["variables"]["adminNsgRules"][1]["properties"]["sourceAddressPrefixes"] = ["*"]
    elif surface == "client-subnet":
        rule = next(item for item in template["resources"]
                    if item.get("copy", {}).get("name") == "managementAdminRules")
        rule["properties"] = rule["properties"].replace("'172.22.40.0/23'", "'0.0.0.0/0'")
    else:
        routes = next(item for item in template["resources"]
                      if "rt-cp-management" in item.get("name", ""))
        routes["properties"]["copy"][0]["input"]["properties"]["nextHopType"] = "VirtualNetworkGateway"
    with pytest.raises(ValueError, match="admin"):
        Templates.validate_checkpoint_foundation(template)


def test_customer_form_uses_only_portal_supported_functions():
    import re
    # createUiDefinition rejects unknown functions at load time, even in unevaluated branches.
    supported = {
        "contains", "empty", "filter", "first", "last", "length", "map", "skip", "split", "take",
        "bool", "decodeBase64", "decodeUriComponent", "encodeBase64", "encodeUriComponent",
        "float", "int", "parse", "string", "addHours", "addMinutes", "addSeconds", "utcNow",
        "and", "coalesce", "equals", "greater", "greaterOrEquals", "if", "less", "lessOrEquals",
        "not", "or", "add", "ceil", "div", "floor", "max", "min", "mod", "mul", "rand", "range",
        "sub", "basics", "location", "resourceGroup", "steps", "subscription", "concat",
        "endsWith", "guid", "indexOf", "lastIndexOf", "replace", "startsWith", "substring",
        "toLower", "toUpper"}
    form = json.loads((Path(__file__).parents[1] / "portal/customer-form.json").read_text())
    expressions = []

    def walk(value):
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str) and value.startswith("[") and value.endswith("]"):
            expressions.append(re.sub(r"'[^']*'", "''", value))

    walk(form)
    used = {name for text in expressions for name in re.findall(r"\b([A-Za-z]+)\(", text)}
    assert used and used <= supported, used - supported


def test_provider_settings_validate_optional_office_home_defaults(monkeypatch):
    values = {
        "FAAS_ADMIN_OBJECT_IDS": json.dumps([TENANT]),
        "FAAS_MANAGEMENT_CLIENT_SECRET": "unit-management",
        "FAAS_MANAGEMENT_TENANT_ID": TENANT, "FAAS_MANAGEMENT_CLIENT_ID": CLIENT,
        "FAAS_MANAGEMENT_ORIGIN": "https://unit-admin.azurewebsites.net",
        "FAAS_TABLE_ENDPOINT": "https://unit.table.core.windows.net",
        "FAAS_MANAGEMENT_VAULT_URL": "https://unit.vault.azure.net",
        "FAAS_ARTIFACT_ACCOUNT_URL": "https://unit.blob.core.windows.net",
        "FAAS_API_URL": "https://unit-api.azurewebsites.net",
        "FAAS_API_APPLICATION_ID": CLIENT, "FAAS_API_ROLE_ID": TENANT,
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("FAAS_ADMIN_ALLOWED_SOURCES", raising=False)
    assert ManagementSettings.from_env().admin_allowed_sources == []
    monkeypatch.setenv("FAAS_ADMIN_ALLOWED_SOURCES", '["8.8.8.8","1.1.1.1"]')
    assert ManagementSettings.from_env().admin_allowed_sources == ["1.1.1.1/32", "8.8.8.8/32"]
    monkeypatch.setenv("FAAS_ADMIN_ALLOWED_SOURCES", '["0.0.0.0/0"]')
    with pytest.raises(ValueError):
        ManagementSettings.from_env()


class DictionaryRulebaseApi(AdminApi):
    """Real Management API shape: rule actions are UIDs resolved through objects-dictionary."""

    def __init__(self, action_name="Drop"):
        super().__init__()
        self.rules[-1]["action"] = "action-uid"
        self.action_name = action_name

    def call(self, command, body, allowed=()):
        result = super().call(command, body, allowed)
        if command == "show-access-rulebase":
            result["objects-dictionary"] = [{"uid": "other", "name": "Accept"},
                                            {"uid": "action-uid", "name": self.action_name}]
        return result


def test_admin_policy_resolves_cleanup_action_uid_through_objects_dictionary():
    api = DictionaryRulebaseApi()
    assert configurator(api, ["8.8.8.8"]).run() == gaia.BgpStatus(2, 2)
    assert any(command == "install-policy" for command, _ in api.requests)
    assert not any(command == "set-access-rule" for command, _ in api.requests)


@pytest.mark.parametrize("action_name", ["Accept", None])
def test_admin_policy_rejects_cleanup_rule_that_is_not_drop_or_unresolved(action_name):
    api = DictionaryRulebaseApi(action_name or "Drop")
    if action_name is None:
        api.rules[-1]["action"] = "missing-uid"
    with pytest.raises(gaia.CheckpointGaiaError, match="drop cleanup rule"):
        configurator(api, ["8.8.8.8"]).run()
    assert not any(command == "install-policy" for command, _ in api.requests)
