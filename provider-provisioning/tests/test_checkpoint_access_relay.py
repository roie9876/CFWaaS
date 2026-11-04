import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import httpx
import pytest

from service.checkpoint_access_relay import publish_checkpoint_access
from service.checkpoint_gaia import CheckpointGaiaError
from service.checkpoint_runner_config import load_checkpoint_runner_config
from test_checkpoint_modules import fixture_runner_inputs


def relay_inputs():
    inputs = fixture_runner_inputs()
    value = inputs.config.model_dump()
    value.update(schemaVersion=3, managementRelayUrl="https://unit-admin.azurewebsites.net",
                 managementRelayClientId="00000000-0000-0000-0000-000000000091")
    config = load_checkpoint_runner_config({
        "FAAS_CONFIG": json.dumps(value), "FAAS_RUNNER_CLIENT_ID": value["runnerClientId"],
    })
    return SimpleNamespace(config=config, credentials=inputs.credentials)


def test_schema3_requires_complete_https_provider_relay_and_preserves_legacy():
    old = fixture_runner_inputs().config
    assert old.schemaVersion == 1 and not old.managementRelayUrl
    inputs = relay_inputs()
    assert inputs.config.schemaVersion == 3
    for field, value in (("managementRelayUrl", "http://unit-admin.azurewebsites.net"),
                         ("managementRelayUrl", "https://evil.example"),
                         ("managementRelayClientId", ""), ("schemaVersion", 2)):
        config = inputs.config.model_dump()
        config[field] = value
        with pytest.raises(ValueError):
            load_checkpoint_runner_config({
                "FAAS_CONFIG": json.dumps(config), "FAAS_RUNNER_CLIENT_ID": config["runnerClientId"],
            })


def test_relay_sends_no_sic_and_uses_exact_audience_without_redirects(capsys):
    inputs = relay_inputs()
    identity = Mock()
    identity.get_token.return_value.token = "unit-access-token"
    resources, client = Mock(), Mock()
    resources.resources.get_by_id.side_effect = lambda resource_id, version: SimpleNamespace(
        id=resource_id, properties={"provisioningState": "Succeeded", "ipAddress": "8.8.8.8"},
    )
    client.post.return_value = httpx.Response(200, json={"status": "stored"})
    with patch("service.checkpoint_access_relay.ResourceManagementClient") as factory, \
            patch("service.checkpoint_access_relay.httpx.Client") as http:
        factory.return_value.__enter__.return_value = resources
        http.return_value.__enter__.return_value = client
        publish_checkpoint_access(inputs, identity)
    identity.get_token.assert_called_once_with(inputs.config.managementRelayClientId + "/.default")
    assert http.call_args.kwargs == {"timeout": 30, "follow_redirects": False, "trust_env": False}
    sent = client.post.call_args.kwargs["json"]
    assert set(sent) == {
        "environmentId", "providerGroupName", "managementPublicIp", "gatewayPublicIp", "managementPassword"}
    assert sent["managementPassword"] == inputs.credentials.management_password
    assert inputs.credentials.sic_key not in json.dumps(sent)
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("status", [301, 302, 401, 403, 422])
def test_relay_rejects_redirects_and_auth_failures_without_leaking_bodies(status):
    inputs = relay_inputs()
    resources, client, identity = Mock(), Mock(), Mock()
    identity.get_token.return_value.token = "unit-access-token"
    resources.resources.get_by_id.side_effect = lambda resource_id, version: SimpleNamespace(
        id=resource_id, properties={"provisioningState": "Succeeded", "ipAddress": "8.8.8.8"},
    )
    client.post.return_value = httpx.Response(status, text=inputs.credentials.management_password)
    with patch("service.checkpoint_access_relay.ResourceManagementClient") as factory, \
            patch("service.checkpoint_access_relay.httpx.Client") as http:
        factory.return_value.__enter__.return_value = resources
        http.return_value.__enter__.return_value = client
        with pytest.raises(CheckpointGaiaError) as error:
            publish_checkpoint_access(inputs, identity)
    assert inputs.credentials.management_password not in str(error.value)
    assert client.post.call_count == 1


def test_reveal_browser_clears_all_password_inputs_and_invalidates_pending_responses():
    import shutil
    import subprocess
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the reveal-panel check")
    html = (Path(__file__).resolve().parents[1] / "service/static/management.html").read_text()
    functions = html[html.index("let secretTimer;"):html.index("async function request(")]
    script = r"""
const assert = require("node:assert/strict");
class Element {
  constructor(tag="div") { this.tag=tag; this.children=[]; this.value=""; this.listeners={}; this.style={}; }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children=items; }
  setAttribute(name,value) { this[name]=value; }
  addEventListener(name,fn) { this.listeners[name]=fn; }
  querySelectorAll(tag) { return this.children.flatMap(c=>[
    ...(c.tag===tag?[c]:[]), ...c.querySelectorAll(tag)]); }
}
const elements=Object.fromEntries(["secret","secret-panel","connection-details"].map(id=>[id,new Element()]));
globalThis.document={getElementById:id=>elements[id],createElement:tag=>new Element(tag)};
const notice=new Element();
""" + functions + r"""
renderConnectionDetails([{
 environmentId:"unit-environment",credentialStatus:"available",
 routing:{nextHopIp:"172.18.10.7",instructions:"Customer-owned routes only"},
 management:{username:"admin",publicIp:"8.8.8.8",password:"unit!private!password",ssh:"ssh admin@8.8.8.8"},
 gateway:{username:"admin",publicIp:"1.1.1.1",authentication:"SSH key only"}
}]);
const inputs=elements["connection-details"].querySelectorAll("input");
assert.equal(inputs.length,1);
assert.equal(inputs[0].value,"unit!private!password");
elements.secret.value="unit-api-credential";
const generation=revealGeneration;
clearSecret();
assert.equal(elements.secret.value,"");
assert.equal(inputs[0].value,"");
assert.equal(elements["connection-details"].children.length,0);
assert.equal(elements["secret-panel"].hidden,true);
assert.notEqual(generation,revealGeneration);
"""
    result = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
