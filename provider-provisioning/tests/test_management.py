import copy
import json
import shutil
import sys
import subprocess
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import UUID, uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from service.auth import Authenticator, Owner
from service.config import Customer, Settings
from service.customer_stores import CustomerStores
from service.enrollment import CustomerBinding, EnrollmentError
from service.management import ManagementSettings, create_app, directory_settings
from service.management_auth import ManagementAuthenticator
from service.models import EnvironmentRequest
from service.profiles import ProfilePublisher
from service.store import Change, Conflict, DomainError


def uid(number):
    return str(UUID(int=number))


TENANT, ADMIN, CLIENT = uid(1), uid(2), uid(3)
ORIGIN = "https://unit-admin.azurewebsites.net"


@pytest.fixture(scope="module")
def signing():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = jwt.PyJWK(RSAAlgorithm.to_jwk(private.public_key(), as_dict=True))
    return private, SimpleNamespace(get=lambda kid: key)


def identity(signing, **overrides):
    now = int(time.time())
    claims = {"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
              "aud": CLIENT, "tid": TENANT, "oid": ADMIN,
              "exp": now + 300, "nbf": now - 1, "iat": now - 1, "name": "Lab administrator"}
    claims.update(overrides)
    return jwt.encode(claims, signing[0], algorithm="RS256", headers={"kid": "unit"})


def authentication(signing):
    return ManagementAuthenticator(TENANT, CLIENT, {ADMIN}, ORIGIN, signing[1])


@pytest.fixture
def dependencies(signing):
    service = Mock()
    service.registry.list_customers.return_value = []
    service.onboard.return_value = {"customerId": uid(4), "status": "Ready"}
    service.reveal.return_value = {"secret": "unit-credential", "expiresAt": "2099-01-01T00:00:00Z"}
    service.deployment.return_value = {"portalUrl": "https://portal.azure.com/#create/Microsoft.Template",
                                      "expiresAt": "2099-01-01T00:00:00Z"}
    with TestClient(create_app(service, authentication(signing)), base_url=ORIGIN) as client:
        yield client, service, {
            "x-ms-token-aad-id-token": identity(signing),
            "Origin": ORIGIN, "Idempotency-Key": str(uuid4()),
        }


def test_console_requires_signed_provider_administrator(dependencies):
    client, service, headers = dependencies
    unauthenticated = client.get("/")
    assert unauthenticated.status_code == 401
    assert "Sign in again" in unauthenticated.text
    assert '/.auth/login/aad?post_login_redirect_uri=%2F' in unauthenticated.text
    assert unauthenticated.headers["Cache-Control"] == "no-store"
    assert client.get("/admin/customers").json() == {"detail": "AdministratorSignInRequired"}
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert "Provider administration" in response.text
    assert 'name="maxEnvironments"' not in response.text
    assert "crypto.randomUUID" in response.text
    assert "localStorage" not in response.text
    assert "innerHTML" not in response.text
    policy = response.headers["Content-Security-Policy"]
    assert "script-src 'sha256-" in policy
    assert "script-src 'unsafe-inline'" not in policy
    assert response.headers["Cache-Control"] == "no-store"
    service.onboard.assert_not_called()


def test_console_does_not_replace_forbidden_admin_response(dependencies, signing):
    client, _, headers = dependencies
    headers["x-ms-token-aad-id-token"] = identity(signing, oid=uid(9))
    response = client.get("/", headers=headers)
    assert response.status_code == 403
    assert response.json() == {"detail": "AdministratorNotAuthorized"}


@pytest.mark.parametrize("fragment,removed", [
    ("#token=redacted", True), ("#access_token=redacted", True),
    ("#state=fixture&id_token=redacted", True), ("#section", False),
])
def test_console_removes_authentication_fragments_from_browser_history(fragment, removed):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise browser fragment handling")
    html = (Path(__file__).resolve().parents[1] / "service/static/management.html").read_text()
    script = html.split("<script>", 1)[1].split("</script>", 1)[0]
    preamble = """
const assert = require("node:assert/strict");
let replaced = null;
globalThis.window = {
  location: {hash: process.argv[1], pathname: "/", search: "?scoutTheme=light"},
  history: {replaceState: (_state, _title, url) => { replaced = url; }},
  matchMedia: () => ({matches: false})
};
globalThis.document = {documentElement: {setAttribute: () => {}}};
"""
    assertion = "\nassert.equal(replaced, " + ('"/?scoutTheme=light"' if removed else "null") + ");"
    result = subprocess.run([node, "-e", preamble + script + assertion, fragment],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_console_reports_empty_http_errors_without_json_parse_failure():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise the browser request helper")
    html = (Path(__file__).resolve().parents[1] / "service/static/management.html").read_text()
    helper = html[html.index("async function request("):html.index("\nfunction button(")]
    script = """
const assert = require("node:assert/strict");
globalThis.crypto = require("node:crypto").webcrypto;
""" + helper + r"""
function response(status, contentType, body) {
  return {ok: status >= 200 && status < 300, status,
          headers: {get: () => contentType}, text: async () => body};
}
(async () => {
  globalThis.fetch = async () => response(403, null, "");
  await assert.rejects(request("/admin/customers", "POST", {}), /Request rejected \(HTTP 403\)/);
  globalThis.fetch = async () => response(403, "application/json", '{"detail":"InvalidRequestOrigin"}');
  await assert.rejects(request("/admin/customers", "POST", {}), /InvalidRequestOrigin/);
  globalThis.fetch = async () => response(401, "application/json", '{"detail":"AdministratorSignInRequired"}');
  await assert.rejects(request("/admin/customers"), /session expired.*Sign in again/);
  globalThis.fetch = async () => response(401, null, "");
  await assert.rejects(request("/admin/customers"), /session expired.*Sign in again/);
  globalThis.fetch = async () => response(409, "application/json", '{"detail":"CustomerNameAlreadyEnrolled"}');
  await assert.rejects(request("/admin/customers", "POST", {}), /customer with this name already exists/);
  globalThis.fetch = async () => response(200, "application/json", '{"customers":[]}');
  assert.deepEqual(await request("/admin/customers"), {customers: []});
  globalThis.fetch = async () => response(200, "application/json", "{");
  await assert.rejects(request("/admin/customers"), /Invalid JSON response \(HTTP 200\)/);
  globalThis.fetch = async () => response(200, "text/html", "");
  await assert.rejects(request("/admin/customers"), /Expected a JSON response \(HTTP 200\)/);
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("overrides,status", [
    ({"oid": uid(9)}, 403),
    ({"tid": uid(9)}, 401),
    ({"aud": uid(9)}, 401),
    ({"iss": "https://issuer.example"}, 401),
    ({"exp": 1}, 401),
    ({"idtyp": "app"}, 401),
])
def test_administrator_identity_rejection(dependencies, signing, overrides, status):
    client, service, headers = dependencies
    headers["x-ms-token-aad-id-token"] = identity(signing, **overrides)
    assert client.get("/admin/customers", headers=headers).status_code == status
    service.registry.list_customers.assert_not_called()


@pytest.mark.parametrize("origin", [None, "https://attacker.example", "null"])
def test_mutations_require_exact_browser_origin(dependencies, origin):
    client, service, headers = dependencies
    headers.pop("Origin")
    if origin is not None:
        headers["Origin"] = origin
    response = client.post("/admin/customers", headers=headers, json={
        "name": "Contoso", "tenantId": uid(4), "subscriptionId": uid(5)})
    assert response.status_code == 403
    service.onboard.assert_not_called()


def test_onboarding_passes_verified_actor_and_idempotency(dependencies):
    client, service, headers = dependencies
    response = client.post("/admin/customers", headers=headers, json={
        "name": "Contoso", "tenantId": uid(4), "subscriptionId": uid(5)})
    assert response.status_code == 200
    body, actor, key = service.onboard.call_args.args
    assert body.tenantId == uid(4)
    assert actor == ADMIN
    assert key == headers["Idempotency-Key"]


def test_no_secret_returned_in_customer_inventory(dependencies):
    client, service, headers = dependencies
    service.registry.list_customers.return_value = [{"customerId": uid(4), "name": "Contoso",
                                                     "status": "Ready"}]
    response = client.get("/admin/customers", headers=headers)
    assert response.status_code == 200
    assert "unit-credential" not in response.text
    revealed = client.post(f"/admin/customers/{uid(4)}/reveal", headers=headers, json={})
    assert revealed.json()["secret"] == "unit-credential"
    assert revealed.headers["Cache-Control"] == "no-store"
    service.reveal.assert_called_once_with(uid(4), ADMIN)


@pytest.mark.parametrize("action", ["rotate", "revoke", "recover", "archive"])
def test_customer_mutation_routes(dependencies, action):
    client, service, headers = dependencies
    getattr(service, action).return_value = {"status": "Ready"}
    response = client.post(f"/admin/customers/{uid(4)}/{action}", headers=headers, json={})
    assert response.status_code == 200
    args = (uid(4), ADMIN, headers["Idempotency-Key"])
    getattr(service, action).assert_called_once_with(*(args + (None,) if action == "rotate" else args))


def test_rotation_validates_custom_lifetime(dependencies):
    client, service, headers = dependencies
    path = f"/admin/customers/{uid(4)}/rotate"
    service.rotate.return_value = {"status": "Ready"}
    assert client.post(path, headers=headers, json={"credentialHours": 8760}).status_code == 200
    service.rotate.assert_called_once_with(uid(4), ADMIN, headers["Idempotency-Key"], 8760)
    for hours in (0, 8761, True, "24"):
        assert client.post(path, headers=headers, json={"credentialHours": hours}).status_code == 422
    service.rotate.reset_mock()
    assert client.post(path, headers={**headers, "Content-Type": "application/json"}).status_code == 200
    service.rotate.assert_called_once_with(uid(4), ADMIN, headers["Idempotency-Key"], None)


def test_management_errors_do_not_echo_secret_bodies(dependencies, caplog):
    client, service, headers = dependencies
    service.reveal.side_effect = RuntimeError("unit-credential must not be logged")
    response = client.post(f"/admin/customers/{uid(4)}/reveal", headers=headers, json={})
    assert response.status_code == 503
    assert "unit-credential" not in response.text
    assert "unit-credential" not in caplog.text
    service.reveal.side_effect = EnrollmentError(409, "CredentialAlreadyRevealed")
    response = client.post(f"/admin/customers/{uid(4)}/reveal", headers=headers, json={})
    assert response.json() == {"detail": "CredentialAlreadyRevealed"}


def binding(index):
    return CustomerBinding(customer_id=uid(index), name="Contoso", tenant=uid(index + 10),
                           subscription=uid(index + 20), principal=uid(index + 30),
                           client=uid(index + 40), max_environments=2, status="Ready")


def test_registry_authentication_binds_server_owned_customer(signing):
    member = binding(4)
    registry = Mock()
    registry.lookup.return_value = member
    settings = Settings(CLIENT, None, "https://unit.table.core.windows.net",
                        "https://unit.vault.azure.net", auth_mode="provider-api-registry",
                        authority_tenant=TENANT)
    auth = Authenticator(settings, signing[1], registry)
    token = identity(signing, oid=member.principal, azp=member.client, ver="2.0",
                     idtyp="app", roles=["FirewallDeployment.Request"])
    owner = auth.authenticate("Bearer " + token)
    assert owner == Owner(member.tenant, member.principal, member.client)
    registry.lookup.assert_called_once_with(member.client, member.principal)
    registry.lookup.return_value = None
    with pytest.raises(Exception) as rejected:
        auth.authenticate("Bearer " + token)
    assert rejected.value.status_code == 403


class MemoryBackend:
    def __init__(self):
        self.rows = {}
        self.version = 0

    def get(self, partition, key):
        return copy.deepcopy(self.rows.get((partition, key)))

    def transact(self, changes: list[Change]):
        for change in changes:
            identity = (change.row["PartitionKey"], change.row["RowKey"])
            current = self.rows.get(identity)
            if (change.etag is None and current is not None
                    or change.etag is not None and (current or {}).get("_etag") != change.etag):
                raise Conflict()
        for change in changes:
            self.version += 1
            row = copy.deepcopy(change.row)
            row["_etag"] = str(self.version)
            self.rows[(row["PartitionKey"], row["RowKey"])] = row

    def jobs(self, partition):
        return [copy.deepcopy(value) for (part, key), value in self.rows.items()
                if part == partition and key.startswith("job:")]


def test_customer_stores_keep_independent_quota_and_ownership():
    first, second = binding(4), binding(5)
    registry = Mock()
    registry.lookup.side_effect = lambda client, principal: next(
        (item for item in (first, second) if (item.client, item.principal) == (client, principal)), None)
    settings = Settings(CLIENT, None, "https://unit.table.core.windows.net",
                        "https://unit.vault.azure.net", auth_mode="provider-api-registry",
                        authority_tenant=TENANT)
    router = CustomerStores(MemoryBackend(), settings, registry)
    owners = [Owner(item.tenant, item.principal, item.client) for item in (first, second)]
    stores = [router.for_owner(owner) for owner in owners]
    operation = stores[0].reserve(owners[0], "proof", EnvironmentRequest(mode="proof"))
    assert stores[1].reserve(owners[1], "proof", EnvironmentRequest(mode="proof"))["status"] == "Pending"
    with pytest.raises(DomainError):
        stores[1].owned(owners[1], str(operation["environmentId"]))
    assert stores[0].partition == stores[1].partition
    assert len(stores[0].candidates()) == 1
    assert stores[1].claim(str(operation["environmentId"]), "other-worker") is None
    assert stores[0]._quota()["allocated"] == 2


def test_legacy_customer_limits_do_not_cap_retained_allocations():
    first, second = binding(4), binding(5)
    registry = Mock()
    registry.lookup.side_effect = lambda client, principal: next(
        (item for item in (first, second) if (item.client, item.principal) == (client, principal)), None)
    owners = [Owner(item.tenant, item.principal, item.client) for item in (first, second)]
    settings = Settings(CLIENT, None, "https://unit.table.core.windows.net",
                        "https://unit.vault.azure.net", auth_mode="provider-api-registry",
                        authority_tenant=TENANT, max_caller_active=10)
    stores = CustomerStores(MemoryBackend(), settings, registry)
    proof = EnvironmentRequest(mode="proof")
    for owner in owners:
        store = stores.for_owner(owner)
        for index in range(7):
            operation = store.reserve(owner, str(index), proof)
            lease = store.claim(str(operation["environmentId"]), "worker")
            assert lease is not None
            store.finish(lease, "Ready")
    assert stores.for_owner(owners[0])._quota()["allocated"] == 14


def test_same_tenant_legacy_allocations_are_isolated():
    first = binding(4)
    second = replace(binding(5), tenant=first.tenant, subscription=first.subscription,
                     allocation_key="customer:" + uid(5))
    registry = Mock()
    settings = Settings(CLIENT, None, "https://unit.table.core.windows.net",
                        "https://unit.vault.azure.net", auth_mode="provider-api-registry",
                        authority_tenant=TENANT, max_caller_active=3)
    backend = MemoryBackend()
    router = CustomerStores(backend, settings, registry)
    stores = [router.bound(item) for item in (first, second)]
    owners = [Owner(item.tenant, item.principal, item.client) for item in (first, second)]
    first_op = stores[0].reserve(owners[0], "one", EnvironmentRequest(mode="proof"))
    stores[0].reserve(owners[0], "two", EnvironmentRequest(mode="proof"))
    stores[1].reserve(owners[1], "one", EnvironmentRequest(mode="proof"))
    stores[1].reserve(owners[1], "two", EnvironmentRequest(mode="proof"))
    for store, owner in zip(stores, owners):
        store.reserve(owner, "three", EnvironmentRequest(mode="proof"))
    with pytest.raises(DomainError) as foreign:
        stores[1].owned(owners[1], str(first_op["environmentId"]))
    assert foreign.value.status == 404
    quota = stores[0]._quota()
    assert json.loads(str(quota["allocations"])) == {first.tenant: 3, second.allocation_key: 3}
    old_key = (stores[0].partition, "op:" + str(first_op["environmentId"]))
    backend.rows[old_key].pop("allocationKey")
    lease = stores[0].claim(str(first_op["environmentId"]), "worker")
    assert lease is not None
    stores[0].finish(lease, "Failed", release=True)
    assert json.loads(str(stores[0]._quota()["allocations"])) == {
        first.tenant: 2, second.allocation_key: 3}
    second_job = stores[1].candidates()[0]
    second_lease = stores[1].claim(str(second_job["environmentId"]), "worker")
    assert second_lease is not None
    stores[1].finish(second_lease, "Failed", release=True)
    assert json.loads(str(stores[0]._quota()["allocations"])) == {
        first.tenant: 2, second.allocation_key: 2}


def test_public_api_does_not_load_privileged_worker_modules():
    result = subprocess.run(
        [sys.executable, "-c",
         "import sys; import service.api; "
         "assert 'service.worker' not in sys.modules; "
         "assert 'service.provisioner' not in sys.modules; "
         "assert 'service.enrollment_azure' not in sys.modules"],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_customer_profiles_never_default_the_api_secret(tmp_path):
    names = ["runId", "deploymentMode", "expectedCustomerTenantId", "expectedCustomerSubscriptionId",
             "enrolledCustomerResourceGroupId", "apiUrl", "apiResource", "apiAuthorityTenantId",
             "apiClientId", "customerConnectionsTemplateBase64"]
    preflight = "FirewallUnavailable /v1/firewall-types/checkpoint-byol/readiness"
    template = {"parameters": {name: {"type": "string"} for name in names},
                "resources": [{"type": "Microsoft.Resources/deployments", "name": name,
                               "properties": {
                                   "parameters": {"firewallType": {"value": "[parameters('firewallType')]"}},
                                   "template": {
                                       "variables": {"connector": preflight + " GroupOwnershipError /retry-group"},
                                       "resources": [{"type": "Microsoft.Resources/deploymentScripts",
                                                      "properties": {"environmentVariables": [
                                                          {"name": "FAAS_FIREWALL_TYPE",
                                                           "value": "[parameters('firewallType')]"}]}}]}}}
                              for name in ("customer-authorization-proof", "customer-provider-connection")]}
    template["parameters"]["apiClientSecret"] = {"type": "securestring"}
    template["parameters"]["firewallType"] = {"type": "string", "defaultValue": "ubuntu",
                                              "allowedValues": ["ubuntu", "checkpoint-byol", "checkpoint-vmss"]}
    form = {"view": {"properties": {"title": "FaaS customer deployment - recovery-enabled release",
                                   "steps": [{"elements": [
        {"name": "apiClientSecret", "type": "Microsoft.Common.PasswordBox",
         "constraints": {"required": True}},
        {"name": "apiClientId"}, {"name": "runId"},
        {"name": "firewallType", "defaultValue": "Ubuntu simulator",
         "constraints": {"allowedValues": [
             {"label": "Ubuntu simulator", "value": "ubuntu"},
             {"label": "Check Point", "value": "checkpoint-byol"},
             {"label": "Check Point scale set", "value": "checkpoint-vmss"}]}}]}]},
        "outputs": {"parameters": {"firewallType": "[steps('basics').firewallType]"}}}}
    for name, value in (("customer.json", template), ("customer-form.json", form),
                        ("customer-connections.json", {"resources": []})):
        (tmp_path / name).write_text(json.dumps(value))
    with patch("service.profiles.BlobServiceClient"):
        publisher = ProfilePublisher(Mock(), "https://unit.blob.core.windows.net",
                                     "https://unit-api.azurewebsites.net", "api://" + CLIENT,
                                     TENANT, tmp_path)
    prepared, ui = publisher.documents(binding(4))
    assert "defaultValue" not in prepared["parameters"]["apiClientSecret"]
    assert prepared["parameters"]["expectedCustomerTenantId"]["defaultValue"] == binding(4).tenant
    assert prepared["parameters"]["apiClientId"]["defaultValue"] == binding(4).client
    assert "defaultValue" not in ui["view"]["properties"]["steps"][0]["elements"][0]
    template["resources"][1]["properties"]["template"]["variables"]["connector"] = "old connector"
    (tmp_path / "customer.json").write_text(json.dumps(template))
    with pytest.raises(ValueError, match="Customer recovery release is incomplete"):
        publisher.documents(binding(4))

    template["resources"][1]["properties"]["template"]["variables"]["connector"] = preflight + " GroupOwnershipError /retry-group"
    template["resources"][0]["properties"]["template"]["variables"]["connector"] = "old proof connector"
    (tmp_path / "customer.json").write_text(json.dumps(template))
    with pytest.raises(ValueError, match="Customer firewall selection release is incomplete"):
        publisher.documents(binding(4))

    template["resources"][0]["properties"]["template"]["variables"]["connector"] = preflight
    template["resources"][1]["properties"]["template"]["resources"][0]["properties"]["environmentVariables"] = []
    (tmp_path / "customer.json").write_text(json.dumps(template))
    with pytest.raises(ValueError, match="Customer firewall selection release is incomplete"):
        publisher.documents(binding(4))


@pytest.mark.parametrize("configured", [True, False])
def test_provider_directory_discovery_requires_v2_idtyp_and_exact_api(configured):
    settings = ManagementSettings(
        TENANT, CLIENT, "unit-management", frozenset({ADMIN}), ORIGIN,
        "https://unit.table.core.windows.net", "https://unit.vault.azure.net",
        "https://unit.blob.core.windows.net", "https://unit-api.azurewebsites.net", uid(6), uid(7))
    api = {"appId": uid(6), "identifierUris": ["api://" + uid(6)],
           "api": {"requestedAccessTokenVersion": 2},
           "optionalClaims": {"accessToken": [{"name": "idtyp"}] if configured else []}}
    documents = [
        {"value": [{"id": uid(8), "appId": CLIENT}]},
        {"value": [{"id": uid(9), "appId": uid(6)}]},
        {"value": [api]},
    ]
    import httpx
    with patch("service.management.ClientSecretCredential") as credential, \
            patch("service.management.httpx.Client") as transport:
        credential.return_value.get_token.return_value.token = "unit-token"
        transport.return_value.__enter__.return_value.get.side_effect = [
            httpx.Response(200, json=value, request=httpx.Request("GET", "https://graph.microsoft.com"))
            for value in documents]
        if configured:
            result = directory_settings(settings)
            assert result.provider_api_principal_id == uid(9)
            assert result.management_principal_id == uid(8)
        else:
            with pytest.raises(EnrollmentError) as error:
                directory_settings(settings)
            assert error.value.code == "ProviderApiTokenConfigurationRequired"
        credential.return_value.close.assert_called_once()


@pytest.mark.parametrize("management_release", [True, False])
def test_provider_release_never_presets_management_credential(management_release, tmp_path):
    import prepare_provider_installation as release
    template = {"parameters": {
        "managementApplicationSecret": {"type": "securestring"},
        "codePackageUri": {"type": "securestring"},
        **{name: {"type": "string"} for name in (
            "codePackageSha256", "providerTemplateSha256", "controlResourceGroupName",
            "dataResourceGroupName", "runId", "releaseStorageAccountName",
            "releaseStorageResourceGroupName")},
    }}
    package = {"includesManagement": management_release, "packageSha256": "a" * 64,
               "providerTemplateSha256": "b" * 64}
    uri = ("https://unit.blob.core.windows.net/release/apps.zip?"
           "sp=r&sr=b&spr=https&skoid=unit&sig=unit-read-only&se=2099-01-01T00%3A00%3A00Z")
    with patch.object(release, "compile_bicep", return_value=json.dumps(template).encode()), \
            patch.object(release, "save_private") as save:
        if management_release:
            release.prepare(tmp_path, uri, package)
            prepared = save.call_args_list[0].args[1]
            assert "defaultValue" not in prepared["parameters"]["managementApplicationSecret"]
            assert prepared["parameters"]["codePackageSha256"]["defaultValue"] == "a" * 64
        else:
            with pytest.raises(ValueError):
                release.prepare(tmp_path, uri, package)
            save.assert_not_called()


def test_provider_release_uses_managed_identity_without_stored_sas(tmp_path):
    import prepare_provider_installation as release
    names = ("codePackageSha256", "providerTemplateSha256", "controlResourceGroupName",
             "dataResourceGroupName", "runId", "releaseStorageAccountName",
             "releaseStorageResourceGroupName")
    template = {"parameters": {name: {"type": "string"} for name in names}}
    template["parameters"].update(managementApplicationSecret={"type": "securestring"},
                                  codePackageUri={"type": "securestring"})
    package = {"includesManagement": True, "packageSha256": "a" * 64,
               "providerTemplateSha256": "b" * 64}
    uri = "https://unitstore.blob.core.windows.net/releases/sha/apps.zip"
    with patch.object(release, "compile_bicep", return_value=json.dumps(template).encode()), \
            patch.object(release, "save_private") as save:
        release.prepare(tmp_path, uri, package, "unitstore", "rg-release")
        prepared = save.call_args_list[0].args[1]["parameters"]
        assert prepared["codePackageUri"]["defaultValue"] == uri
        assert prepared["releaseStorageAccountName"]["defaultValue"] == "unitstore"
        assert prepared["releaseStorageResourceGroupName"]["defaultValue"] == "rg-release"
        assert "defaultValue" not in prepared["managementApplicationSecret"]
        with pytest.raises(ValueError):
            release.prepare(tmp_path, uri, package, "otherstore", "rg-release")
