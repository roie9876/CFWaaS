import copy
import json
from dataclasses import replace
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID

import httpx
import jwt
import pytest
from azure.core.exceptions import ClientAuthenticationError, ResourceNotFoundError
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from pydantic import ValidationError

import test_checkpoint_vmss as vmss
import test_enrollment
import test_management as management_tests
import test_service as existing
from service.checkpoint_foundation import validate_checkpoint_foundation
from service.checkpoint_gaia import BgpStatus, CheckpointGaiaError
from service.checkpoint_provisioner import CheckpointSettings
from service.checkpoint_runner_config import load_checkpoint_runner_config
from service.enrollment import CustomerBinding, EnrollmentError
from service.peering_lab import (PARTITION, PHASES, PeeringAuthorizationRequired,
                                 PeeringLabRequest, PeeringLabs, PeeringLabSettings)
from service.peering_templates import peering_foundation
from service.store import Change

ROOT = Path(__file__).resolve().parents[1]
OWNER = existing.PRINCIPAL
CUSTOMER = str(UUID(int=40))
CUSTOMER_TENANT = str(UUID(int=41))
CUSTOMER_SUBSCRIPTION = str(UUID(int=42))
REQUEST = {
    "customerId": CUSTOMER, "workloadSshPublicKey": existing.RUNNER_SETTINGS.provider_ssh_public_key,
    "adminAllowedSources": ["8.8.8.8"], "approveLabCosts": True, "approveCrossTenantPeering": True,
}
signing = management_tests.signing
dependencies = management_tests.dependencies
NETWORK_APP = str(UUID(int=60))
NETWORK_IDENTITY = str(UUID(int=61))
NETWORK_PRINCIPALS = {existing.PROVIDER_TENANT: str(UUID(int=62)), CUSTOMER_TENANT: str(UUID(int=63))}


def network_token(tenant, app=NETWORK_APP, idtyp="app"):
    return jwt.encode({"tid": tenant, "idtyp": idtyp, "appid": app, "oid": NETWORK_PRINCIPALS[tenant]},
                      "test-only-signing-key-0123456789abcdef", algorithm="HS256")


@pytest.fixture(scope="module")
def templates():
    def compile(name):
        result = subprocess.run(["az", "bicep", "build", "--file", str(ROOT / "infra" / name), "--stdout"],
                                capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    return compile("provider-checkpoint-foundation.bicep"), compile("peering-customer.bicep")


class Vault:
    def __init__(self):
        self.values = {}

    def set_secret(self, name, text, **kwargs):
        versions = self.values.setdefault(name, [])
        versions.append(SimpleNamespace(value=text, version=str(len(versions)), enabled=True, options=kwargs))

    def get_secret(self, name, **kwargs):
        return self.values[name][-1]

    def list_properties_of_secret_versions(self, name, **kwargs):
        if name not in self.values:
            raise ResourceNotFoundError()
        return self.values[name]

    def update_secret_properties(self, name, version, enabled, **kwargs):
        next(value for value in self.values[name] if value.version == version).enabled = enabled


@pytest.fixture
def lab(templates):
    backend, vault = test_enrollment.Memory(), Vault()
    registry = Mock(backend=backend)
    registry.binding.return_value = CustomerBinding(
        CUSTOMER, "Test customer", CUSTOMER_TENANT, CUSTOMER_SUBSCRIPTION,
        existing.API_PRINCIPAL, existing.API_CLIENT, 3, "Ready")
    checkpoint = CheckpointSettings(templates[0], {"private": "fixture"}, "unused", "unused",
                                    "fixtureacr.azurecr.io", "a" * 64, existing.RUNNER_SETTINGS)
    settings = PeeringLabSettings(existing.PROVIDER_TENANT, existing.SUBSCRIPTION, existing.CLIENT,
                                  checkpoint, templates[1], NETWORK_APP, NETWORK_IDENTITY)
    service = PeeringLabs(settings, registry, vault, http=Mock(), network_token_factory=network_token)
    service._tokens = Mock(return_value={"provider": "provider-token", "customer": "customer-token"})
    result = service.create(PeeringLabRequest.model_validate(REQUEST), OWNER, "request-one")
    return SimpleNamespace(service=service, backend=backend, vault=vault, registry=registry,
                           row=service._row(result["environmentId"], OWNER), settings=settings)


def authorize(lab):
    row = lab.service._row(lab.row["environmentId"], OWNER)
    row.update(providerAuthorized=True, customerAuthorized=True)
    lab.backend.transact([Change(row, row["_etag"])])
    return lab.service._row(row["environmentId"], OWNER)


def evidence_for(row):
    store = Mock()
    store.operation.return_value = {"providerGroupName": row["providerGroupId"].rsplit("/", 1)[1],
                                    "providerGroupId": row["providerGroupId"]}
    lease = SimpleNamespace(environment_id=row["environmentId"])
    foundation, private, group, control, identity = existing.checkpoint_runner_fixture(store, lease)
    value = foundation["checkpointFoundation"]["value"]
    del value["routeServerAsn"]
    del value["routeServerPeerAddresses"]
    value.update(firewallTopology="vmss", connectivityMode="peering")
    foundation["connectionManifest"]["value"] = {
        "connectivityMode": "peering", "providerVnetId": value["securityVnetId"], "firewallVip": "172.22.20.4"}
    return foundation, private, group, control, identity


def test_specialization_has_only_one_provider_vnet_and_no_vpn_or_dynamic_routing(templates):
    source = copy.deepcopy(templates[0])
    result = peering_foundation(source)
    assert source == templates[0]
    assert set(result["parameters"]) == {"location", "environmentId", "adminAllowedSources", "firewallTopology"}
    types = [resource["type"] for resource in result["resources"]]
    assert types.count("Microsoft.Network/virtualNetworks") == 1
    assert not any(kind in types for kind in (
        "Microsoft.Resources/deployments", "Microsoft.Network/virtualNetworkGateways",
        "Microsoft.Network/localNetworkGateways", "Microsoft.Network/connections",
        "Microsoft.Network/virtualHubs", "Microsoft.Network/virtualNetworkAppliances"))
    assert not any("routeServer" in field for field in result["outputs"]["checkpointFoundation"]["value"])
    assert result["outputs"]["connectionManifest"]["value"]["firewallVip"] == "172.22.20.4"


def test_customer_template_deploys_exactly_two_mana_profile_vms_with_static_inspection_routes(templates):
    template = templates[1]
    networks = next(resource for resource in template["resources"] if resource["type"] == "Microsoft.Network/virtualNetworks")
    assert networks["copy"]["count"] == "[length(variables('prefixes'))]"
    assert template["variables"]["prefixes"] == ["10.211.0.0/16", "10.212.0.0/16"]
    routes = next(resource for resource in template["resources"] if resource["type"] == "Microsoft.Network/routeTables")
    assert routes["properties"]["disableBgpRoutePropagation"] is True
    assert all(route["properties"]["nextHopIpAddress"] == "172.22.20.4" for route in routes["properties"]["routes"])
    workload = next(resource for resource in template["resources"] if resource["type"] == "Microsoft.Resources/deployments")
    values = workload["properties"]["parameters"]
    assert values["size"]["value"] == "Standard_D4s_v6"
    assert values["acceleratedNetworking"]["value"] is True
    assert values["diskControllerType"]["value"] == "NVMe"
    verification = next(resource for resource in template["resources"] if resource["type"].endswith("/runCommands"))
    assert verification["properties"]["treatFailureAsDeploymentFailure"] is True
    assert verification["properties"]["timeoutInSeconds"] == 600
    assert "replace(" in verification["properties"]["source"]["script"]
    assert not any(resource["type"] == "Microsoft.Network/publicIPAddresses" for resource in template["resources"])


def test_peering_runner_has_no_bgp_peers_and_preserves_vmss_pinned_deployment(lab):
    row = lab.row
    foundation, private, group, control, identity = evidence_for(row)
    config = lab.settings.checkpoint
    lab.service.settings = PeeringLabSettings(
        lab.settings.provider_tenant, lab.settings.provider_subscription, lab.settings.oauth_client_id,
        CheckpointSettings(config.foundation_template, config.private_template, control, identity["id"],
                           config.registry_server, config.image_sha256, config.runner), lab.settings.customer_template)
    lab.service._arm = Mock(return_value=identity)
    spec, body = lab.service._runner_spec(row, {"foundation": foundation, "private": private},
                                         {"provider": "token"})
    runtime = load_checkpoint_runner_config(dict(spec.environment))
    assert runtime.schemaVersion == 5 and runtime.connectivityMode == "peering"
    assert runtime.firewallTopology == "vmss"
    assert runtime.routeServerPeers is None and runtime.routeServerAsn is None
    assert spec.image.endswith("@sha256:" + "a" * 64)
    assert "password" not in body.decode().lower()
    assert "sic" not in body.decode().lower()
    for mutation in ("unexpected-bgp", "foreign-vip", "vpn-mode"):
        bad = copy.deepcopy(foundation)
        if mutation == "unexpected-bgp":
            bad["checkpointFoundation"]["value"]["routeServerAsn"] = 65515
        elif mutation == "foreign-vip":
            bad["connectionManifest"]["value"]["firewallVip"] = "10.0.0.1"
        else:
            bad["checkpointFoundation"]["value"]["connectivityMode"] = "vpn"
        with pytest.raises(ValueError):
            validate_checkpoint_foundation(bad, existing.SUBSCRIPTION, group, row["environmentId"], "vmss", "peering")


def test_gaia_peering_configures_each_gateway_without_bgp_or_nat():
    api, logs = vmss.ScaleSetApi(), []
    configurator = vmss.gaia.CheckpointConfigurator(
        api, "00000000-0000-0000-0000-000000000004", "s" * 48, "P" * 16,
        None, None, logs.append, sleep=lambda _seconds: None, gateways=vmss.GATEWAYS,
        internal_load_balancer_ip="172.22.20.4", connectivity_mode="peering")
    assert configurator.run() == BgpStatus(0, 0)
    assert "health-probe-responder-configured" in logs
    assert {targets for name, targets in api.script_targets if name == "faas-probe-responder"} == {
        (gateway.name,) for gateway in vmss.GATEWAYS}
    rules = {body["name"]: body for command, body in api.requests if command == "add-access-rule"}
    assert rules[vmss.gaia.EAST_WEST_RULE]["service"] == rules[vmss.gaia.EGRESS_RULE]["service"] == "Any"
    configurator._run_script = Mock(return_value="faas-peering-routes-configured\n")
    assert configurator.ensure_peering_routes() == BgpStatus(0, 0)
    calls = configurator._run_script.call_args_list
    assert [call.kwargs["target"] for call in calls] == [gateway.name for gateway in vmss.GATEWAYS]
    script = calls[0].args[1]
    assert "set static-route 10.211.0.0/16 nexthop gateway address 172.22.20.1" in script
    assert "set static-route 10.212.0.0/16 nexthop gateway address 172.22.20.1" in script
    assert "bgp" not in script and "nat" not in script
    configurator._run_script.return_value = "failed"
    with pytest.raises(CheckpointGaiaError):
        configurator.ensure_peering_routes()


@pytest.mark.parametrize("change", [
    {"approveLabCosts": False}, {"approveCrossTenantPeering": False}, {"adminAllowedSources": []},
    {"adminAllowedSources": ["0.0.0.0/0"]}, {"workloadSshPublicKey": "PRIVATE KEY"},
    {"customerId": "invalid"}, {"providerSubscriptionId": existing.SUBSCRIPTION},
    {"approveLabCosts": 1}, {"approveCrossTenantPeering": "true"},
])
def test_request_rejects_missing_approval_invalid_keys_and_scope_overrides(change):
    with pytest.raises(ValidationError):
        PeeringLabRequest.model_validate({**REQUEST, **change})


def test_create_is_idempotent_bound_to_enrollment_and_does_not_grant_azure_roles(lab):
    service = lab.service
    result = service.create(PeeringLabRequest.model_validate(REQUEST), OWNER, "request-one")
    assert result["environmentId"] == lab.row["environmentId"]
    assert "request" not in result and "owner" not in result
    assert result["customerGroupId"].startswith("/subscriptions/" + CUSTOMER_SUBSCRIPTION)
    assert result["providerGroupId"].startswith("/subscriptions/" + existing.SUBSCRIPTION)
    service.http.request.assert_not_called()
    with pytest.raises(EnrollmentError, match="IdempotencyConflict"):
        service.create(PeeringLabRequest.model_validate({**REQUEST, "adminAllowedSources": ["1.1.1.1"]}),
                       OWNER, "request-one")
    with pytest.raises(EnrollmentError, match="NotFound"):
        service.advance(result["environmentId"], existing.OTHER)


def test_revoked_or_same_tenant_customer_is_rejected(lab):
    binding = lab.registry.binding.return_value
    lab.registry.binding.return_value = CustomerBinding(**{**binding.__dict__, "status": "Revoked"})
    with pytest.raises(EnrollmentError, match="CustomerNotReady"):
        lab.service.create(PeeringLabRequest.model_validate(REQUEST), OWNER, "different")
    lab.registry.binding.return_value = CustomerBinding(**{**binding.__dict__, "tenant": existing.PROVIDER_TENANT})
    with pytest.raises(EnrollmentError, match="SeparateTenants"):
        lab.service.create(PeeringLabRequest.model_validate(REQUEST), OWNER, "different")


def test_advance_requires_authorization_and_lease(lab):
    lab.service._step = Mock()
    result = lab.service.advance(lab.row["environmentId"], OWNER)
    assert result["status"] == "AwaitingAuthorization"
    lab.service._step.assert_not_called()
    row = authorize(lab)
    row["busyUntil"] = int(time.time()) + 60
    lab.backend.transact([Change(row, row["_etag"])])
    lab.service.advance(row["environmentId"], OWNER)
    lab.service._step.assert_not_called()


def test_resume_persists_stages_and_waits_for_verification_before_ready(lab):
    row = authorize(lab)
    service = lab.service
    calls = []

    def step(current, tokens, evidence):
        calls.append(current["stage"])
        evidence["lastStage"] = current["stage"]
        return True
    service._step = Mock(side_effect=step)
    for stage in range(9):
        result = service.advance(row["environmentId"], OWNER)
        assert result["status"] != "Ready"
        assert result["phase"] == PHASES[stage + 1]
    stored = service._row(row["environmentId"], OWNER)
    assert json.loads(stored["evidence"])["lastStage"] == 8
    for side in ("provider", "customer"):
        service._write_auth(stored, side, {"fixture": "temporary-token-cache"})
    restarted = PeeringLabs(lab.settings, lab.registry, lab.vault, http=Mock())
    restarted._tokens = Mock(side_effect=AssertionError("Cleanup must not load a token"))
    result = restarted.advance(row["environmentId"], OWNER)
    assert result["status"] == "Ready"
    assert calls == list(range(9))
    assert all(not value.enabled for versions in lab.vault.values.values() for value in versions)


@pytest.mark.parametrize("error,status", [
    (EnrollmentError(403, "PeeringArmPermissionRequired"), "NeedsAttention"),
    (EnrollmentError(503, "PeeringArmTemporarilyUnavailable"), "Retrying"),
    (EnrollmentError(422, "PeeringDeploymentFailed"), "Failed"),
    (ValueError("private evidence"), "Failed"),
])
def test_errors_are_visible_and_never_success_shaped(lab, error, status, caplog):
    row = authorize(lab)
    lab.service._step = Mock(side_effect=error)
    result = lab.service.advance(row["environmentId"], OWNER)
    assert result["status"] == status
    assert result["errorCode"]
    assert "private evidence" not in json.dumps(result) + caplog.text
    assert lab.service._row(row["environmentId"], OWNER)["busyUntil"] == 0
    if status == "NeedsAttention":
        assert result["providerAuthorized"] and result["customerAuthorized"]
        lab.service.advance(row["environmentId"], OWNER)
        assert lab.service._step.call_count == 1


def token_cache(lab, side, home):
    lab.service._write_auth(lab.row, side, {"cache": "{}", "account": {"home_account_id": home},
                                          "homeAccount": home})


def test_independent_signed_tenant_accounts_do_not_reset_completed_authorization(lab):
    row = authorize(lab)
    token_cache(lab, "provider", "provider-home-account")
    token_cache(lab, "customer", "customer-home-account")
    lab.service.msal_factory = lambda tenant, cache: SimpleNamespace(
        acquire_token_silent=lambda scopes, **kwargs: {"access_token": tenant + "-token"})
    tokens = PeeringLabs._tokens(lab.service, row)
    assert tokens == {"provider": existing.PROVIDER_TENANT + "-token", "customer": CUSTOMER_TENANT + "-token"}
    assert row["providerAuthorized"] and row["customerAuthorized"]


def test_expired_authorization_invalidates_only_the_affected_tenant(lab):
    row = authorize(lab)
    token_cache(lab, "provider", "provider-home")
    token_cache(lab, "customer", "customer-home")
    lab.service.msal_factory = lambda tenant, cache: SimpleNamespace(
        acquire_token_silent=lambda scopes, **kwargs: (
            {"error": "interaction_required"} if tenant == existing.PROVIDER_TENANT else {"access_token": "valid"}))
    with pytest.raises(PeeringAuthorizationRequired) as error:
        PeeringLabs._tokens(lab.service, row)
    assert error.value.side == "provider"
    assert not row["providerAuthorized"] and row["customerAuthorized"]


def test_resume_reuses_existing_attempt_after_legacy_home_account_rejection(lab):
    row = lab.service._row(lab.row["environmentId"], OWNER)
    row.update(errorCode="PeeringRequiresSameGuestAdministrator", providerAuthorized=False, customerAuthorized=False)
    lab.backend.transact([Change(row, row["_etag"])])
    result = lab.service.resume(row["environmentId"], OWNER)
    assert result["environmentId"] == row["environmentId"]
    assert result["status"] == "Deploying" and result["errorCode"] == ""
    assert result["providerAuthorized"] and result["customerAuthorized"]
    lab.service._tokens.assert_called_once()
    assert lab.service._tokens.call_args.kwargs == {"force_refresh": True}


def test_cancel_unused_pending_attempt_releases_active_slot_without_deleting_resources(lab):
    request = PeeringLabRequest.model_validate(REQUEST)
    lab.service.create(request, OWNER, "second")
    lab.service.create(request, OWNER, "third")
    with pytest.raises(EnrollmentError, match="PeeringLabActiveLimit"):
        lab.service.create(request, OWNER, "blocked")
    result = lab.service.cancel(lab.row["environmentId"], OWNER)
    assert result["status"] == "Failed" and result["errorCode"] == "PeeringLabCancelled"
    assert lab.service.create(request, OWNER, "new-after-cancel")["status"] == "AwaitingAuthorization"
    lab.service.http.request.assert_not_called()
    with pytest.raises(EnrollmentError, match="PeeringLabNotFound"):
        lab.service.cancel(result["environmentId"], existing.OTHER)


def test_four_cross_tenant_peering_directions_use_primary_and_auxiliary_tokens(lab):
    records, writes = {}, []
    def respond(request):
        path = request.url.path
        if request.method == "PUT":
            value = json.loads(request.content)
            value["properties"]["peeringState"] = "Connected"
            records[path] = value
            writes.append(request)
            return httpx.Response(201, json=value)
        return httpx.Response(200, json=records[path]) if path in records else httpx.Response(404)
    lab.service.http = httpx.Client(transport=httpx.MockTransport(respond))
    evidence = {}
    for index in range(8):
        ready = lab.service._peerings(lab.row, {"provider": "provider-token", "customer": "customer-token"}, evidence)
        assert ready is (index == 7)
    assert len(writes) == 4
    assert all(write.url.host == "management.azure.com" for write in writes)
    for write in writes:
        side = "customer" if CUSTOMER_SUBSCRIPTION in write.url.path else "provider"
        other = "provider" if side == "customer" else "customer"
        assert write.headers["Authorization"] == "Bearer " + side + "-token"
        assert write.headers["x-ms-authorization-auxiliary"] == "Bearer " + other + "-token"
        props = json.loads(write.content)["properties"]
        assert props["allowForwardedTraffic"] is True
        assert props["allowGatewayTransit"] is False and props["useRemoteGateways"] is False
    assert all("checkpoint" in write.url.path or "customer-workload" in write.url.path for write in writes)


def test_existing_peering_conflict_is_not_overwritten(lab):
    lab.service._arm = Mock(return_value={"properties": {"remoteVirtualNetwork": {"id": "/foreign"}}})
    with pytest.raises(EnrollmentError, match="Conflict"):
        lab.service._peerings(lab.row, {"provider": "token", "customer": "token"}, {})
    assert lab.service._arm.call_count == 1


def test_arm_permission_errors_never_expose_upstream_tokens(lab):
    lab.service.http = httpx.Client(transport=httpx.MockTransport(
        lambda request: httpx.Response(403, json={"detail": "PRIVATE-UPSTREAM-RESPONSE"})))
    with pytest.raises(EnrollmentError, match="PeeringArmPermissionRequired") as error:
        lab.service._arm("PUT", lab.row["providerGroupId"], "2022-09-01", "PRIVATE-TOKEN", {})
    assert "PRIVATE" not in str(error.value)


def test_device_authorization_checks_signed_tenant_and_provider_administrator(lab):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = jwt.PyJWK(RSAAlgorithm.to_jwk(private.public_key(), as_dict=True))
    lab.service.keys_factory = lambda tenant: SimpleNamespace(get=lambda kid: key, close=lambda: None)
    client = Mock()
    client.initiate_device_flow.return_value = {
        "device_code": "private-device-code", "user_code": "ABCDEF12",
        "verification_uri": "https://microsoft.com/devicelogin", "expires_in": 900,
    }
    client.get_accounts.return_value = [{"home_account_id": "same-home-account"}]
    lab.service.msal_factory = lambda tenant, cache: client
    challenge = lab.service.signin(lab.row["environmentId"], OWNER, "provider")
    assert "device_code" not in challenge
    now = int(time.time())
    claims = {"iss": f"https://login.microsoftonline.com/{existing.PROVIDER_TENANT}/v2.0",
              "aud": lab.settings.oauth_client_id, "tid": existing.PROVIDER_TENANT,
              "oid": existing.OTHER, "iat": now, "nbf": now, "exp": now + 300}
    client.acquire_token_by_device_flow.return_value = {"access_token": "provider-token", "id_token": jwt.encode(
        claims, private, algorithm="RS256", headers={"kid": "fixture"})}
    with pytest.raises(EnrollmentError, match="IdentityMismatch"):
        lab.service.poll_signin(lab.row["environmentId"], OWNER, "provider")
    claims["oid"] = OWNER
    client.acquire_token_by_device_flow.return_value = {"access_token": "provider-token", "id_token": jwt.encode(
        claims, private, algorithm="RS256", headers={"kid": "fixture"})}
    assert lab.service.poll_signin(lab.row["environmentId"], OWNER, "provider") == {"status": "authorized"}
    assert lab.service.poll_signin(lab.row["environmentId"], OWNER, "provider") == {"status": "authorized"}
    assert lab.service._row(lab.row["environmentId"], OWNER)["providerAuthorized"]
    assert lab.vault.values
    assert all(value.options["expires_on"].tzinfo is not None
               for versions in lab.vault.values.values() for value in versions)

def test_signin_cannot_overwrite_a_deployment_lease_or_its_credentials(lab):
    row = authorize(lab)
    row["busyUntil"] = time.time() + 60
    lab.backend.transact([Change(row, row["_etag"])])
    with pytest.raises(EnrollmentError, match="PeeringLabBusy"):
        lab.service.signin(row["environmentId"], OWNER, "provider")
    assert not lab.vault.values


def test_http_surface_is_opt_in_and_admin_authenticated(dependencies, lab):
    client, _, headers = dependencies
    assert client.get("/admin/peering-labs", headers=headers).json() == {"enabled": False, "labs": []}
    assert client.post("/admin/peering-labs", headers=headers, json=REQUEST).status_code == 409
    client.app.state.peering_labs = lab.service
    assert client.get("/admin/peering-labs").status_code == 401
    response = client.post("/admin/peering-labs", headers=headers, json=REQUEST)
    assert response.status_code == 202
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["customerId"] == CUSTOMER
    result = client.post("/admin/peering-labs/" + response.json()["environmentId"] + "/advance", headers=headers, json={})
    assert result.status_code == 200, result.json()
    assert result.json()["status"] == "AwaitingAuthorization"
    bad = client.post("/admin/peering-labs", headers=headers, json={**REQUEST, "approveLabCosts": False})
    assert bad.status_code == 422


def test_actual_orchestration_reconciles_arm_stages_and_never_boots_vms_before_firewall(lab):
    row = authorize(lab)
    foundation, private, group, control, identity = evidence_for(row)
    old = lab.settings.checkpoint
    lab.service.settings = replace(lab.settings, checkpoint=CheckpointSettings(
        old.foundation_template, old.private_template, control, identity["id"],
        old.registry_server, old.image_sha256, old.runner))
    records, writes = {}, []
    def respond(request):
        path = request.url.path
        if path == identity["id"]:
            return httpx.Response(200, json=identity)
        if "/runCommands/" in path:
            return httpx.Response(200, json={"properties": {"instanceView": {
                "executionState": "Succeeded", "exitCode": 0,
                "output": "FAAS_MANA_VERIFIED\nFAAS_ORIGINAL_SOURCE_AND_EGRESS_VERIFIED\n",
            }}})
        if path in ("/subscriptions/" + existing.SUBSCRIPTION, "/subscriptions/" + CUSTOMER_SUBSCRIPTION):
            tenant = existing.PROVIDER_TENANT if path.endswith(existing.SUBSCRIPTION) else CUSTOMER_TENANT
            return httpx.Response(200, json={"tenantId": tenant, "state": "Enabled"})
        if request.method == "GET":
            return httpx.Response(200, json=records[path]) if path in records else httpx.Response(404)
        assert request.method == "PUT"
        document = json.loads(request.content)
        writes.append((path, copy.deepcopy(document), dict(request.headers)))
        document["id"] = path
        if "/deployments/" in path:
            name = path.rsplit("/", 1)[1]
            outputs = foundation if name == "peering-foundation" else private if name == "peering-private" else {}
            document["properties"].update(provisioningState="Succeeded", outputs=outputs)
        elif "/roleAssignments/" in path:
            document["properties"]["scope"] = path.split("/providers/Microsoft.Authorization/")[0]
        elif "/virtualNetworkPeerings/" in path:
            document["properties"]["peeringState"] = "Connected"
        elif "/containerGroups/" in path:
            spec, _ = lab.service._runner_spec(row, {"foundation": foundation, "private": private},
                                             {"provider": "provider-token"})
            document = existing.runner_resource(spec, state="Terminated", exit_code=0)
        records[path] = document
        return httpx.Response(201, json=document)
    lab.service.http = httpx.Client(transport=httpx.MockTransport(respond))
    for _ in range(50):
        result = lab.service.advance(row["environmentId"], OWNER)
        assert result["status"] not in ("Failed", "AwaitingAuthorization", "Retrying"), result
        if result["status"] == "Ready":
            break
    assert result["status"] == "Ready"
    names = [path.rsplit("/", 1)[1] for path, _, _ in writes if "/deployments/" in path]
    assert names == ["peering-foundation", "peering-private", "peering-networks",
                     "peering-workloads", "peering-verification"]
    runner_position = next(i for i, (path, _, _) in enumerate(writes) if "/containerGroups/" in path)
    vm_position = next(i for i, (path, _, _) in enumerate(writes) if path.endswith("/peering-workloads"))
    assert runner_position < vm_position
    peerings = [(path, headers) for path, _, headers in writes if "/virtualNetworkPeerings/" in path]
    assert len(peerings) == 4
    # Every peering write uses the shared peering identity, never the two administrators' user tokens.
    for path, headers in peerings:
        side = "customer" if CUSTOMER_SUBSCRIPTION in path else "provider"
        tenant = CUSTOMER_TENANT if side == "customer" else existing.PROVIDER_TENANT
        other = existing.PROVIDER_TENANT if side == "customer" else CUSTOMER_TENANT
        assert headers["authorization"] == "Bearer " + network_token(tenant)
        assert headers["x-ms-authorization-auxiliary"] == "Bearer " + network_token(other)
    first_peering = next(i for i, (path, _, _) in enumerate(writes) if "/virtualNetworkPeerings/" in path)
    network_roles = [(i, path, document) for i, (path, document, _) in enumerate(writes)
                     if "/roleAssignments/" in path and "/virtualNetworks/" in path]
    assert len(network_roles) == 3 and all(i < first_peering for i, _, _ in network_roles)
    verify = next(document for path, document, _ in writes if path.endswith("/peering-verification"))
    assert verify["properties"]["parameters"]["verifyWorkloads"]["value"] is True
    assert verify["properties"]["parameters"]["deployWorkloads"]["value"] is True


@pytest.mark.parametrize("change", [
    {"exitCode": 1}, {"exitCode": True}, {"output": "FAAS_ORIGINAL_SOURCE_AND_EGRESS_VERIFIED"},
    {"output": "FAAS_MANA_VERIFIED"}, {"executionState": "Failed"},
])
def test_ready_requires_both_verification_markers_and_zero_exit_code(lab, change):
    view = {"executionState": "Succeeded", "exitCode": 0,
            "output": "FAAS_MANA_VERIFIED\nFAAS_ORIGINAL_SOURCE_AND_EGRESS_VERIFIED\n"}
    lab.service._arm = Mock(return_value={"properties": {"instanceView": {**view, **change}}})
    with pytest.raises(EnrollmentError, match="PeeringWorkloadVerificationFailed"):
        lab.service._verify_workload(lab.row, {"customer": "token"}, {})


def test_active_limit_is_atomic_under_concurrent_reservations(lab):
    from concurrent.futures import ThreadPoolExecutor
    request = PeeringLabRequest.model_validate(REQUEST)
    def create(index):
        try:
            return lab.service.create(request, OWNER, "parallel-" + str(index))
        except EnrollmentError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(create, range(5)))
    rows = lab.backend.list_rows(PARTITION, "lab:", 100)
    assert len(rows) == 3
    assert sum(isinstance(result, dict) for result in results) == 2
    assert all(isinstance(result, dict) or result in ("PeeringLabActiveLimit", "PeeringReservationContention")
               for result in results)


@pytest.mark.parametrize("driver,source,success", [
    ("mana", "10.211.0.4", True), ("mlx5", "10.211.0.4", False), ("mana", "172.22.20.5", False),
])
def test_live_verification_requires_actual_mana_and_original_source(monkeypatch, driver, source, success):
    script = (ROOT / "infra/cloud-init/verify-peering.sh").read_text().split("python3 - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    script = script.replace("__SOURCE_IP__", "10.211.0.4").replace("__REMOTE_IP__", "10.212.0.4")
    monkeypatch.setattr(Path, "glob", lambda self, pattern: [SimpleNamespace(resolve=lambda: SimpleNamespace(name=driver))])
    ticks = iter(range(0, 2000, 301))
    monkeypatch.setattr(time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(time, "sleep", lambda seconds: None)
    import urllib.request
    def response(url, timeout):
        import io
        if url.startswith("http:"):
            return io.StringIO(json.dumps({"sourceIp": source}))
        return SimpleNamespace(status=200, __enter__=lambda self: self, __exit__=lambda *args: None)
    class Internet:
        status = 200
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout:
                        response(url, timeout) if url.startswith("http:") else Internet())
    if success:
        exec(compile(script, "verify-peering", "exec"), {})
    else:
        with pytest.raises(SystemExit):
            exec(compile(script, "verify-peering", "exec"), {})


def test_network_roles_are_network_contributor_on_only_the_three_lab_vnets_by_each_tenant(lab):
    writes = []
    def respond(request):
        if request.method == "GET":
            return httpx.Response(404)
        writes.append((request.url.path, json.loads(request.content), request.headers["authorization"]))
        return httpx.Response(201, json={})
    lab.service.http = httpx.Client(transport=httpx.MockTransport(respond))
    evidence = {}
    network = lab.service._network_tokens(lab.row)
    lab.service._network_roles(lab.row, {"provider": "provider-token", "customer": "customer-token"}, network, evidence)
    assert "networkRolesAt" in evidence
    assert len(writes) == 3
    for path, body, authorization in writes:
        scope = path.split("/providers/Microsoft.Authorization/")[0]
        assert scope.split("/providers/Microsoft.Network/virtualNetworks/")[1] in (
            "vnet-cp-security-" + lab.row["environmentId"][:8], "vnet-peering-workload-0", "vnet-peering-workload-1")
        assert body["properties"]["roleDefinitionId"].endswith("/4d97b98b-1d4f-4787-a291-c67834d212e7")
        customer = CUSTOMER_SUBSCRIPTION in path
        assert authorization == "Bearer " + ("customer-token" if customer else "provider-token")
        assert body["properties"]["principalId"] == NETWORK_PRINCIPALS[CUSTOMER_TENANT if customer else existing.PROVIDER_TENANT]


@pytest.mark.parametrize("token,code", [
    (lambda tenant: network_token(tenant, app=str(UUID(int=99))), "PeeringNetworkIdentityInvalid"),
    (lambda tenant: network_token(tenant, idtyp="user"), "PeeringNetworkIdentityInvalid"),
    (lambda tenant: network_token(existing.PROVIDER_TENANT), "PeeringNetworkIdentityInvalid"),
])
def test_network_identity_tokens_must_be_the_peering_app_in_the_requested_tenant(lab, token, code):
    lab.service.network_token_factory = token
    with pytest.raises(EnrollmentError, match=code):
        lab.service._network_tokens(lab.row)


def test_missing_customer_consent_pauses_with_clear_action_and_keeps_signins(lab):
    row = authorize(lab)
    row["stage"] = 5
    lab.backend.transact([Change(row, row["_etag"])])
    def factory(tenant):
        if tenant == CUSTOMER_TENANT:
            raise ClientAuthenticationError("AADSTS700016: private detail token=secret-value")
        return network_token(tenant)
    lab.service.network_token_factory = factory
    result = lab.service.advance(row["environmentId"], OWNER)
    assert result["status"] == "NeedsAttention"
    assert result["errorCode"] == "PeeringCustomerTenantConsentRequired:AADSTS700016"
    assert "secret-value" not in json.dumps(result)
    assert result["providerAuthorized"] and result["customerAuthorized"]


def test_peering_permission_errors_during_role_propagation_are_retried(lab):
    row = authorize(lab)
    row.update(stage=5, evidence=json.dumps({"networkRolesAt": int(time.time())}))
    lab.backend.transact([Change(row, row["_etag"])])
    lab.service._peerings = Mock(side_effect=EnrollmentError(403, "PeeringArmPermissionRequired"))
    result = lab.service.advance(row["environmentId"], OWNER)
    assert result["status"] == "Retrying" and result["errorCode"] == "PeeringRolePropagationPending"
    stored = lab.service._row(row["environmentId"], OWNER)
    stored["evidence"] = json.dumps({"networkRolesAt": int(time.time()) - 3600})
    lab.backend.transact([Change(stored, stored["_etag"])])
    result = lab.service.advance(row["environmentId"], OWNER)
    assert result["status"] == "NeedsAttention" and result["errorCode"] == "PeeringArmPermissionRequired"


def test_unconfigured_network_identity_is_explicit_not_success(lab):
    row = authorize(lab)
    row["stage"] = 5
    lab.backend.transact([Change(row, row["_etag"])])
    lab.service.network_token_factory = None
    result = lab.service.advance(row["environmentId"], OWNER)
    assert result["status"] == "Failed" and result["errorCode"] == "PeeringNetworkIdentityNotConfigured"


def test_resume_extends_deployment_window_and_authorization_cache_expiry(lab):
    row = lab.service._row(lab.row["environmentId"], OWNER)
    row.update(status="NeedsAttention", expiresAt=int(time.time()) + 600)
    lab.backend.transact([Change(row, row["_etag"])])
    for side in ("provider", "customer"):
        lab.service._write_auth(row, side, {"cache": "{}", "account": {"home_account_id": side}})
    lab.service.resume(row["environmentId"], OWNER)
    stored = lab.service._row(row["environmentId"], OWNER)
    assert stored["expiresAt"] > time.time() + 5 * 3600
    for side in ("provider", "customer"):
        latest = lab.vault.values["faas-peering-" + row["environmentId"] + "-" + side][-1]
        assert json.loads(latest.value)["account"] == {"home_account_id": side}
        assert latest.options["expires_on"].timestamp() == stored["expiresAt"]


def failed_runner_lab(lab, stage=6, code="PeeringCheckpointRunnerFailed"):
    row = lab.service._row(lab.row["environmentId"], OWNER)
    row.update(status="Failed", errorCode=code, stage=stage, authRetired=True,
               evidence=json.dumps({"foundation": "kept", "peeringIndex": 8}))
    lab.backend.transact([Change(row, row["_etag"])])
    return row


@pytest.mark.parametrize("code", ["PeeringCheckpointRunnerFailed", "PeeringEvidenceInvalid"])
def test_runner_failure_reopens_for_reauthorization_and_keeps_earlier_evidence(lab, code):
    row = failed_runner_lab(lab, code=code)
    assert lab.service.list(OWNER)[0]["retryable"] is True
    result = lab.service.resume(row["environmentId"], OWNER)
    assert result["status"] == "AwaitingAuthorization" and result["errorCode"] == ""
    assert not result["providerAuthorized"] and not result["customerAuthorized"]
    stored = lab.service._row(row["environmentId"], OWNER)
    evidence = json.loads(stored["evidence"])
    assert evidence == {"foundation": "kept", "peeringIndex": 8, "runnerRetry": True}
    assert stored["stage"] == 6 and stored["authRetired"] is False
    assert stored["expiresAt"] > time.time() + 5 * 3600
    lab.service.http.request.assert_not_called()


@pytest.mark.parametrize("stage,code", [(6, "PeeringLabCancelled"), (6, "PeeringDeploymentFailed"),
                                        (8, "PeeringCheckpointRunnerFailed"), (4, "PeeringEvidenceInvalid")])
def test_only_runner_stage_failures_can_be_reopened(lab, stage, code):
    row = failed_runner_lab(lab, stage, code)
    assert lab.service.list(OWNER)[0]["retryable"] is False
    with pytest.raises(EnrollmentError, match="PeeringLabNotResumable"):
        lab.service.resume(row["environmentId"], OWNER)


def runner_document(state=None, provisioning="Succeeded"):
    current = {"state": state} if state else {}
    return {"properties": {"provisioningState": provisioning, "containers": [{"properties": {
        "instanceView": {"currentState": current}}}]}}


@pytest.mark.parametrize("document,deleted,error", [
    (runner_document("Terminated"), True, None),
    (runner_document(provisioning="Failed"), True, None),
    (runner_document(provisioning="Deleting"), False, None),
    (runner_document("Running"), False, "PeeringRunnerStillActive"),
])
def test_runner_retry_deletes_only_a_stopped_runner(lab, document, deleted, error):
    calls = []
    def arm(method, path, version, token, body=None, *args, **kwargs):
        calls.append(method)
        return document if method == "GET" else {}
    lab.service._arm = arm
    lab.service._runner_spec = Mock(return_value=(SimpleNamespace(job_id="/subscriptions/x/runner"), b"{}"))
    evidence = {"runnerRetry": True}
    if error:
        with pytest.raises(EnrollmentError, match=error):
            lab.service._runner(lab.row, evidence, {"provider": "token"})
    else:
        assert lab.service._runner(lab.row, evidence, {"provider": "token"}) is False
    assert ("DELETE" in calls) is deleted
    assert evidence == {"runnerRetry": True}


def test_runner_retry_relaunches_once_the_old_runner_is_gone(lab):
    calls = []
    def arm(method, path, version, token, body=None, *args, **kwargs):
        calls.append(method)
        return None if method == "GET" else {}
    lab.service._arm = arm
    lab.service._runner_spec = Mock(return_value=(SimpleNamespace(job_id="/subscriptions/x/runner"), b"{}"))
    import service.peering_lab as module
    original = module.validate_checkpoint_runner_request
    module.validate_checkpoint_runner_request = lambda spec, body: None
    try:
        evidence = {"runnerRetry": True}
        assert lab.service._runner(lab.row, evidence, {"provider": "token"}) is False
    finally:
        module.validate_checkpoint_runner_request = original
    assert calls == ["GET", "PUT"] and evidence == {}


def observe_runner(lab, monkeypatch, outcome, evidence):
    import service.peering_lab as module
    lab.service._arm = lambda *args, **kwargs: {"properties": {}}
    lab.service._runner_spec = Mock(return_value=(SimpleNamespace(job_id="/subscriptions/x/runner"), b"{}"))
    def validate(current, spec):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    monkeypatch.setattr(module, "validate_checkpoint_runner_observation", validate)
    return lab.service._runner(lab.row, evidence, {"provider": "token"})


def test_transient_runner_evidence_rejection_waits_instead_of_failing(lab, monkeypatch):
    from service.checkpoint_runner import CheckpointRunnerError
    evidence = {}
    assert observe_runner(lab, monkeypatch, CheckpointRunnerError("Invalid Check Point runner status"), evidence) is False
    assert evidence["runnerRejectedSince"] <= time.time()
    running = SimpleNamespace(state="running", exit_code=None)
    assert observe_runner(lab, monkeypatch, running, evidence) is False
    assert "runnerRejectedSince" not in evidence


def test_persistent_runner_evidence_rejection_still_fails(lab, monkeypatch):
    from service.checkpoint_runner import CheckpointRunnerError
    evidence = {"runnerRejectedSince": int(time.time()) - 301}
    with pytest.raises(CheckpointRunnerError):
        observe_runner(lab, monkeypatch, CheckpointRunnerError("Invalid Check Point runner image"), evidence)


def test_transient_runner_rejection_is_persisted_by_advance_not_failed(lab, monkeypatch):
    from service.checkpoint_runner import CheckpointRunnerError
    row = authorize(lab)
    row["stage"] = 6
    lab.backend.transact([Change(row, row["_etag"])])
    lab.service._tokens = Mock(return_value={"provider": "p", "customer": "c"})
    lab.service._arm = lambda *args, **kwargs: {"properties": {}}
    lab.service._runner_spec = Mock(return_value=(SimpleNamespace(job_id="/subscriptions/x/runner"), b"{}"))
    import service.peering_lab as module
    monkeypatch.setattr(module, "validate_checkpoint_runner_observation",
                        Mock(side_effect=CheckpointRunnerError("Invalid Check Point runner status")))
    result = lab.service.advance(row["environmentId"], OWNER)
    assert result["status"] == "Deploying" and result["errorCode"] == ""
    stored = lab.service._row(row["environmentId"], OWNER)
    assert stored["stage"] == 6 and "runnerRejectedSince" in json.loads(stored["evidence"])


def test_remove_hides_only_failed_labs_and_never_calls_azure(lab):
    with pytest.raises(EnrollmentError, match="PeeringLabNotRemovable"):
        lab.service.remove(lab.row["environmentId"], OWNER)
    row = failed_runner_lab(lab)
    row = lab.service._row(row["environmentId"], OWNER)
    row["authRetired"] = False
    lab.backend.transact([Change(row, row["_etag"])])
    lab.service._write_auth(row, "provider", {"cache": "{}"})
    assert lab.service.remove(row["environmentId"], OWNER) == {"environmentId": row["environmentId"], "removed": True}
    assert lab.service.list(OWNER) == []
    assert all(not value.enabled for versions in lab.vault.values.values() for value in versions)
    with pytest.raises(EnrollmentError, match="PeeringLabNotFound"):
        lab.service.remove(row["environmentId"], existing.OTHER)
    lab.service.http.request.assert_not_called()
