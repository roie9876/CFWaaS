import copy
import hashlib
import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import httpx
import jwt
import pytest
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError, ServiceResponseError
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import HTTPException
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm
from pydantic import ValidationError

from service.api import create_app, public_operation
from service.auth import Authenticator, Owner, TrustedKeys
from service.azure_data import SecretMaterial, TableBackend, Vault, secret_names
from service.config import Customer, Settings, WorkerSettings, endpoint
from service.checkpoint_apply_journal import CheckpointApplyJournal, CheckpointApplyStateError
from service.checkpoint_credential_journal import (
    CheckpointCredentialJournal, CheckpointCredentialStateError,
)
from service.checkpoint_credentials import generate_checkpoint_credentials
from service.checkpoint_runner_journal import CheckpointRunnerJournal, CheckpointRunnerStateError
from service.checkpoint_runner import (
    CheckpointRunnerError, CheckpointRunnerObserver, build_checkpoint_runner_request, build_checkpoint_runner_spec,
    validate_checkpoint_runner_observation, validate_checkpoint_runner_request,
)
from service.checkpoint_runner_config import (
    CheckpointRunnerConfigError, CheckpointRunnerSettings, ensure_checkpoint_runner_credentials,
    load_checkpoint_runner_config, read_checkpoint_runner_inputs,
)
from service.checkpoint_vault import (
    CONTENT_TYPE, CheckpointCredentialPending, CheckpointCredentialVault, CheckpointVaultError,
)
from service.models import (ConnectionManifest, EnvironmentRequest, parse_stored_environment_request,
                            stored_environment_request)
from service.provisioner import AzureArm, ProvisionError, Provisioner
from service.store import Change, Conflict, DomainError, Lease, LostLease, Store, StoreUnavailable
from service.templates import NETWORK_PARAMETERS, Templates
from service.worker import Worker

TENANT = "00000000-0000-0000-0000-000000000001"
PRINCIPAL = "00000000-0000-0000-0000-000000000002"
CLIENT = "00000000-0000-0000-0000-000000000003"
OTHER = "00000000-0000-0000-0000-000000000004"
SUBSCRIPTION = "00000000-0000-0000-0000-000000000005"
AUDIENCE = "00000000-0000-0000-0000-000000000006"
PROVIDER_TENANT = "00000000-0000-0000-0000-000000000007"
API_PRINCIPAL = "00000000-0000-0000-0000-000000000008"
API_CLIENT = "00000000-0000-0000-0000-000000000009"
OWNER = Owner(TENANT, PRINCIPAL, CLIENT)
RUNNER_SETTINGS = CheckpointRunnerSettings(
    "1.2.3", "2.3.4", "Standard_D4ds_v5", "Standard_D4ds_v5",
    Ed25519PublicKey.from_public_bytes(bytes(range(32))).public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode())
ENDPOINT = {"publicIp": "8.8.8.8", "bgpAddress": "10.0.0.4", "asn": 64512}
NETWORK = {"mode": "network", "customerIngress": ENDPOINT,
           "customerDelivery": {**ENDPOINT, "publicIp": "1.1.1.1"}}
MANIFEST = {"providerIngress": ENDPOINT, "providerDelivery": ENDPOINT,
            "firewallVip": "10.0.0.100"}


class MemoryBackend:
    """Test-only atomic backend; never imported or available as a production fallback."""

    def __init__(self):
        self.rows = {}
        self.lock = threading.RLock()
        self.version = 0
        self.conflicts = 0

    def get(self, partition, key):
        with self.lock:
            return copy.deepcopy(self.rows.get((partition, key)))

    def transact(self, changes):
        with self.lock:
            if self.conflicts:
                self.conflicts -= 1
                raise Conflict()
            for change in changes:
                key = (change.row["PartitionKey"], change.row["RowKey"])
                current = self.rows.get(key)
                if ((change.etag is None and current is not None)
                        or (change.etag is not None and
                            (current is None or current["_etag"] != change.etag))):
                    raise Conflict()
            for change in changes:
                self.version += 1
                row = copy.deepcopy(change.row)
                row["_etag"] = str(self.version)
                self.rows[(row["PartitionKey"], row["RowKey"])] = row

    def jobs(self, partition):
        with self.lock:
            return [copy.deepcopy(row) for (part, key), row in self.rows.items()
                    if part == partition and key.startswith("job:")
                    and row["status"] in ("pending", "retry", "busy")]


@pytest.fixture
def settings():
    return Settings(AUDIENCE, Customer(TENANT, PRINCIPAL, CLIENT),
                    "https://test.table.core.windows.net", "https://test.vault.azure.net")


@pytest.fixture
def backend():
    return MemoryBackend()


@pytest.fixture
def store(settings, backend):
    return Store(backend, settings)


@pytest.fixture(scope="session")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def claims():
    now = int(time.time())
    return {"aud": AUDIENCE, "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
            "tid": TENANT, "oid": PRINCIPAL, "azp": CLIENT, "idtyp": "app",
            "roles": ["FirewallDeployment.Request"], "ver": "2.0",
            "exp": now + 600, "nbf": now - 10, "iat": now - 10}


def make_key_client(signing_key, tenant):
    calls = []
    jwk = json.loads(RSAAlgorithm.to_jwk(signing_key.public_key()))
    jwk.update(kid="valid", use="sig", alg="RS256")

    def handler(request):
        calls.append(str(request.url))
        if str(request.url).endswith("openid-configuration"):
            return httpx.Response(200, json={
                "issuer": f"https://login.microsoftonline.com/{tenant}/v2.0",
                "jwks_uri": f"https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"})
        return httpx.Response(200, json={"keys": [jwk]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    return client, calls


@pytest.fixture
def key_client(signing_key):
    return make_key_client(signing_key, TENANT)


@pytest.fixture
def auth(settings, key_client):
    keys = TrustedKeys(TENANT, key_client[0])
    yield Authenticator(settings, keys)
    keys.close()


@pytest.fixture
def provider_settings(settings):
    return replace(settings, customer=Customer(TENANT, API_PRINCIPAL, API_CLIENT),
                   auth_mode="provider-api-client", authority_tenant=PROVIDER_TENANT)


@pytest.fixture
def provider_claims(claims):
    return {**claims, "tid": PROVIDER_TENANT,
            "iss": f"https://login.microsoftonline.com/{PROVIDER_TENANT}/v2.0",
            "oid": API_PRINCIPAL, "azp": API_CLIENT}


@pytest.fixture
def provider_auth(provider_settings, signing_key):
    client, _ = make_key_client(signing_key, PROVIDER_TENANT)
    keys = TrustedKeys(PROVIDER_TENANT, client)
    yield Authenticator(provider_settings, keys)
    keys.close()


def token(signing_key, claims, **changes):
    return jwt.encode({**claims, **changes}, signing_key, algorithm="RS256",
                      headers={"kid": "valid"})


@pytest.fixture
def api(settings, store, auth):
    vault = Mock(spec=Vault)
    vault.read.side_effect = lambda name, version=None: "super-secret-" + name.rsplit("-", 1)[-1]
    with TestClient(create_app(settings, store, auth, vault),
                    raise_server_exceptions=False) as client:
        yield client, vault


def test_valid_jwt_cached_and_only_trusted_metadata(auth, signing_key, claims, key_client):
    bearer = "Bearer " + token(signing_key, claims)
    assert auth.authenticate(bearer) == OWNER
    assert auth.authenticate(bearer) == OWNER
    assert key_client[1] == [
        f"https://login.microsoftonline.com/{TENANT}/v2.0/.well-known/openid-configuration",
        f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys"]


def test_provider_jwt_maps_to_business_owner_and_partition(
        provider_auth, provider_settings, provider_claims, signing_key, backend):
    owner = Owner(TENANT, API_PRINCIPAL, API_CLIENT)
    bearer = "Bearer " + token(signing_key, provider_claims)
    assert provider_auth.authenticate(bearer) == owner
    store = Store(backend, provider_settings)
    with TestClient(create_app(provider_settings, store, provider_auth, Mock(spec=Vault))) as client:
        headers = {"Authorization": bearer, "Idempotency-Key": "provider-client"}
        response = client.post("/v1/environments", json={}, headers=headers)
        assert response.status_code == 202
        environment_id = response.json()["environmentId"]
        row = store.owned(owner, environment_id)
        assert (row["tenant"], row["principal"], row["client"]) == (
            TENANT, API_PRINCIPAL, API_CLIENT)
        assert client.get(response.headers["location"], headers=headers).status_code == 200
        assert client.post("/v1/environments", json={}, headers={
            **headers, "Idempotency-Key": "second"}).status_code == 202
        assert client.post("/v1/environments", json={}, headers={
            **headers, "Idempotency-Key": "third"}).status_code == 429
    assert store.partition == TENANT
    assert {partition for partition, _ in backend.rows} == {TENANT}
    quota = backend.rows[(TENANT, "quota")]
    assert quota["allocated"] == 2
    assert json.loads(quota["callers"]) == {owner.key: 2}


@pytest.mark.parametrize("changes,status", [
    ({"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "tid": TENANT}, 401),
    ({"tid": TENANT}, 401),
    ({"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0"}, 401),
    ({"iss": f"https://login.microsoftonline.com/{PROVIDER_TENANT}/v2.0/"}, 401),
    ({"aud": CLIENT}, 401), ({"aud": [AUDIENCE]}, 401),
    ({"aud": f"api://{AUDIENCE}"}, 401),
    ({"oid": PRINCIPAL}, 403), ({"azp": CLIENT}, 403),
    ({"appid": CLIENT}, 403), ({"roles": []}, 403),
    ({"roles": ["Other"]}, 403), ({"roles": "FirewallDeployment.Request"}, 403),
    ({"idtyp": "user"}, 403), ({"scp": ""}, 403),
    ({"scp": "FirewallDeployment.Request"}, 403),
])
def test_provider_jwt_rejects_claims(
        provider_auth, signing_key, provider_claims, changes, status):
    with pytest.raises(HTTPException) as caught:
        provider_auth.authenticate("Bearer " + token(signing_key, provider_claims, **changes))
    assert caught.value.status_code == status


def test_provider_jwt_rejects_unsigned_and_wrong_signature(provider_auth, provider_claims):
    unsigned = jwt.encode(provider_claims, key=None, algorithm="none", headers={"kid": "valid"})
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for encoded in (unsigned, token(other, provider_claims)):
        with pytest.raises(HTTPException) as caught:
            provider_auth.authenticate("Bearer " + encoded)
        assert caught.value.status_code == 401


def test_authenticator_pins_issuer_independently_of_injected_keys(
        provider_settings, key_client, signing_key, provider_claims):
    keys = TrustedKeys(TENANT, key_client[0])
    try:
        auth = Authenticator(provider_settings, keys)
        with pytest.raises(HTTPException) as caught:
            auth.authenticate("Bearer " + token(
                signing_key, provider_claims,
                iss=f"https://login.microsoftonline.com/{TENANT}/v2.0"))
        assert caught.value.status_code == 401
    finally:
        keys.close()


def test_api_startup_uses_provider_authority(monkeypatch, provider_settings):
    from service import api

    monkeypatch.setattr(api.Settings, "from_env", Mock(return_value=provider_settings))
    factories = {}
    for name in ("ManagedIdentityCredential", "TableBackend", "Vault", "TrustedKeys"):
        factories[name] = Mock()
        monkeypatch.setattr(api, name, factories[name])
    with TestClient(api.create_app()) as client:
        assert client.get("/healthz").status_code == 200
        assert client.app.state.store.partition == TENANT
        factories["TrustedKeys"].assert_called_once_with(PROVIDER_TENANT)
    factories["TrustedKeys"].return_value.close.assert_called_once_with()


@pytest.mark.parametrize("changes,status", [
    ({"aud": "evil"}, 401), ({"aud": [AUDIENCE, "evil"]}, 401),
    ({"iss": "https://evil.example/v2.0"}, 401), ({"tid": OTHER}, 401),
    ({"ver": "1.0"}, 401), ({"exp": 1}, 401), ({"nbf": 9999999999}, 401),
    ({"iat": 9999999999}, 401), ({"roles": []}, 403),
    ({"roles": "FirewallDeployment.Request"}, 403), ({"roles": ["Other"]}, 403),
    ({"idtyp": "user"}, 403), ({"scp": ""}, 403),
    ({"scp": "FirewallDeployment.Request"}, 403), ({"oid": OTHER}, 403),
    ({"azp": OTHER}, 403), ({"appid": OTHER}, 403),
])
def test_jwt_rejects_claims(auth, signing_key, claims, changes, status):
    with pytest.raises(HTTPException) as caught:
        auth.authenticate("Bearer " + token(signing_key, claims, **changes))
    assert caught.value.status_code == status


@pytest.mark.parametrize("missing", ["exp", "nbf", "iat", "iss", "aud", "tid", "oid", "ver", "idtyp"])
def test_required_claims(auth, signing_key, claims, missing):
    del claims[missing]
    with pytest.raises(HTTPException) as caught:
        auth.authenticate("Bearer " + token(signing_key, claims))
    assert caught.value.status_code == 401


def test_appid_fallback_and_matching_appid(auth, signing_key, claims):
    assert auth.authenticate("Bearer " + token(signing_key, claims, appid=CLIENT)) == OWNER
    del claims["azp"]
    assert auth.authenticate("Bearer " + token(signing_key, claims, appid=CLIENT)) == OWNER


@pytest.mark.parametrize("authorization", [None, "", "Basic xyz", "Bearer junk",
                                         "Bearer " + "x" * 17000])
def test_bad_authorization(auth, authorization):
    with pytest.raises(HTTPException) as caught:
        auth.authenticate(authorization)
    assert caught.value.status_code == 401


def test_wrong_signature_and_algorithm(auth, signing_key, claims):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(HTTPException):
        auth.authenticate("Bearer " + token(other, claims))
    encoded = jwt.encode(claims, "x" * 32, algorithm="HS256", headers={"kid": "valid"})
    with pytest.raises(HTTPException):
        auth.authenticate("Bearer " + encoded)


def test_missing_kid_bounded_refresh(auth, signing_key, claims, key_client):
    for kid in ("unrecognized1", "unrecognized2", "unrecognized3"):
        bad = jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": kid})
        with pytest.raises(HTTPException):
            auth.authenticate("Bearer " + bad)
    assert len(key_client[1]) == 2


@pytest.mark.parametrize("uri", ["https://evil.example/keys",
                               "http://login.microsoftonline.com/common/discovery/v2.0/keys",
                               "https://login.microsoftonline.com.evil.example/keys"])
def test_discovery_refuses_untrusted_jwks(uri):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, json={
            "issuer": f"https://login.microsoftonline.com/{TENANT}/v2.0", "jwks_uri": uri})

    keys = TrustedKeys(TENANT, httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(ValueError):
        keys.get("valid")
    assert calls == [keys.metadata]
    keys.close()


@pytest.mark.parametrize("body", [
    {"region": "westus"}, {"tier": "premium"}, {"mode": "script"},
    {"template": {}}, {"resourceGroup": "other"}, {"command": "echo"},
    {"mode": "network"}, {"customerIngress": ENDPOINT},
    {**NETWORK, "customerIngress": {**ENDPOINT, "publicIp": "10.0.0.2"}},
    {**NETWORK, "customerIngress": {**ENDPOINT, "publicIp": "::1"}},
    {**NETWORK, "customerIngress": {**ENDPOINT, "publicIp": ".".join(("224", "0", "0", "1"))}},
    {**NETWORK, "customerIngress": {**ENDPOINT, "bgpAddress": "8.8.8.8"}},
    {**NETWORK, "customerIngress": {**ENDPOINT, "bgpAddress": "127.0.0.1"}},
    {**NETWORK, "customerIngress": {**ENDPOINT, "asn": 65535}},
    {**NETWORK, "customerIngress": {**ENDPOINT, "asn": 64511}},
    {**NETWORK, "customerIngress": {**ENDPOINT, "asn": "64512"}},
    {**NETWORK, "customerIngress": {**ENDPOINT, "resourceId": "/subscriptions/evil"}},
    {**NETWORK, "_faasParallelProviderNetworking": True},
])
def test_strict_request_refusals(body):
    with pytest.raises(ValidationError):
        EnvironmentRequest.model_validate(body)


def test_request_canonical_digest():
    default = EnvironmentRequest()
    explicit = EnvironmentRequest.model_validate({"mode": "proof", "tier": "lab",
                                                  "region": "eastus2"})
    assert default.digest() == explicit.digest()
    assert EnvironmentRequest.model_validate(NETWORK).mode == "network"

    legacy = {"region": "eastus2", "tier": "lab", "mode": "proof",
              "customerIngress": None, "customerDelivery": None}
    assert default.canonical() == json.dumps(legacy, sort_keys=True, separators=(",", ":"))
    assert default.digest() == EnvironmentRequest(firewallType="ubuntu").digest()
    assert EnvironmentRequest(firewallType="checkpoint-byol").digest() != default.digest()


def test_checkpoint_selection_is_authenticated_and_fails_before_reservation(api, store, signing_key, claims):
    client, _ = api
    headers = {"Authorization": "Bearer " + token(signing_key, claims), "Idempotency-Key": "checkpoint"}
    path = "/v1/firewall-types/checkpoint-byol/readiness"
    assert client.get(path).status_code == 401
    response = client.get(path, headers=headers)
    assert response.status_code == 409
    assert response.json() == {"detail": "CheckpointDeploymentUnavailable"}
    for body in ({"firewallType": "checkpoint-byol"}, {**NETWORK, "firewallType": "checkpoint-byol"}):
        response = client.post("/v1/environments", json=body, headers=headers)
        assert response.status_code == 409
        assert response.json() == {"detail": "CheckpointDeploymentUnavailable"}
    assert not store.backend.rows


def test_explicit_ubuntu_keeps_existing_idempotency_and_stored_request(store):
    original = store.reserve(OWNER, "legacy-ubuntu", EnvironmentRequest.model_validate(NETWORK))
    explicit = store.reserve(OWNER, "legacy-ubuntu",
                             EnvironmentRequest.model_validate({**NETWORK, "firewallType": "ubuntu"}))
    assert original["environmentId"] == explicit["environmentId"]
    assert "firewallType" not in json.loads(str(original["request"]))


def test_api_health_and_missing_auth(api):
    client, _ = api
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/healthz").headers["cache-control"] == "no-store"
    assert client.post("/v1/environments", json={}).status_code == 401
    assert client.get("/openapi.json").status_code == 404


def test_api_idempotency_status_secret_separation(api, store, signing_key, claims):
    client, vault = api
    headers = {"Authorization": "Bearer " + token(signing_key, claims), "Idempotency-Key": "one"}
    assert client.post("/v1/environments", json={}, headers={
        "Authorization": headers["Authorization"]}).status_code == 422
    response = client.post("/v1/environments", json=NETWORK, headers=headers)
    assert response.status_code == 202
    environment_id = response.json()["environmentId"]
    assert client.post("/v1/environments", json=NETWORK, headers=headers).json() == response.json()
    assert client.post("/v1/environments", json={}, headers=headers).status_code == 409
    assert client.get(response.headers["location"], headers=headers).status_code == 200
    material_url = f"/v1/environments/{environment_id}/connection-material"
    assert client.get(material_url, headers=headers).status_code == 409
    lease = store.claim(environment_id, "worker")
    store.bind_secret_versions(lease, {"ingress": "version-one", "delivery": "version-two"})
    store.finish(lease, "Ready", MANIFEST)
    ordinary = client.get(response.headers["location"], headers=headers)
    assert ordinary.json()["connectionManifest"] == MANIFEST
    assert "SharedKey" not in ordinary.text and "super-secret" not in ordinary.text
    material = client.get(material_url, headers=headers)
    assert material.status_code == 200
    assert material.headers["cache-control"] == "no-store"
    assert set(material.json()) == {"environmentId", "ingressSharedKey", "deliverySharedKey"}
    assert [call.args[0] for call in vault.read.call_args_list] == list(secret_names(environment_id))


def test_parallel_operation_preserves_connection_material_access(
        settings, backend, auth, signing_key, claims):
    configured = replace(settings, parallel_provider_networking=True)
    store = Store(backend, configured)
    vault = Mock(spec=Vault)
    vault.read.side_effect = ["ingress-secret", "delivery-secret"]
    headers = {"Authorization": "Bearer " + token(signing_key, claims), "Idempotency-Key": "parallel-api"}
    with TestClient(create_app(configured, store, auth, vault), raise_server_exceptions=False) as client:
        response = client.post("/v1/environments", json=NETWORK, headers=headers)
        assert response.status_code == 202
        environment_id = response.json()["environmentId"]
        lease = store.claim(environment_id, "worker")
        store.bind_secret_versions(lease, {"ingress": "version-one", "delivery": "version-two"})
        store.finish(lease, "Ready", MANIFEST)

        material = client.get(f"/v1/environments/{environment_id}/connection-material", headers=headers)

    assert material.status_code == 200
    assert material.headers["cache-control"] == "no-store"
    assert set(material.json()) == {"environmentId", "ingressSharedKey", "deliverySharedKey"}


def test_api_rejects_other_caller_and_tenant(api, signing_key, claims):
    client, vault = api
    good = {"Authorization": "Bearer " + token(signing_key, claims), "Idempotency-Key": "own"}
    environment_id = client.post("/v1/environments", headers=good, json={}).json()["environmentId"]
    for changes, status in [({"oid": OTHER}, 403), ({"tid": OTHER}, 401)]:
        headers = {"Authorization": "Bearer " + token(signing_key, claims, **changes)}
        assert client.get(f"/v1/operations/{environment_id}", headers=headers).status_code == status
        assert client.get(f"/v1/environments/{environment_id}/connection-material",
                          headers=headers).status_code == status
    vault.read.assert_not_called()


def test_owned_hides_same_tenant_different_caller_and_foreign_customer(store):
    operation = store.reserve(OWNER, "own", EnvironmentRequest())
    for owner in (Owner(TENANT, OTHER, CLIENT), Owner(TENANT, PRINCIPAL, OTHER),
                  Owner(OTHER, PRINCIPAL, CLIENT)):
        with pytest.raises(DomainError) as caught:
            store.owned(owner, str(operation["environmentId"]))
        assert caught.value.status == 404


def test_api_missing_operation_and_proof_no_secrets(api, signing_key, claims, store):
    client, vault = api
    headers = {"Authorization": "Bearer " + token(signing_key, claims), "Idempotency-Key": "proof"}
    assert client.get(f"/v1/operations/{uuid4()}", headers=headers).status_code == 404
    environment_id = client.post("/v1/environments", headers=headers, json={}).json()["environmentId"]
    store.finish(store.claim(environment_id, "worker"), "Ready")
    assert client.get(f"/v1/environments/{environment_id}/connection-material",
                      headers=headers).status_code == 409
    vault.read.assert_not_called()


def test_api_safe_dependency_failure(api, store, signing_key, claims, monkeypatch, caplog):
    client, _ = api
    monkeypatch.setattr(store, "reserve", Mock(side_effect=RuntimeError("PRIVATE-TOKEN")))
    response = client.post("/v1/environments", json={}, headers={
        "Authorization": "Bearer " + token(signing_key, claims), "Idempotency-Key": "key"})
    assert response.status_code == 503
    assert "PRIVATE-TOKEN" not in response.text
    assert "PRIVATE-TOKEN" not in caplog.text
    assert "code=ApiDependencyUnavailable" in caplog.text


def test_authenticated_readiness_reports_only_safe_dependency_codes(api, store, signing_key, claims, monkeypatch):
    client, _ = api
    headers = {"Authorization": "Bearer " + token(signing_key, claims)}
    assert client.get("/v1/readiness").status_code == 401
    assert client.get("/v1/readiness", headers=headers).json() == {"status": "ready"}
    monkeypatch.setattr(store.backend, "get", Mock(side_effect=ValueError("PRIVATE-DEPENDENCY-DETAIL")))
    response = client.get("/v1/readiness", headers=headers)
    assert response.status_code == 503
    assert response.json()["detail"]["component"] == "operation-store"
    assert response.json()["detail"]["type"] == "ValueError"
    assert "PRIVATE-DEPENDENCY-DETAIL" not in response.text


def test_validation_errors_never_echo_tokens_or_customer_payload(api, signing_key, claims):
    client, _ = api
    response = client.post("/v1/environments", json={"token": "PRIVATE-BODY-TOKEN"}, headers={
        "Authorization": "Bearer " + token(signing_key, claims), "Idempotency-Key": "key"})
    assert response.status_code == 422
    assert response.json() == {"detail": "InvalidRequest"}
    assert "PRIVATE-BODY-TOKEN" not in response.text


@pytest.mark.parametrize("key", ["", "a" * 129, "space here", "\n", "ø"])
def test_invalid_idempotency_keys(store, key):
    with pytest.raises(DomainError) as caught:
        store.reserve(OWNER, key, EnvironmentRequest())
    assert caught.value.code == "InvalidIdempotencyKey"
    assert not store.backend.rows


def test_atomic_quota_and_idempotency_under_concurrency(settings, backend):
    configured = replace(settings, max_caller_active=4)
    stores = [Store(backend, configured) for _ in range(10)]

    def reserve(index):
        try:
            return stores[index].reserve(OWNER, "same", EnvironmentRequest())["environmentId"]
        except DomainError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(reserve, range(10)))
    assert len(set(results)) == 1
    assert backend.get(TENANT, "quota")["allocated"] == 1
    assert len(backend.rows) == 4
    assert Store(backend, configured).owned(OWNER, results[0])["status"] == "Pending"


def test_ready_allocations_are_retained_without_a_capacity_limit(settings, backend):
    store = Store(backend, replace(settings, max_caller_active=1))
    op = store.reserve(OWNER, "1", EnvironmentRequest())
    with pytest.raises(DomainError) as caught:
        store.reserve(OWNER, "2", EnvironmentRequest())
    assert caught.value.code == "CallerActiveLimit"
    store.finish(store.claim(str(op["environmentId"]), "w"), "Ready")
    quota = backend.get(TENANT, "quota")
    assert (quota["allocated"], quota["active"]) == (1, 0)
    for index in range(2, 13):
        created = store.reserve(OWNER, str(index), EnvironmentRequest())
        store.finish(store.claim(str(created["environmentId"]), "w"), "Ready")
    assert backend.get(TENANT, "quota")["allocated"] == 12
    assert store.reserve(OWNER, "1", EnvironmentRequest())["status"] == "Ready"


def test_allocation_tracking_keeps_active_limits(settings, backend):
    store = Store(backend, replace(settings, max_caller_active=2))
    store.reserve(OWNER, "1", EnvironmentRequest())
    store.reserve(OWNER, "2", EnvironmentRequest())
    with pytest.raises(DomainError) as caught:
        store.reserve(OWNER, "3", EnvironmentRequest())
    assert caught.value.code == "CallerActiveLimit"


def test_failure_reconciliation_releases_and_idempotency_never_resets(store, backend):
    op = store.reserve(OWNER, "1", EnvironmentRequest())
    environment_id = str(op["environmentId"])
    store.finish(store.claim(environment_id, "w"), "Failed", code="DeploymentFailed", release=True)
    assert backend.get(TENANT, "quota")["allocated"] == 0
    assert store.reserve(OWNER, "1", EnvironmentRequest())["status"] == "Failed"
    assert backend.get(TENANT, "quota")["allocated"] == 0


@pytest.fixture
def failed_isolated_group(settings, backend):
    configured = replace(settings, auth_mode="provider-api-registry",
                         authority_tenant=PROVIDER_TENANT, provider_group_mode="isolated")
    store = Store(backend, configured)
    operation = store.reserve(OWNER, "group-retry", EnvironmentRequest.model_validate(NETWORK))
    environment_id = str(operation["environmentId"])
    lease = store.claim(environment_id, "worker")
    store.begin_provider_group(lease)
    store.finish(lease, "Failed", code="GroupOwnershipError")
    return store, environment_id, lease


def test_group_retry_is_atomic_owner_bound_and_keeps_allocation(failed_isolated_group, backend):
    store, environment_id, old_lease = failed_isolated_group
    before = store.owned(OWNER, environment_id)
    quota_before = backend.get(store.partition, "quota")
    with pytest.raises(DomainError) as denied:
        store.retry_failed_group(Owner(TENANT, OTHER, CLIENT), environment_id)
    assert denied.value.code == "NotFound"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _: store.retry_failed_group(OWNER, environment_id), range(8)))
    assert all(result["status"] == "Pending" for result in results)
    after = store.owned(OWNER, environment_id)
    quota_after = backend.get(store.partition, "quota")
    assert after["providerGroupName"] == before["providerGroupName"]
    assert after["providerGroupState"] == "creating"
    assert after["request"] == before["request"]
    assert (quota_after["allocated"], quota_after["allocations"]) == (
        quota_before["allocated"], quota_before["allocations"])
    assert quota_after["active"] == 1
    assert json.loads(quota_after["callers"])[OWNER.key] == 1
    lease = store.claim(environment_id, "new-worker")
    assert lease.fence == old_lease.fence + 1
    with pytest.raises(LostLease):
        store.finish(old_lease, "Ready")
    store.finish(lease, "Ready")
    assert store.retry_failed_group(OWNER, environment_id)["status"] == "Ready"
    assert backend.get(store.partition, "quota")["active"] == 0


@pytest.mark.parametrize("change", ["different_error", "bound_group", "secrets", "exhausted", "allocation"])
def test_group_retry_rejects_ineligible_state(failed_isolated_group, backend, change):
    store, environment_id, _ = failed_isolated_group
    operation = store.owned(OWNER, environment_id)
    if change == "different_error":
        operation["errorCode"] = "DeploymentFailed"
    elif change == "bound_group":
        operation["providerGroupState"] = "created"
    elif change == "secrets":
        operation["secretVersions"] = '{"ingress":"version"}'
    if change in {"different_error", "bound_group", "secrets"}:
        backend.transact([Change(operation, operation["_etag"])])
    elif change == "exhausted":
        job = backend.get(store.partition, "job:" + environment_id)
        job["attempts"] = store.settings.max_attempts
        backend.transact([Change(job, job["_etag"])])
    else:
        quota = backend.get(store.partition, "quota")
        quota["allocated"] = 0
        backend.transact([Change(quota, quota["_etag"])])
    with pytest.raises(DomainError) as rejected:
        store.retry_failed_group(OWNER, environment_id)
    assert rejected.value.code == "GroupRetryNotEligible"
    assert store.owned(OWNER, environment_id)["status"] == "Failed"


def test_group_retry_respects_active_limit(failed_isolated_group):
    store, environment_id, _ = failed_isolated_group
    for index in range(store.settings.max_caller_active):
        store.reserve(OWNER, f"other-{index}", EnvironmentRequest())
    with pytest.raises(DomainError) as rejected:
        store.retry_failed_group(OWNER, environment_id)
    assert rejected.value.code == "CallerActiveLimit"
    assert store.owned(OWNER, environment_id)["status"] == "Failed"


def test_group_retry_api_requires_owner(failed_isolated_group):
    store, environment_id, _ = failed_isolated_group
    authenticator = Mock()
    authenticator.authenticate.return_value = Owner(TENANT, OTHER, CLIENT)
    with TestClient(create_app(store.settings, store, authenticator, Mock(spec=Vault))) as client:
        path = f"/v1/operations/{environment_id}/retry-group"
        assert client.post(path).status_code == 404
        authenticator.authenticate.return_value = OWNER
        response = client.post(path)
        assert response.status_code == 202
        assert response.json()["status"] == "Pending"
        assert response.json()["environmentId"] == environment_id


def test_active_and_running_limits(settings, backend):
    store = Store(backend, replace(settings, max_caller_active=2))
    first = store.reserve(OWNER, "1", EnvironmentRequest())
    second = store.reserve(OWNER, "2", EnvironmentRequest())
    with pytest.raises(DomainError) as caught:
        store.reserve(OWNER, "3", EnvironmentRequest())
    assert caught.value.code == "CallerActiveLimit"
    lease = store.claim(str(first["environmentId"]), "a")
    assert store.claim(str(second["environmentId"]), "b") is None
    store.finish(lease, "Ready")
    assert store.claim(str(second["environmentId"]), "b")


def test_bounded_conflict_retry_only(store, backend):
    backend.conflicts = 2
    store.reserve(OWNER, "retry", EnvironmentRequest())
    backend.conflicts = 100
    with pytest.raises(StoreUnavailable):
        store.reserve(OWNER, "bounded", EnvironmentRequest())
    assert len(backend.rows) == 4


def test_non_conflict_store_error_not_retried(store, backend, monkeypatch):
    call = Mock(side_effect=RuntimeError("unavailable"))
    monkeypatch.setattr(backend, "transact", call)
    with pytest.raises(RuntimeError):
        store.reserve(OWNER, "key", EnvironmentRequest())
    assert call.call_count == 1


def test_durable_outbox_lease_recovery_and_fenced_commit(store, backend, settings):
    environment_id = str(store.reserve(OWNER, "durable", EnvironmentRequest())["environmentId"])
    first = store.claim(environment_id, "crashed")
    assert first.fence == 1
    assert store.claim(environment_id, "other") is None
    job = backend.get(TENANT, "job:" + environment_id)
    job["leaseUntil"] = time.time() - 1
    backend.transact([Change(job, job["_etag"])])
    recovered = Store(backend, settings)
    second = recovered.claim(environment_id, "recovered")
    assert second.fence == 2
    assert len(recovered.candidates()) == 1
    with pytest.raises(LostLease):
        store.finish(first, "Ready")
    with pytest.raises(LostLease):
        store.renew(first)
    recovered.finish(second, "Ready")
    assert recovered.owned(OWNER, environment_id)["status"] == "Ready"
    assert recovered.candidates() == []
    assert json.loads(backend.get(TENANT, "quota")["running"])[OWNER.key] == 0


def test_retry_backoff_does_not_free_capacity(store, backend):
    environment_id = str(store.reserve(OWNER, "retry", EnvironmentRequest())["environmentId"])
    lease = store.claim(environment_id, "a")
    store.finish(lease, "Retry", code="ProviderTemporarilyUnavailable")
    assert store.claim(environment_id, "b") is None
    quota = backend.get(TENANT, "quota")
    assert (quota["allocated"], quota["active"]) == (1, 1)
    job = backend.get(TENANT, "job:" + environment_id)
    second = store.claim(environment_id, "b", now=float(job["nextAttempt"]) + 0.1)
    assert second and second.fence == 2


def test_stale_etag_atomic_no_partial_write(backend):
    backend.transact([Change({"PartitionKey": TENANT, "RowKey": "one", "value": 1})])
    row = backend.get(TENANT, "one")
    with pytest.raises(Conflict):
        backend.transact([Change({"PartitionKey": TENANT, "RowKey": "two"}),
                          Change(row, "not-current")])
    assert backend.get(TENANT, "two") is None


def test_environment_resource_group_name_is_stable_and_validated():
    from service.provisioner import environment_resource_group_name

    first = TENANT
    second = PRINCIPAL
    assert environment_resource_group_name(first) == "rg-faas-env-" + first
    assert environment_resource_group_name(first) != environment_resource_group_name(second)
    with pytest.raises(ValueError):
        environment_resource_group_name("../existing-group")


def test_isolated_target_is_fixed_at_reservation(settings, backend):
    settings = replace(settings, max_caller_active=4)
    isolated = Store(backend, replace(settings, provider_group_mode="isolated"))
    request = EnvironmentRequest.model_validate(NETWORK)
    operation = isolated.reserve(OWNER, "isolated-network", request)
    assert operation["providerGroupMode"] == "isolated"
    assert str(operation["providerGroupName"]).startswith("rg-faas-env-")
    assert parse_stored_environment_request(str(operation["request"]))[2] is True
    with pytest.raises(ValidationError):
        EnvironmentRequest.model_validate_json(str(operation["request"]))

    legacy = Store(backend, replace(settings, provider_group_mode="shared"))
    replay = legacy.reserve(OWNER, "isolated-network", request)
    assert replay["providerGroupMode"] == "isolated"
    assert replay["providerGroupName"] == operation["providerGroupName"]
    assert legacy.reserve(OWNER, "shared-network", request)["providerGroupMode"] == "shared"
    assert isolated.reserve(OWNER, "proof", EnvironmentRequest())["providerGroupMode"] == "shared"
    assert "providerGroupMode" not in public_operation(operation)
    assert "providerGroupName" not in public_operation(operation)
    assert "_faasIsolatedProviderGroup" not in json.dumps(public_operation(operation))


def test_registry_isolated_environment_collision_preserves_existing_owner(
        settings, backend, monkeypatch):
    uuid4_value = uuid4()
    monkeypatch.setattr("service.store.uuid5", lambda *_: uuid4_value)
    first_settings = replace(
        settings, auth_mode="provider-api-registry", authority_tenant=PROVIDER_TENANT,
        provider_group_mode="isolated")
    second_customer = Customer(OTHER, API_PRINCIPAL, API_CLIENT)
    second_settings = replace(first_settings, customer=second_customer)
    first, second = Store(backend, first_settings), Store(backend, second_settings)
    second_owner = Owner(OTHER, API_PRINCIPAL, API_CLIENT)
    request = EnvironmentRequest.model_validate(NETWORK)

    original = first.reserve(OWNER, "first", request)
    with pytest.raises(StoreUnavailable):
        second.reserve(second_owner, "second", request)

    assert first.partition == second.partition
    retained = first.owned(OWNER, str(uuid4_value))
    assert retained["providerGroupName"] == original["providerGroupName"]
    assert retained["client"] == CLIENT
    with pytest.raises(DomainError) as error:
        second.owned(second_owner, str(uuid4_value))
    assert error.value.code == "NotFound"


def test_parallel_networking_is_fixed_at_reservation(settings, backend):
    settings = replace(settings, max_caller_active=4)
    enabled = Store(backend, replace(settings, parallel_provider_networking=True))
    request = EnvironmentRequest.model_validate(NETWORK)
    operation = enabled.reserve(OWNER, "parallel-network", request)
    assert parse_stored_environment_request(str(operation["request"]))[1] is True
    with pytest.raises(ValidationError):
        EnvironmentRequest.model_validate_json(str(operation["request"]))
    assert "_faasParallelProviderNetworking" not in json.dumps(public_operation(operation))

    disabled = Store(backend, settings)
    replay = disabled.reserve(OWNER, "parallel-network", request)
    assert parse_stored_environment_request(str(replay["request"]))[1] is True
    sequential = disabled.reserve(OWNER, "sequential-network", request)
    proof = enabled.reserve(OWNER, "parallel-proof", EnvironmentRequest())
    assert parse_stored_environment_request(str(sequential["request"]))[1] is False
    assert parse_stored_environment_request(str(proof["request"]))[1] is False


def test_isolated_group_rejects_existing_unowned_resources():
    from types import SimpleNamespace
    from service.environment_groups import EnvironmentGroups, GroupOwnershipError

    resources, authorization = Mock(), Mock()
    group_id = OTHER
    operation = {"environmentId": TENANT,
                 "client": CLIENT, "providerGroupName": "rg-faas-env-" + group_id}
    resources.resource_groups.get.return_value = SimpleNamespace(
        name=operation["providerGroupName"], location="eastus2", tags={"purpose": "other"})
    groups = EnvironmentGroups(resources, authorization, SUBSCRIPTION, PRINCIPAL)
    with pytest.raises(GroupOwnershipError):
        groups.ensure(operation, "eastus2", lambda: None)
    resources.resource_groups.create_or_update.assert_not_called()
    authorization.role_assignments.create.assert_not_called()


def test_provider_group_binding_is_fenced_and_immutable(settings, backend):
    store = Store(backend, replace(settings, provider_group_mode="isolated"))
    operation = store.reserve(OWNER, "isolated-fence", EnvironmentRequest.model_validate(NETWORK))
    lease = store.claim(str(operation["environmentId"]), "worker")
    group = str(operation["providerGroupName"])
    scope = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{group}"
    store.begin_provider_group(lease)
    with pytest.raises(LostLease):
        store.bind_provider_group(lease, SUBSCRIPTION, scope + "-other")
    store.bind_provider_group(lease, SUBSCRIPTION, scope)
    store.bind_provider_group(lease, SUBSCRIPTION, scope)
    row = store.operation(lease)
    assert row["providerGroupState"] == "created"
    assert row["providerGroupId"] == scope
    job = backend.get(TENANT, "job:" + str(operation["environmentId"]))
    job["leaseUntil"] = 0.0
    backend.transact([Change(job, job["_etag"])])
    with pytest.raises(LostLease):
        store.bind_provider_group(lease, SUBSCRIPTION, scope)


def test_isolated_group_creation_fails_closed_without_atomic_create():
    from service.environment_groups import EnvironmentGroups, GroupCreationUnavailable

    resources, authorization = Mock(), Mock()
    resources.resource_groups.get.side_effect = ResourceNotFoundError()
    manager = EnvironmentGroups(resources, authorization, SUBSCRIPTION, PRINCIPAL)
    operation = {"environmentId": TENANT, "client": CLIENT,
                 "providerGroupName": "rg-faas-env-" + OTHER}
    begin, bind = Mock(), Mock()

    with pytest.raises(GroupCreationUnavailable):
        manager.ensure(operation, "eastus2", lambda: None, begin, bind)

    begin.assert_not_called()
    bind.assert_not_called()
    resources.resource_groups.create_or_update.assert_not_called()
    authorization.role_assignments.create.assert_not_called()


def test_isolated_group_creation_does_not_overwrite_a_concurrent_group():
    from service.environment_groups import EnvironmentGroups, GroupCreationUnavailable

    resources, authorization = Mock(), Mock()
    existing = {"tags": {"owner": "another-workload"}}

    def missing_then_created(_name):
        resources.resource_groups.create_or_update.side_effect = (
            lambda _name, properties, **kwargs: existing.update(tags=properties["tags"]))
        raise ResourceNotFoundError()

    resources.resource_groups.get.side_effect = missing_then_created
    manager = EnvironmentGroups(resources, authorization, SUBSCRIPTION, PRINCIPAL)
    operation = {"environmentId": TENANT, "client": CLIENT,
                 "providerGroupName": "rg-faas-env-" + OTHER}

    with pytest.raises(GroupCreationUnavailable):
        manager.ensure(operation, "eastus2", lambda: None, Mock(), Mock())

    assert existing["tags"] == {"owner": "another-workload"}
    resources.resource_groups.create_or_update.assert_not_called()
    authorization.role_assignments.create.assert_not_called()


def test_isolated_group_uncertain_create_is_not_replayed():
    from service.environment_groups import EnvironmentGroups, GroupCreationUncertain

    resources, authorization = Mock(), Mock()
    resources.resource_groups.get.side_effect = ResourceNotFoundError()
    manager = EnvironmentGroups(resources, authorization, SUBSCRIPTION, PRINCIPAL)
    operation = {"environmentId": TENANT, "client": CLIENT,
                 "providerGroupName": "rg-faas-env-" + OTHER,
                 "providerGroupState": "creating"}
    with pytest.raises(GroupCreationUncertain):
        manager.ensure(operation, "eastus2", lambda: None)
    resources.resource_groups.create_or_update.assert_not_called()
    authorization.role_assignments.create.assert_not_called()


@pytest.fixture
def target():
    return WorkerSettings(SUBSCRIPTION, "rg-fixed-provider",
                          Path("service/templates/no-network.json"), "", "")


@pytest.fixture
def templates(target):
    return Templates(target)


def network_templates(templates):
    templates.network = {
        "$schema": templates.proof["$schema"], "contentVersion": "1.0.0.0",
        "parameters": {name: {"type": kind} for name, kind in NETWORK_PARAMETERS.items()},
        "resources": templates.proof["resources"],
        "outputs": {"connectionManifest": {"type": "object", "value": MANIFEST}},
    }
    return templates


class FakeArm:
    def __init__(self, outputs=None, state="Succeeded"):
        self.state, self.outputs = state, outputs or {}
        self.deployment = None
        self.starts = []

    def get(self, name):
        return (self.state, self.outputs) if self.deployment else None

    def start(self, name, template, parameters):
        self.starts.append((name, template, parameters))
        self.deployment = name

    def proof_absent(self, environment_id):
        return False


def test_real_proof_template_and_arm_contract(templates, target):
    arm, vault, check = FakeArm(), Mock(spec=Vault), Mock()
    environment_id = str(uuid4())
    provisioner = Provisioner(arm, vault, templates, target)
    assert provisioner.provision(environment_id, EnvironmentRequest(), check) == {}
    name, template, parameters = arm.starts[0]
    assert name == "faas-" + environment_id
    assert len(template["resources"]) == 1
    assert template["resources"][0]["type"] == "Microsoft.Network/routeTables"
    assert set(parameters) == {"location", "environmentId"}
    vault.ensure.assert_not_called()
    assert check.call_count >= 4


def test_reconcile_existing_success_no_redeploy_or_secret_write(templates, target):
    arm, vault = FakeArm(), Mock(spec=Vault)
    arm.deployment = "already-created"
    assert Provisioner(arm, vault, templates, target).provision(
        str(uuid4()), EnvironmentRequest(), lambda: None) == {}
    assert arm.starts == []
    vault.ensure.assert_not_called()


def test_reconcile_running_then_success(templates, target):
    arm = FakeArm(state="Running")
    arm.deployment = "existing"
    waits = []

    def wait(seconds):
        waits.append(seconds)
        arm.state = "Succeeded"

    provisioner = Provisioner(arm, Mock(spec=Vault), templates, target, wait)
    assert provisioner.provision(str(uuid4()), EnvironmentRequest(), lambda: None) == {}
    assert waits == [5] and arm.starts == []


def test_network_secrets_exactly_two_and_only_secure_arm_parameters(templates, target):
    network_templates(templates)
    arm = FakeArm(outputs={"connectionManifest": {"type": "Object", "value": MANIFEST}})
    vault = Mock(spec=Vault)
    vault.ensure.side_effect = [SecretMaterial("ingress-SECRET", "version-one"),
                                SecretMaterial("delivery-SECRET", "version-two")]
    environment_id = str(uuid4())
    bind_versions = Mock()
    result = Provisioner(arm, vault, templates, target).provision(
        environment_id, EnvironmentRequest.model_validate(NETWORK), lambda: None,
        bind_versions=bind_versions)
    assert result == MANIFEST
    assert "SECRET" not in json.dumps(result)
    assert [call.args[0] for call in vault.ensure.call_args_list] == list(secret_names(environment_id))
    parameters = arm.starts[0][2]
    assert set(parameters) == set(NETWORK_PARAMETERS)
    assert parameters["ingressSharedKey"] == {"value": "ingress-SECRET"}
    assert parameters["customerIngressAsn"] == {"value": 64512}
    assert parameters["parallelProviderNetworking"] == {"value": False}
    bind_versions.assert_called_once_with({"ingress": "version-one", "delivery": "version-two"})


def test_network_retry_uses_pinned_versions_not_latest(templates, target):
    network_templates(templates)
    arm = FakeArm(outputs={"connectionManifest": {"type": "Object", "value": MANIFEST}})
    vault = Mock(spec=Vault)
    vault.read.side_effect = ["ingress-PINNED", "delivery-PINNED"]
    environment_id = str(uuid4())
    versions = {"ingress": "earlier-one", "delivery": "earlier-two"}
    result = Provisioner(arm, vault, templates, target).provision(
        environment_id, EnvironmentRequest.model_validate(NETWORK), lambda: None,
        secret_versions=versions)
    assert result == MANIFEST
    assert [call.args for call in vault.read.call_args_list] == [
        (secret_names(environment_id)[0], "earlier-one"),
        (secret_names(environment_id)[1], "earlier-two")]
    vault.ensure.assert_not_called()
    assert arm.starts[0][2]["ingressSharedKey"] == {"value": "ingress-PINNED"}


def test_secret_version_binding_is_fenced_immutable_and_not_public(store, backend):
    environment_id = str(store.reserve(OWNER, "versions", EnvironmentRequest())["environmentId"])
    lease = store.claim(environment_id, "worker")
    versions = {"ingress": "stable-version-one", "delivery": "stable-version-two"}
    store.bind_secret_versions(lease, versions)
    store.bind_secret_versions(lease, versions)
    with pytest.raises(LostLease):
        store.bind_secret_versions(lease, {"ingress": "changed", "delivery": "changed"})
    operation = store.owned(OWNER, environment_id)
    assert json.loads(operation["secretVersions"]) == versions
    assert "secretVersions" not in public_operation(operation)
    job = backend.get(TENANT, "job:" + environment_id)
    job["leaseUntil"] = 0.0
    backend.transact([Change(job, job["_etag"])])
    with pytest.raises(LostLease):
        store.bind_secret_versions(lease, versions)


def test_worker_network_persists_only_references_before_arm(store, backend, templates, target):
    network_templates(templates)
    environment_id = str(store.reserve(
        OWNER, "worker-network", EnvironmentRequest.model_validate(NETWORK))["environmentId"])
    arm = FakeArm(outputs={"connectionManifest": {"type": "Object", "value": MANIFEST}})
    vault = Mock(spec=Vault)
    vault.ensure.side_effect = [SecretMaterial("NEVER-TABLE-INGRESS", "v-one"),
                                SecretMaterial("NEVER-TABLE-DELIVERY", "v-two")]
    original_start = arm.start

    def assert_bound_before_arm(*args):
        operation = store.owned(OWNER, environment_id)
        assert json.loads(operation["secretVersions"]) == {"ingress": "v-one", "delivery": "v-two"}
        return original_start(*args)

    arm.start = assert_bound_before_arm
    worker = Worker(store, Provisioner(arm, vault, templates, target))
    worker.tick()
    operation = store.owned(OWNER, environment_id)
    assert operation["status"] == "Ready"
    assert "NEVER-TABLE" not in json.dumps(list(backend.rows.values()))
    assert public_operation(operation)["connectionManifest"] == MANIFEST


@pytest.mark.parametrize("legacy", [False, True])
def test_existing_shared_network_stays_in_shared_group(
        settings, backend, templates, target, legacy):
    network_templates(templates)
    store = Store(backend, settings)
    operation = store.reserve(OWNER, "existing-shared-network",
                              EnvironmentRequest.model_validate(NETWORK))
    environment_id = str(operation["environmentId"])
    if legacy:
        operation = store.owned(OWNER, environment_id)
        operation.pop("providerGroupMode")
        operation.pop("providerGroupName")
        backend.transact([Change(operation, str(operation["_etag"]))])
    arm = FakeArm(outputs={"connectionManifest": {"type": "Object", "value": MANIFEST}})
    vault = Mock(spec=Vault)
    vault.ensure.side_effect = [SecretMaterial("ingress", "v-one"),
                                SecretMaterial("delivery", "v-two")]
    groups, isolated_factory = Mock(), Mock()
    later_worker_store = Store(backend, replace(
        settings, provider_group_mode="isolated", parallel_provider_networking=True))

    assert Worker(later_worker_store, Provisioner(arm, vault, templates, target),
                  groups, isolated_factory).tick()

    assert store.owned(OWNER, environment_id)["status"] == "Ready"
    assert len(arm.starts) == 1
    assert arm.starts[0][2]["parallelProviderNetworking"] == {"value": False}
    groups.ensure.assert_not_called()
    isolated_factory.assert_not_called()


def test_worker_uses_the_reserved_parallel_networking_mode(settings, backend, templates, target):
    network_templates(templates)
    store = Store(backend, replace(settings, parallel_provider_networking=True))
    operation = store.reserve(OWNER, "parallel-worker", EnvironmentRequest.model_validate(NETWORK))
    arm = FakeArm(outputs={"connectionManifest": {"type": "Object", "value": MANIFEST}})
    vault = Mock(spec=Vault)
    vault.ensure.side_effect = [SecretMaterial("ingress", "v-one"),
                                SecretMaterial("delivery", "v-two")]
    later_worker_store = Store(backend, settings)

    assert Worker(later_worker_store, Provisioner(arm, vault, templates, target)).tick()

    assert store.owned(OWNER, str(operation["environmentId"]))["status"] == "Ready"
    assert arm.starts[0][2]["parallelProviderNetworking"] == {"value": True}


@pytest.mark.parametrize("invalid", ["true", 1, None])
def test_worker_rejects_invalid_recorded_parallel_mode(settings, backend, templates, target, invalid):
    store = Store(backend, settings)
    operation = store.reserve(OWNER, "invalid-parallel", EnvironmentRequest.model_validate(NETWORK))
    row = store.owned(OWNER, str(operation["environmentId"]))
    request = json.loads(str(row["request"]))
    request["_faasParallelProviderNetworking"] = invalid
    row["request"] = json.dumps(request)
    backend.transact([Change(row, str(row["_etag"]))])
    arm, vault = FakeArm(), Mock(spec=Vault)

    assert Worker(store, Provisioner(arm, vault, templates, target)).tick()

    result = store.owned(OWNER, str(operation["environmentId"]))
    assert result["status"] == "Failed"
    assert result["errorCode"] == "InvalidProviderNetworkingMode"
    assert not arm.starts
    vault.ensure.assert_not_called()


@pytest.mark.parametrize("group_mode", ["shared", "isolated"])
def test_worker_rejects_checkpoint_before_creating_group_or_using_ubuntu(
        settings, backend, templates, target, group_mode):
    store = Store(backend, replace(settings, provider_group_mode=group_mode))
    operation = store.reserve(OWNER, "checkpoint-guard", EnvironmentRequest.model_validate(NETWORK))
    row = store.owned(OWNER, str(operation["environmentId"]))
    request = json.loads(str(row["request"]))
    request["firewallType"] = "checkpoint-byol"
    row["request"] = json.dumps(request)
    backend.transact([Change(row, str(row["_etag"]))])
    groups, isolated_factory, arm, vault = Mock(), Mock(), FakeArm(), Mock(spec=Vault)

    assert Worker(store, Provisioner(arm, vault, templates, target),
                  groups, isolated_factory).tick()

    result = store.owned(OWNER, str(operation["environmentId"]))
    assert result["status"] == "Failed"
    assert result["errorCode"] == "CheckpointDeploymentUnavailable"
    groups.ensure.assert_not_called()
    isolated_factory.assert_not_called()
    vault.ensure.assert_not_called()
    assert not arm.starts


@pytest.fixture
def checkpoint_journal(settings, backend):
    store = Store(backend, replace(settings, provider_group_mode="isolated"))
    operation = store.reserve(OWNER, "checkpoint-credential", EnvironmentRequest.model_validate(NETWORK))
    row = store.owned(OWNER, str(operation["environmentId"]))
    request = json.loads(str(row["request"]))
    request["firewallType"] = "checkpoint-byol"
    row["request"] = json.dumps(request)
    row["providerGroupState"] = "created"
    row["providerGroupId"] = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{row['providerGroupName']}"
    backend.transact([Change(row, str(row["_etag"]))])
    lease = store.claim(str(row["environmentId"]), "checkpoint-worker")
    return store, backend, lease, CheckpointCredentialJournal(store, SUBSCRIPTION)


def checkpoint_vault_id(store, lease):
    group = store.operation(lease)["providerGroupId"]
    return f"{group}/providers/Microsoft.KeyVault/vaults/kvcp{'a' * 13}"


def test_checkpoint_credential_journal_reserves_once_and_binds_an_immutable_version(checkpoint_journal):
    store, _, lease, journal = checkpoint_journal
    vault_id = checkpoint_vault_id(store, lease)
    first = journal.reserve(lease, vault_id)
    assert first.may_write_once and first.version is None
    repeated = journal.reserve(lease, vault_id)
    assert repeated.name == first.name and repeated.version is None and not repeated.may_write_once
    version = "a" * 32
    journal.prepare(lease, vault_id, first.name, "c" * 64)
    journal.prepare(lease, vault_id, first.name, "c" * 64)
    with pytest.raises(CheckpointCredentialStateError, match="fingerprint mismatch"):
        journal.prepare(lease, vault_id, first.name, "d" * 64)
    journal.bind(lease, vault_id, first.name, version)
    journal.bind(lease, vault_id, first.name, version)
    bound = journal.reserve(lease, vault_id)
    assert bound.name == first.name and bound.version == version and not bound.may_write_once
    assert journal.bound(lease, vault_id).version == version
    saved = json.loads(str(store.operation(lease)["checkpointCredentialRef"]))
    assert saved == {"name": first.name, "state": "bound", "version": version,
                     "vaultId": vault_id.lower(), "fingerprint": "c" * 64, "writerFence": lease.fence}
    assert "c" * 64 not in repr(journal.bound(lease, vault_id))
    with pytest.raises(CheckpointCredentialStateError, match="version mismatch"):
        journal.bind(lease, vault_id, first.name, "b" * 32)


def test_checkpoint_credential_journal_only_one_writer_under_concurrency(checkpoint_journal):
    store, _, lease, journal = checkpoint_journal
    vault_id = checkpoint_vault_id(store, lease)
    with ThreadPoolExecutor(max_workers=8) as executor:
        reservations = list(executor.map(lambda _: journal.reserve(lease, vault_id), range(8)))
    assert len({item.name for item in reservations}) == 1
    assert sum(item.may_write_once for item in reservations) == 1


def test_checkpoint_credential_journal_binds_one_vault_and_never_reserves_on_read(checkpoint_journal):
    store, _, lease, journal = checkpoint_journal
    vault_id = checkpoint_vault_id(store, lease)
    with pytest.raises(CheckpointCredentialStateError, match="not bound"):
        journal.bound(lease, vault_id)
    assert "checkpointCredentialRef" not in store.operation(lease)
    with pytest.raises(CheckpointCredentialStateError, match="vault scope"):
        journal.reserve(lease, vault_id.replace(SUBSCRIPTION, OTHER))
    reservation = journal.reserve(lease, vault_id)
    other_vault = vault_id[:-13] + "b" * 13
    with pytest.raises(CheckpointCredentialStateError, match="vault mismatch"):
        journal.reserve(lease, other_vault)
    with pytest.raises(CheckpointCredentialStateError, match="reservation mismatch"):
        journal.bind(lease, other_vault, reservation.name, "a" * 32)
    with pytest.raises(CheckpointCredentialStateError, match="not bound"):
        journal.bound(lease, vault_id)


def test_checkpoint_credential_journal_refuses_stale_lease_and_wrong_scope(checkpoint_journal):
    store, backend, lease, journal = checkpoint_journal
    vault_id = checkpoint_vault_id(store, lease)
    first = journal.reserve(lease, vault_id)
    journal.prepare(lease, vault_id, first.name, "c" * 64)
    job = backend.get(store.partition, "job:" + lease.environment_id)
    job["leaseUntil"] = 0.0
    backend.transact([Change(job, str(job["_etag"]))])
    with pytest.raises(LostLease):
        journal.bind(lease, vault_id, first.name, "a" * 32)

    next_lease = store.claim(lease.environment_id, "new-worker")
    assert next_lease is not None
    assert not journal.reserve(next_lease, vault_id).may_write_once
    wrong = CheckpointCredentialJournal(store, OTHER)
    with pytest.raises(CheckpointCredentialStateError, match="operation"):
        wrong.reserve(next_lease, vault_id)


def test_checkpoint_credential_journal_recovers_before_write_preparation(checkpoint_journal):
    store, backend, lease, journal = checkpoint_journal
    vault_id = checkpoint_vault_id(store, lease)
    first = journal.reserve(lease, vault_id)
    job = backend.get(store.partition, "job:" + lease.environment_id)
    job["leaseUntil"] = 0.0
    backend.transact([Change(job, str(job["_etag"]))])
    next_lease = store.claim(lease.environment_id, "new-worker")
    assert next_lease is not None
    takeover = journal.reserve(next_lease, vault_id)
    assert takeover.name == first.name and takeover.may_write_once
    with pytest.raises(LostLease):
        journal.prepare(lease, vault_id, first.name, "c" * 64)
    journal.prepare(next_lease, vault_id, takeover.name, "d" * 64)
    assert not journal.reserve(next_lease, vault_id).may_write_once


def test_checkpoint_credential_journal_never_accepts_corrupt_or_foreign_references(checkpoint_journal):
    store, backend, lease, journal = checkpoint_journal
    vault_id = checkpoint_vault_id(store, lease)
    first = journal.reserve(lease, vault_id)
    with pytest.raises(CheckpointCredentialStateError, match="reservation mismatch"):
        journal.bind(lease, vault_id, "cp-credentials-" + "0" * 32, "a" * 32)
    row = store.operation(lease)
    row["checkpointCredentialRef"] = '{"name":"leaked-sensitive-value","state":"reserved","version":""}'
    backend.transact([Change(row, str(row["_etag"]))])
    with pytest.raises(CheckpointCredentialStateError) as error:
        journal.reserve(lease, vault_id)
    assert "leaked-sensitive-value" not in str(error.value)
    assert first.name not in str(error.value)


def test_checkpoint_credential_journal_rejects_existing_ubuntu_operations(store, backend):
    operation = store.reserve(OWNER, "not-checkpoint", EnvironmentRequest.model_validate(NETWORK))
    lease = store.claim(str(operation["environmentId"]), "worker")
    with pytest.raises(CheckpointCredentialStateError, match="operation"):
        CheckpointCredentialJournal(store, SUBSCRIPTION).reserve(lease, "invalid")
    assert "checkpointCredentialRef" not in store.operation(lease)


def checkpoint_runner_id(store, lease):
    group = store.operation(lease)["providerGroupId"]
    return (f"{group}/providers/Microsoft.ContainerInstance/containerGroups/"
            f"cg-cp-runner-{lease.environment_id}")


def test_checkpoint_runner_journal_fences_one_launch_and_terminal_result(checkpoint_journal):
    store, _, lease, scope = checkpoint_journal
    journal, job_id, digest = CheckpointRunnerJournal(scope), checkpoint_runner_id(store, lease), "a" * 64
    first = journal.reserve(lease, job_id, digest)
    assert first.state == "reserved" and first.may_prepare
    assert digest not in repr(first)
    assert not journal.reserve(lease, job_id, digest).may_prepare
    assert journal.read(lease, job_id, digest).state == "reserved"
    with pytest.raises(CheckpointRunnerStateError, match="transition"):
        journal.finish(lease, job_id, digest, 0)
    assert journal.begin_launch(lease, job_id, digest)
    assert not journal.begin_launch(lease, job_id, digest)
    journal.observe_running(lease, job_id, digest)
    journal.observe_running(lease, job_id, digest)
    with pytest.raises(CheckpointRunnerStateError, match="exit code"):
        journal.finish(lease, job_id, digest, False)
    journal.finish(lease, job_id, digest, 0)
    journal.finish(lease, job_id, digest, 0)
    result = journal.reserve(lease, job_id, digest)
    assert result.state == "succeeded" and result.exit_code == 0 and not result.may_prepare
    with pytest.raises(CheckpointRunnerStateError, match="transition"):
        journal.finish(lease, job_id, digest, 1)
    public = json.dumps(public_operation(store.operation(lease)))
    assert digest not in public and job_id.lower() not in public.lower()


def test_checkpoint_runner_journal_allows_only_one_concurrent_launch(checkpoint_journal):
    store, _, lease, scope = checkpoint_journal
    journal, job_id = CheckpointRunnerJournal(scope), checkpoint_runner_id(store, lease)
    journal.reserve(lease, job_id, "a" * 64)
    with ThreadPoolExecutor(max_workers=8) as executor:
        starts = list(executor.map(lambda _: journal.begin_launch(lease, job_id, "a" * 64), range(8)))
    assert sum(starts) == 1
    assert journal.reserve(lease, job_id, "a" * 64).state == "launching"


@pytest.mark.parametrize("started", [False, True])
def test_checkpoint_runner_journal_reconciles_after_lease_loss_without_duplicate_launch(checkpoint_journal, started):
    store, backend, lease, scope = checkpoint_journal
    journal, job_id, digest = CheckpointRunnerJournal(scope), checkpoint_runner_id(store, lease), "a" * 64
    journal.reserve(lease, job_id, digest)
    if started:
        assert journal.begin_launch(lease, job_id, digest)
    job = backend.get(store.partition, "job:" + lease.environment_id)
    job["leaseUntil"] = 0.0
    backend.transact([Change(job, str(job["_etag"]))])
    next_lease = store.claim(lease.environment_id, "checkpoint-recovery")
    assert next_lease is not None
    with pytest.raises(LostLease):
        journal.begin_launch(lease, job_id, digest)
    recovered = journal.reserve(next_lease, job_id, digest)
    assert recovered.may_prepare is (not started)
    assert recovered.state == ("launching" if started else "reserved")
    assert journal.begin_launch(next_lease, job_id, digest) is (not started)


def test_checkpoint_runner_journal_records_failure_without_retry(checkpoint_journal):
    store, _, lease, scope = checkpoint_journal
    journal, job_id, digest = CheckpointRunnerJournal(scope), checkpoint_runner_id(store, lease), "a" * 64
    journal.reserve(lease, job_id, digest)
    journal.begin_launch(lease, job_id, digest)
    journal.finish(lease, job_id, digest, 137)
    result = journal.reserve(lease, job_id, digest)
    assert result.state == "failed" and result.exit_code == 137 and not result.may_prepare
    assert not journal.begin_launch(lease, job_id, digest)
    with pytest.raises(CheckpointRunnerStateError, match="transition"):
        journal.observe_running(lease, job_id, digest)


def test_checkpoint_runner_journal_records_provisioning_failure_without_retry(checkpoint_journal):
    store, _, lease, scope = checkpoint_journal
    journal, job_id, digest = CheckpointRunnerJournal(scope), checkpoint_runner_id(store, lease), "a" * 64
    with pytest.raises(CheckpointRunnerStateError, match="mismatch"):
        journal.read(lease, job_id, digest)
    journal.reserve(lease, job_id, digest)
    journal.begin_launch(lease, job_id, digest)
    journal.fail_provisioning(lease, job_id, digest)
    result = journal.read(lease, job_id, digest)
    assert result.state == "failed" and result.exit_code is None
    assert not journal.begin_launch(lease, job_id, digest)


@pytest.mark.parametrize("mutation", ["foreign_group", "foreign_subscription", "other_job", "bad_digest"])
def test_checkpoint_runner_journal_rejects_foreign_or_invalid_inputs(checkpoint_journal, mutation):
    store, _, lease, scope = checkpoint_journal
    journal, job_id, digest = CheckpointRunnerJournal(scope), checkpoint_runner_id(store, lease), "a" * 64
    if mutation == "foreign_group":
        job_id = job_id.replace("rg-faas-env-", "rg-foreign-", 1)
    elif mutation == "foreign_subscription":
        job_id = job_id.replace(SUBSCRIPTION, OTHER)
    elif mutation == "other_job":
        job_id += "-other"
    else:
        digest = "PRIVATE-VALUE"
    with pytest.raises(CheckpointRunnerStateError) as error:
        journal.reserve(lease, job_id, digest)
    assert "PRIVATE-VALUE" not in str(error.value)
    assert "checkpointRunnerRef" not in store.operation(lease)


def test_checkpoint_runner_journal_rejects_corruption_and_different_spec(checkpoint_journal):
    store, backend, lease, scope = checkpoint_journal
    journal, job_id, digest = CheckpointRunnerJournal(scope), checkpoint_runner_id(store, lease), "a" * 64
    journal.reserve(lease, job_id, digest)
    with pytest.raises(CheckpointRunnerStateError, match="mismatch"):
        journal.reserve(lease, job_id, "b" * 64)
    row = store.operation(lease)
    row["checkpointRunnerRef"] = '{"jobId":"PRIVATE-VALUE","specSha256":"bad","state":"launching"}'
    backend.transact([Change(row, str(row["_etag"]))])
    with pytest.raises(CheckpointRunnerStateError) as error:
        journal.reserve(lease, job_id, digest)
    assert "PRIVATE-VALUE" not in str(error.value)


def test_checkpoint_apply_journal_binds_one_job_and_exact_plan(checkpoint_journal):
    store, _, lease, scope = checkpoint_journal
    journal, job_id, digest = CheckpointApplyJournal(scope), checkpoint_runner_id(store, lease), "a" * 64
    first = journal.reserve(lease, job_id, digest)
    assert first.may_start_once and first.state == "starting"
    assert digest not in repr(first)
    assert not journal.reserve(lease, job_id, digest).may_start_once
    with pytest.raises(CheckpointApplyStateError, match="mismatch"):
        journal.reserve(lease, job_id, "b" * 64)
    with pytest.raises(CheckpointApplyStateError, match="did not complete"):
        journal.succeed(lease, job_id, digest, 1)
    with pytest.raises(CheckpointApplyStateError, match="did not complete"):
        journal.succeed(lease, job_id, digest, False)
    journal.succeed(lease, job_id, digest, 0)
    journal.succeed(lease, job_id, digest, 0)
    repeated = journal.reserve(lease, job_id, digest)
    assert repeated.state == "succeeded" and not repeated.may_start_once
    public = json.dumps(public_operation(store.operation(lease)))
    assert digest not in public and job_id.lower() not in public.lower()


def test_checkpoint_apply_journal_only_one_start_under_concurrency(checkpoint_journal):
    store, _, lease, scope = checkpoint_journal
    journal, job_id = CheckpointApplyJournal(scope), checkpoint_runner_id(store, lease)
    with ThreadPoolExecutor(max_workers=8) as executor:
        reservations = list(executor.map(lambda _: journal.reserve(lease, job_id, "a" * 64), range(8)))
    assert sum(item.may_start_once for item in reservations) == 1
    assert {item.state for item in reservations} == {"starting"}


def test_checkpoint_apply_journal_never_restarts_ambiguous_apply_after_lease_loss(checkpoint_journal):
    store, backend, lease, scope = checkpoint_journal
    journal, job_id, digest = CheckpointApplyJournal(scope), checkpoint_runner_id(store, lease), "a" * 64
    journal.reserve(lease, job_id, digest)
    job = backend.get(store.partition, "job:" + lease.environment_id)
    job["leaseUntil"] = 0.0
    backend.transact([Change(job, str(job["_etag"]))])
    with pytest.raises(LostLease):
        journal.succeed(lease, job_id, digest, 0)
    next_lease = store.claim(lease.environment_id, "checkpoint-recovery")
    assert next_lease is not None
    pending = journal.reserve(next_lease, job_id, digest)
    assert pending.state == "starting" and not pending.may_start_once
    with pytest.raises(CheckpointApplyStateError, match="mismatch"):
        journal.reserve(next_lease, job_id, "b" * 64)


@pytest.mark.parametrize("mutation", ["foreign_group", "foreign_subscription", "other_job", "bad_digest"])
def test_checkpoint_apply_journal_rejects_foreign_or_invalid_inputs(checkpoint_journal, mutation):
    store, _, lease, scope = checkpoint_journal
    journal, job_id, digest = CheckpointApplyJournal(scope), checkpoint_runner_id(store, lease), "a" * 64
    if mutation == "foreign_group":
        job_id = job_id.replace("rg-faas-env-", "rg-foreign-", 1)
    elif mutation == "foreign_subscription":
        job_id = job_id.replace(SUBSCRIPTION, OTHER)
    elif mutation == "other_job":
        job_id += "-other"
    else:
        digest = "PRIVATE-VALUE"
    with pytest.raises(CheckpointApplyStateError) as error:
        journal.reserve(lease, job_id, digest)
    assert "PRIVATE-VALUE" not in str(error.value)
    assert "checkpointApplyRef" not in store.operation(lease)


def test_checkpoint_apply_journal_rejects_missing_and_corrupt_state(checkpoint_journal):
    store, backend, lease, scope = checkpoint_journal
    journal, job_id, digest = CheckpointApplyJournal(scope), checkpoint_runner_id(store, lease), "a" * 64
    with pytest.raises(CheckpointApplyStateError, match="mismatch"):
        journal.succeed(lease, job_id, digest, 0)
    row = store.operation(lease)
    row["checkpointApplyRef"] = '{"jobId":"PRIVATE-VALUE","planSha256":"bad","state":"starting"}'
    backend.transact([Change(row, str(row["_etag"]))])
    with pytest.raises(CheckpointApplyStateError) as error:
        journal.reserve(lease, job_id, digest)
    assert "PRIVATE-VALUE" not in str(error.value)


def checkpoint_vault_fixture(store, lease):
    group_id = store.operation(lease)["providerGroupId"]
    vault_id = checkpoint_vault_id(store, lease)
    endpoint_id = f"{group_id}/providers/Microsoft.Network/privateEndpoints/pe-cp-vault-{lease.environment_id[:8]}"
    storage_id = f"{group_id}/providers/Microsoft.Storage/storageAccounts/stcp{'a' * 13}"
    outputs = {key: {"type": "String", "value": value} for key, value in {
        "credentialVaultId": vault_id, "credentialVaultUri": f"https://kvcp{'a' * 13}.vault.azure.net/",
        "stateStorageId": storage_id, "stateBlobEndpoint": f"https://stcp{'a' * 13}.blob.core.windows.net/",
        "stateContainerName": "terraform-state", "credentialPrivateEndpointId": endpoint_id,
        "statePrivateEndpointId": f"{group_id}/providers/Microsoft.Network/privateEndpoints/pe-cp-blob-{lease.environment_id[:8]}",
    }.items()}
    vault = {
        "id": vault_id,
        "tags": {"purpose": "provider-provisioning-checkpoint-private-data", "environmentId": lease.environment_id},
        "properties": {
            "tenantId": PROVIDER_TENANT, "provisioningState": "Succeeded",
            "enableRbacAuthorization": True, "enableSoftDelete": True, "enablePurgeProtection": True,
            "publicNetworkAccess": "Disabled", "networkAcls": {"defaultAction": "Deny", "bypass": "None"},
            "vaultUri": outputs["credentialVaultUri"]["value"],
            "privateEndpointConnections": [{"properties": {
                "privateEndpoint": {"id": endpoint_id},
                "provisioningState": "Succeeded",
                "privateLinkServiceConnectionState": {"status": "Approved"}}}],
        },
    }
    endpoint = {
        "id": endpoint_id,
        "properties": {
            "provisioningState": "Succeeded",
            "subnet": {"id": (f"{group_id}/providers/Microsoft.Network/virtualNetworks/"
                              f"vnet-cp-security-{lease.environment_id[:8]}/subnets/private-endpoints")},
            "privateLinkServiceConnections": [{"properties": {
                "privateLinkServiceId": vault_id, "groupIds": ["vault"],
                "privateLinkServiceConnectionState": {"status": "Approved"}}}],
        },
    }
    resources = Mock()
    def get_by_id(resource_id, _api):
        resource = vault if resource_id.lower() == vault_id.lower() else endpoint
        return SimpleNamespace(as_dict=lambda: copy.deepcopy(resource))
    resources.resources.get_by_id.side_effect = get_by_id
    return outputs, vault, resources


def checkpoint_runner_fixture(store, lease):
    private_outputs, _, _ = checkpoint_vault_fixture(store, lease)
    group = str(store.operation(lease)["providerGroupName"])
    group_id = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{group}"
    prefix = group_id + "/providers/Microsoft.Network"
    suffix = lease.environment_id[:8]
    vnet_name = "vnet-cp-security-" + suffix
    vnet = f"{prefix}/virtualNetworks/{vnet_name}"
    foundation = {
        "securityVnetId": vnet, "securityVnetName": vnet_name,
        "firewallFrontendSubnetId": vnet + "/subnets/firewall-frontend",
        "firewallBackendSubnetId": vnet + "/subnets/firewall-backend",
        "managementSubnetId": vnet + "/subnets/management",
        "automationSubnetId": vnet + "/subnets/automation",
        "privateEndpointsSubnetId": vnet + "/subnets/private-endpoints",
        "automationNsgId": f"{prefix}/networkSecurityGroups/nsg-cp-automation-{suffix}",
        "automationNatGatewayId": f"{prefix}/natGateways/nat-cp-automation-{suffix}",
        "automationPublicIpId": f"{prefix}/publicIPAddresses/pip-cp-automation-{suffix}",
        "firewallNsgId": f"{prefix}/networkSecurityGroups/nsg-cp-firewall-{suffix}",
        "managementNsgId": f"{prefix}/networkSecurityGroups/nsg-cp-management-{suffix}",
        "firewallFrontendPrivateIp": "172.22.10.4", "firewallBackendPrivateIp": "172.22.20.4",
        "routeServerAsn": 65515, "routeServerPeerAddresses": ["172.20.254.4", "172.20.254.5"],
    }
    endpoint = {"publicIp": "8.8.8.8", "bgpAddress": "172.20.255.30", "asn": 65515}
    foundation_outputs = {
        "connectionManifest": {"type": "Object", "value": {
            "providerIngress": endpoint, "providerDelivery": {**endpoint, "publicIp": "1.1.1.1", "asn": 65031}}},
        "checkpointFoundation": {"type": "Object", "value": foundation},
    }
    control_group = "rg-faas-cp-control-" + OTHER
    identity_id = (f"/subscriptions/{SUBSCRIPTION}/resourcegroups/{control_group}"
                   "/providers/Microsoft.ManagedIdentity/userAssignedIdentities/faas-cp-publisher-fixture1")
    identity = {"id": identity_id, "location": "eastus2",
                "tags": {"purpose": "provider-provisioning-checkpoint-publisher"},
                "properties": {"tenantId": PROVIDER_TENANT, "clientId": CLIENT, "principalId": PRINCIPAL}}
    return foundation_outputs, private_outputs, group, control_group, identity


def build_runner_fixture(store, lease):
    foundation, private, group, control, identity = checkpoint_runner_fixture(store, lease)
    return build_checkpoint_runner_spec(
        foundation, private, SUBSCRIPTION, PROVIDER_TENANT, group, lease.environment_id, control, identity,
        "fixtureacr.azurecr.io", "a" * 64, RUNNER_SETTINGS)


def runner_resource(spec, state="Running", exit_code=None):
    current = {"state": state}
    if exit_code is not None:
        current["exitCode"] = exit_code
    return {
        "id": spec.job_id, "location": "eastus2",
        "tags": {"purpose": "provider-provisioning-checkpoint-runner", "environmentId": spec.environment_id},
        "identity": {"type": "UserAssigned", "userAssignedIdentities": {
            spec.identity_id: {"clientId": spec.identity_client_id, "principalId": spec.identity_principal_id}}},
        "properties": {
            "osType": "Linux", "restartPolicy": "Never", "sku": "Standard",
            "subnetIds": [{"id": spec.subnet_id}], "dnsConfig": {"nameServers": ["168.63.129.16"]},
            "imageRegistryCredentials": [{"server": "fixtureacr.azurecr.io", "identity": spec.identity_id}],
            "containers": [{"name": "runner", "properties": {
                "image": spec.image, "command": [], "ports": [],
                "environmentVariables": [{"name": key, "value": value} for key, value in spec.environment],
                "resources": {"requests": {"cpu": 2, "memoryInGB": 4}},
                "securityContext": {"privileged": False},
                "instanceView": {"restartCount": 0, "currentState": current},
            }}],
            "ipAddress": {"type": "Private", "ip": "172.22.40.4", "ports": []},
            "provisioningState": "Succeeded",
        },
    }


def test_checkpoint_runner_spec_binds_provider_identity_and_contains_no_credentials(checkpoint_journal):
    store, _, lease, _ = checkpoint_journal
    spec = build_runner_fixture(store, lease)
    assert spec.job_id == checkpoint_runner_id(store, lease)
    assert spec.subnet_id.endswith("/subnets/automation")
    assert spec.image.endswith("@sha256:" + "a" * 64)
    values = dict(spec.environment)
    assert set(values) == {"FAAS_CONFIG", "FAAS_RUNNER_CLIENT_ID"}
    config = load_checkpoint_runner_config(values)
    assert config.environmentId == lease.environment_id and config.runnerClientId == CLIENT
    assert config.providerGroupId.endswith("/" + store.operation(lease)["providerGroupName"])
    assert config.routeServerPeers == ("172.20.254.4", "172.20.254.5")
    assert config.credentialVaultUri.startswith("https://kvcp")
    text = values["FAAS_CONFIG"].lower()
    assert "password" not in text and "sic" not in text and "secret" not in text
    assert values["FAAS_CONFIG"] not in repr(spec)
    with pytest.raises(ValidationError):
        config.runnerClientId = OTHER


def checkpoint_runner_request_fixture(store, lease):
    foundation, private, group, control, identity = checkpoint_runner_fixture(store, lease)
    return build_checkpoint_runner_request(
        foundation, private, SUBSCRIPTION, PROVIDER_TENANT, group, lease.environment_id, control, identity,
        "fixtureacr.azurecr.io", "a" * 64, RUNNER_SETTINGS)


def runner_environment(store, lease, **changes):
    values = dict(build_runner_fixture(store, lease).environment)
    config = json.loads(values["FAAS_CONFIG"])
    config.update(changes)
    values["FAAS_CONFIG"] = json.dumps(config)
    return values


@pytest.mark.parametrize("change", [
    {"schemaVersion": 2}, {"environmentId": "PRIVATE-VALUE"}, {"providerSubscriptionId": OTHER},
    {"providerTenantId": "PRIVATE-VALUE"}, {"providerGroupId": "/subscriptions/x/resourceGroups/other"},
    {"runnerClientId": OTHER}, {"gatewayImageVersion": "latest"}, {"managementVmSize": "PRIVATE-VALUE"},
    {"providerSshPublicKey": "PRIVATE-VALUE"}, {"credentialVaultUri": "https://kvcpbbbbbbbbbbbbb.vault.azure.net/"},
    {"stateBlobEndpoint": "https://PRIVATE-VALUE/"}, {"stateContainer": "other"},
    {"firewallFrontendIp": "10.0.0.4"}, {"routeServerAsn": 65000}, {"routeServerPeers": ["203.0.113.4", "203.0.113.5"]},
    {"managementPassword": "PRIVATE-VALUE"},
])
def test_checkpoint_runner_config_rejects_tampering_without_echoing(checkpoint_journal, change):
    store, _, lease, _ = checkpoint_journal
    with pytest.raises(CheckpointRunnerConfigError) as error:
        load_checkpoint_runner_config(runner_environment(store, lease, **change))
    assert "PRIVATE-VALUE" not in str(error.value)


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "oversize", "bad_json", "zero_client"])
def test_checkpoint_runner_config_rejects_malformed_environment(checkpoint_journal, mutation):
    store, _, lease, _ = checkpoint_journal
    values = dict(build_runner_fixture(store, lease).environment)
    if mutation == "missing":
        del values["FAAS_CONFIG"]
    elif mutation == "duplicate":
        values["FAAS_CONFIG"] = values["FAAS_CONFIG"][:-1] + ',"schemaVersion":1}'
    elif mutation == "oversize":
        values["FAAS_CONFIG"] = " " * (16 * 1024 + 1)
    elif mutation == "bad_json":
        values["FAAS_CONFIG"] = "PRIVATE-VALUE"
    else:
        values["FAAS_RUNNER_CLIENT_ID"] = "00000000-0000-0000-0000-000000000000"
    with pytest.raises(CheckpointRunnerConfigError) as error:
        load_checkpoint_runner_config(values)
    assert "PRIVATE-VALUE" not in str(error.value)


class FakeSecretClient:
    def __init__(self):
        self.versions, self.writes, self.fail_write_after_store = {}, 0, False

    def list_properties_of_secret_versions(self, name, **kwargs):
        assert kwargs["logging_enable"] is False
        if name not in self.versions:
            raise ResourceNotFoundError()
        return [SimpleNamespace(version=version) for version in self.versions[name]]

    def set_secret(self, name, value, **kwargs):
        self.writes += 1
        version = format(self.writes, "032x")
        self.versions.setdefault(name, {})[version] = SimpleNamespace(
            name=name, value=value, properties=SimpleNamespace(
                version=version, enabled=kwargs["enabled"], content_type=kwargs["content_type"],
                tags=kwargs["tags"]))
        if self.fail_write_after_store:
            raise ServiceResponseError("PRIVATE-VALUE")

    def get_secret(self, name, version, **kwargs):
        return self.versions[name][version]


def test_checkpoint_runner_creates_credentials_once_and_reuses_them(checkpoint_journal):
    store, _, lease, _ = checkpoint_journal
    config = load_checkpoint_runner_config(dict(build_runner_fixture(store, lease).environment))
    client = FakeSecretClient()
    first = ensure_checkpoint_runner_credentials(config, client)
    second = ensure_checkpoint_runner_credentials(config, client)
    assert first == second and client.writes == 1
    assert list(client.versions) == ["cp-credentials-" + lease.environment_id]
    assert first.management_password not in repr(first) and first.sic_key not in repr(first)


def test_checkpoint_runner_reuses_credential_after_ambiguous_write(checkpoint_journal):
    store, _, lease, _ = checkpoint_journal
    config = load_checkpoint_runner_config(dict(build_runner_fixture(store, lease).environment))
    client = FakeSecretClient()
    client.fail_write_after_store = True
    with pytest.raises(ServiceResponseError):
        ensure_checkpoint_runner_credentials(config, client)
    client.fail_write_after_store = False
    ensure_checkpoint_runner_credentials(config, client)
    assert client.writes == 1


@pytest.mark.parametrize("mutation", ["two_versions", "value", "disabled", "tags", "content_type"])
def test_checkpoint_runner_rejects_unexpected_credentials_without_rotation(checkpoint_journal, mutation):
    store, _, lease, _ = checkpoint_journal
    config = load_checkpoint_runner_config(dict(build_runner_fixture(store, lease).environment))
    client = FakeSecretClient()
    ensure_checkpoint_runner_credentials(config, client)
    secret = next(iter(client.versions[config.credential_name].values()))
    if mutation == "two_versions":
        client.set_secret(config.credential_name, secret.value, enabled=True, content_type=CONTENT_TYPE,
                          tags=secret.properties.tags)
    elif mutation == "value":
        secret.value = "PRIVATE-VALUE"
    elif mutation == "disabled":
        secret.properties.enabled = False
    elif mutation == "tags":
        secret.properties.tags = {"environmentId": OTHER}
    else:
        secret.properties.content_type = "text/plain"
    writes = client.writes
    with pytest.raises(CheckpointVaultError) as error:
        ensure_checkpoint_runner_credentials(config, client)
    assert "PRIVATE-VALUE" not in str(error.value)
    assert client.writes == writes


def test_checkpoint_runner_inputs_use_only_its_managed_identity(checkpoint_journal, monkeypatch):
    store, _, lease, _ = checkpoint_journal
    values = dict(build_runner_fixture(store, lease).environment)
    identity, client = Mock(), Mock()
    fake = FakeSecretClient()
    for name in ("list_properties_of_secret_versions", "set_secret", "get_secret"):
        setattr(client, name, getattr(fake, name))
    credential_factory = Mock(return_value=identity)
    vault_factory = Mock(return_value=client)
    monkeypatch.setattr("service.checkpoint_runner_config.ManagedIdentityCredential", credential_factory)
    monkeypatch.setattr("service.checkpoint_runner_config.SecretClient", vault_factory)
    inputs = read_checkpoint_runner_inputs(values)
    credential_factory.assert_called_once_with(client_id=CLIENT)
    assert vault_factory.call_args.args == (inputs.config.credentialVaultUri, identity)
    assert inputs.credentials.management_password not in repr(inputs)
    client.close.assert_called_once_with()
    identity.close.assert_called_once_with()


def test_checkpoint_runner_inputs_redact_vault_errors(checkpoint_journal, monkeypatch):
    store, _, lease, _ = checkpoint_journal
    identity, client = Mock(), Mock()
    client.list_properties_of_secret_versions.side_effect = ServiceResponseError("PRIVATE-VALUE")
    monkeypatch.setattr("service.checkpoint_runner_config.ManagedIdentityCredential", Mock(return_value=identity))
    monkeypatch.setattr("service.checkpoint_runner_config.SecretClient", Mock(return_value=client))
    with pytest.raises(CheckpointRunnerConfigError) as error:
        read_checkpoint_runner_inputs(dict(build_runner_fixture(store, lease).environment))
    assert "PRIVATE-VALUE" not in str(error.value)
    client.set_secret.assert_not_called()
    client.close.assert_called_once_with()
    identity.close.assert_called_once_with()


def test_checkpoint_runner_credential_round_trip_through_key_vault_sdk(checkpoint_journal, monkeypatch):
    from azure.core.credentials import AccessToken
    from azure.core.pipeline.transport import HttpResponse, HttpTransport
    from azure.keyvault.secrets import SecretClient

    store, _, lease, _ = checkpoint_journal
    values = dict(build_runner_fixture(store, lease).environment)
    config = load_checkpoint_runner_config(values)

    class Response(HttpResponse):
        def __init__(self, request, status, payload, headers):
            super().__init__(request, None)
            self.status_code, self.headers, self.payload = status, headers, payload
            self.content_type = "application/json"

        def body(self):
            return json.dumps(self.payload).encode()

        def json(self):
            return self.payload

    class Transport(HttpTransport):
        def __init__(self):
            self.secret, self.requests = None, []

        def open(self):
            pass

        def close(self):
            pass

        def __exit__(self, *args):
            self.close()

        def send(self, request, **kwargs):
            if not request.headers.get("Authorization"):
                return Response(request, 401, {}, {"WWW-Authenticate": (
                    f'Bearer authorization="https://login.microsoftonline.com/{PROVIDER_TENANT}", '
                    'resource="https://vault.azure.net"')})
            self.requests.append(request.method)
            base = f"{config.credentialVaultUri}secrets/{config.credential_name}"
            if request.method == "PUT":
                payload = json.loads(request.body)
                self.secret = {"id": base + "/" + "a" * 32, "value": payload["value"],
                               "contentType": payload["contentType"], "tags": payload["tags"],
                               "attributes": {"enabled": True}}
                return Response(request, 200, self.secret, {"Content-Type": "application/json"})
            if "/versions" in request.url:
                if self.secret is None:
                    return Response(request, 404, {"error": {"code": "SecretNotFound", "message": "x"}},
                                    {"Content-Type": "application/json"})
                listed = {key: value for key, value in self.secret.items() if key != "value"}
                return Response(request, 200, {"value": [listed]}, {"Content-Type": "application/json"})
            return Response(request, 200, self.secret, {"Content-Type": "application/json"})

    transport = Transport()
    identity = Mock(spec=["get_token", "close"])
    identity.get_token.return_value = AccessToken("fixture-token", int(time.time()) + 3600)
    monkeypatch.setattr("service.checkpoint_runner_config.ManagedIdentityCredential", Mock(return_value=identity))
    monkeypatch.setattr("service.checkpoint_runner_config.SecretClient",
                        lambda url, credential, **kwargs: SecretClient(url, credential, transport=transport, **kwargs))
    first = read_checkpoint_runner_inputs(values)
    second = read_checkpoint_runner_inputs(values)
    assert first.credentials == second.credentials
    assert transport.requests.count("PUT") == 1


def test_checkpoint_runner_request_is_scoped_secret_free_and_matches_observer(checkpoint_journal):
    store, _, lease, _ = checkpoint_journal
    spec, body = checkpoint_runner_request_fixture(store, lease)
    assert spec == build_runner_fixture(store, lease)
    assert isinstance(body, bytes)
    validate_checkpoint_runner_request(spec, body)
    request = json.loads(body)
    assert set(request) == {"location", "tags", "identity", "properties"}
    props = request["properties"]
    assert set(props) == {"osType", "sku", "restartPolicy", "subnetIds", "dnsConfig",
                          "imageRegistryCredentials", "containers"}
    assert props["subnetIds"] == [{"id": spec.subnet_id}]
    assert props["imageRegistryCredentials"] == [{"server": "fixtureacr.azurecr.io", "identity": spec.identity_id}]
    container = props["containers"][0]
    assert set(container["properties"]) == {"image", "environmentVariables", "resources", "securityContext"}
    assert all(set(variable) == {"name", "value"} for variable in container["properties"]["environmentVariables"])

    evidence = copy.deepcopy(request)
    evidence["id"] = spec.job_id
    evidence["identity"]["userAssignedIdentities"][spec.identity_id] = {
        "clientId": spec.identity_client_id, "principalId": spec.identity_principal_id}
    evidence["properties"]["provisioningState"] = "Succeeded"
    evidence["properties"]["ipAddress"] = {"type": "Private", "ip": "172.22.40.4", "ports": []}
    evidence["properties"]["containers"][0]["properties"]["instanceView"] = {
        "restartCount": 0, "currentState": {"state": "Running"}}
    assert validate_checkpoint_runner_observation(evidence, spec).state == "running"


@pytest.mark.parametrize("mutation", ["environment", "secret", "registry", "command", "subnet", "wrong_type"])
def test_checkpoint_runner_request_rejects_mutation_without_echoing_values(checkpoint_journal, mutation):
    store, _, lease, _ = checkpoint_journal
    spec, body = checkpoint_runner_request_fixture(store, lease)
    request = json.loads(body)
    props = request["properties"]
    if mutation == "environment":
        props["containers"][0]["properties"]["environmentVariables"].append(
            {"name": "PRIVATE-VALUE", "value": "PRIVATE-VALUE"})
    elif mutation == "secret":
        props["containers"][0]["properties"]["environmentVariables"][0]["secureValue"] = "PRIVATE-VALUE"
    elif mutation == "registry":
        props["imageRegistryCredentials"][0]["password"] = "PRIVATE-VALUE"
    elif mutation == "command":
        props["containers"][0]["properties"]["command"] = ["PRIVATE-VALUE"]
    elif mutation == "subnet":
        props["subnetIds"][0]["id"] = "PRIVATE-VALUE"
    altered = "PRIVATE-VALUE" if mutation == "wrong_type" else json.dumps(
        request, sort_keys=True, separators=(",", ":")).encode()
    with pytest.raises(CheckpointRunnerError) as error:
        validate_checkpoint_runner_request(spec, altered)
    assert "PRIVATE-VALUE" not in str(error.value)


def test_checkpoint_runner_request_fingerprint_binds_the_complete_body(checkpoint_journal, monkeypatch):
    from service import checkpoint_runner

    store, _, lease, _ = checkpoint_journal
    spec, body = checkpoint_runner_request_fixture(store, lease)
    original = spec.sha256
    assert replace(spec, identity_client_id=OTHER).sha256 != original
    assert replace(spec, identity_principal_id=OTHER).sha256 != original
    assert replace(spec, image=spec.image.replace("a" * 64, "c" * 64)).sha256 != original

    make_request = checkpoint_runner._checkpoint_runner_request
    def changed_request(value):
        result = make_request(value)
        result["properties"]["sku"] = "Confidential"
        return result
    monkeypatch.setattr(checkpoint_runner, "_checkpoint_runner_request", changed_request)
    assert spec.sha256 != original
    with pytest.raises(CheckpointRunnerError):
        validate_checkpoint_runner_request(spec, body)


def test_checkpoint_runner_request_matches_azure_sdk_serialization(checkpoint_journal):
    from io import BytesIO

    from azure.core.credentials import AccessToken
    from azure.core.pipeline.transport import HttpResponse, HttpTransport
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.resource.resources.models import GenericResource, Identity, IdentityUserAssignedIdentitiesValue

    class Response(HttpResponse):
        def __init__(self, request):
            super().__init__(request, None)
            self.status_code = 200
            self.headers = {"Content-Type": "application/json"}
            self.content_type = "application/json"

        def body(self):
            return b"{}"

        def read(self):
            return self.body()

        def stream_download(self, _pipeline, **_kwargs):
            return iter([self.body()])

    class Transport(HttpTransport):
        def __init__(self):
            self.requests = []

        def open(self):
            pass

        def close(self):
            pass

        def __exit__(self, *args):
            self.close()

        def send(self, request, **kwargs):
            self.requests.append(request)
            return Response(request)

    store, _, lease, _ = checkpoint_journal
    spec, body = checkpoint_runner_request_fixture(store, lease)
    request = json.loads(body)
    model = GenericResource(
        location=request["location"], tags=request["tags"], properties=request["properties"],
        identity=Identity(type="UserAssigned", user_assigned_identities={
            spec.identity_id: IdentityUserAssignedIdentitiesValue()}))
    credential = Mock(spec=["get_token"])
    credential.get_token.return_value = AccessToken("fixture-token", int(time.time()) + 3600)
    transport = Transport()
    arm = ResourceManagementClient(credential, SUBSCRIPTION, transport=transport,
                                   logging_enable=False, retry_total=0)
    try:
        arm.resources.begin_create_or_update_by_id(spec.job_id, "2023-05-01", model, polling=False).result()
        validate_checkpoint_runner_request(spec, body)
        arm.resources.begin_create_or_update_by_id(
            spec.job_id, "2023-05-01", BytesIO(body), polling=False).result()
        assert len(transport.requests) == 2
        outgoing = transport.requests[0]
        assert outgoing.method == "PUT" and spec.job_id.lower() in outgoing.url.lower()
        assert json.loads(outgoing.body) == request
        exact = transport.requests[1]
        assert exact.method == "PUT" and exact.body.read() == body
    finally:
        arm.close()


@pytest.mark.parametrize("mutation", ["identity_id", "identity_tenant", "identity_client", "identity_principal",
                                      "identity_zero_client", "identity_zero_principal", "identity_tag",
                                      "identity_location", "identity_isolation", "control_group", "foreign_subscription",
                                      "registry", "registry_trailing_hyphen",
                                      "image_digest", "settings_type", "settings_image", "settings_key"])
def test_checkpoint_runner_spec_rejects_foreign_or_untrusted_inputs(checkpoint_journal, mutation):
    store, _, lease, _ = checkpoint_journal
    foundation, private, group, control, identity = checkpoint_runner_fixture(store, lease)
    subscription, registry, image, config = SUBSCRIPTION, "fixtureacr.azurecr.io", "a" * 64, RUNNER_SETTINGS
    if mutation == "identity_id":
        identity["id"] = "PRIVATE-VALUE"
    elif mutation == "identity_tenant":
        identity["properties"]["tenantId"] = OTHER
    elif mutation == "identity_client":
        identity["properties"]["clientId"] = "PRIVATE-VALUE"
    elif mutation == "identity_principal":
        identity["properties"]["principalId"] = "PRIVATE-VALUE"
    elif mutation == "identity_zero_client":
        identity["properties"]["clientId"] = "00000000-0000-0000-0000-000000000000"
    elif mutation == "identity_zero_principal":
        identity["properties"]["principalId"] = "00000000-0000-0000-0000-000000000000"
    elif mutation == "identity_tag":
        identity["tags"]["purpose"] = "PRIVATE-VALUE"
    elif mutation == "identity_location":
        identity["location"] = "PRIVATE-VALUE"
    elif mutation == "identity_isolation":
        identity["properties"]["isolationScope"] = "PRIVATE-VALUE"
    elif mutation == "control_group":
        control = "PRIVATE-VALUE"
    elif mutation == "foreign_subscription":
        subscription = OTHER
    elif mutation == "registry":
        registry = "PRIVATE-VALUE"
    elif mutation == "registry_trailing_hyphen":
        registry = "fixture-.azurecr.io"
    elif mutation == "image_digest":
        image = "PRIVATE-VALUE"
    elif mutation == "settings_type":
        config = "PRIVATE-VALUE"
    elif mutation == "settings_image":
        config = replace(RUNNER_SETTINGS, gateway_image_version="PRIVATE-VALUE")
    else:
        config = replace(RUNNER_SETTINGS, provider_ssh_public_key="PRIVATE-VALUE")
    with pytest.raises(ValueError) as error:
        build_checkpoint_runner_spec(foundation, private, subscription, PROVIDER_TENANT, group,
                                     lease.environment_id, control, identity, registry, image, config)
    assert "PRIVATE-VALUE" not in str(error.value)


@pytest.mark.parametrize("mutation", [
    "job_id", "location", "purpose", "env_tag", "identity_type", "identity_id", "identity_client",
    "identity_principal", "extra_identity", "subnet", "dns", "search_domain", "restart_policy", "os_type",
    "extra_container", "extra_init", "volume", "diagnostics", "secret_reference", "extension",
    "config_map", "liveness_probe", "readiness_probe", "image", "command", "port", "environment",
    "extra_env", "secret_env", "registry", "registry_identity", "registry_password", "privileged",
    "privilege_escalation", "root_user", "root_group", "capabilities", "cpu", "memory", "public_ip",
    "foreign_private_ip", "reserved_private_ip", "restart_count", "invalid_exit",
])
def test_checkpoint_runner_observation_rejects_unsafe_job_evidence(checkpoint_journal, mutation):
    store, _, lease, _ = checkpoint_journal
    spec = build_runner_fixture(store, lease)
    resource = runner_resource(spec)
    props, identity = resource["properties"], resource["identity"]
    container = props["containers"][0]["properties"]
    registry = props["imageRegistryCredentials"][0]
    if mutation == "job_id":
        resource["id"] = "PRIVATE-VALUE"
    elif mutation == "location":
        resource["location"] = "PRIVATE-VALUE"
    elif mutation == "purpose":
        resource["tags"]["purpose"] = "PRIVATE-VALUE"
    elif mutation == "env_tag":
        resource["tags"]["environmentId"] = OTHER
    elif mutation == "identity_type":
        identity["type"] = "SystemAssigned"
    elif mutation == "identity_id":
        identity["userAssignedIdentities"] = {"PRIVATE-VALUE": {}}
    elif mutation in ("identity_client", "identity_principal"):
        key = "clientId" if mutation == "identity_client" else "principalId"
        identity["userAssignedIdentities"][spec.identity_id][key] = OTHER
    elif mutation == "extra_identity":
        identity["userAssignedIdentities"]["PRIVATE-VALUE"] = {}
    elif mutation == "subnet":
        props["subnetIds"][0]["id"] = "PRIVATE-VALUE"
    elif mutation == "dns":
        props["dnsConfig"]["nameServers"] = ["1.1.1.1"]
    elif mutation == "search_domain":
        props["dnsConfig"]["searchDomains"] = "PRIVATE-VALUE"
    elif mutation == "restart_policy":
        props["restartPolicy"] = "Always"
    elif mutation == "os_type":
        props["osType"] = "Windows"
    elif mutation == "extra_container":
        props["containers"].append({})
    elif mutation == "extra_init":
        props["initContainers"] = [{}]
    elif mutation == "volume":
        props["volumes"] = [{}]
    elif mutation == "diagnostics":
        props["diagnostics"] = {"workspaceKey": "PRIVATE-VALUE"}
    elif mutation == "secret_reference":
        props["secretReferences"] = [{"name": "PRIVATE-VALUE"}]
    elif mutation == "extension":
        props["extensions"] = [{"name": "PRIVATE-VALUE"}]
    elif mutation == "config_map":
        container["configMap"] = {"keyValuePairs": {"value": "PRIVATE-VALUE"}}
    elif mutation == "liveness_probe":
        container["livenessProbe"] = {"exec": {"command": ["PRIVATE-VALUE"]}}
    elif mutation == "readiness_probe":
        container["readinessProbe"] = {"exec": {"command": ["PRIVATE-VALUE"]}}
    elif mutation == "image":
        container["image"] = "PRIVATE-VALUE"
    elif mutation == "command":
        container["command"] = ["PRIVATE-VALUE"]
    elif mutation == "port":
        container["ports"] = [{"port": 80}]
    elif mutation == "environment":
        container["environmentVariables"][0]["value"] = "PRIVATE-VALUE"
    elif mutation == "extra_env":
        container["environmentVariables"].append({"name": "PRIVATE-VALUE", "value": "x"})
    elif mutation == "secret_env":
        container["environmentVariables"][0]["secureValue"] = "PRIVATE-VALUE"
    elif mutation == "registry":
        registry["server"] = "PRIVATE-VALUE"
    elif mutation == "registry_identity":
        registry["identity"] = "PRIVATE-VALUE"
    elif mutation == "registry_password":
        registry["password"] = "PRIVATE-VALUE"
    elif mutation == "privileged":
        container["securityContext"]["privileged"] = True
    elif mutation == "privilege_escalation":
        container["securityContext"]["allowPrivilegeEscalation"] = True
    elif mutation == "root_user":
        container["securityContext"]["runAsUser"] = 0
    elif mutation == "root_group":
        container["securityContext"]["runAsGroup"] = 0
    elif mutation == "capabilities":
        container["securityContext"]["capabilities"] = {"add": ["NET_ADMIN"]}
    elif mutation == "cpu":
        container["resources"]["requests"]["cpu"] = True
    elif mutation == "memory":
        container["resources"]["requests"]["memoryInGB"] = 8
    elif mutation == "public_ip":
        props["ipAddress"]["type"] = "Public"
    elif mutation == "foreign_private_ip":
        props["ipAddress"]["ip"] = "172.22.10.4"
    elif mutation == "reserved_private_ip":
        props["ipAddress"]["ip"] = "172.22.40.1"
    elif mutation == "restart_count":
        container["instanceView"]["restartCount"] = 1
    else:
        container["instanceView"]["currentState"] = {"state": "Terminated", "exitCode": False}
    with pytest.raises(CheckpointRunnerError) as error:
        validate_checkpoint_runner_observation(resource, spec)
    assert "PRIVATE-VALUE" not in str(error.value)


@pytest.mark.parametrize("state,exit_code,expected", [
    ("Waiting", None, "pending"), ("Running", None, "running"),
    ("Terminated", 0, "completed"), ("Terminated", 137, "completed"),
])
def test_checkpoint_runner_observation_distinguishes_job_status(checkpoint_journal, state, exit_code, expected):
    store, _, lease, _ = checkpoint_journal
    result = validate_checkpoint_runner_observation(runner_resource(build_runner_fixture(store, lease), state, exit_code),
                                                    build_runner_fixture(store, lease))
    assert result.state == expected and result.exit_code == exit_code


@pytest.mark.parametrize("exit_code", [0, 40, 137])
def test_checkpoint_runner_accepts_terminated_aci_after_private_ip_release(checkpoint_journal, exit_code):
    store, _, lease, _ = checkpoint_journal
    spec = build_runner_fixture(store, lease)
    resource = runner_resource(spec, "Terminated", exit_code)
    resource["properties"].pop("ipAddress", None)
    result = validate_checkpoint_runner_observation(resource, spec)
    assert result.state == "completed" and result.exit_code == exit_code


def test_checkpoint_runner_still_requires_private_ip_while_running(checkpoint_journal):
    store, _, lease, _ = checkpoint_journal
    spec = build_runner_fixture(store, lease)
    resource = runner_resource(spec)
    resource["properties"].pop("ipAddress", None)
    with pytest.raises(CheckpointRunnerError, match="Invalid Check Point runner status"):
        validate_checkpoint_runner_observation(resource, spec)


def test_checkpoint_runner_observer_never_relaunches_an_ambiguous_job(checkpoint_journal):
    store, _, lease, scope = checkpoint_journal
    spec, journal, resources = build_runner_fixture(store, lease), CheckpointRunnerJournal(scope), Mock()
    observer = CheckpointRunnerObserver(journal, resources)
    with pytest.raises(CheckpointRunnerStateError):
        observer.observe(lease, spec)
    resources.resources.get_by_id.assert_not_called()
    journal.reserve(lease, spec.job_id, spec.sha256)
    resources.resources.get_by_id.side_effect = ResourceNotFoundError()
    assert observer.observe(lease, spec).state == "not_started"
    assert journal.begin_launch(lease, spec.job_id, spec.sha256)
    assert observer.observe(lease, spec).state == "unconfirmed"
    assert not journal.begin_launch(lease, spec.job_id, spec.sha256)
    resources.resources.begin_create_or_update_by_id.assert_not_called()
    resources.resources.begin_delete_by_id.assert_not_called()


def test_checkpoint_runner_observer_reconciles_verified_termination_without_marking_firewall_ready(checkpoint_journal):
    store, _, lease, scope = checkpoint_journal
    spec, journal, resources = build_runner_fixture(store, lease), CheckpointRunnerJournal(scope), Mock()
    observer = CheckpointRunnerObserver(journal, resources)
    journal.reserve(lease, spec.job_id, spec.sha256)
    journal.begin_launch(lease, spec.job_id, spec.sha256)
    result = runner_resource(spec)
    resources.resources.get_by_id.side_effect = lambda *_: SimpleNamespace(
        serialize=lambda **_kwargs: copy.deepcopy(result))
    assert observer.observe(lease, spec).state == "running"
    assert journal.read(lease, spec.job_id, spec.sha256).state == "running"
    result["properties"]["containers"][0]["properties"]["instanceView"]["currentState"] = {
        "state": "Terminated", "exitCode": 0}
    assert observer.observe(lease, spec).state == "completed"
    assert journal.read(lease, spec.job_id, spec.sha256).state == "succeeded"
    assert store.operation(lease)["status"] == "Running"
    assert observer.observe(lease, spec).state == "completed"


def test_checkpoint_runner_observer_rejects_unexpected_existing_job(checkpoint_journal):
    store, _, lease, scope = checkpoint_journal
    spec, journal, resources = build_runner_fixture(store, lease), CheckpointRunnerJournal(scope), Mock()
    observer = CheckpointRunnerObserver(journal, resources)
    journal.reserve(lease, spec.job_id, spec.sha256)
    resource = runner_resource(spec)
    resources.resources.get_by_id.return_value = SimpleNamespace(serialize=lambda **_kwargs: resource)
    with pytest.raises(CheckpointRunnerError, match="Unexpected existing"):
        observer.observe(lease, spec)
    assert journal.read(lease, spec.job_id, spec.sha256).state == "reserved"
    resources.resources.begin_create_or_update_by_id.assert_not_called()


@pytest.mark.parametrize("kind", ["container", "provisioning"])
def test_checkpoint_runner_observer_records_failure_without_relaunch(checkpoint_journal, kind):
    store, _, lease, scope = checkpoint_journal
    spec, journal, resources = build_runner_fixture(store, lease), CheckpointRunnerJournal(scope), Mock()
    observer = CheckpointRunnerObserver(journal, resources)
    journal.reserve(lease, spec.job_id, spec.sha256)
    journal.begin_launch(lease, spec.job_id, spec.sha256)
    resource = runner_resource(spec, "Terminated", 137)
    if kind == "provisioning":
        resource["properties"]["provisioningState"] = "Failed"
    resources.resources.get_by_id.return_value = SimpleNamespace(serialize=lambda **_kwargs: resource)
    observation = observer.observe(lease, spec)
    assert observation.state == ("completed" if kind == "container" else "provisioning_failed")
    result = journal.read(lease, spec.job_id, spec.sha256)
    assert result.state == "failed"
    assert result.exit_code == (137 if kind == "container" else None)
    assert not journal.begin_launch(lease, spec.job_id, spec.sha256)


def test_checkpoint_runner_observer_redacts_read_errors_and_rejects_changed_results(checkpoint_journal):
    store, _, lease, scope = checkpoint_journal
    spec, journal, resources = build_runner_fixture(store, lease), CheckpointRunnerJournal(scope), Mock()
    observer = CheckpointRunnerObserver(journal, resources)
    journal.reserve(lease, spec.job_id, spec.sha256)
    journal.begin_launch(lease, spec.job_id, spec.sha256)
    resources.resources.get_by_id.side_effect = HttpResponseError("PRIVATE-VALUE")
    with pytest.raises(CheckpointRunnerError) as error:
        observer.observe(lease, spec)
    assert "PRIVATE-VALUE" not in str(error.value)
    resources.resources.get_by_id.side_effect = None
    resource = Mock()
    resource.serialize.side_effect = HttpResponseError("PRIVATE-VALUE")
    resources.resources.get_by_id.return_value = resource
    with pytest.raises(CheckpointRunnerError) as error:
        observer.observe(lease, spec)
    assert "PRIVATE-VALUE" not in str(error.value)
    resources.resources.get_by_id.return_value = SimpleNamespace(
        serialize=lambda **_kwargs: runner_resource(spec, "Terminated", 0))
    observer.observe(lease, spec)
    resources.resources.get_by_id.return_value = SimpleNamespace(
        serialize=lambda **_kwargs: runner_resource(spec, "Running"))
    with pytest.raises(CheckpointRunnerError, match="result changed"):
        observer.observe(lease, spec)


@pytest.mark.parametrize("missing", [False, True])
def test_checkpoint_runner_observer_rejects_lease_loss_during_read(checkpoint_journal, missing):
    store, backend, lease, scope = checkpoint_journal
    spec, journal, resources = build_runner_fixture(store, lease), CheckpointRunnerJournal(scope), Mock()
    journal.reserve(lease, spec.job_id, spec.sha256)
    journal.begin_launch(lease, spec.job_id, spec.sha256)

    def get_resource(*_):
        job = backend.get(store.partition, "job:" + lease.environment_id)
        job["leaseUntil"] = 0.0
        backend.transact([Change(job, str(job["_etag"]))])
        if missing:
            raise ResourceNotFoundError("PRIVATE-VALUE")
        return SimpleNamespace(serialize=lambda **_kwargs: runner_resource(spec))

    resources.resources.get_by_id.side_effect = get_resource
    with pytest.raises(LostLease) as error:
        CheckpointRunnerObserver(journal, resources).observe(lease, spec)
    assert error.value.__context__ is None
    next_lease = store.claim(lease.environment_id, "checkpoint-recovery")
    assert next_lease is not None
    assert journal.read(next_lease, spec.job_id, spec.sha256).state == "launching"


def test_checkpoint_runner_observer_uses_actual_arm_sdk_response_shape(checkpoint_journal):
    from azure.core.credentials import AccessToken
    from azure.core.pipeline.transport import HttpResponse, HttpTransport
    from azure.mgmt.resource import ResourceManagementClient

    class Response(HttpResponse):
        def __init__(self, request, resource):
            super().__init__(request, None)
            self.status_code = 200
            self.headers = {"Content-Type": "application/json"}
            self.content_type = "application/json"
            self.payload = json.dumps(resource).encode()

        def body(self):
            return self.payload

    class Transport(HttpTransport):
        def __init__(self, resource):
            self.resource = resource
            self.requests = []

        def open(self):
            pass

        def close(self):
            pass

        def __exit__(self, *args):
            self.close()

        def send(self, request, **kwargs):
            self.requests.append((request.method, request.url))
            return Response(request, self.resource)

    store, _, lease, scope = checkpoint_journal
    spec, journal = build_runner_fixture(store, lease), CheckpointRunnerJournal(scope)
    journal.reserve(lease, spec.job_id, spec.sha256)
    journal.begin_launch(lease, spec.job_id, spec.sha256)
    credential = Mock(spec=["get_token"])
    credential.get_token.return_value = AccessToken("fixture-token", int(time.time()) + 3600)
    transport = Transport(runner_resource(spec, "Terminated", 0))
    arm = ResourceManagementClient(credential, SUBSCRIPTION, transport=transport,
                                   logging_enable=False, retry_total=0)
    try:
        assert CheckpointRunnerObserver(journal, arm).observe(lease, spec).state == "completed"
        assert len(transport.requests) == 1
        method, url = transport.requests[0]
        assert method == "GET" and spec.job_id.lower() in url.lower()
        assert journal.read(lease, spec.job_id, spec.sha256).state == "succeeded"
    finally:
        arm.close()


class CheckpointMemorySecrets:
    def __init__(self):
        self.lock = threading.RLock()
        self.secret = None
        self.versions = []
        self.set_calls = 0
        self.failure = None
        self.after_write = None

    def set_secret(self, name, value, **kwargs):
        with self.lock:
            self.set_calls += 1
            assert kwargs["retry_total"] == 0 and kwargs["logging_enable"] is False
            assert kwargs["tracing_options"] == {"enabled": False}
            if self.failure == "before":
                self.failure = None
                raise ServiceResponseError("PRIVATE-VALUE")
            properties = SimpleNamespace(
                version="a" * 32, enabled=kwargs["enabled"],
                content_type=kwargs["content_type"], tags=kwargs["tags"])
            self.secret = SimpleNamespace(name=name, value=value, properties=properties)
            self.versions.append(properties)
            if self.after_write:
                self.after_write()
            if self.failure == "after":
                self.failure = None
                raise ServiceResponseError("PRIVATE-VALUE")
            return self.secret

    def list_properties_of_secret_versions(self, name, **kwargs):
        assert kwargs["retry_total"] == 0 and kwargs["logging_enable"] is False
        assert kwargs["tracing_options"] == {"enabled": False}
        with self.lock:
            if self.secret is None:
                raise ResourceNotFoundError("PRIVATE-VALUE")
            return iter(list(self.versions))

    def get_secret(self, name, version=None, **kwargs):
        assert kwargs["retry_total"] == 0 and kwargs["logging_enable"] is False
        assert kwargs["tracing_options"] == {"enabled": False}
        with self.lock:
            if self.secret is None or self.secret.name != name or self.secret.properties.version != version:
                raise ResourceNotFoundError("PRIVATE-VALUE")
            return self.secret

    def close(self):
        pass


@pytest.fixture
def checkpoint_private_vault(checkpoint_journal, monkeypatch):
    store, backend, lease, journal = checkpoint_journal
    outputs, vault, resources = checkpoint_vault_fixture(store, lease)
    secrets = CheckpointMemorySecrets()
    factory = Mock(return_value=secrets)
    monkeypatch.setattr("service.checkpoint_vault.SecretClient", factory)
    adapter = CheckpointCredentialVault(journal, PROVIDER_TENANT, resources, Mock())
    return store, backend, lease, adapter, outputs, vault, resources, secrets, factory


def test_checkpoint_vault_writes_once_and_reads_only_bound_version(checkpoint_private_vault):
    store, _, lease, adapter, outputs, _, _, secrets, factory = checkpoint_private_vault
    reference = adapter.ensure(lease, outputs)
    assert adapter.ensure(lease, outputs) == reference
    credentials = adapter.read(lease, outputs)
    assert secrets.set_calls == 1
    assert factory.call_args.kwargs["retry_total"] == 0
    assert factory.call_args.kwargs["logging_enable"] is False
    assert secrets.secret.properties.content_type == CONTENT_TYPE
    assert reference.version == "a" * 32
    assert credentials.management_password not in repr(credentials)
    assert credentials.sic_key not in repr(credentials)
    saved = str(store.operation(lease)["checkpointCredentialRef"])
    assert credentials.management_password not in saved and credentials.sic_key not in saved
    public = json.dumps(public_operation(store.operation(lease)))
    assert reference.name not in public and reference.vault_id not in public
    assert json.loads(saved)["fingerprint"] not in public


def test_checkpoint_vault_recovers_ambiguous_success_without_another_write(checkpoint_private_vault, caplog):
    store, _, lease, adapter, outputs, _, _, secrets, _ = checkpoint_private_vault
    secrets.failure = "after"
    with pytest.raises(CheckpointVaultError) as error:
        adapter.ensure(lease, outputs)
    assert "PRIVATE-VALUE" not in str(error.value)
    assert json.loads(str(store.operation(lease)["checkpointCredentialRef"]))["state"] == "reserved"
    reference = adapter.ensure(lease, outputs)
    assert reference.version == "a" * 32
    assert secrets.set_calls == 1
    assert json.loads(str(store.operation(lease)["checkpointCredentialRef"]))["state"] == "bound"
    value = json.loads(secrets.secret.value)
    assert value["managementPassword"] not in caplog.text and value["sicKey"] not in caplog.text


def test_checkpoint_vault_does_not_repeat_an_unresolved_write_after_restart(checkpoint_private_vault):
    store, backend, lease, adapter, outputs, _, _, secrets, _ = checkpoint_private_vault
    secrets.failure = "before"
    with pytest.raises(CheckpointVaultError):
        adapter.ensure(lease, outputs)
    job = backend.get(store.partition, "job:" + lease.environment_id)
    job["leaseUntil"] = 0.0
    backend.transact([Change(job, str(job["_etag"]))])
    next_lease = store.claim(lease.environment_id, "checkpoint-recovery")
    assert next_lease is not None
    with pytest.raises(CheckpointCredentialPending) as error:
        adapter.ensure(next_lease, outputs)
    assert "PRIVATE-VALUE" not in str(error.value)
    assert secrets.set_calls == 1


def test_checkpoint_vault_never_binds_multiple_secret_versions(checkpoint_private_vault):
    store, _, lease, adapter, outputs, _, _, secrets, _ = checkpoint_private_vault
    secrets.failure = "after"
    with pytest.raises(CheckpointVaultError):
        adapter.ensure(lease, outputs)
    secrets.versions.append(SimpleNamespace(version="b" * 32))
    with pytest.raises(CheckpointVaultError, match="Multiple"):
        adapter.ensure(lease, outputs)
    assert secrets.set_calls == 1
    assert json.loads(str(store.operation(lease)["checkpointCredentialRef"]))["state"] == "reserved"


def test_checkpoint_vault_rejects_modified_bound_material_without_replacement(checkpoint_private_vault):
    _, _, lease, adapter, outputs, _, _, secrets, _ = checkpoint_private_vault
    adapter.ensure(lease, outputs)
    value = json.loads(secrets.secret.value)
    value["sicKey"] = "b" * 48
    secrets.secret.value = json.dumps(value, separators=(",", ":"))
    with pytest.raises(CheckpointVaultError, match="fingerprint mismatch"):
        adapter.read(lease, outputs)
    with pytest.raises(CheckpointVaultError, match="fingerprint mismatch"):
        adapter.ensure(lease, outputs)
    assert secrets.set_calls == 1


def test_checkpoint_vault_rejects_public_vault_before_reservation(checkpoint_private_vault):
    store, _, lease, adapter, outputs, vault, _, secrets, factory = checkpoint_private_vault
    vault["properties"]["publicNetworkAccess"] = "Enabled"
    with pytest.raises(ValueError, match="not private"):
        adapter.ensure(lease, outputs)
    assert "checkpointCredentialRef" not in store.operation(lease)
    assert secrets.set_calls == 0
    factory.assert_not_called()


def test_checkpoint_vault_read_does_not_reserve_or_create_credentials(checkpoint_private_vault):
    store, _, lease, adapter, outputs, _, _, secrets, factory = checkpoint_private_vault
    with pytest.raises(CheckpointCredentialStateError, match="not bound"):
        adapter.read(lease, outputs)
    assert "checkpointCredentialRef" not in store.operation(lease)
    assert secrets.set_calls == 0
    factory.assert_not_called()


def test_checkpoint_vault_reconciles_after_writer_loses_lease(checkpoint_private_vault):
    store, backend, lease, adapter, outputs, _, _, secrets, _ = checkpoint_private_vault
    def expire():
        job = backend.get(store.partition, "job:" + lease.environment_id)
        job["leaseUntil"] = 0.0
        backend.transact([Change(job, str(job["_etag"]))])
    secrets.after_write = expire
    with pytest.raises(LostLease):
        adapter.ensure(lease, outputs)
    next_lease = store.claim(lease.environment_id, "checkpoint-recovery")
    assert next_lease is not None
    assert adapter.ensure(next_lease, outputs).version == "a" * 32
    assert secrets.set_calls == 1


def test_checkpoint_vault_recovers_reservation_before_write_preparation(checkpoint_private_vault):
    store, backend, lease, adapter, outputs, _, _, secrets, _ = checkpoint_private_vault
    vault_id = checkpoint_vault_id(store, lease)
    first = adapter.journal.reserve(lease, vault_id)
    job = backend.get(store.partition, "job:" + lease.environment_id)
    job["leaseUntil"] = 0.0
    backend.transact([Change(job, str(job["_etag"]))])
    next_lease = store.claim(lease.environment_id, "checkpoint-recovery")
    assert next_lease is not None
    assert adapter.ensure(next_lease, outputs).name == first.name
    assert secrets.set_calls == 1


def test_checkpoint_vault_never_writes_after_lease_lost_during_preparation(checkpoint_private_vault, monkeypatch):
    store, backend, lease, adapter, outputs, _, _, secrets, _ = checkpoint_private_vault
    prepare = adapter.journal.prepare
    def prepare_then_expire(*args):
        prepare(*args)
        job = backend.get(store.partition, "job:" + lease.environment_id)
        job["leaseUntil"] = 0.0
        backend.transact([Change(job, str(job["_etag"]))])
    monkeypatch.setattr(adapter.journal, "prepare", prepare_then_expire)
    with pytest.raises(LostLease):
        adapter.ensure(lease, outputs)
    next_lease = store.claim(lease.environment_id, "checkpoint-recovery")
    assert next_lease is not None
    with pytest.raises(CheckpointCredentialPending):
        adapter.ensure(next_lease, outputs)
    assert secrets.set_calls == 0


def test_checkpoint_vault_concurrent_attempts_never_duplicate_write(checkpoint_private_vault):
    _, _, lease, adapter, outputs, _, _, secrets, _ = checkpoint_private_vault
    def attempt(_):
        try:
            return adapter.ensure(lease, outputs)
        except CheckpointCredentialPending:
            return None
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(attempt, range(8)))
    assert any(item is not None for item in results)
    assert secrets.set_calls == 1
    assert adapter.ensure(lease, outputs).version == "a" * 32


@pytest.mark.parametrize("mutation", ["value", "valid_different_value", "name", "version", "content_type",
                                      "tags", "disabled"])
def test_checkpoint_vault_rejects_tampered_secret_without_echoing_it(checkpoint_private_vault, mutation):
    store, _, lease, adapter, outputs, _, _, secrets, _ = checkpoint_private_vault
    secrets.failure = "after"
    with pytest.raises(CheckpointVaultError):
        adapter.ensure(lease, outputs)
    if mutation == "value":
        secrets.secret.value = "PRIVATE-VALUE"
    elif mutation == "valid_different_value":
        value = json.loads(secrets.secret.value)
        value["sicKey"] = "b" * 48
        secrets.secret.value = json.dumps(value, separators=(",", ":"))
    elif mutation == "name":
        secrets.secret.name = "PRIVATE-VALUE"
    elif mutation == "version":
        secrets.secret.properties.version = "PRIVATE-VALUE"
    elif mutation == "content_type":
        secrets.secret.properties.content_type = "PRIVATE-VALUE"
    elif mutation == "tags":
        secrets.secret.properties.tags = {"purpose": "PRIVATE-VALUE"}
    else:
        secrets.secret.properties.enabled = False
    with pytest.raises((CheckpointVaultError, CheckpointCredentialPending)) as error:
        adapter.ensure(lease, outputs)
    assert "PRIVATE-VALUE" not in str(error.value)
    assert secrets.set_calls == 1
    assert json.loads(str(store.operation(lease)["checkpointCredentialRef"]))["state"] == "reserved"


@pytest.mark.parametrize("failure", ["transport", "http503"])
def test_checkpoint_vault_real_sdk_does_not_retry_authenticated_secret_write(
        checkpoint_private_vault, monkeypatch, caplog, failure):
    from azure.core.credentials import AccessToken
    from azure.core.pipeline.transport import HttpResponse, HttpTransport
    from azure.keyvault.secrets import SecretClient

    class Challenge(HttpResponse):
        def __init__(self, request):
            super().__init__(request, None)
            self.status_code = 401
            self.headers = {"WWW-Authenticate": (
                f'Bearer authorization="https://login.microsoftonline.com/{PROVIDER_TENANT}", '
                'resource="https://vault.azure.net"')}
            self.content_type = "application/json"

        def body(self):
            return b'{}'

        def json(self):
            return {}

    class Transport(HttpTransport):
        def __init__(self):
            self.requests = []
            self.value = None

        def open(self):
            pass

        def close(self):
            pass

        def __exit__(self, *args):
            self.close()

        def send(self, request, **kwargs):
            if request.body is not None:
                self.value = json.loads(request.body)["value"]
            authenticated = bool(request.headers.get("Authorization"))
            self.requests.append((request.method, authenticated))
            if not authenticated:
                return Challenge(request)
            if failure == "http503":
                response = Challenge(request)
                response.status_code = 503
                response.headers = {"Content-Type": "application/json"}
                return response
            raise ServiceResponseError("PRIVATE-VALUE")

    _, _, lease, adapter, outputs, _, _, _, _ = checkpoint_private_vault
    transport = Transport()
    credential = Mock(spec=["get_token"])
    credential.get_token.return_value = AccessToken("fixture-token", int(time.time()) + 3600)
    def client(references):
        return SecretClient(references.vault_uri, credential, transport=transport,
                            retry_total=0, logging_enable=False)
    monkeypatch.setattr(adapter, "_client", client)
    caplog.set_level(logging.DEBUG)
    with pytest.raises(CheckpointVaultError) as error:
        adapter.ensure(lease, outputs)
    assert "PRIVATE-VALUE" not in str(error.value)
    assert 1 <= len(transport.requests) <= 2
    assert all(method == "PUT" for method, _ in transport.requests)
    assert sum(authenticated for _, authenticated in transport.requests) == 1
    assert transport.value is not None
    value = json.loads(transport.value)
    assert value["managementPassword"] not in caplog.text and value["sicKey"] not in caplog.text


def test_checkpoint_vault_validates_real_arm_sdk_response_shapes(checkpoint_private_vault):
    from azure.core.credentials import AccessToken
    from azure.core.pipeline.transport import HttpResponse, HttpTransport
    from azure.mgmt.resource import ResourceManagementClient

    class Response(HttpResponse):
        def __init__(self, request, resource):
            super().__init__(request, None)
            self.status_code = 200
            self.headers = {"Content-Type": "application/json"}
            self.content_type = "application/json"
            self.payload = json.dumps(resource).encode()

        def body(self):
            return self.payload

    class Transport(HttpTransport):
        def __init__(self, vault, endpoint):
            self.vault, self.endpoint = vault, endpoint
            self.requests = []

        def open(self):
            pass

        def close(self):
            pass

        def __exit__(self, *args):
            self.close()

        def send(self, request, **kwargs):
            self.requests.append(request.url)
            resource = self.vault if "/microsoft.keyvault/vaults/" in request.url.lower() else self.endpoint
            return Response(request, resource)

    store, _, lease, adapter, outputs, vault, resources, secrets, _ = checkpoint_private_vault
    endpoint = resources.resources.get_by_id(outputs["credentialPrivateEndpointId"]["value"], "").as_dict()
    credential = Mock(spec=["get_token"])
    credential.get_token.return_value = AccessToken("fixture-token", int(time.time()) + 3600)
    transport = Transport(vault, endpoint)
    arm = ResourceManagementClient(credential, SUBSCRIPTION, transport=transport,
                                   logging_enable=False, retry_total=0)
    adapter.resources = arm
    try:
        assert adapter.ensure(lease, outputs).version == "a" * 32
        assert len(transport.requests) == 2
        assert all(store.operation(lease)["providerGroupName"].lower() in url.lower()
                   for url in transport.requests)
        assert secrets.set_calls == 1
    finally:
        arm.close()


@pytest.mark.parametrize("ambiguous", [False, True])
def test_checkpoint_vault_real_sdk_round_trip_preserves_secret_version(
        checkpoint_private_vault, monkeypatch, ambiguous):
    from azure.core.credentials import AccessToken
    from azure.core.pipeline.transport import HttpResponse, HttpTransport
    from azure.keyvault.secrets import SecretClient

    class Response(HttpResponse):
        def __init__(self, request, status, payload, headers):
            super().__init__(request, None)
            self.status_code, self.headers = status, headers
            self.content_type = "application/json"
            self.payload = payload

        def body(self):
            return json.dumps(self.payload).encode()

        def json(self):
            return self.payload

    class Transport(HttpTransport):
        def __init__(self):
            self.secret = None
            self.writes = 0

        def open(self):
            pass

        def close(self):
            pass

        def __exit__(self, *args):
            self.close()

        def send(self, request, **kwargs):
            if not request.headers.get("Authorization"):
                return Response(request, 401, {}, {"WWW-Authenticate": (
                    f'Bearer authorization="https://login.microsoftonline.com/{PROVIDER_TENANT}", '
                    'resource="https://vault.azure.net"')})
            if request.method == "PUT":
                self.writes += 1
                payload = json.loads(request.body)
                secret_url = request.url.split("?", 1)[0].rstrip("/")
                self.secret = {
                    "id": f"{secret_url}/{'a' * 32}", "value": payload["value"],
                    "contentType": payload["contentType"], "tags": payload["tags"],
                    "attributes": {"enabled": True},
                }
                if ambiguous:
                    raise ServiceResponseError("PRIVATE-VALUE")
            elif "/versions" in request.url:
                properties = {key: value for key, value in self.secret.items() if key != "value"}
                return Response(request, 200, {"value": [properties]}, {"Content-Type": "application/json"})
            return Response(request, 200, self.secret, {"Content-Type": "application/json"})

    _, _, lease, adapter, outputs, _, _, _, _ = checkpoint_private_vault
    transport = Transport()
    credential = Mock(spec=["get_token"])
    credential.get_token.return_value = AccessToken("fixture-token", int(time.time()) + 3600)
    def client(references):
        return SecretClient(references.vault_uri, credential, transport=transport,
                            retry_total=0, logging_enable=False)
    monkeypatch.setattr(adapter, "_client", client)
    if ambiguous:
        with pytest.raises(CheckpointVaultError):
            adapter.ensure(lease, outputs)
    reference = adapter.ensure(lease, outputs)
    credentials = adapter.read(lease, outputs)
    assert reference.version == "a" * 32
    assert transport.writes == 1
    assert len(credentials.management_password) >= 16
    assert len(credentials.sic_key) == 48


def test_provisioner_rejects_checkpoint_before_arm_or_vault(templates, target):
    arm, vault = Mock(), Mock(spec=Vault)
    provisioner = Provisioner(arm, vault, templates, target)
    with pytest.raises(ProvisionError) as error:
        provisioner.provision(str(uuid4()),
                              EnvironmentRequest.model_validate({**NETWORK, "firewallType": "checkpoint-byol"}),
                              lambda: None)
    assert error.value.code == "CheckpointDeploymentUnavailable"
    arm.get.assert_not_called()
    vault.ensure.assert_not_called()


def test_worker_rejects_parallel_mode_for_a_proof(settings, backend, templates, target):
    store = Store(backend, settings)
    operation = store.reserve(OWNER, "invalid-parallel-proof", EnvironmentRequest())
    row = store.owned(OWNER, str(operation["environmentId"]))
    request = json.loads(str(row["request"]))
    request["_faasParallelProviderNetworking"] = True
    row["request"] = json.dumps(request)
    backend.transact([Change(row, str(row["_etag"]))])
    arm = FakeArm()

    assert Worker(store, Provisioner(arm, Mock(spec=Vault), templates, target)).tick()

    result = store.owned(OWNER, str(operation["environmentId"]))
    assert result["status"] == "Failed"
    assert result["errorCode"] == "InvalidProviderNetworkingMode"
    assert not arm.starts


@pytest.mark.parametrize("remove_marker", [True, False])
def test_worker_rejects_mismatched_isolated_mode(
        settings, backend, templates, target, remove_marker):
    network_templates(templates)
    store = Store(backend, replace(settings, provider_group_mode="isolated"))
    operation = store.reserve(OWNER, "isolated-marker", EnvironmentRequest.model_validate(NETWORK))
    row = store.owned(OWNER, str(operation["environmentId"]))
    if remove_marker:
        request = json.loads(str(row["request"]))
        request.pop("_faasIsolatedProviderGroup")
        row["request"] = json.dumps(request)
    else:
        row["providerGroupMode"] = "shared"
    backend.transact([Change(row, str(row["_etag"]))])
    groups, isolated_factory, arm = Mock(), Mock(), FakeArm()

    assert Worker(store, Provisioner(arm, Mock(spec=Vault), templates, target),
                  groups, isolated_factory).tick()

    result = store.owned(OWNER, str(operation["environmentId"]))
    assert result["status"] == "Failed"
    assert result["errorCode"] == "InvalidProviderGroupMode"
    groups.ensure.assert_not_called()
    isolated_factory.assert_not_called()
    assert arm.starts == []


def test_unavailable_isolated_creation_fails_without_azure_writes(
        settings, backend, templates, target):
    from service.environment_groups import EnvironmentGroups

    network_templates(templates)
    store = Store(backend, replace(settings, provider_group_mode="isolated"))
    operation = store.reserve(OWNER, "unavailable-group",
                              EnvironmentRequest.model_validate(NETWORK))
    resources, authorization = Mock(), Mock()
    resources.resource_groups.get.side_effect = ResourceNotFoundError()
    groups = EnvironmentGroups(resources, authorization, SUBSCRIPTION, PRINCIPAL)
    arm, vault, isolated_factory = FakeArm(), Mock(spec=Vault), Mock()

    assert Worker(store, Provisioner(arm, vault, templates, target),
                  groups, isolated_factory).tick()

    result = store.owned(OWNER, str(operation["environmentId"]))
    assert result["status"] == "Failed"
    assert result["errorCode"] == "GroupCreationUnavailable"
    assert result.get("providerGroupState", "new") == "new"
    assert backend.get(TENANT, "quota")["allocated"] == 1
    resources.resource_groups.create_or_update.assert_not_called()
    authorization.role_assignments.create.assert_not_called()
    isolated_factory.assert_not_called()
    vault.ensure.assert_not_called()
    assert arm.starts == []


def test_isolated_worker_uses_only_bound_group(settings, backend, templates, target):
    network_templates(templates)
    store = Store(backend, replace(settings, provider_group_mode="isolated"))
    operation = store.reserve(OWNER, "isolated-worker", EnvironmentRequest.model_validate(NETWORK))
    shared = FakeArm()
    isolated = FakeArm(outputs={"connectionManifest": {"type": "Object", "value": MANIFEST}})
    isolated.close = Mock()
    groups = Mock()
    groups.subscription = SUBSCRIPTION
    scope = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{operation['providerGroupName']}"

    def ensure(row, location, check, begin, bind):
        check()
        begin()
        bind(scope)
        return row["providerGroupName"]

    groups.ensure.side_effect = ensure
    factory = Mock(return_value=isolated)
    vault = Mock(spec=Vault)
    vault.ensure.side_effect = [SecretMaterial("ingress", "v-one"),
                                SecretMaterial("delivery", "v-two")]
    assert Worker(store, Provisioner(shared, vault, templates, target), groups, factory).tick()
    row = store.owned(OWNER, str(operation["environmentId"]))
    assert row["status"] == "Ready" and row["providerGroupId"] == scope
    factory.assert_called_once_with(operation["providerGroupName"])
    assert shared.starts == [] and len(isolated.starts) == 1
    isolated.close.assert_called_once()


@pytest.mark.parametrize("manifest", [
    {**MANIFEST, "ingressSharedKey": "DO-NOT-LEAK"},
    {**MANIFEST, "providerIngress": {**ENDPOINT, "key": "DO-NOT-LEAK"}},
    {**MANIFEST, "providerIngress": {**ENDPOINT, "publicIp": "10.1.1.1"}},
    {**MANIFEST, "firewallVip": "not-ip"},
])
def test_manifest_rejects_unknown_fields_and_secrets(templates, target, manifest):
    network_templates(templates)
    arm = FakeArm(outputs={"connectionManifest": {"type": "Object", "value": manifest}})
    arm.deployment = "existing"
    with pytest.raises(ProvisionError) as caught:
        Provisioner(arm, Mock(spec=Vault), templates, target).provision(
            str(uuid4()), EnvironmentRequest.model_validate(NETWORK), lambda: None)
    assert caught.value.code == "InvalidConnectionManifest"
    assert "DO-NOT-LEAK" not in str(caught.value)


def test_disabled_network_fails_without_arm_write(templates, target):
    arm = FakeArm()
    with pytest.raises(ProvisionError) as caught:
        Provisioner(arm, Mock(spec=Vault), templates, target).provision(
            str(uuid4()), EnvironmentRequest.model_validate(NETWORK), lambda: None)
    assert caught.value.code == "NetworkTemplateNotConfigured"
    assert caught.value.release
    assert not arm.starts


@pytest.mark.parametrize("status,code,retryable", [
    (401, "ProviderAuthorizationNotReady", True),
    (403, "ProviderAuthorizationNotReady", True),
    (429, "ProviderTemporarilyUnavailable", True),
    (503, "ProviderTemporarilyUnavailable", True),
    (400, "ProviderDeploymentRejected", False),
])
def test_arm_safe_errors(templates, target, status, code, retryable):
    arm = Mock()
    error = HttpResponseError("PRIVATE-CUSTOMER-SECRET")
    error.status_code = status
    arm.get.side_effect = error
    with pytest.raises(ProvisionError) as caught:
        Provisioner(arm, Mock(spec=Vault), templates, target).provision(
            str(uuid4()), EnvironmentRequest(), lambda: None)
    assert caught.value.code == code and caught.value.retryable == retryable
    assert "PRIVATE" not in str(caught.value)


def test_failed_proof_only_releases_after_reconciliation(templates, target):
    arm = FakeArm(state="Failed")
    arm.deployment = "existing"
    arm.proof_absent = Mock(return_value=True)
    with pytest.raises(ProvisionError) as caught:
        Provisioner(arm, Mock(spec=Vault), templates, target).provision(
            str(uuid4()), EnvironmentRequest(), lambda: None)
    assert caught.value.release
    arm.proof_absent.assert_called_once()


@pytest.mark.parametrize("mutate", [
    lambda t: t.update(unknownField=True),
    lambda t: t.update(**{"$schema": "https://evil/template"}),
    lambda t: t["parameters"].update(arbitraryResourceId={"type": "string"}),
    lambda t: t["parameters"]["environmentId"].update(type="secureString"),
    lambda t: t["resources"][0].update(scope="/subscriptions/elsewhere"),
    lambda t: t["resources"][0].update(type="Microsoft.Authorization/roleAssignments"),
    lambda t: t["resources"][0].update(type="Microsoft.Resources/deployments"),
    lambda t: t["resources"][0].update(type="Microsoft.Compute/virtualMachines/extensions"),
    lambda t: t.update(outputs={"secret": {"type": "string", "value": "bad"}}),
])
def test_template_refuses_contract_drift_and_scope_escape(templates, mutate):
    template = copy.deepcopy(templates.proof)
    mutate(template)
    with pytest.raises(ValueError):
        Templates.validate(template, False)


def test_pinned_network_template_load_and_hash_refusal(templates, target, signing_key):
    network_templates(templates)
    # Stay inside test-owned service path; no temporary directories.
    path = Path("service/templates/.test-provider.json")
    raw = json.dumps(templates.network).encode()
    path.write_bytes(raw)
    try:
        key = signing_key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
        configured = replace(target, template_path=path,
                             template_sha256=hashlib.sha256(raw).hexdigest(), ssh_public_key=key)
        assert Templates(configured).network
        with pytest.raises(ValueError, match="hash"):
            Templates(replace(configured, template_sha256="0" * 64))
        with pytest.raises(ValueError):
            Templates(replace(configured, ssh_public_key="invalid"))
    finally:
        path.unlink()


def test_missing_network_inputs_do_not_block_proof_startup(target):
    assert Templates(replace(target, template_sha256="a" * 64)).network is None
    existing = Path("service/templates/proof.json")
    assert Templates(replace(target, template_path=existing,
                             template_sha256="a" * 64)).network is None


def test_complete_network_config_requires_existing_artifact(target, signing_key):
    key = signing_key.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
    with pytest.raises(ValueError, match="template is unavailable"):
        Templates(replace(target, template_sha256="a" * 64, ssh_public_key=key))


def nested_template(templates):
    template = copy.deepcopy(network_templates(templates).network)
    child = copy.deepcopy(templates.proof)
    template["resources"] = [{
        "type": "Microsoft.Resources/deployments", "apiVersion": "2024-03-01",
        "name": "server-owned-module",
        "properties": {"mode": "Incremental", "expressionEvaluationOptions": {"scope": "inner"},
                       "template": child, "parameters": {}}}]
    return template


def test_embedded_same_group_modules_are_validated_recursively(templates):
    assert Templates.validate(nested_template(templates), True)


@pytest.mark.parametrize("identity,valid", [
    ({"type": "SystemAssigned"}, True),
    ({"type": "UserAssigned", "userAssignedIdentities": {"/arbitrary": {}}}, False),
    ({"type": "SystemAssigned", "userAssignedIdentities": {}}, False),
])
def test_vm_identity_is_system_assigned_only(templates, identity, valid):
    template = copy.deepcopy(network_templates(templates).network)
    template["resources"][0].update(type="Microsoft.Compute/virtualMachines", identity=identity)
    if valid:
        assert Templates.validate(template, True)
    else:
        with pytest.raises(ValueError):
            Templates.validate(template, True)


@pytest.mark.parametrize("mutate", [
    lambda t: t["resources"][0].update(subscriptionId=OTHER),
    lambda t: t["resources"][0].update(resourceGroup="foreign"),
    lambda t: t["resources"][0]["properties"].update(templateLink={"uri": "https://evil"}),
    lambda t: t["resources"][0]["properties"].update(mode="Complete"),
    lambda t: t["resources"][0]["properties"].update(template="[variables('arbitrary')]"),
    lambda t: t["resources"][0]["properties"].update(expressionEvaluationOptions={"scope": "outer"}),
    lambda t: t["resources"][0]["properties"]["template"]["resources"][0].update(
        type="Microsoft.Authorization/roleAssignments"),
])
def test_nested_module_scope_and_type_refusals(templates, mutate):
    template = nested_template(templates)
    mutate(template)
    with pytest.raises(ValueError):
        Templates.validate(template, True)


def test_worker_ready_and_no_secret_persistence(store, templates, target, backend):
    environment_id = str(store.reserve(OWNER, "worker", EnvironmentRequest())["environmentId"])
    provisioner = Provisioner(FakeArm(), Mock(spec=Vault), templates, target)
    worker = Worker(store, provisioner)
    assert worker.tick()
    assert store.owned(OWNER, environment_id)["status"] == "Ready"
    assert not worker.tick()
    assert backend.get(TENANT, "quota")["allocated"] == 1


def test_worker_retry_max_bounded_and_safe_errors(store, backend):
    environment_id = str(store.reserve(OWNER, "worker-error", EnvironmentRequest())["environmentId"])
    provisioner = Mock(spec=Provisioner)
    provisioner.provision.side_effect = RuntimeError("DO-NOT-LOG-TOKEN")
    worker = Worker(store, provisioner)
    for index in range(store.settings.max_attempts):
        job = backend.get(TENANT, "job:" + environment_id)
        job["nextAttempt"] = 0.0
        backend.transact([Change(job, job["_etag"])])
        assert worker.tick()
    operation = store.owned(OWNER, environment_id)
    assert operation["status"] == "Failed"
    assert operation["errorCode"] == "WorkerDependencyUnavailable"
    assert "DO-NOT" not in json.dumps(list(backend.rows.values()))
    assert backend.get(TENANT, "quota")["allocated"] == 1


def test_worker_renews_lease_during_slow_arm(settings, backend):
    store = Store(backend, replace(settings, lease_seconds=0.09))
    environment_id = str(store.reserve(OWNER, "slow", EnvironmentRequest())["environmentId"])
    provisioner = Mock(spec=Provisioner)

    def slow(environment_id, request, check, *args):
        time.sleep(0.2)
        check()
        return {}

    provisioner.provision.side_effect = slow
    worker = Worker(store, provisioner)
    assert worker.tick()
    assert store.owned(OWNER, environment_id)["status"] == "Ready"


def test_worker_lost_lease_never_finalizes(store, backend):
    environment_id = str(store.reserve(OWNER, "lost", EnvironmentRequest())["environmentId"])
    provisioner = Mock(spec=Provisioner)

    def lose_lease(*args):
        job = backend.get(TENANT, "job:" + environment_id)
        job["leaseUntil"] = 0.0
        backend.transact([Change(job, job["_etag"])])
        return {}

    provisioner.provision.side_effect = lose_lease
    worker = Worker(store, provisioner)
    worker.tick()
    assert store.owned(OWNER, environment_id)["status"] == "Running"
    assert backend.get(TENANT, "job:" + environment_id)["status"] == "busy"


def test_heartbeat_failure_prevents_final_commit(settings, backend, monkeypatch):
    store = Store(backend, replace(settings, lease_seconds=0.06))
    environment_id = str(store.reserve(OWNER, "heartbeat-loss", EnvironmentRequest())["environmentId"])
    monkeypatch.setattr(store, "renew", Mock(side_effect=RuntimeError("PRIVATE-ERROR")))
    provisioner = Mock(spec=Provisioner)

    def slow(*args):
        time.sleep(0.12)
        return {}

    provisioner.provision.side_effect = slow
    assert Worker(store, provisioner).tick()
    assert store.owned(OWNER, environment_id)["status"] == "Running"
    assert "PRIVATE-ERROR" not in json.dumps(list(backend.rows.values()))


@pytest.mark.parametrize("provider_mode", [False, True])
def test_worker_app_lifespan_readonly_health_and_clean_shutdown(
        settings, provider_settings, target, monkeypatch, provider_mode):
    from service import worker_app
    settings = provider_settings if provider_mode else settings
    backend = MemoryBackend()
    backend.close = Mock()
    credential, arm, vault = Mock(), Mock(), Mock(spec=Vault)
    monkeypatch.setattr(worker_app.Settings, "from_env", Mock(return_value=settings))
    monkeypatch.setattr(worker_app.WorkerSettings, "from_env", Mock(return_value=target))
    constructor = Mock(return_value=credential)
    monkeypatch.setattr(worker_app, "ManagedIdentityCredential", constructor)
    monkeypatch.setattr(worker_app, "TableBackend", Mock(return_value=backend))
    monkeypatch.setattr(worker_app, "Vault", Mock(return_value=vault))
    monkeypatch.setattr(worker_app, "AzureArm", Mock(return_value=arm))
    with TestClient(worker_app.app) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.post("/v1/environments", json={}).status_code == 404
        assert worker_app.app.state.thread.is_alive()
        constructor.assert_called_once_with(retry_total=2, connection_timeout=5, read_timeout=10)
        worker_app.AzureArm.assert_called_once_with(target, credential)
        assert worker_app.app.state.worker.store.settings == settings
        assert worker_app.app.state.worker.store.partition == TENANT
    assert not worker_app.app.state.thread.is_alive()
    assert worker_app.app.state.worker.stop.is_set()
    assert backend.rows == {}
    backend.close.assert_called_once()
    vault.close.assert_called_once()
    arm.close.assert_called_once()
    credential.close.assert_called_once()


def test_arm_adapter_only_fixed_subscription_group_and_managed_credential(monkeypatch, target):
    constructor = Mock()
    monkeypatch.setattr("service.provisioner.ResourceManagementClient", constructor)
    credential = Mock()
    arm = AzureArm(target, credential)
    constructor.assert_called_once_with(
        credential, SUBSCRIPTION, logging_enable=False,
        retry_total=2, connection_timeout=5, read_timeout=30)
    arm.start("faas-fixed", {"resources": []}, {})
    args, kwargs = constructor.return_value.deployments.begin_create_or_update.call_args
    assert args[:2] == ("rg-fixed-provider", "faas-fixed")
    assert args[2].properties.mode == "Incremental"
    assert kwargs == {"polling": False}
    constructor.return_value.deployments.get.side_effect = ResourceNotFoundError()
    assert arm.get("faas-fixed") is None
    constructor.return_value.resources.get.side_effect = ResourceNotFoundError()
    assert arm.proof_absent(str(uuid4()))
    assert constructor.return_value.resources.get.call_args.args[0] == "rg-fixed-provider"


def test_api_source_does_not_import_worker_or_arm():
    import ast
    source = ast.parse(Path("service/api.py").read_text())
    imported = [node.module for node in ast.walk(source) if isinstance(node, ast.ImportFrom)]
    assert not any("provisioner" in (name or "") or "mgmt" in (name or "")
                   or "worker" in (name or "") for name in imported)
    assert "DefaultAzureCredential" not in Path("service/api.py").read_text()


def test_table_adapter_etags_no_table_creation_and_partition_query(monkeypatch):
    constructor = Mock()
    monkeypatch.setattr("service.azure_data.TableClient", constructor)
    credential = Mock()
    backend = TableBackend("https://fixed.table.core.windows.net", credential)
    assert constructor.call_args.args == ("https://fixed.table.core.windows.net", "Operations")
    row = {"PartitionKey": TENANT, "RowKey": "key", "_etag": "etag", "status": "busy"}
    backend.transact([Change(row, "etag")])
    operation = constructor.return_value.submit_transaction.call_args.args[0][0]
    assert operation[0] == "update" and "_etag" not in operation[1]
    assert operation[2]["etag"] == "etag"
    assert operation[2]["match_condition"].name == "IfNotModified"
    constructor.return_value.query_entities.return_value = []
    assert backend.jobs(TENANT) == []
    assert constructor.return_value.query_entities.call_args.kwargs["parameters"] == {
        "partition": TENANT}
    constructor.return_value.create_table.assert_not_called()


@pytest.mark.parametrize("status,exception", [(409, Conflict), (412, Conflict), (403, HttpResponseError),
                                             (503, HttpResponseError)])
def test_table_adapter_retries_only_preconditions(monkeypatch, status, exception):
    constructor = Mock()
    monkeypatch.setattr("service.azure_data.TableClient", constructor)
    backend = TableBackend("https://fixed.table.core.windows.net", Mock())
    error = HttpResponseError()
    error.status_code = status
    constructor.return_value.submit_transaction.side_effect = error
    with pytest.raises(exception):
        backend.transact([Change({"PartitionKey": TENANT, "RowKey": "new"})])


def test_vault_generates_once_and_reuses_existing(monkeypatch):
    constructor = Mock()
    monkeypatch.setattr("service.azure_data.SecretClient", constructor)
    vault = Vault("https://fixed.vault.azure.net", Mock())
    client = constructor.return_value
    client.get_secret.side_effect = ResourceNotFoundError()
    client.set_secret.return_value.properties.version = "saved-version"
    client.set_secret.return_value.value = "generated-value"
    check = Mock()
    name = secret_names(str(uuid4()))[0]
    value = vault.ensure(name, check)
    assert value.version == "saved-version"
    assert len(client.set_secret.call_args.args[1]) >= 40
    assert client.set_secret.call_args.args[0] == name
    assert client.set_secret.call_args.kwargs == {"content_type": "application/ipsec-psk"}
    check.assert_called()
    client.get_secret.side_effect = None
    client.get_secret.return_value.value = value.value
    client.get_secret.return_value.properties.version = value.version
    assert vault.ensure(name, check) == value
    assert client.set_secret.call_count == 1


@pytest.mark.parametrize("value,suffix", [
    ("http://test.vault.azure.net", ".vault.azure.net"),
    ("https://test.vault.azure.net.evil.example", ".vault.azure.net"),
    ("https://" + "fixture:" + "pass" + "@" + "test.vault.azure.net", ".vault.azure.net"),
    ("https://test.vault.azure.net/arbitrary", ".vault.azure.net"),
])
def test_config_fixed_azure_endpoints(value, suffix):
    with pytest.raises(ValueError):
        endpoint(value, suffix)


@pytest.mark.parametrize("changes", [
    {"auth_mode": "unknown"}, {"auth_mode": ""}, {"auth_mode": None},
    {"auth_mode": "provider-api-client", "authority_tenant": None},
    {"auth_mode": "provider-api-client", "authority_tenant": ""},
    {"auth_mode": "provider-api-client", "authority_tenant": "not-a-uuid"},
    {"authority_tenant": ""}, {"authority_tenant": "not-a-uuid"},
    {"audience": ""}, {"audience": f"api://{AUDIENCE}"},
    {"parallel_provider_networking": "true"},
])
def test_invalid_authentication_settings(settings, changes):
    with pytest.raises(ValueError):
        replace(settings, **changes)


@pytest.fixture
def auth_environment(monkeypatch):
    values = {"FAAS_API_AUDIENCE": AUDIENCE, "FAAS_TRUSTED_TENANT_ID": TENANT,
              "FAAS_TRUSTED_PRINCIPAL_ID": API_PRINCIPAL, "FAAS_TRUSTED_CLIENT_ID": API_CLIENT,
              "FAAS_TABLE_ENDPOINT": "https://test.table.core.windows.net",
              "FAAS_VAULT_URL": "https://test.vault.azure.net"}
    for name in ("FAAS_AUTH_MODE", "FAAS_AUTHORITY_TENANT_ID", "FAAS_CUSTOMERS_JSON",
                 "FAAS_PROVIDER_GROUP_MODE", "FAAS_PROVIDER_PARALLEL_NETWORKING",
                 "FAAS_ALLOW_ISOLATED_LAB_RISK"):
        monkeypatch.delenv(name, raising=False)
    for name, value in values.items():
        monkeypatch.setenv(name, value)


@pytest.mark.parametrize("mode,authority,expected", [
    (None, None, TENANT),
    ("customer-managed-identity", TENANT, TENANT),
    ("provider-api-client", PROVIDER_TENANT, PROVIDER_TENANT),
])
def test_authentication_environment_modes(auth_environment, monkeypatch, mode, authority, expected):
    if mode is not None:
        monkeypatch.setenv("FAAS_AUTH_MODE", mode)
    if authority is not None:
        monkeypatch.setenv("FAAS_AUTHORITY_TENANT_ID", authority)
    configured = Settings.from_env()
    assert configured.auth_mode == (mode or "customer-managed-identity")
    assert configured.authority_tenant == expected
    assert configured.customer == Customer(TENANT, API_PRINCIPAL, API_CLIENT)
    assert configured.parallel_provider_networking is False
    assert Store(MemoryBackend(), configured).partition == TENANT


def test_unqualified_isolated_group_mode_cannot_be_enabled(auth_environment, monkeypatch):
    monkeypatch.setenv("FAAS_PROVIDER_GROUP_MODE", "isolated")
    with pytest.raises(ValueError, match="lab risk approval"):
        Settings.from_env()


def test_isolated_group_mode_requires_explicit_registry_lab_approval(auth_environment, monkeypatch):
    monkeypatch.setenv("FAAS_PROVIDER_GROUP_MODE", "isolated")
    monkeypatch.setenv("FAAS_ALLOW_ISOLATED_LAB_RISK", "true")
    with pytest.raises(ValueError, match="registry-mode"):
        Settings.from_env()
    monkeypatch.setenv("FAAS_AUTH_MODE", "provider-api-registry")
    monkeypatch.setenv("FAAS_AUTHORITY_TENANT_ID", PROVIDER_TENANT)
    assert Settings.from_env().provider_group_mode == "isolated"


@pytest.mark.parametrize("value", ["", "yes", "1"])
def test_invalid_isolated_lab_risk_setting_fails_closed(auth_environment, monkeypatch, value):
    monkeypatch.setenv("FAAS_ALLOW_ISOLATED_LAB_RISK", value)
    with pytest.raises(ValueError, match="lab risk"):
        Settings.from_env()


@pytest.mark.parametrize("value,expected", [("true", True), ("false", False), ("TRUE", True)])
def test_parallel_networking_environment_is_explicit(auth_environment, monkeypatch, value, expected):
    monkeypatch.setenv("FAAS_PROVIDER_PARALLEL_NETWORKING", value)
    assert Settings.from_env().parallel_provider_networking is expected


@pytest.mark.parametrize("value", ["", "yes", "1"])
def test_invalid_parallel_networking_environment_fails_closed(auth_environment, monkeypatch, value):
    monkeypatch.setenv("FAAS_PROVIDER_PARALLEL_NETWORKING", value)
    with pytest.raises(ValueError, match="networking mode"):
        Settings.from_env()


@pytest.mark.parametrize("changes", [
    {"FAAS_AUTH_MODE": "unknown"}, {"FAAS_AUTH_MODE": ""},
    {"FAAS_AUTHORITY_TENANT_ID": None},
    {"FAAS_AUTHORITY_TENANT_ID": ""},
    {"FAAS_AUTHORITY_TENANT_ID": "not-a-uuid"},
    {"FAAS_API_AUDIENCE": f"api://{AUDIENCE}"},
    {"FAAS_TRUSTED_TENANT_ID": None},
    {"FAAS_TRUSTED_PRINCIPAL_ID": None},
    {"FAAS_TRUSTED_CLIENT_ID": None},
])
def test_invalid_authentication_environment(auth_environment, monkeypatch, changes):
    monkeypatch.setenv("FAAS_AUTH_MODE", "provider-api-client")
    monkeypatch.setenv("FAAS_AUTHORITY_TENANT_ID", PROVIDER_TENANT)
    for name, value in changes.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    with pytest.raises((KeyError, ValueError)):
        Settings.from_env()


def test_environment_settings_single_bound_record(monkeypatch):
    values = {"FAAS_API_AUDIENCE": AUDIENCE, "FAAS_TRUSTED_TENANT_ID": TENANT,
              "FAAS_TRUSTED_PRINCIPAL_ID": PRINCIPAL, "FAAS_TRUSTED_CLIENT_ID": CLIENT,
              "FAAS_TABLE_ENDPOINT": "https://test.table.core.windows.net",
              "FAAS_VAULT_URL": "https://test.vault.azure.net"}
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("FAAS_CUSTOMERS_JSON", json.dumps([
        {"tenantId": TENANT, "principalId": PRINCIPAL, "clientId": CLIENT}]))
    assert Settings.from_env().customer.tenant == TENANT
    monkeypatch.setenv("FAAS_CUSTOMERS_JSON", json.dumps([
        {"tenantId": OTHER, "principalId": PRINCIPAL, "clientId": CLIENT}]))
    with pytest.raises(ValueError):
        Settings.from_env()


def test_legacy_capacity_environment_settings_are_ignored(monkeypatch, caplog):
    values = {"FAAS_API_AUDIENCE": AUDIENCE, "FAAS_TRUSTED_TENANT_ID": TENANT,
              "FAAS_TRUSTED_PRINCIPAL_ID": PRINCIPAL, "FAAS_TRUSTED_CLIENT_ID": CLIENT,
              "FAAS_TABLE_ENDPOINT": "https://test.table.core.windows.net",
              "FAAS_VAULT_URL": "https://test.vault.azure.net", "FAAS_MAX_ENVIRONMENTS": "7"}
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("FAAS_CUSTOMERS_JSON", raising=False)
    monkeypatch.setenv("FAAS_MAX_INSTANCES", "8")
    assert Settings.from_env().max_caller_active == 2
    assert "Legacy environment allocation limits are ignored" in caplog.text


def test_real_arm_sdk_transport_serialization_and_provider_token_only(monkeypatch, target):
    from azure.core.credentials import AccessToken
    from azure.core.pipeline.transport import HttpResponse, HttpTransport
    from azure.mgmt.resource import ResourceManagementClient

    class Response(HttpResponse):
        def __init__(self, request):
            super().__init__(request, None)
            self.status_code = 200
            self.headers = {"Content-Type": "application/json"}
            self.content_type = "application/json"

        def body(self):
            return json.dumps({"id": f"/subscriptions/{SUBSCRIPTION}/resourceGroups/"
                               "rg-fixed-provider/providers/Microsoft.Resources/deployments/faas-test",
                               "name": "faas-test", "properties": {
                                   "provisioningState": "Succeeded", "outputs": {}}}).encode()

        def stream_download(self, pipeline, **kwargs):
            return iter([self.body()])

        def read(self):
            return self.body()

    class Transport(HttpTransport):
        def __init__(self):
            self.requests = []

        def open(self):
            pass

        def close(self):
            pass

        def __exit__(self, *args):
            self.close()

        def send(self, request, **kwargs):
            self.requests.append(request)
            return Response(request)

    credential = Mock(spec=["get_token"])
    credential.get_token.return_value = AccessToken("WORKER-MI-TOKEN", int(time.time()) + 3600)
    transport = Transport()

    def construct(credential, subscription, **kwargs):
        return ResourceManagementClient(credential, subscription, transport=transport, **kwargs)

    monkeypatch.setattr("service.provisioner.ResourceManagementClient", construct)
    arm = AzureArm(target, credential)
    arm.start("faas-test", {"resources": []}, {"environmentId": {"value": "fixed-id"}})
    assert arm.get("faas-test") == ("Succeeded", {})
    assert len(transport.requests) == 2
    put, get = transport.requests
    assert put.method == "PUT" and get.method == "GET"
    assert all(request.url.startswith(
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION}/"
        "resourcegroups/rg-fixed-provider/") for request in transport.requests)
    assert all(request.headers["Authorization"] == "Bearer WORKER-MI-TOKEN"
               for request in transport.requests)
    payload = json.loads(put.body)
    assert payload["properties"]["mode"] == "Incremental"
    assert payload["properties"]["parameters"] == {"environmentId": {"value": "fixed-id"}}
    assert credential.get_token.call_args.args == ("https://management.azure.com/.default",)
    arm.close()


# --- Optional Check Point orchestration (disabled unless explicitly configured) ---

from service.checkpoint_provisioner import CheckpointProvisioner, CheckpointSettings


class CheckpointFakeArm:
    def __init__(self, outputs, states=None):
        self.outputs, self.states = outputs, states or {}
        self.deployments, self.starts, self.closed = set(), [], 0

    def get(self, name):
        if name not in self.deployments:
            return None
        return self.states.get(name, "Succeeded"), self.outputs[name.split("-")[2]]

    def start(self, name, template, parameters):
        self.starts.append((name, template, parameters))
        self.deployments.add(name)

    def close(self):
        self.closed += 1


def checkpoint_provisioner_fixture(store, lease, job_states, foundation_state="Succeeded"):
    foundation, private, group, control, identity = checkpoint_runner_fixture(store, lease)
    spec = build_runner_fixture(store, lease)
    arm = CheckpointFakeArm({"foundation": foundation, "private": private},
                            {f"faas-cp-foundation-{lease.environment_id}": foundation_state})
    groups = Mock()
    groups.ensure.return_value = group
    resources = Mock()
    puts = []
    states = list(job_states)

    def get_by_id(resource_id, _api):
        if resource_id == identity["id"]:
            return SimpleNamespace(serialize=lambda **_kwargs: copy.deepcopy(identity))
        if resource_id.lower() != spec.job_id.lower():
            raise AssertionError("Unexpected resource read")
        current = states.pop(0) if len(states) > 1 else states[0]
        if current is None or not puts:
            raise ResourceNotFoundError()
        return SimpleNamespace(serialize=lambda **_kwargs: runner_resource(spec, *current))

    def create(resource_id, api, body, **kwargs):
        puts.append((resource_id, api, body.read(), kwargs))

    resources.resources.get_by_id.side_effect = get_by_id
    resources.resources.begin_create_or_update_by_id.side_effect = create
    vault = Mock(spec=Vault)
    vault.ensure.side_effect = [SecretMaterial("ingress-psk", "v1"), SecretMaterial("delivery-psk", "v2")]
    settings = CheckpointSettings({"fixture": "foundation"}, {"fixture": "private"}, control, identity["id"],
                                  "fixtureacr.azurecr.io", "a" * 64, RUNNER_SETTINGS)
    provisioner = CheckpointProvisioner(settings, groups, lambda _group: arm, resources, vault,
                                        SUBSCRIPTION, PROVIDER_TENANT, wait=lambda _seconds: None)
    return SimpleNamespace(provisioner=provisioner, arm=arm, groups=groups, resources=resources, puts=puts,
                           vault=vault, spec=spec, foundation=foundation, group=group)


def run_checkpoint(fixture, store, lease):
    operation = store.operation(lease)
    request, _, _ = parse_stored_environment_request(str(operation["request"]))
    return fixture.provisioner.provision(lease, store, operation, request, lambda: store.checked_job(lease))


def test_checkpoint_provisioner_runs_stages_once_and_returns_manifest(checkpoint_journal):
    store, _, lease, scope = checkpoint_journal
    fixture = checkpoint_provisioner_fixture(store, lease, [None, ("Running",), ("Terminated", 0)])
    manifest = run_checkpoint(fixture, store, lease)
    assert manifest == fixture.foundation["connectionManifest"]["value"]
    names = [name for name, _, _ in fixture.arm.starts]
    assert names == [f"faas-cp-foundation-{lease.environment_id}", f"faas-cp-private-{lease.environment_id}"]
    foundation_parameters = fixture.arm.starts[0][2]
    assert foundation_parameters["ingressSharedKey"]["value"] == "ingress-psk"
    assert set(fixture.arm.starts[1][2]) == {"location", "environmentId"}
    assert len(fixture.puts) == 1
    job_id, api, body, kwargs = fixture.puts[0]
    assert job_id == fixture.spec.job_id and kwargs["polling"] is False
    validate_checkpoint_runner_request(fixture.spec, body)
    assert "ingress-psk" not in body.decode() and "delivery-psk" not in body.decode()
    journal = CheckpointRunnerJournal(scope)
    assert journal.read(lease, fixture.spec.job_id, fixture.spec.sha256).state == "succeeded"
    assert json.loads(str(store.operation(lease)["secretVersions"])) == {"ingress": "v1", "delivery": "v2"}
    assert fixture.arm.closed == 1


def test_checkpoint_provisioner_recovers_without_redeploying_or_relaunching(checkpoint_journal):
    store, _, lease, scope = checkpoint_journal
    fixture = checkpoint_provisioner_fixture(store, lease, [None, ("Running",), ("Terminated", 0)])
    run_checkpoint(fixture, store, lease)
    fixture.vault.ensure.side_effect = AssertionError("keys must be reused")
    fixture.vault.read.side_effect = lambda name, version: {"v1": "ingress-psk", "v2": "delivery-psk"}[version]
    run_checkpoint(fixture, store, lease)
    assert len(fixture.arm.starts) == 2 and len(fixture.puts) == 1


@pytest.mark.parametrize("final", [("Terminated", 1), "provisioning_failed"])
def test_checkpoint_provisioner_fails_without_relaunch(checkpoint_journal, final):
    store, _, lease, _ = checkpoint_journal
    state = ("Terminated", 1) if final != "provisioning_failed" else ("Terminated", 1)
    fixture = checkpoint_provisioner_fixture(store, lease, [None, state])
    if final == "provisioning_failed":
        original = fixture.resources.resources.get_by_id.side_effect

        def failed(resource_id, api):
            value = original(resource_id, api)
            if resource_id.lower() == fixture.spec.job_id.lower():
                document = value.serialize()
                document["properties"]["provisioningState"] = "Failed"
                return SimpleNamespace(serialize=lambda **_kwargs: document)
            return value
        fixture.resources.resources.get_by_id.side_effect = failed
    with pytest.raises(ProvisionError) as error:
        run_checkpoint(fixture, store, lease)
    assert error.value.code == "CheckpointRunnerFailed" and not error.value.retryable
    with pytest.raises(ProvisionError):
        run_checkpoint(fixture, store, lease)
    assert len(fixture.puts) == 1


def test_checkpoint_provisioner_never_relaunches_an_unconfirmed_job(checkpoint_journal, monkeypatch):
    from service import checkpoint_provisioner

    store, _, lease, scope = checkpoint_journal
    fixture = checkpoint_provisioner_fixture(store, lease, [None])
    fixture.resources.resources.begin_create_or_update_by_id.side_effect = lambda *args, **kwargs: None
    monkeypatch.setattr(checkpoint_provisioner, "RUNNER_TIMEOUT", 0)
    with pytest.raises(ProvisionError) as error:
        run_checkpoint(fixture, store, lease)
    assert error.value.code == "CheckpointRunnerUnconfirmed"
    with pytest.raises(ProvisionError):
        run_checkpoint(fixture, store, lease)
    assert fixture.resources.resources.begin_create_or_update_by_id.call_count == 1
    assert CheckpointRunnerJournal(scope).read(lease, fixture.spec.job_id, fixture.spec.sha256).state == "launching"


def test_checkpoint_provisioner_stops_on_failed_or_invalid_foundation(checkpoint_journal):
    store, _, lease, _ = checkpoint_journal
    fixture = checkpoint_provisioner_fixture(store, lease, [None], foundation_state="Failed")
    with pytest.raises(ProvisionError) as error:
        run_checkpoint(fixture, store, lease)
    assert error.value.code == "CheckpointDeploymentFailed"
    assert len(fixture.arm.starts) == 1 and not fixture.puts
    fixture = checkpoint_provisioner_fixture(store, lease, [None])
    fixture.arm.outputs["foundation"] = {"connectionManifest": {"type": "Object", "value": {}}}
    with pytest.raises(ProvisionError) as error:
        run_checkpoint(fixture, store, lease)
    assert error.value.code == "InvalidCheckpointFoundation" and not fixture.puts


@pytest.mark.parametrize("status,code,retryable", [(403, "ProviderAuthorizationNotReady", True),
                                                   (400, "ProviderDeploymentRejected", False)])
def test_checkpoint_provisioner_maps_azure_errors_without_detail(checkpoint_journal, status, code, retryable):
    store, _, lease, _ = checkpoint_journal
    fixture = checkpoint_provisioner_fixture(store, lease, [None])
    error = HttpResponseError("PRIVATE-VALUE")
    error.status_code = status

    def reject(*_args):
        raise error
    fixture.arm.start = reject
    with pytest.raises(ProvisionError) as raised:
        run_checkpoint(fixture, store, lease)
    assert (raised.value.code, raised.value.retryable) == (code, retryable)
    assert fixture.arm.closed == 1


def test_checkpoint_provisioner_rejects_unsupported_requests(checkpoint_journal):
    store, _, lease, _ = checkpoint_journal
    fixture = checkpoint_provisioner_fixture(store, lease, [None])
    operation = store.operation(lease)
    with pytest.raises(ProvisionError) as error:
        fixture.provisioner.provision(lease, store, operation, EnvironmentRequest.model_validate(NETWORK), Mock())
    assert error.value.code == "CheckpointDeploymentUnavailable"
    fixture.groups.ensure.assert_not_called()


def test_worker_routes_checkpoint_only_to_configured_provisioner(checkpoint_journal, templates, target):
    store, _, lease, _ = checkpoint_journal
    checkpoint = Mock()
    checkpoint.provision.return_value = {"providerIngress": ENDPOINT, "providerDelivery": ENDPOINT}
    arm, vault = FakeArm(), Mock(spec=Vault)
    worker = Worker(store, Provisioner(arm, vault, templates, target), Mock(), Mock(), checkpoint)
    worker.process(lease)
    result = store.owned(OWNER, lease.environment_id)
    assert result["status"] == "Ready"
    assert checkpoint.provision.call_count == 1 and not arm.starts
    vault.ensure.assert_not_called()


def test_checkpoint_reservation_requires_explicit_isolated_enablement(settings, backend):
    with pytest.raises(ValueError):
        replace(settings, checkpoint_enabled=True)
    enabled = Store(backend, replace(settings, provider_group_mode="isolated", checkpoint_enabled=True))
    operation = enabled.reserve(OWNER, "cp-enabled", EnvironmentRequest.model_validate(
        {**NETWORK, "firewallType": "checkpoint-byol"}))
    request, parallel, isolated = parse_stored_environment_request(str(operation["request"]))
    assert request.firewallType == "checkpoint-byol" and isolated and not parallel
    parallel_store = Store(backend, replace(settings, provider_group_mode="isolated", checkpoint_enabled=True,
                                            parallel_provider_networking=True))
    operation = parallel_store.reserve(OWNER, "cp-parallel", EnvironmentRequest.model_validate(
        {**NETWORK, "firewallType": "checkpoint-byol"}))
    assert parse_stored_environment_request(str(operation["request"]))[1] is False
    with pytest.raises(DomainError) as error:
        enabled.reserve(OWNER, "cp-proof", EnvironmentRequest(firewallType="checkpoint-byol"))
    assert error.value.code == "CheckpointDeploymentUnavailable"
    disabled = Store(backend, replace(settings, provider_group_mode="isolated"))
    with pytest.raises(DomainError):
        disabled.reserve(OWNER, "cp-disabled", EnvironmentRequest.model_validate(
            {**NETWORK, "firewallType": "checkpoint-byol"}))


def test_checkpoint_enablement_from_environment(monkeypatch):
    for name, value in {"FAAS_API_AUDIENCE": AUDIENCE, "FAAS_TABLE_ENDPOINT": "https://t.table.core.windows.net",
                        "FAAS_VAULT_URL": "https://v.vault.azure.net", "FAAS_AUTH_MODE": "provider-api-registry",
                        "FAAS_AUTHORITY_TENANT_ID": TENANT}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("FAAS_CHECKPOINT_ENABLED", "true")
    with pytest.raises(ValueError):
        Settings.from_env()
    monkeypatch.setenv("FAAS_PROVIDER_GROUP_MODE", "isolated")
    monkeypatch.setenv("FAAS_ALLOW_ISOLATED_LAB_RISK", "true")
    assert Settings.from_env().checkpoint_enabled is True
    monkeypatch.setenv("FAAS_CHECKPOINT_ENABLED", "yes")
    with pytest.raises(ValueError):
        Settings.from_env()


def checkpoint_worker_environment(monkeypatch, tmp_path):
    from service.config import CheckpointWorkerSettings
    foundation, private = tmp_path / "foundation.json", tmp_path / "private.json"
    foundation.write_bytes(b'{"fixture":"foundation"}')
    private.write_bytes(b'{"fixture":"private"}')
    values = {
        "FAAS_CHECKPOINT_ENABLED": "true", "FAAS_CHECKPOINT_CLIENT_ID": CLIENT,
        "FAAS_CHECKPOINT_PRINCIPAL_ID": PRINCIPAL, "FAAS_CHECKPOINT_CONTROL_GROUP": "rg-faas-cp-control-" + OTHER,
        "FAAS_CHECKPOINT_IDENTITY_NAME": "faas-cp-publisher-abcd1234", "FAAS_CHECKPOINT_DEFINITION": "faas-cp-def",
        "FAAS_CHECKPOINT_REGISTRY_SERVER": "fixtureacr.azurecr.io", "FAAS_CHECKPOINT_IMAGE_SHA256": "a" * 64,
        "FAAS_CHECKPOINT_GATEWAY_IMAGE_VERSION": "1.2.3", "FAAS_CHECKPOINT_MANAGEMENT_IMAGE_VERSION": "1.2.3",
        "FAAS_CHECKPOINT_GATEWAY_VM_SIZE": "Standard_F4s",
        "FAAS_CHECKPOINT_MANAGEMENT_VM_SIZE": "Standard_F8s",
        "FAAS_CHECKPOINT_FOUNDATION_TEMPLATE_PATH": str(foundation),
        "FAAS_CHECKPOINT_FOUNDATION_TEMPLATE_SHA256": hashlib.sha256(foundation.read_bytes()).hexdigest(),
        "FAAS_CHECKPOINT_PRIVATE_TEMPLATE_PATH": str(private),
        "FAAS_CHECKPOINT_PRIVATE_TEMPLATE_SHA256": hashlib.sha256(private.read_bytes()).hexdigest(),
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    worker = WorkerSettings(SUBSCRIPTION, "rg-x", Path("unused"), "", RUNNER_SETTINGS.provider_ssh_public_key,
                            SUBSCRIPTION, CLIENT, CLIENT, PRINCIPAL, "host", "parent", "app", "def", True)
    return CheckpointWorkerSettings, worker


def test_checkpoint_worker_settings_are_absent_unless_explicitly_enabled(monkeypatch, tmp_path):
    cls, worker = checkpoint_worker_environment(monkeypatch, tmp_path)
    monkeypatch.setenv("FAAS_CHECKPOINT_ENABLED", "false")
    assert cls.from_env(worker) is None
    monkeypatch.setenv("FAAS_CHECKPOINT_ENABLED", "true")
    config = cls.from_env(worker)
    assert config.identity_id.endswith("/userAssignedIdentities/faas-cp-publisher-abcd1234")
    assert f"/resourceGroups/rg-faas-cp-control-{OTHER}/" in config.identity_id
    with pytest.raises(ValueError):
        cls.from_env(replace(worker, managed_host_allow_azure_condition=False))


@pytest.mark.parametrize("name,value", [
    ("FAAS_CHECKPOINT_CONTROL_GROUP", "rg-other"), ("FAAS_CHECKPOINT_IDENTITY_NAME", "faas-isolated-id"),
    ("FAAS_CHECKPOINT_REGISTRY_SERVER", "evil.example.com"), ("FAAS_CHECKPOINT_IMAGE_SHA256", "latest"),
    ("FAAS_CHECKPOINT_GATEWAY_IMAGE_VERSION", "latest"), ("FAAS_CHECKPOINT_GATEWAY_VM_SIZE", "huge"),
    ("FAAS_CHECKPOINT_MANAGEMENT_VM_SIZE", "Standard_"),
    ("FAAS_CHECKPOINT_CLIENT_ID", "PRIVATE-VALUE"), ("FAAS_CHECKPOINT_FOUNDATION_TEMPLATE_SHA256", "x"),
])
def test_checkpoint_worker_settings_reject_invalid_values(monkeypatch, tmp_path, name, value):
    cls, worker = checkpoint_worker_environment(monkeypatch, tmp_path)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError) as error:
        cls.from_env(worker)
    assert "PRIVATE-VALUE" not in str(error.value)


def test_checkpoint_templates_load_only_with_matching_pins(monkeypatch, tmp_path):
    from service import checkpoint_provisioner
    cls, worker = checkpoint_worker_environment(monkeypatch, tmp_path)
    config = cls.from_env(worker)
    monkeypatch.setattr(Templates, "validate_checkpoint_foundation", staticmethod(lambda template: template))
    monkeypatch.setattr(Templates, "validate_checkpoint_private_data", staticmethod(lambda template: template))
    loaded = checkpoint_provisioner.load_checkpoint_settings(config)
    assert loaded.foundation_template == {"fixture": "foundation"}
    assert (loaded.runner.gateway_vm_size, loaded.runner.management_vm_size) == ("Standard_F4s", "Standard_F8s")
    config.foundation_template_path.write_bytes(b'{"fixture":"changed"}')
    with pytest.raises(ValueError, match="hash mismatch"):
        checkpoint_provisioner.load_checkpoint_settings(config)


def test_checkpoint_readiness_reads_lifespan_settings_and_matches_connector(settings, store, auth, signing_key,
                                                                           claims):
    import importlib.util
    spec = importlib.util.spec_from_file_location("customer_connector_contract",
                                                  Path(__file__).parents[1] / "scripts/customer_connector.py")
    connector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(connector)
    enabled = replace(settings, provider_group_mode="isolated", checkpoint_enabled=True)
    app = create_app(enabled, store, auth, Mock(spec=Vault))
    headers = {"Authorization": "Bearer " + token(signing_key, claims)}
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get(connector.CHECKPOINT_READINESS, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"firewallType": "checkpoint-byol", "status": "ready"}


def test_group_retry_accepts_failure_before_application_request(settings, backend):
    configured = replace(settings, auth_mode="provider-api-registry",
                         authority_tenant=PROVIDER_TENANT, provider_group_mode="isolated")
    store = Store(backend, configured)
    environment_id = str(store.reserve(OWNER, "host-check", EnvironmentRequest.model_validate(NETWORK))["environmentId"])
    store.finish(store.claim(environment_id, "worker"), "Failed", code="GroupOwnershipError")
    assert store.owned(OWNER, environment_id).get("providerGroupState", "new") == "new"
    assert store.retry_failed_group(OWNER, environment_id)["status"] == "Pending"
    lease = store.claim(environment_id, "new-worker")
    store.begin_provider_group(lease)
    assert store.owned(OWNER, environment_id)["providerGroupState"] == "creating"


def test_group_retry_can_be_requested_again_after_the_retry_fails(settings, backend):
    configured = replace(settings, auth_mode="provider-api-registry",
                         authority_tenant=PROVIDER_TENANT, provider_group_mode="isolated")
    store = Store(backend, configured)
    environment_id = str(store.reserve(OWNER, "retry-twice", EnvironmentRequest.model_validate(NETWORK))["environmentId"])
    for attempt in range(2):
        store.finish(store.claim(environment_id, f"worker-{attempt}"), "Failed", code="GroupOwnershipError")
        assert store.retry_failed_group(OWNER, environment_id)["status"] == "Pending"
        assert store.retry_failed_group(OWNER, environment_id)["status"] == "Pending"
    job = backend.get(store.partition, "job:" + environment_id)
    assert int(job["attempts"]) == 2


def failed_checkpoint_after_group(settings, backend, code="InvalidCheckpointFoundation"):
    configured = replace(settings, auth_mode="provider-api-registry", authority_tenant=PROVIDER_TENANT,
                         provider_group_mode="isolated", checkpoint_enabled=True)
    store = Store(backend, configured)
    body = EnvironmentRequest.model_validate({**NETWORK, "firewallType": "checkpoint-byol"})
    environment_id = str(store.reserve(OWNER, "cp-resume", body)["environmentId"])
    lease = store.claim(environment_id, "worker")
    store.begin_provider_group(lease)
    name = store.owned(OWNER, environment_id)["providerGroupName"]
    store.bind_provider_group(lease, SUBSCRIPTION, f"/subscriptions/{SUBSCRIPTION}/resourceGroups/{name}")
    store.finish(lease, "Failed", code=code)
    return store, body, environment_id


def test_checkpoint_foundation_failure_resumes_on_the_same_request(settings, backend):
    store, body, environment_id = failed_checkpoint_after_group(settings, backend)
    before = store.owned(OWNER, environment_id)
    resumed = store.reserve(OWNER, "cp-resume", body)
    assert resumed["status"] == "Pending" and resumed["environmentId"] == environment_id
    after = store.owned(OWNER, environment_id)
    assert (after["providerGroupId"], after["secretVersions"]) == (before["providerGroupId"],
                                                                 before["secretVersions"])
    assert store.reserve(OWNER, "cp-resume", body)["status"] == "Pending"
    assert backend.get(store.partition, "quota")["active"] == 1
    lease = store.claim(environment_id, "worker-2")
    assert int(store.checked_job(lease)["attempts"]) == 2


def test_checkpoint_resume_is_limited_to_retained_foundation_failures(settings, backend):
    store, body, environment_id = failed_checkpoint_after_group(settings, backend, "CheckpointRunnerFailed")
    assert store.reserve(OWNER, "cp-resume", body)["status"] == "Failed"
    job = backend.get(store.partition, "job:" + environment_id)
    assert job["status"] == "done"


def test_checkpoint_provisioner_reads_route_server_peers_when_outputs_are_stale(checkpoint_journal):
    store, _, lease, _ = checkpoint_journal
    fixture = checkpoint_provisioner_fixture(store, lease, [None, ("Running",), ("Terminated", 0)])
    fixture.arm.outputs["foundation"]["checkpointFoundation"]["value"]["routeServerPeerAddresses"] = []
    hub_suffix = "/virtualHubs/rs-cp-pi-" + lease.environment_id[:8]
    original = fixture.resources.resources.get_by_id.side_effect
    hub = {"provisioningState": "Succeeded", "routingState": "Provisioned",
           "virtualRouterIps": ["172.20.254.4", "172.20.254.5"]}

    def get_by_id(resource_id, api):
        if resource_id.endswith(hub_suffix):
            return SimpleNamespace(properties=dict(hub))
        return original(resource_id, api)

    fixture.resources.resources.get_by_id.side_effect = get_by_id
    assert run_checkpoint(fixture, store, lease) == fixture.foundation["connectionManifest"]["value"]


def test_checkpoint_provisioner_waits_for_route_server_peers(checkpoint_journal):
    store, _, lease, _ = checkpoint_journal
    fixture = checkpoint_provisioner_fixture(store, lease, [None])
    fixture.arm.outputs["foundation"]["checkpointFoundation"]["value"]["routeServerPeerAddresses"] = []
    fixture.resources.resources.get_by_id.side_effect = lambda _id, _api: SimpleNamespace(properties={
        "provisioningState": "Succeeded", "routingState": "Provisioning", "virtualRouterIps": []})
    with pytest.raises(ProvisionError) as caught:
        run_checkpoint(fixture, store, lease)
    assert caught.value.code == "ProviderTemporarilyUnavailable" and caught.value.retryable
    assert fixture.puts == []


def test_runner_observation_accepts_azure_empty_config_map(checkpoint_journal):
    store, _, lease, _ = checkpoint_journal
    spec = build_runner_fixture(store, lease)
    resource = runner_resource(spec)
    resource["properties"]["containers"][0]["properties"]["configMap"] = {"keyValuePairs": {}}
    assert validate_checkpoint_runner_observation(resource, spec).state == "running"


def test_checkpoint_resume_covers_runner_observation_failure(settings, backend):
    store, body, _ = failed_checkpoint_after_group(settings, backend, "CheckpointRunnerUnconfirmed")
    assert store.reserve(OWNER, "cp-resume", body)["status"] == "Pending"


def test_admin_sources_survive_storage_foundation_worker_and_runner_config(checkpoint_journal):
    store, backend, lease, _ = checkpoint_journal
    row = store.owned(OWNER, lease.environment_id)
    request, _, _ = parse_stored_environment_request(row["request"])
    request.adminAllowedSources = ["1.1.1.0/24", "8.8.8.8/32"]
    row["request"] = stored_environment_request(request, False, True)
    backend.transact([Change(row, str(row["_etag"]))])
    fixture = checkpoint_provisioner_fixture(store, lease, [None])
    fixture.provisioner.settings.foundation_template["parameters"] = {
        "adminAllowedSources": {"type": "array", "defaultValue": [], "maxLength": 16}}
    fixture.provisioner._run_job = Mock()
    assert run_checkpoint(fixture, store, lease) == fixture.foundation["connectionManifest"]["value"]
    assert fixture.arm.starts[0][2]["adminAllowedSources"]["value"] == request.adminAllowedSources
    spec, body = fixture.provisioner._run_job.call_args.args[3:5]
    validate_checkpoint_runner_request(spec, body)
    config = load_checkpoint_runner_config(dict(spec.environment))
    assert config.schemaVersion == 2 and config.adminAllowedSources == request.adminAllowedSources
    old = build_runner_fixture(store, lease)
    assert old.sha256 != spec.sha256
    assert "adminAllowedSources" not in json.loads(dict(old.environment)["FAAS_CONFIG"])
    assert load_checkpoint_runner_config(dict(old.environment)).schemaVersion == 1
    assert fixture.puts == []


def test_admin_runner_config_rejects_legacy_schema_and_nonpublic_sources(checkpoint_journal):
    store, _, lease, _ = checkpoint_journal
    environment = dict(build_runner_fixture(store, lease).environment)
    config = json.loads(environment["FAAS_CONFIG"])
    config["adminAllowedSources"] = ["8.8.8.8/32"]
    environment["FAAS_CONFIG"] = json.dumps(config)
    with pytest.raises(CheckpointRunnerConfigError):
        load_checkpoint_runner_config(environment)
    config["schemaVersion"] = 2
    environment["FAAS_CONFIG"] = json.dumps(config)
    assert load_checkpoint_runner_config(environment).adminAllowedSources == ["8.8.8.8/32"]
    config["adminAllowedSources"] = ["10.0.0.1/32"]
    environment["FAAS_CONFIG"] = json.dumps(config)
    with pytest.raises(CheckpointRunnerConfigError):
        load_checkpoint_runner_config(environment)


def test_admin_sources_block_old_foundation_before_provider_changes(checkpoint_journal):
    store, _, lease, _ = checkpoint_journal
    fixture = checkpoint_provisioner_fixture(store, lease, [None])
    operation = store.operation(lease)
    request, _, _ = parse_stored_environment_request(operation["request"])
    request.adminAllowedSources = ["8.8.8.8/32"]
    with pytest.raises(ProvisionError) as error:
        fixture.provisioner.provision(lease, store, operation, request, lambda: None)
    assert error.value.code == "CheckpointAdminAccessUnavailable"
    fixture.groups.ensure.assert_not_called()
    fixture.vault.ensure.assert_not_called()
    assert not fixture.arm.starts and not fixture.puts
