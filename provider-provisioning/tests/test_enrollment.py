import copy
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError

from service.enrollment import (
    ApplicationIdentity, Credential, CustomerBinding, EnrollmentError,
    EnrollmentRegistry, EnrollmentRequest, EnrollmentService, PARTITION, customer_name_key,
)
from service.enrollment_azure import (
    API_ROLE, GRAPH_ORIGIN, GRAPH_SCOPE, EnrollmentVault, GraphDirectory, GraphSettings,
)
from service.store import Conflict


def guid():
    return str(uuid4())


ACTOR = guid()
SECRET = "unit-test-only-credential"
FUTURE = "2099-01-01T00:00:00+00:00"


class Memory:
    def __init__(self):
        self.rows = {}
        self.lock = threading.RLock()
        self.version = 0
        self.conflicts = 0
        self.lost_response = False

    def get(self, partition, key):
        with self.lock:
            return copy.deepcopy(self.rows.get((partition, key)))

    def list_rows(self, partition, prefix, limit):
        with self.lock:
            return [copy.deepcopy(row) for (part, key), row in self.rows.items()
                    if part == partition and key.startswith(prefix)][:limit]

    def jobs(self, partition):
        return []

    def transact(self, changes):
        with self.lock:
            if self.conflicts:
                self.conflicts -= 1
                raise Conflict()
            for change in changes:
                current = self.rows.get((change.row["PartitionKey"], change.row["RowKey"]))
                if ((change.etag is None and current is not None)
                        or (change.etag is not None
                            and (current is None or current["_etag"] != change.etag))):
                    raise Conflict()
            for change in changes:
                row = copy.deepcopy(change.row)
                self.version += 1
                row["_etag"] = str(self.version)
                self.rows[(row["PartitionKey"], row["RowKey"])] = row
            if self.lost_response:
                self.lost_response = False
                raise RuntimeError(SECRET)


class FakeGraph:
    def __init__(self):
        self.calls = []
        self.fail = ""
        self.applications = {}
        self.app_customers = {}
        self.principals = {}
        self.principal_clients = {}
        self.passwords = {}
        self.password_markers = {}
        self.password_serial = 0
        self.entered = None
        self.release = None

    def call(self, operation, *args):
        self.calls.append((operation, *args))
        if self.fail == operation:
            raise RuntimeError(SECRET)

    def create_application(self, customer_id):
        self.call("application", customer_id)
        if self.entered:
            self.entered.set()
            assert self.release.wait(5)
        app = ApplicationIdentity(guid(), guid())
        self.applications[app.object_id] = app
        self.app_customers[app.object_id] = customer_id
        return app

    def create_principal(self, client_id):
        self.call("principal", client_id)
        principal = guid()
        self.principals[principal] = False
        self.principal_clients[principal] = client_id
        return principal

    def find_principal(self, client_id):
        self.call("find_principal", client_id)
        return next((principal for principal, client in self.principal_clients.items()
                     if client == client_id), None)

    def verify_application(self, customer_id, application):
        self.call("verify_application", customer_id, application.object_id)
        assert self.applications[application.object_id] == application
        assert self.app_customers[application.object_id] == customer_id

    def verify(self, binding, application_id):
        self.call("verify", binding.customer_id, application_id)
        assert self.applications[application_id].client_id == binding.client
        assert binding.principal in self.principals

    def grant_role(self, principal):
        self.call("grant", principal)

    def ensure_role(self, principal):
        self.call("ensure_role", principal)

    def password_keys(self, application_id, customer_id):
        self.call("password_keys", application_id, customer_id)
        return [key for key, (app, marker) in self.password_markers.items()
                if app == application_id and marker.startswith(f"faas-enrollment:{customer_id}:")]

    def add_password(self, application_id, expires_at, marker):
        self.call("password", application_id)
        self.password_serial += 1
        credential = Credential(guid(), SECRET + str(self.password_serial), expires_at)
        self.passwords[credential.key_id] = credential
        self.password_markers[credential.key_id] = (application_id, marker)
        return credential

    def remove_password(self, application_id, key_id):
        self.call("remove", application_id, key_id)
        self.passwords.pop(key_id)
        self.password_markers.pop(key_id)

    def set_enabled(self, principal_id, enabled):
        self.call("enabled", principal_id, enabled)
        self.principals[principal_id] = enabled


class FakeVault:
    def __init__(self):
        self.values = {}
        self.fail_write = False
        self.fail_read = False
        self.reads = 0

    def write(self, customer_id, secret, expires):
        if self.fail_write:
            raise RuntimeError(SECRET)
        name, version = "customer-" + customer_id, uuid4().hex
        self.values[(name, version)] = secret
        return {"name": name, "version": version}

    def read(self, name, version):
        self.reads += 1
        if self.fail_read:
            raise EnrollmentError(502, "VaultReadFailed")
        return self.values[(name, version)]


@pytest.fixture
def env():
    backend, graph, vault = Memory(), FakeGraph(), FakeVault()
    registry = EnrollmentRegistry(backend)
    publisher = Mock()
    publisher.publish.side_effect = lambda binding: {
        "portalUrl": "https://portal.example/" + guid() + "?sas=unit-test-only",
        "expiresAt": FUTURE,
    }
    service = EnrollmentService(registry, graph, vault, publisher)
    return SimpleNamespace(backend=backend, graph=graph, vault=vault,
                           registry=registry, service=service, publisher=publisher)


def request(**kwargs):
    return EnrollmentRequest(name="Customer", tenantId=guid(), subscriptionId=guid(), **kwargs)


def onboard(env, body=None, key=None):
    return env.service.onboard(body or request(), ACTOR, key or guid())


def error(code, call):
    with pytest.raises(EnrollmentError) as caught:
        call()
    assert caught.value.code == code
    assert SECRET not in str(caught.value)
    return caught.value

def test_customer_scope_defaults_preserve_legacy_onboarding_fields():
    body = request()
    assert body.enrollment_fields() == {
        "name": body.name, "tenantId": body.tenantId, "subscriptionId": body.subscriptionId,
        "credentialHours": 24, "maxEnvironments": 3}
    with pytest.raises(ValidationError, match="ProviderLabAcknowledgementRequired"):
        request(scopeMode="provider-lab")


def test_provider_lab_scope_is_persisted_without_rebinding_other_customers(env):
    existing = onboard(env)
    body = request(scopeMode="provider-lab", providerLabAcknowledged=True)
    created = onboard(env, body)
    assert created["scopeMode"] == "provider-lab"
    binding = env.registry._binding(env.registry._customer(created["customerId"]))
    assert binding.scope_mode == "provider-lab" and binding.provider_lab_acknowledged
    assert env.registry.get(existing["customerId"])["tenantId"] == existing["tenantId"]
    assert "scopeMode" not in env.registry.get(existing["customerId"])
    row = env.backend.rows[(PARTITION, "customer:" + created["customerId"])]
    row["providerLabAcknowledged"] = False
    error("EnrollmentStoreUnavailable", lambda: env.registry.get(created["customerId"]))


def test_archive_requires_revocation_and_retains_worker_and_audit_records(env):
    customer = onboard(env)
    customer_id = customer["customerId"]
    error("EnrollmentNotReady", lambda: env.service.archive(customer_id, ACTOR, guid()))
    env.service.revoke(customer_id, ACTOR, guid())
    operation_key = guid()
    archived = env.service.archive(customer_id, ACTOR, operation_key)
    assert archived["status"] == "Archived"
    assert env.service.archive(customer_id, ACTOR, operation_key) == archived
    assert env.registry.list_customers() == []
    assert env.registry.lookup(customer["clientId"], customer["principalId"]) is None
    assert env.registry.worker_customers()[0].status == "Archived"
    assert env.graph.principals[customer["principalId"]] is False
    assert any(row.get("event") == "Archived" for row in env.backend.rows.values())


def test_two_customers_isolated_and_safe(env):
    first, second = onboard(env), onboard(env)
    assert first["customerId"] != second["customerId"]
    assert first["clientId"] != second["clientId"]
    assert first["principalId"] != second["principalId"]
    assert len(env.registry.list_customers()) == 2
    assert len(env.registry.worker_customers()) == 2
    binding = env.registry.lookup(first["clientId"], first["principalId"])
    assert binding.customer_id == first["customerId"]
    assert binding.tenant == first["tenantId"]
    assert binding.subscription == first["subscriptionId"]
    assert binding.max_environments == 3
    assert env.registry.lookup(first["clientId"], second["principalId"]) is None
    assert env.registry.lookup(second["clientId"], first["principalId"]) is None
    assert env.registry.lookup(guid(), guid()) is None
    assert env.registry.lookup("https://attacker.example", first["principalId"]) is None
    serialized = json.dumps(list(env.backend.rows.values()))
    assert SECRET not in serialized
    assert "secretText" not in serialized
    assert "sas=" not in serialized
    for customer in env.registry.list_customers():
        assert not {"vaultName", "vaultVersion", "passwordKeyId", "applicationId"} & customer.keys()
    assert len(env.vault.values) == 2
    assert all(SECRET in value for value in env.vault.values.values())


def test_same_tenant_and_subscription_support_separate_customers(env):
    body = request()
    first = onboard(env, body)
    env.backend.rows[(PARTITION, "customer:" + first["customerId"])].pop("allocationKey")
    second = onboard(env, body.model_copy(update={"name": "Second customer"}))
    assert first["tenantId"] == second["tenantId"] == body.tenantId
    assert first["subscriptionId"] == second["subscriptionId"] == body.subscriptionId
    assert first["customerId"] != second["customerId"]
    assert first["clientId"] != second["clientId"]
    assert first["principalId"] != second["principalId"]
    first_binding = env.registry.lookup(first["clientId"], first["principalId"])
    second_binding = env.registry.lookup(second["clientId"], second["principalId"])
    assert first_binding.allocation_key == body.tenantId
    assert second_binding.allocation_key == "customer:" + second["customerId"]
    assert env.registry.lookup(first["clientId"], second["principalId"]) is None


def test_invalid_customer_allocation_binding_fails_closed(env):
    customer = onboard(env)
    env.backend.rows[(PARTITION, "customer:" + customer["customerId"])]["allocationKey"] = "customer:" + guid()
    error("EnrollmentStoreUnavailable",
          lambda: env.registry.lookup(customer["clientId"], customer["principalId"]))


@pytest.mark.parametrize("name", ["customer", " CUSTOMER ", "ＣＵＳＴＯＭＥＲ"])
def test_same_tenant_name_is_unique_even_for_existing_unindexed_customer(env, name):
    body = request()
    original = onboard(env, body)
    del env.backend.rows[(PARTITION, customer_name_key(body.tenantId, body.name))]
    error("CustomerNameAlreadyEnrolled",
          lambda: onboard(env, body.model_copy(update={"name": name, "subscriptionId": guid()})))
    assert env.registry.get(original["customerId"])["status"] == "Ready"
    assert len(env.graph.applications) == 1


def test_new_name_index_blocks_normalized_duplicates(env):
    body = request()
    onboard(env, body)
    onboard(env, body.model_copy(update={"name": "Other"}))
    error("CustomerNameAlreadyEnrolled",
          lambda: onboard(env, body.model_copy(update={"name": "  OTHER  "})))
    assert len(env.graph.applications) == 2


def test_concurrent_same_tenant_different_customers_both_succeed(env):
    first = request()
    second = first.model_copy(update={"name": "Second"})
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda body: onboard(env, body), (first, second)))
    assert all(result["status"] == "Ready" for result in results)
    assert results[0]["customerId"] != results[1]["customerId"]


def test_concurrent_normalized_duplicate_names_create_only_one_customer(env):
    first = request()
    second = first.model_copy(update={"name": "  CUSTOMER  "})
    def create(body):
        try:
            return onboard(env, body)["status"]
        except EnrollmentError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(create, (first, second)))
    assert sorted(results) == ["CustomerNameAlreadyEnrolled", "Ready"]
    assert len(env.graph.applications) == 1


def test_dependency_failure_preserves_safe_status_and_stage_without_secrets(env, caplog):
    env.graph.create_principal = Mock(side_effect=EnrollmentError(
        502, "GraphRequestFailed", 403, "CreateServicePrincipal", "Authorization_RequestDenied"))
    error("EnrollmentDependencyFailed", lambda: onboard(env))
    row = env.registry.list_customers()[0]
    assert row["status"] == "NeedsAttention"
    assert row["errorCode"] == "GraphRequestFailedHttp403"
    assert row["failureStage"] == "CreatePrincipal"
    assert row["dependencyOperation"] == "CreateServicePrincipal"
    assert row["dependencyReason"] == "Authorization_RequestDenied"
    assert SECRET not in json.dumps(row)
    assert SECRET not in caplog.text


@pytest.mark.parametrize("changes", [
    {"tenantId": "A" * 36}, {"tenantId": "{" + guid() + "}"},
    {"subscriptionId": guid().upper()}, {"credentialHours": 0}, {"credentialHours": 8761},
    {"credentialHours": True}, {"maxEnvironments": -1}, {"maxEnvironments": True},
    {"unknown": "field"}, {"name": "  "}, {"name": "bad\nname"},
])
def test_strict_request(changes):
    data = {"name": "Name", "tenantId": guid(), "subscriptionId": guid(), **changes}
    with pytest.raises(ValidationError):
        EnrollmentRequest(**data)


def test_request_bounds():
    assert request(credentialHours=8760, maxEnvironments=100).credentialHours == 8760
    assert request(credentialHours=1, maxEnvironments=0).maxEnvironments == 0


def test_legacy_customer_limit_is_accepted_but_not_advertised(env, caplog):
    customer = onboard(env, request(maxEnvironments=2))
    assert "maxEnvironments" not in customer
    assert "Legacy customer environment allocation limit is ignored" in caplog.text
    binding = env.registry.lookup(customer["clientId"], customer["principalId"])
    assert binding.max_environments == 2


def test_idempotency_and_immutable_owner(env):
    body = request()
    first = onboard(env, body, "key")
    assert onboard(env, body, "key") == first
    assert sum(call[0] == "application" for call in env.graph.calls) == 1
    error("IdempotencyConflict",
          lambda: onboard(env, body.model_copy(update={"name": "Changed"}), "key"))
    for changes in ({"subscriptionId": guid()}, {"tenantId": guid()}):
        error("IdempotencyConflict",
              lambda: onboard(env, body.model_copy(update=changes), "key"))
    error("CustomerNameAlreadyEnrolled",
          lambda: onboard(env, body.model_copy(update={"subscriptionId": guid()})))
    assert env.registry.get(first["customerId"])["subscriptionId"] == body.subscriptionId
    error("IdempotencyConflict",
          lambda: env.service.rotate(first["customerId"], ACTOR, "key"))


def test_concurrent_owner_and_operation_fencing(env):
    body = request()
    env.graph.entered, env.graph.release = threading.Event(), threading.Event()
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(onboard, env, body, "key")
        try:
            assert env.graph.entered.wait(5)
            error("EnrollmentInProgress", lambda: onboard(env, body, "key"))
            error("CustomerNameAlreadyEnrolled", lambda: onboard(env, body, "other"))
        finally:
            env.graph.release.set()
        assert future.result()["status"] == "Ready"
    assert len(env.graph.applications) == 1
    assert len(env.graph.passwords) == 1


def test_bounded_contention_and_retry_before_side_effects(env):
    env.backend.conflicts = 3
    assert onboard(env)["status"] == "Ready"
    assert len(env.graph.applications) == 1
    env.backend.conflicts = 99
    error("EnrollmentContention", lambda: onboard(env))
    assert env.backend.conflicts == 91
    assert len(env.graph.applications) == 1


def test_uncertain_store_reservation_never_starts_graph(env):
    body = request()
    env.backend.lost_response = True
    error("EnrollmentStoreUnavailable", lambda: onboard(env, body, "key"))
    error("EnrollmentInProgress", lambda: onboard(env, body, "key"))
    assert not env.graph.calls


@pytest.mark.parametrize("step", ["application", "principal", "grant", "password", "enabled"])
def test_uncertain_graph_writes_not_retried(env, step):
    body = request()
    env.graph.fail = step
    error("EnrollmentDependencyFailed", lambda: onboard(env, body, "key"))
    error("EnrollmentNeedsAttention", lambda: onboard(env, body, "key"))
    error("CustomerNameAlreadyEnrolled", lambda: onboard(env, body, "other"))
    assert sum(call[0] == step for call in env.graph.calls) == 1
    safe = env.registry.list_customers()[0]
    assert safe["status"] == "NeedsAttention"
    assert safe["errorCode"] == "EnrollmentDependencyFailed"
    if "clientId" in safe and "principalId" in safe:
        assert env.registry.lookup(safe["clientId"], safe["principalId"]) is None
    assert SECRET not in json.dumps(list(env.backend.rows.values()))


@pytest.mark.parametrize("method,collection", [
    ("create_application", "applications"),
    ("create_principal", "principals"),
    ("add_password", "passwords"),
])
def test_graph_side_effect_committed_but_response_lost_never_repeats(env, method, collection):
    original = getattr(env.graph, method)

    def uncertain(*args):
        original(*args)
        raise RuntimeError(SECRET)

    setattr(env.graph, method, uncertain)
    body = request()
    error("EnrollmentDependencyFailed", lambda: onboard(env, body, "key"))
    assert len(getattr(env.graph, collection)) == 1
    error("EnrollmentNeedsAttention", lambda: onboard(env, body, "key"))
    error("CustomerNameAlreadyEnrolled", lambda: onboard(env, body, "new-key"))
    assert len(getattr(env.graph, collection)) == 1
    assert SECRET not in json.dumps(list(env.backend.rows.values()))


def test_duplicate_client_cannot_rebind_existing_customer(env):
    first = onboard(env)
    original_application = next(iter(env.graph.applications.values()))
    env.graph.create_application = Mock(return_value=original_application)
    error("EnrollmentDependencyFailed", lambda: onboard(env))
    binding = env.registry.lookup(first["clientId"], first["principalId"])
    assert binding.customer_id == first["customerId"]
    assert len(env.graph.passwords) == 1
    assert env.registry._get("client:" + first["clientId"])["customerId"] == first["customerId"]


def test_identity_persisted_before_later_writes(env):
    original = env.graph.create_principal

    def principal(client):
        row = env.registry._customers()[0]
        assert row["clientId"] == client
        assert row["applicationId"] in env.graph.applications
        return original(client)

    env.graph.create_principal = principal
    original_grant = env.graph.grant_role

    def grant(principal_id):
        row = env.registry._customers()[0]
        assert row["principalId"] == principal_id
        assert env.registry._get("client:" + row["clientId"])["customerId"] == row["customerId"]
        return original_grant(principal_id)

    env.graph.grant_role = grant
    onboard(env)


def test_repeated_reveals_are_audited_and_rotation_uses_new_version(env):
    customer = onboard(env)
    cid = customer["customerId"]
    secret = env.service.reveal(cid, ACTOR)
    assert secret["secret"].startswith(SECRET)
    assert set(secret) == {"secret", "expiresAt"}
    assert env.service.reveal(cid, ACTOR) == secret
    assert env.vault.reads == 2
    rotated = env.service.rotate(cid, ACTOR, "rotation", 8760)
    assert rotated["status"] == "Ready" and not rotated["revealed"]
    assert rotated["credentialHours"] == 8760
    remaining = datetime.fromisoformat(rotated["credentialExpiresAt"]).timestamp() - time.time()
    assert 8760 * 3600 - 5 <= remaining <= 8760 * 3600
    assert env.service.reveal(cid, ACTOR)["secret"] != secret["secret"]
    reveals = [row for row in env.backend.rows.values() if row.get("event") == "RevealClaimed"]
    assert len(reveals) == 3
    assert all(row["customerId"] == cid and row["actorOid"] == ACTOR for row in reveals)
    assert len(env.graph.passwords) == 1
    assert env.service.rotate(cid, ACTOR, "rotation", 8760)["status"] == "Ready"
    error("IdempotencyConflict", lambda: env.service.rotate(cid, ACTOR, "rotation", 24))
    assert sum(call[0] == "password" for call in env.graph.calls) == 2


def test_concurrent_reveals_are_each_audited(env):
    cid = onboard(env)["customerId"]

    def reveal():
        try:
            return env.service.reveal(cid, ACTOR)
        except EnrollmentError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: reveal(), range(8)))
    assert all(isinstance(result, dict) for result in results)
    assert env.vault.reads == 8
    assert len([row for row in env.backend.rows.values() if row.get("event") == "RevealClaimed"]) == 8


def test_reveal_dependency_failure_can_be_retried(env):
    cid = onboard(env)["customerId"]
    env.vault.fail_read = True
    error("CredentialReadFailed", lambda: env.service.reveal(cid, ACTOR))
    env.vault.fail_read = False
    assert env.service.reveal(cid, ACTOR)["secret"].startswith(SECRET)
    assert env.vault.reads == 2
    assert len([row for row in env.backend.rows.values() if row.get("event") == "RevealClaimed"]) == 2


def test_reveal_uncertain_claim_does_not_read(env):
    cid = onboard(env)["customerId"]
    env.backend.lost_response = True
    error("EnrollmentStoreUnavailable", lambda: env.service.reveal(cid, ACTOR))
    assert env.vault.reads == 0
    assert env.service.reveal(cid, ACTOR)["secret"].startswith(SECRET)
    assert env.vault.reads == 1


def test_reveal_bounded_contention_does_not_read(env):
    cid = onboard(env)["customerId"]
    env.backend.conflicts = 100
    error("EnrollmentContention", lambda: env.service.reveal(cid, ACTOR))
    assert env.backend.conflicts == 92
    assert env.vault.reads == 0


def test_reveal_concurrent_revoke_during_read_fails_closed(env):
    customer = onboard(env)
    original_read = env.vault.read

    def read(*args):
        env.service.revoke(customer["customerId"], ACTOR, "revoke-during-reveal")
        return original_read(*args)

    env.vault.read = read
    error("CredentialUnavailable", lambda: env.service.reveal(customer["customerId"], ACTOR))
    assert env.registry.get(customer["customerId"])["revealed"]


def test_expired_secret_not_revealed_or_accepted_but_worker_finishes(env, monkeypatch):
    customer = onboard(env)
    deadline = datetime.fromisoformat(customer["credentialExpiresAt"]).timestamp()
    monkeypatch.setattr("service.enrollment.time.time", lambda: deadline + 1)
    error("CredentialUnavailable", lambda: env.service.reveal(customer["customerId"], ACTOR))
    assert env.registry.lookup(customer["clientId"], customer["principalId"]) is None
    assert len(env.registry.worker_customers()) == 1
    assert not env.vault.reads


def test_rotation_disables_and_retires_only_after_vault_write(env):
    customer = onboard(env)
    cid = customer["customerId"]
    old_key = next(iter(env.graph.passwords))
    original_write = env.vault.write
    original_remove = env.graph.remove_password

    def write(*args):
        assert env.registry.get(cid)["status"] == "Rotating"
        assert env.registry.lookup(customer["clientId"], customer["principalId"]) is None
        assert not env.graph.principals[customer["principalId"]]
        assert old_key in env.graph.passwords
        return original_write(*args)

    def remove(*args):
        assert len(env.vault.values) == 2
        return original_remove(*args)

    env.vault.write, env.graph.remove_password = write, remove
    env.service.rotate(cid, ACTOR, "rotate")
    operations = [item[0] for item in env.graph.calls]
    assert operations.index("remove") > operations.index("password")
    assert old_key not in env.graph.passwords
    assert env.graph.principals[customer["principalId"]]


def test_failed_rotation_keeps_old_password_but_disables_principal(env):
    customer = onboard(env)
    old_key = next(iter(env.graph.passwords))
    env.vault.fail_write = True
    error("EnrollmentDependencyFailed",
          lambda: env.service.rotate(customer["customerId"], ACTOR, "rotate"))
    assert old_key in env.graph.passwords
    assert not env.graph.principals[customer["principalId"]]
    assert env.registry.lookup(customer["clientId"], customer["principalId"]) is None
    error("EnrollmentNeedsAttention",
          lambda: env.service.rotate(customer["customerId"], ACTOR, "rotate"))
    assert len(env.graph.passwords) == 2


def test_revoke_really_disables_principal_and_rejects_old_tokens(env):
    customer = onboard(env)
    cid = customer["customerId"]
    revoked = env.service.revoke(cid, ACTOR, "revoke")
    assert revoked["status"] == "Revoked"
    assert not env.graph.principals[customer["principalId"]]
    assert env.registry.lookup(customer["clientId"], customer["principalId"]) is None
    assert env.registry.worker_customers()[0].status == "Revoked"
    assert len(env.graph.applications) == 1
    assert len(env.graph.passwords) == 1
    assert env.service.revoke(cid, ACTOR, "revoke") == revoked
    error("CredentialUnavailable", lambda: env.service.reveal(cid, ACTOR))
    error("EnrollmentNotReady", lambda: env.service.rotate(cid, ACTOR, "rotate"))


def test_revoke_after_failed_rotation(env):
    customer = onboard(env)
    env.vault.fail_write = True
    error("EnrollmentDependencyFailed",
          lambda: env.service.rotate(customer["customerId"], ACTOR, "rotate"))
    assert env.service.revoke(customer["customerId"], ACTOR, "revoke")["status"] == "Revoked"


def test_recover_reactivates_revoked_customer_with_fresh_secret_and_same_identity(env):
    customer = onboard(env)
    cid = customer["customerId"]
    old_secret = env.service.reveal(cid, ACTOR)["secret"]
    old_key = next(iter(env.graph.passwords))
    env.service.revoke(cid, ACTOR, "revoke")
    recovered = env.service.recover(cid, ACTOR, "recover")
    assert recovered["status"] == "Ready"
    assert not recovered["revealed"]
    for field in ("customerId", "tenantId", "subscriptionId", "clientId", "principalId"):
        assert recovered[field] == customer[field]
    assert env.registry.lookup(customer["clientId"], customer["principalId"])
    assert env.graph.principals[customer["principalId"]]
    assert old_key not in env.graph.passwords
    assert env.service.reveal(cid, ACTOR)["secret"] != old_secret
    assert len(env.graph.passwords) == 1
    assert len(env.graph.applications) == 1
    assert env.service.recover(cid, ACTOR, "recover")["status"] == "Ready"
    assert env.graph.password_serial == 2
    error("IdempotencyConflict", lambda: env.service.rotate(cid, ACTOR, "recover"))


def test_recover_failed_rotation_cleans_only_enrollment_credentials(env):
    customer = onboard(env)
    cid = customer["customerId"]
    env.vault.fail_write = True
    error("EnrollmentDependencyFailed",
          lambda: env.service.rotate(cid, ACTOR, "rotate"))
    assert len(env.graph.passwords) == 2
    foreign_key = guid()
    foreign_secret = Credential(foreign_key, "other-purpose-unit-test", FUTURE)
    env.graph.passwords[foreign_key] = foreign_secret
    env.graph.password_markers[foreign_key] = (
        env.registry._customer(cid)["applicationId"], "other-admin-credential")
    env.vault.fail_write = False
    assert env.service.recover(cid, ACTOR, "recover")["status"] == "Ready"
    assert len(env.graph.passwords) == 2
    assert env.graph.passwords[foreign_key] == foreign_secret
    assert sum(call[0] == "remove" for call in env.graph.calls) == 2
    assert SECRET not in json.dumps(list(env.backend.rows.values()))


@pytest.mark.parametrize("crash_method", ["create_principal", "add_password", "vault_write"])
def test_recover_crash_reconciles_ids_and_retires_uncertain_keys(env, monkeypatch, crash_method):
    body = request()
    target, method = ((env.vault, "write") if crash_method == "vault_write"
                      else (env.graph, crash_method))
    original = getattr(target, method)

    def crash(*args):
        original(*args)
        raise SystemExit("simulated process termination")

    setattr(target, method, crash)
    with pytest.raises(SystemExit):
        onboard(env, body, "onboard")
    setattr(target, method, original)
    safe = env.registry.list_customers()[0]
    cid = safe["customerId"]
    assert "recoveryAvailableAt" in safe
    error("EnrollmentInProgress", lambda: env.service.recover(cid, ACTOR, "recover"))
    deadline = env.registry._customer(cid)["leaseUntil"]
    monkeypatch.setattr("service.enrollment.time.time", lambda: deadline + 1)
    recovered = env.service.recover(cid, ACTOR, "recover")
    assert recovered["status"] == "Ready"
    assert len(env.graph.applications) == 1
    assert len(env.graph.principals) == 1
    assert len(env.graph.passwords) == 1
    assert env.graph.principals[recovered["principalId"]]
    assert env.registry.lookup(recovered["clientId"], recovered["principalId"])
    error("EnrollmentNeedsAttention", lambda: onboard(env, body, "onboard"))
    assert env.service.reveal(cid, ACTOR)["secret"].startswith(SECRET)


def test_recover_known_app_without_any_principal_can_create_one(env):
    env.graph.fail = "principal"
    error("EnrollmentDependencyFailed", lambda: onboard(env))
    customer = env.registry.list_customers()[0]
    env.graph.fail = ""
    assert env.service.recover(customer["customerId"], ACTOR, "recover")["status"] == "Ready"
    assert len(env.graph.applications) == 1
    assert len(env.graph.principals) == 1


def test_recover_lost_application_id_returns_actionable_portal_guidance_without_adoption(env):
    original = env.graph.create_application

    def uncertain(cid):
        original(cid)
        raise RuntimeError(SECRET)

    env.graph.create_application = uncertain
    error("EnrollmentDependencyFailed", lambda: onboard(env))
    customer = env.registry.list_customers()[0]
    recovered = env.service.recover(customer["customerId"], ACTOR, "recover")
    assert recovered["status"] == "NeedsAttention"
    assert recovered["errorCode"] == "ApplicationIdentityUnverified"
    assert "https://entra.microsoft.com/" in recovered["recoveryGuidance"]
    assert "App registrations > All applications" in recovered["recoveryGuidance"]
    assert "owner" in recovered["recoveryGuidance"]
    assert "cannot safely bind" in recovered["recoveryGuidance"]
    assert len(env.graph.applications) == 1
    assert len(env.graph.calls) == 1
    assert not env.graph.passwords


def test_recover_rejects_mismatched_application_before_any_graph_mutation(env):
    customer = onboard(env)
    cid = customer["customerId"]
    env.graph.app_customers[next(iter(env.graph.applications))] = guid()
    env.graph.calls.clear()
    error("EnrollmentDependencyFailed", lambda: env.service.recover(cid, ACTOR, "recover"))
    assert [call[0] for call in env.graph.calls] == ["verify_application"]
    assert len(env.graph.passwords) == 1
    assert env.registry.get(cid)["status"] == "NeedsAttention"


def test_recover_uncertain_new_password_is_reconciled_not_retried(env):
    customer = onboard(env)
    cid = customer["customerId"]
    original = env.graph.add_password

    def uncertain(*args):
        original(*args)
        raise RuntimeError(SECRET)

    env.graph.add_password = uncertain
    error("EnrollmentDependencyFailed", lambda: env.service.recover(cid, ACTOR, "recover"))
    serial = env.graph.password_serial
    assert len(env.graph.passwords) == 1
    assert not env.graph.principals[customer["principalId"]]
    error("EnrollmentNeedsAttention", lambda: env.service.recover(cid, ACTOR, "recover"))
    assert env.graph.password_serial == serial
    env.graph.add_password = original
    assert env.service.recover(cid, ACTOR, "recover-again")["status"] == "Ready"
    assert len(env.graph.passwords) == 1
    assert env.graph.password_serial == serial + 1


def test_recover_uncertain_password_removal_reenumerates_before_new_password(env):
    customer = onboard(env)
    cid = customer["customerId"]
    old_key = next(iter(env.graph.passwords))
    original = env.graph.remove_password

    def uncertain(*args):
        original(*args)
        raise RuntimeError(SECRET)

    env.graph.remove_password = uncertain
    error("EnrollmentDependencyFailed", lambda: env.service.recover(cid, ACTOR, "recover"))
    assert old_key not in env.graph.passwords
    assert env.graph.password_serial == 1
    env.graph.remove_password = original
    assert env.service.recover(cid, ACTOR, "recover-again")["status"] == "Ready"
    assert sum(call[0] == "remove" and call[-1] == old_key for call in env.graph.calls) == 1


def test_recover_expired_fence_prevents_stale_password_response_saving_secret(env, monkeypatch):
    original = env.graph.add_password
    entered, release = threading.Event(), threading.Event()
    first = True

    def delayed(*args):
        nonlocal first
        credential = original(*args)
        if first:
            first = False
            entered.set()
            assert release.wait(5)
        return credential

    env.graph.add_password = delayed
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(onboard, env)
        try:
            assert entered.wait(5)
            row = env.registry._customers()[0]
            cid, deadline = row["customerId"], row["leaseUntil"]
            monkeypatch.setattr("service.enrollment.time.time", lambda: deadline + 1)
            recovered = env.service.recover(cid, ACTOR, "recover")
            assert recovered["status"] == "Ready"
            assert len(env.vault.values) == 1
        finally:
            release.set()
        error("EnrollmentDependencyFailed", future.result)
    assert env.registry.get(cid)["status"] == "Ready"
    assert len(env.graph.passwords) == 1
    assert len(env.vault.values) == 1


def test_recover_can_itself_be_recovered_after_crash(env, monkeypatch):
    customer = onboard(env)
    cid = customer["customerId"]
    original = env.graph.add_password

    def crash(*args):
        original(*args)
        raise SystemExit("simulated recovery process termination")

    env.graph.add_password = crash
    with pytest.raises(SystemExit):
        env.service.recover(cid, ACTOR, "first-recovery")
    assert env.registry.get(cid)["status"] == "Recovering"
    assert not env.graph.principals[customer["principalId"]]
    deadline = env.registry._customer(cid)["leaseUntil"]
    monkeypatch.setattr("service.enrollment.time.time", lambda: deadline + 1)
    env.graph.add_password = original
    assert env.service.recover(cid, ACTOR, "second-recovery")["status"] == "Ready"
    assert len(env.graph.passwords) == 1
    error("EnrollmentNeedsAttention", lambda: env.service.recover(cid, ACTOR, "first-recovery"))


def test_deployment_is_explicit_fresh_and_not_persisted(env):
    customer = onboard(env)
    assert not env.publisher.publish.called
    first = env.service.deployment(customer["customerId"], ACTOR)
    second = env.service.deployment(customer["customerId"], ACTOR)
    assert first["portalUrl"] != second["portalUrl"]
    assert env.publisher.publish.call_count == 2
    assert "sas=" not in json.dumps(list(env.backend.rows.values()))
    env.publisher.publish.side_effect = RuntimeError(SECRET)
    error("DeploymentPublishFailed",
          lambda: env.service.deployment(customer["customerId"], ACTOR))
    assert "portalUrl" not in env.registry.get(customer["customerId"])


def test_deployment_concurrent_revoke_does_not_return_link(env):
    customer = onboard(env)

    def publish(binding):
        env.service.revoke(binding.customer_id, ACTOR, "revoke-during-publication")
        return {"portalUrl": "https://portal.example/?sas=unit-test-only", "expiresAt": FUTURE}

    env.publisher.publish.side_effect = publish
    error("DeploymentPublishFailed",
          lambda: env.service.deployment(customer["customerId"], ACTOR))


def test_list_bound_and_store_errors_fail_closed(env):
    env.backend.list_rows = Mock(return_value=[{}] * 1000)
    assert len(env.registry.list_customers()) == 1000
    env.backend.list_rows.assert_called_once_with(PARTITION, "customer:", 1001)
    env.backend.list_rows.return_value = [{}] * 1001
    error("EnrollmentListLimit", env.registry.list_customers)
    error("EnrollmentListLimit", env.registry.worker_customers)
    env.backend.get = Mock(side_effect=RuntimeError(SECRET))
    error("EnrollmentStoreUnavailable", lambda: env.registry.lookup(guid(), guid()))


def test_audit_has_codes_and_no_sensitive_values(env):
    customer = onboard(env)
    env.service.reveal(customer["customerId"], ACTOR)
    env.service.deployment(customer["customerId"], ACTOR)
    env.service.rotate(customer["customerId"], ACTOR, "rotate")
    env.service.revoke(customer["customerId"], ACTOR, "revoke")
    events = env.backend.list_rows(PARTITION, "audit:", 100)
    assert {event["event"] for event in events} >= {
        "Onboarding", "Ready", "RevealClaimed", "DeploymentRequested",
        "Rotating", "Revoking", "Revoked",
    }
    for event in events:
        assert set(event) == {
            "PartitionKey", "RowKey", "_etag", "customerId", "actorOid", "event", "timestamp",
        }
    assert SECRET not in repr(Credential(guid(), SECRET, FUTURE))


def test_unknown_ids_invalid_actor_and_key(env):
    error("CustomerNotFound", lambda: env.registry.get(guid()))
    error("CustomerNotFound", lambda: env.registry.get("not-an-id"))
    error("InvalidActor", lambda: env.service.onboard(request(), "bad", "key"))
    for key in ("", "with spaces", "x" * 129):
        error("InvalidIdempotencyKey", lambda: env.service.onboard(request(), ACTOR, key))
    assert not env.graph.calls


def graph_settings():
    return GraphSettings(guid(), guid(), guid(), SECRET, guid(), guid(), guid())


def directory(settings=None):
    instance = object.__new__(GraphDirectory)
    instance.settings = settings or graph_settings()
    instance.credential = Mock()
    instance.credential.get_token.return_value = SimpleNamespace(token="unit-test-token")
    return instance


def test_graph_configuration_pins_issuer_and_separate_identity():
    settings = graph_settings()
    assert settings.issuer == (
        "https://login.microsoftonline.com/" + settings.provider_tenant + "/v2.0")
    assert SECRET not in repr(settings)
    with pytest.raises(ValueError):
        replace(settings, management_client_id=settings.provider_api_client_id)
    with pytest.raises(ValueError):
        replace(settings, management_principal_id=settings.provider_api_principal_id)
    with pytest.raises(ValueError):
        replace(settings, provider_tenant="https://attacker.example")
    with pytest.raises(ValueError):
        replace(settings, provider_role_id=str(UUID_ZERO))


UUID_ZERO = "00000000-0000-0000-0000-000000000000"


def test_constructor_uses_provider_management_credential(monkeypatch):
    credential = Mock()
    factory = Mock(return_value=credential)
    monkeypatch.setattr("service.enrollment_azure.ClientSecretCredential", factory)
    settings = graph_settings()
    graph = GraphDirectory(settings)
    assert factory.call_args.args == (
        settings.provider_tenant, settings.management_client_id, SECRET)
    assert factory.call_args.kwargs["authority"] == "login.microsoftonline.com"
    assert factory.call_args.kwargs["retry_total"] == 0
    graph.close()
    credential.close.assert_called_once()


@pytest.mark.parametrize("outcome", ["redirect", "timeout", "throttle", "nextlink"])
def test_graph_transport_no_retry_redirect_or_token_url(outcome):
    graph = directory()
    requests = []

    def handler(req):
        requests.append(req)
        if outcome == "timeout":
            raise httpx.ReadTimeout(SECRET)
        if outcome == "redirect":
            return httpx.Response(307, headers={"Location": "https://attacker.example"})
        if outcome == "nextlink":
            return httpx.Response(200, json={"@odata.nextLink": "https://attacker.example"})
        return httpx.Response(429, json={"error": {"message": SECRET}})

    graph.client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    try:
        error("GraphRequestFailed",
              lambda: graph._request("POST", "/applications", {"secret": SECRET}))
        assert len(requests) == 1
        assert str(requests[0].url) == GRAPH_ORIGIN + "/v1.0/applications"
        graph.credential.get_token.assert_called_once_with(GRAPH_SCOPE)
        error("GraphRequestRejected",
              lambda: graph._request("GET", "https://attacker.example"))
        assert len(requests) == 1
    finally:
        graph.close()


def test_graph_retries_only_read_not_found_for_replication(monkeypatch):
    graph, calls = directory(), []
    clock = SimpleNamespace(monotonic=Mock(side_effect=[0, 1, 3]), sleep=Mock())
    monkeypatch.setattr("service.enrollment_azure.time", clock)
    def handler(request):
        calls.append(request)
        if len(calls) < 3:
            return httpx.Response(404, json={"error": {"message": SECRET}})
        return httpx.Response(200, json={"value": []})
    graph.client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        assert graph._request("GET", "/servicePrincipals/unit/owners", retry_not_found=True) == {"value": []}
        assert len(calls) == 3
        assert [call.args[0] for call in clock.sleep.call_args_list] == [1, 2]
        error("GraphRequestRejected",
              lambda: graph._request("POST", "/servicePrincipals", {}, retry_not_found=True))
        assert len(calls) == 3
    finally:
        graph.close()


def test_graph_does_not_retry_failed_creation_post():
    graph, calls = directory(), []
    def handler(request):
        calls.append(request)
        return httpx.Response(404, json={"error": {"message": SECRET}})
    graph.client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        caught = error("GraphRequestFailed", lambda: graph._request("POST", "/servicePrincipals", {}))
        assert caught.dependency_status == 404
        assert len(calls) == 1
    finally:
        graph.close()


def test_graph_failure_keeps_only_allowlisted_response_code():
    graph = directory()
    graph.client = httpx.Client(transport=httpx.MockTransport(
        lambda req: httpx.Response(403, json={"error": {
            "code": "Authorization_RequestDenied", "message": SECRET}})))
    try:
        caught = error("GraphRequestFailed", lambda: graph._request(
            "POST", "/servicePrincipals", {}, diagnostic_operation="CreateServicePrincipal"))
        assert caught.dependency_status == 403
        assert caught.dependency_operation == "CreateServicePrincipal"
        assert caught.dependency_reason == "Authorization_RequestDenied"
        assert SECRET not in str(caught)
    finally:
        graph.close()


@pytest.mark.parametrize("outcome", ["retry-succeeds", "principal-present", "other-forbidden", "timeout"])
def test_principal_creation_retries_only_explicit_denial_after_reconciliation(outcome, monkeypatch):
    graph, client, app_id, principal = directory(), guid(), guid(), guid()
    calls = []
    clock = SimpleNamespace(monotonic=Mock(return_value=0), sleep=Mock())
    monkeypatch.setattr("service.enrollment_azure.time", clock)
    def handler(request):
        calls.append((request.method, request.url.path))
        path = request.url.path.removeprefix("/v1.0")
        if path.startswith("/applications(appId="):
            return httpx.Response(200, json={"id": app_id, "appId": client})
        if path == f"/applications/{app_id}/owners":
            return httpx.Response(200, json={"value": [{"id": graph.settings.management_principal_id}]})
        if path.startswith("/servicePrincipals(appId="):
            return (httpx.Response(200, json={"id": principal, "appId": client})
                    if outcome == "principal-present" else httpx.Response(404))
        if path == "/servicePrincipals" and request.method == "POST":
            post_count = sum(method == "POST" for method, _ in calls)
            if outcome == "timeout":
                raise httpx.ReadTimeout(SECRET)
            if post_count == 1:
                reason = "AccessDenied" if outcome == "other-forbidden" else "Authorization_RequestDenied"
                return httpx.Response(403, json={"error": {"code": reason, "message": SECRET}})
            return httpx.Response(201, json={"id": principal})
        raise AssertionError("Unexpected Graph call")
    graph.client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        if outcome == "retry-succeeds":
            assert graph.create_principal(client) == principal
            assert sum(method == "POST" for method, _ in calls) == 2
            clock.sleep.assert_called_once_with(2)
        else:
            expected = "PrincipalCreationUncertain" if outcome == "principal-present" else "GraphRequestFailed"
            error(expected, lambda: graph.create_principal(client))
            assert sum(method == "POST" for method, _ in calls) == 1
    finally:
        graph.close()


def provider_responses(graph):
    s = graph.settings
    return {
        f"/servicePrincipals/{s.management_principal_id}?$select=id,appId,appOwnerOrganizationId": {
            "id": s.management_principal_id, "appId": s.management_client_id,
            "appOwnerOrganizationId": s.provider_tenant,
        },
        f"/servicePrincipals/{s.provider_api_principal_id}"
        "?$select=id,appId,appOwnerOrganizationId,appRoles": {
            "id": s.provider_api_principal_id, "appId": s.provider_api_client_id,
            "appOwnerOrganizationId": s.provider_tenant,
            "appRoles": [{"id": s.provider_role_id, "value": API_ROLE, "isEnabled": True,
                          "allowedMemberTypes": ["Application"]}],
        },
    }


@pytest.mark.parametrize("field,value", [
    ("appId", guid()), ("appOwnerOrganizationId", guid()), ("id", guid()),
    ("roleValue", "Other.Role"), ("roleId", guid()), ("roleEnabled", False),
])
def test_graph_provider_binding_and_role_mismatch_rejected(field, value):
    graph = directory()
    responses = provider_responses(graph)
    api = list(responses.values())[1]
    if field.startswith("role"):
        api["appRoles"][0][{
            "roleValue": "value", "roleId": "id", "roleEnabled": "isEnabled",
        }[field]] = value
    else:
        api[field] = value
    graph._request = Mock(side_effect=lambda method, path, body=None: responses[path])
    error("GraphProviderBindingMismatch", lambda: graph.create_application(guid()))
    assert all(call.args[0] == "GET" for call in graph._request.call_args_list)


def test_graph_creation_grants_only_fixed_provider_role_and_never_rbac():
    graph = directory()
    responses = provider_responses(graph)
    app_id, client_id, principal_id, cid = guid(), guid(), guid(), guid()

    def respond(method, path, body=None, **kwargs):
        if path in responses:
            return responses[path]
        if path == f"/applications(appId='{client_id}')?$select=id,appId":
            assert kwargs == {"retry_not_found": True, "diagnostic_operation": "ReadNewApplication"}
            return {"id": app_id, "appId": client_id}
        if path == "/applications":
            assert body["displayName"] == "faas-customer-" + cid
            assert body["signInAudience"] == "AzureADMyOrg"
            assert "uniqueName" not in body
            assert body["requiredResourceAccess"] == [{
                "resourceAppId": graph.settings.provider_api_client_id,
                "resourceAccess": [{"id": graph.settings.provider_role_id, "type": "Role"}],
            }]
            return {"id": app_id, "appId": client_id}
        if path == "/servicePrincipals":
            assert body["accountEnabled"] is False
            assert kwargs == {"diagnostic_operation": "CreateServicePrincipal"}
            return {"id": principal_id}
        assert path == f"/servicePrincipals/{principal_id}/appRoleAssignments"
        assert body == {
            "principalId": principal_id, "resourceId": graph.settings.provider_api_principal_id,
            "appRoleId": graph.settings.provider_role_id,
        }
        return {}

    graph._request = Mock(side_effect=respond)
    assert graph.create_application(cid) == ApplicationIdentity(app_id, client_id)
    assert graph.create_principal(client_id) == principal_id
    graph.grant_role(principal_id)
    assert not any("management.azure.com" in str(call) for call in graph._request.call_args_list)


def binding_responses(graph):
    binding = CustomerBinding(guid(), "Name", guid(), guid(), guid(), guid(), 3, "Ready")
    app_id = guid()
    s = graph.settings
    responses = provider_responses(graph)
    responses.update({
        f"/applications/{app_id}"
        "?$select=id,appId,displayName,tags,signInAudience,requiredResourceAccess": {
            "id": app_id, "appId": binding.client,
            "displayName": "faas-customer-" + binding.customer_id,
            "tags": ["faas-customer:" + binding.customer_id], "signInAudience": "AzureADMyOrg",
            "requiredResourceAccess": [{
                "resourceAppId": s.provider_api_client_id,
                "resourceAccess": [{"id": s.provider_role_id, "type": "Role"}],
            }],
        },
        f"/servicePrincipals/{binding.principal}?$select=id,appId,appOwnerOrganizationId": {
            "id": binding.principal, "appId": binding.client,
            "appOwnerOrganizationId": s.provider_tenant,
        },
        f"/applications/{app_id}/owners?$select=id": {
            "value": [{"id": s.management_principal_id}],
        },
        f"/servicePrincipals/{binding.principal}/owners?$select=id": {
            "value": [{"id": s.management_principal_id}],
        },
        f"/servicePrincipals/{binding.principal}/appRoleAssignments"
        "?$select=resourceId,appRoleId,principalId": {
            "value": [{"principalId": binding.principal,
                       "resourceId": s.provider_api_principal_id, "appRoleId": s.provider_role_id}],
        },
    })
    return binding, app_id, responses


@pytest.mark.parametrize("mutation", ["none", "display", "app", "principal", "owner", "role"])
def test_graph_verifies_immutable_existing_binding(mutation):
    graph = directory()
    binding, app_id, responses = binding_responses(graph)
    if mutation == "display":
        responses[next(key for key in responses if key.startswith(f"/applications/{app_id}?"))][
            "displayName"] = "same-friendly-display-name"
    if mutation == "app":
        responses[next(key for key in responses if key.startswith(f"/applications/{app_id}?"))][
            "appId"] = guid()
    if mutation == "principal":
        responses[f"/servicePrincipals/{binding.principal}?$select=id,appId,appOwnerOrganizationId"][
            "appOwnerOrganizationId"] = binding.tenant
    if mutation == "owner":
        responses[f"/applications/{app_id}/owners?$select=id"]["value"] = []
    if mutation == "role":
        responses[f"/servicePrincipals/{binding.principal}/appRoleAssignments"
                  "?$select=resourceId,appRoleId,principalId"]["value"][0]["resourceId"] = guid()
    graph._request = Mock(side_effect=lambda method, path, body=None, **kwargs: responses[path])
    if mutation == "none":
        graph.verify(binding, app_id)
    else:
        error("GraphBindingMismatch", lambda: graph.verify(binding, app_id))


def test_graph_password_and_disable_endpoints():
    graph = directory()
    app, key, principal = guid(), guid(), guid()
    graph._request = Mock(return_value={
        "keyId": key, "secretText": SECRET, "endDateTime": FUTURE.replace("+00:00", "Z"),
    })
    credential = graph.add_password(app, FUTURE, f"faas-enrollment:{guid()}:{'a' * 64}")
    assert credential.secret == SECRET and SECRET not in repr(credential)
    graph.remove_password(app, key)
    graph.set_enabled(principal, False)
    assert graph._request.call_args_list[-2].args == (
        "POST", f"/applications/{app}/removePassword", {"keyId": key})
    assert graph._request.call_args_list[-1].args == (
        "PATCH", f"/servicePrincipals/{principal}", {"accountEnabled": False})


def test_graph_password_removal_reconciles_conflict(monkeypatch):
    graph, app, key = directory(), guid(), guid()
    conflict = EnrollmentError(502, "GraphRequestFailed", 409)
    graph._request = Mock(side_effect=[conflict, {
        "id": app, "passwordCredentials": [{"keyId": key}],
    }, {}])
    pauses = []
    monkeypatch.setattr("service.enrollment_azure.time.sleep", pauses.append)

    graph.remove_password(app, key)

    assert [call.args[0] for call in graph._request.call_args_list] == ["POST", "GET", "POST"]
    assert pauses


def test_graph_password_removal_does_not_repeat_absent_key(monkeypatch):
    graph, app, key = directory(), guid(), guid()
    graph._request = Mock(side_effect=[EnrollmentError(502, "GraphRequestFailed", 409), {
        "id": app, "passwordCredentials": [],
    }])
    monkeypatch.setattr("service.enrollment_azure.time.sleep", lambda _: None)

    graph.remove_password(app, key)

    assert [call.args[0] for call in graph._request.call_args_list] == ["POST", "GET"]


def test_graph_password_removal_bounds_persistent_conflicts(monkeypatch):
    graph, app, key = directory(), guid(), guid()
    conflict = EnrollmentError(502, "GraphRequestFailed", 409)
    metadata = {"id": app, "passwordCredentials": [{"keyId": key}]}
    graph._request = Mock(side_effect=[conflict, metadata] * 4)
    monkeypatch.setattr("service.enrollment_azure.time.sleep", lambda _: None)

    error("GraphRequestFailed", lambda: graph.remove_password(app, key))

    assert [call.args[0] for call in graph._request.call_args_list] == [
        "POST", "GET", "POST", "GET", "POST", "GET", "POST", "GET"]


def test_graph_password_removal_stops_when_retry_deadline_expires(monkeypatch):
    graph, app, key = directory(), guid(), guid()
    graph._request = Mock(side_effect=EnrollmentError(502, "GraphRequestFailed", 409))
    times = iter([0, 31])
    monkeypatch.setattr("service.enrollment_azure.time.monotonic", lambda: next(times))

    error("GraphRequestFailed", lambda: graph.remove_password(app, key))

    assert graph._request.call_count == 1


@pytest.mark.parametrize("status", [None, 429, 500])
def test_graph_password_removal_does_not_retry_other_failures(status):
    graph, app, key = directory(), guid(), guid()
    graph._request = Mock(side_effect=EnrollmentError(502, "GraphRequestFailed", status))

    error("GraphRequestFailed", lambda: graph.remove_password(app, key))

    assert graph._request.call_count == 1


def test_graph_password_removal_rejects_mismatched_application():
    graph, app, key = directory(), guid(), guid()
    graph._request = Mock(side_effect=[EnrollmentError(502, "GraphRequestFailed", 409), {
        "id": guid(), "passwordCredentials": [],
    }])

    error("GraphBindingMismatch", lambda: graph.remove_password(app, key))

    assert graph._request.call_count == 2


def test_graph_password_removal_rejects_malformed_metadata():
    graph, app, key = directory(), guid(), guid()
    graph._request = Mock(side_effect=[EnrollmentError(502, "GraphRequestFailed", 409), {
        "id": app, "passwordCredentials": [None],
    }])

    error("GraphBindingMismatch", lambda: graph.remove_password(app, key))

    assert graph._request.call_count == 2


def test_graph_recovery_lists_only_exact_enrollment_password_markers():
    graph, app, cid = directory(), guid(), guid()
    key = guid()
    prefix = f"faas-enrollment:{cid}:"
    graph._request = Mock(return_value={
        "id": app, "passwordCredentials": [
            {"keyId": key, "displayName": prefix + "a" * 64},
            {"keyId": guid(), "displayName": f"faas-enrollment:{guid()}:" + "b" * 64},
            {"keyId": guid(), "displayName": "faas-enrollment"},
            {"keyId": guid(), "displayName": "other-admin-password"},
            {"keyId": guid(), "displayName": prefix + "not-an-operation"},
            {"keyId": guid(), "displayName": None},
        ],
    })
    assert graph.password_keys(app, cid) == [key]
    graph._request.assert_called_once_with(
        "GET", f"/applications/{app}?$select=id,passwordCredentials")
    error("GraphPasswordMarkerInvalid", lambda: graph.add_password(app, FUTURE, "unscoped"))


@pytest.mark.parametrize("existing", [False, True])
def test_graph_recovery_ensures_only_pinned_role_and_does_not_duplicate(existing):
    graph, principal = directory(), guid()
    responses = provider_responses(graph)
    assignment_path = f"/servicePrincipals/{principal}/appRoleAssignments"
    responses[assignment_path + "?$select=resourceId,appRoleId,principalId"] = {
        "value": [{
            "principalId": principal,
            "resourceId": graph.settings.provider_api_principal_id,
            "appRoleId": graph.settings.provider_role_id,
        }] if existing else [],
    }

    def respond(method, path, body=None, **kwargs):
        if method == "POST":
            assert path == assignment_path
            assert body["resourceId"] == graph.settings.provider_api_principal_id
            return {}
        return responses[path]

    graph._request = Mock(side_effect=respond)
    graph.ensure_role(principal)
    assert sum(call.args[0] == "POST" for call in graph._request.call_args_list) == (
        0 if existing else 1)


@pytest.mark.parametrize("outcome", ["retry-succeeds", "assignment-present", "other-assignment", "timeout"])
def test_role_grant_retries_only_explicit_not_found_after_reconciliation(outcome, monkeypatch):
    graph, principal = directory(), guid()
    graph._provider = Mock()
    calls = []
    clock = SimpleNamespace(monotonic=Mock(return_value=0), sleep=Mock())
    monkeypatch.setattr("service.enrollment_azure.time", clock)
    expected = {"principalId": principal, "resourceId": graph.settings.provider_api_principal_id,
                "appRoleId": graph.settings.provider_role_id}
    def request(method, path, body=None, **kwargs):
        calls.append(method)
        if method == "POST":
            if outcome == "timeout":
                raise EnrollmentError(502, "GraphRequestFailed")
            if calls.count("POST") == 1:
                raise EnrollmentError(502, "GraphRequestFailed", 404, "", "Request_ResourceNotFound")
            return {}
        if outcome == "assignment-present":
            return {"value": [expected]}
        if outcome == "other-assignment":
            return {"value": [{**expected, "appRoleId": guid()}]}
        return {"value": []}
    graph._request = Mock(side_effect=request)
    if outcome in ("retry-succeeds", "assignment-present"):
        graph.grant_role(principal)
        assert calls.count("POST") == (2 if outcome == "retry-succeeds" else 1)
    else:
        expected_error = "GraphBindingMismatch" if outcome == "other-assignment" else "GraphRequestFailed"
        error(expected_error, lambda: graph.grant_role(principal))
        assert calls.count("POST") == 1


@pytest.mark.parametrize("response", ["found", "missing", "malformed"])
def test_graph_recovery_principal_uses_verified_client_alternate_key(response, monkeypatch):
    graph, client, principal = directory(), guid(), guid()
    requests = []
    clock = SimpleNamespace(monotonic=Mock(side_effect=[0, 31]), sleep=Mock())
    monkeypatch.setattr("service.enrollment_azure.time", clock)

    def handle(req):
        requests.append(req)
        if response == "missing":
            return httpx.Response(404, json={"error": {"message": "not found"}})
        return httpx.Response(
            200, json={"id": principal, "appId": client} if response == "found" else {})

    graph.client = httpx.Client(transport=httpx.MockTransport(handle))
    try:
        if response == "malformed":
            error("GraphBindingMismatch", lambda: graph.find_principal(client))
        else:
            assert graph.find_principal(client) == (principal if response == "found" else None)
        assert len(requests) == 1
        assert requests[0].method == "GET"
        assert f"servicePrincipals(appId='{client}')" in str(requests[0].url)
    finally:
        graph.close()


def test_vault_restricts_names_versions_and_redacts_errors():
    client, cid = Mock(), guid()
    vault = EnrollmentVault(client)
    version = uuid4().hex
    client.set_secret.return_value = SimpleNamespace(
        name="customer-" + cid, properties=SimpleNamespace(version=version))
    reference = vault.write(cid, SECRET, FUTURE)
    assert reference == {"name": "customer-" + cid, "version": version}
    assert client.set_secret.call_args.kwargs["retry_total"] == 0
    assert client.set_secret.call_args.kwargs["logging_enable"] is False
    assert client.set_secret.call_args.kwargs["expires_on"] == datetime(
        2099, 1, 1, tzinfo=timezone.utc)
    client.get_secret.return_value = SimpleNamespace(value=SECRET)
    assert vault.read(reference["name"], version) == SECRET
    for name in ("env-" + cid, "customer-../secret", "customer-" + cid.upper()):
        error("VaultNameInvalid", lambda: vault.read(name, version))
    for invalid in ("", "../secret", "https://attacker.example", "A" * 32):
        error("VaultVersionInvalid", lambda: vault.read(reference["name"], invalid))
    client.set_secret.side_effect = RuntimeError(SECRET)
    client.get_secret.side_effect = RuntimeError(SECRET)
    error("VaultWriteFailed", lambda: vault.write(cid, SECRET, FUTURE))
    error("VaultReadFailed", lambda: vault.read(reference["name"], version))
