import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import UUID, uuid4

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from test_enrollment import Memory
from service.provider_bootstrap import (
    Application, BootstrapContext, BootstrapError, GRAPH_PERMISSIONS,
    ManagementCredential, ProviderBootstrap,
)


def uid(number):
    return str(UUID(int=number))


@pytest.fixture
def context():
    return BootstrapContext(uid(1), uid(2), uid(3), "https://unit-admin.azurewebsites.net")


class Directory:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.entered = None
        self.release = None

    def call(self, operation):
        self.calls.append(operation)
        if self.entered is not None and operation == "CreateApi":
            self.entered.set()
            assert self.release.wait(5)
        if self.fail == operation:
            raise RuntimeError("unit-private-data-must-not-leak")

    def verify_administrator(self, context):
        self.call("VerifyAdmin")

    def create_api(self, context, role_id):
        self.call("CreateApi")
        return Application(uid(10), uid(11), uid(12))

    def create_management(self, context, api):
        self.call("CreateManagement")
        return Application(uid(20), uid(21), uid(22))

    def grant_management_permissions(self, context, management, permissions):
        assert permissions == GRAPH_PERMISSIONS
        self.call("GrantGraphPermissions")

    def verify_management_permissions(self, context, management, permissions):
        assert permissions == GRAPH_PERMISSIONS
        self.call("VerifyGraphPermissions")

    def add_management_credential(self, context, management, expires_at):
        self.call("CreateManagementCredential")
        return ManagementCredential(uid(30), "unit-generated-only", expires_at)


class Vault:
    def __init__(self):
        self.values = {}
        self.fail = False

    def write(self, name, value, expires_at=None):
        self.values[name] = value
        if self.fail:
            raise RuntimeError("unit-private-data-must-not-leak")
        return "a" * 32

    def verify(self, name, version):
        assert name in self.values and version == "a" * 32


@pytest.fixture
def setup():
    backend, directory, vault = Memory(), Directory(), Vault()
    return ProviderBootstrap(backend, directory, vault), backend, directory, vault


def test_bootstrap_success_persists_only_nonsecret_values(context, setup):
    coordinator, backend, directory, vault = setup
    assert coordinator.start(context)["status"] == "Pending"
    assert coordinator.run(context)["status"] == "Ready"
    parameters = coordinator.installation_parameters(context)
    assert parameters["apiApplicationId"] == uid(11)
    assert parameters["managementApplicationId"] == uid(21)
    assert parameters["administratorObjectId"] == context.administrator_id
    assert parameters["nvaSshPublicKey"].startswith("ssh-ed25519 ")
    management_name = "faas-mgmt-" + uid(30).replace("-", "")
    ssh_name = "faas-ssh-" + context.installation_id[:24]
    assert set(vault.values) == {management_name, ssh_name}
    assert parameters["managementSecretName"] == management_name
    assert vault.values[management_name] == "unit-generated-only"
    assert "PRIVATE KEY" in vault.values[ssh_name]
    serialized = json.dumps(list(backend.rows.values()), default=str)
    assert "unit-generated-only" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert "unit-generated-only" not in json.dumps(parameters)
    assert "PRIVATE KEY" not in json.dumps(parameters)
    assert directory.calls.count("GrantGraphPermissions") == 1
    assert directory.calls.count("CreateManagementCredential") == 1


def test_repeated_completed_bootstrap_never_creates_more_credentials(context, setup):
    coordinator, backend, directory, vault = setup
    coordinator.start(context)
    coordinator.run(context)
    calls = list(directory.calls)
    coordinator.start(context)
    coordinator.run(context)
    assert directory.calls == calls


@pytest.mark.parametrize("operation", [
    "CreateApi", "CreateManagement", "GrantGraphPermissions",
    "CreateManagementCredential",
])
def test_uncertain_directory_write_fails_closed_without_replay(context, setup, operation):
    coordinator, backend, directory, vault = setup
    coordinator.start(context)
    directory.fail = operation
    with pytest.raises(BootstrapError) as error:
        coordinator.run(context)
    assert error.value.code == "BootstrapNeedsOperatorReview"
    assert "unit-private-data-must-not-leak" not in str(error.value)
    status = coordinator.status(context)
    assert status["status"] == "NeedsAttention"
    assert status["pendingOperation"] == operation
    with pytest.raises(BootstrapError) as repeated:
        coordinator.run(context)
    assert repeated.value.code == "BootstrapNeedsOperatorReview"
    assert directory.calls.count(operation) == 1


def test_unknown_vault_write_is_not_replayed(context, setup):
    coordinator, backend, directory, vault = setup
    coordinator.start(context)
    vault.fail = True
    with pytest.raises(BootstrapError):
        coordinator.run(context)
    assert coordinator.status(context)["pendingOperation"] == "CreateManagementCredential"
    vault.fail = False
    with pytest.raises(BootstrapError):
        coordinator.run(context)
    assert directory.calls.count("CreateManagementCredential") == 1
    assert "unit-generated-only" not in str(backend.rows)


def test_second_admin_cannot_take_over_existing_setup(context, setup):
    coordinator, backend, directory, vault = setup
    coordinator.start(context)
    other = BootstrapContext(context.tenant_id, context.subscription_id, uid(4), context.management_origin)
    with pytest.raises(BootstrapError) as error:
        coordinator.run(other)
    assert error.value.code == "BootstrapIdentityMismatch"
    assert directory.calls == ["VerifyAdmin"]


def test_different_tenant_or_subscription_creates_separate_setup(context, setup):
    coordinator, backend, directory, vault = setup
    coordinator.start(context)
    other = BootstrapContext(uid(4), uid(5), context.administrator_id, context.management_origin)
    coordinator.start(other)
    assert len(backend.rows) == 2
    assert context.installation_id != other.installation_id


def test_concurrent_runs_cannot_duplicate_external_create(context, setup):
    coordinator, backend, directory, vault = setup
    coordinator.start(context)
    directory.entered, directory.release = threading.Event(), threading.Event()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(coordinator.run, context)
        assert directory.entered.wait(5)
        second = pool.submit(coordinator.run, context)
        with pytest.raises(BootstrapError) as error:
            second.result(timeout=5)
        assert error.value.code == "BootstrapNeedsOperatorReview"
        directory.release.set()
        assert first.result(timeout=5)["status"] == "Ready"
    assert directory.calls.count("CreateApi") == 1


def test_invalid_identity_and_unready_parameters_rejected(context, setup):
    coordinator, backend, directory, vault = setup
    coordinator.start(context)
    with pytest.raises(BootstrapError) as error:
        coordinator.installation_parameters(context)
    assert error.value.code == "BootstrapNotReady"
    with pytest.raises(ValueError):
        BootstrapContext(uid(0), uid(2), uid(3), context.management_origin)
    with pytest.raises(ValueError):
        BootstrapContext(uid(1), uid(2), uid(3), "https://evil.example")


def test_unexpected_identity_verifier_error_is_redacted(context, setup, caplog):
    coordinator, backend, directory, vault = setup
    directory.fail = "VerifyAdmin"
    with pytest.raises(BootstrapError) as error:
        coordinator.start(context)
    assert error.value.code == "BootstrapAdministratorVerificationUnavailable"
    assert "unit-private-data-must-not-leak" not in str(error.value)
    assert "unit-private-data-must-not-leak" not in caplog.text
    assert not backend.rows
