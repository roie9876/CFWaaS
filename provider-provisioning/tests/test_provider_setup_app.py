import json
import sys
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent))
from test_enrollment import Memory
from test_provider_bootstrap import Directory, Vault
from service.provider_bootstrap_auth import VerifiedAdministrator
from service.provider_device_auth import DeviceChallenge, DevicePending
from service.provider_setup_app import SetupSettings, create_app


def uid(number):
    return str(UUID(int=number))


TENANT, SUBSCRIPTION, ADMIN, CLIENT = uid(1), uid(2), uid(3), uid(4)
ORIGIN = "https://unit-setup.azurewebsites.net"
TOKEN = "fixture-" + uuid4().hex
SESSION = "s" * 43


class Device:
    def __init__(self):
        self.pending = False

    def begin(self):
        return DeviceChallenge(SESSION, "ABCDEFGH", "https://microsoft.com/devicelogin", 900)

    def poll(self, session_id):
        assert session_id == SESSION
        if self.pending:
            return DevicePending(5)
        return VerifiedAdministrator(TENANT, ADMIN, TOKEN)


class DirectoryAdapter(Directory):
    def __init__(self, session):
        super().__init__()
        self.session = session
        self.closed = False

    def verify_administrator(self, context):
        assert context.tenant_id == self.session.tenant_id == TENANT
        assert context.administrator_id == self.session.administrator_id == ADMIN
        super().verify_administrator(context)

    def close(self):
        self.closed = True


class Publisher:
    def __init__(self):
        self.context = None
        self.parameters = None

    def publish(self, context, parameters):
        self.context, self.parameters = context, parameters
        return {"portalUrl": "https://portal.azure.com/#create/Microsoft.Template/uri/unit",
                "expiresAt": "2099-01-01T00:00:00Z"}


@pytest.fixture
def setup():
    settings = SetupSettings(
        TENANT, SUBSCRIPTION, CLIENT, ADMIN, ORIGIN, "https://unit-admin.azurewebsites.net",
        "https://unit.table.core.windows.net", "https://unit.vault.azure.net",
        "https://unit.blob.core.windows.net", "rg-release", "unit-vault", "rg-setup",
        "https://unit.blob.core.windows.net/deployment-artifacts/releases/a/apps.zip",
        "a" * 64, "b" * 64,
    )
    device, backend, vault, publisher = Device(), Memory(), Vault(), Publisher()
    adapters = []
    def graph_factory(session):
        adapter = DirectoryAdapter(session)
        adapters.append(adapter)
        return adapter
    with TestClient(create_app(settings, device, backend, vault, publisher, graph_factory),
                    base_url=ORIGIN) as client:
        yield client, device, backend, vault, publisher, adapters


def post(client, path, body=None, origin=ORIGIN):
    return client.post(path, headers={"Origin": origin}, json=body or {})


def test_complete_setup_with_verified_admin_and_no_secret_outputs(setup):
    client, device, backend, vault, publisher, adapters = setup
    assert client.get("/").status_code == 200
    signin = post(client, "/setup/signin")
    assert signin.status_code == 200
    cookie = signin.headers["set-cookie"]
    assert "__Host-faas-setup=" in cookie and "HttpOnly" in cookie and "Secure" in cookie
    assert "SameSite=lax" in cookie and "Path=/" in cookie
    assert signin.headers["cache-control"] == "no-store"
    assert signin.json() == {"userCode": "ABCDEFGH",
                             "verificationUri": "https://microsoft.com/devicelogin", "expiresIn": 900}
    assert "fixture-device-code" not in signin.text
    assert TOKEN not in signin.text
    assert post(client, "/setup/poll").json() == {"status": "SignedIn"}
    rejected = post(client, "/setup/create", {"confirmGraphPermissions": False})
    assert rejected.status_code == 400
    assert rejected.json()["detail"] == "BootstrapGraphApprovalRequired"
    response = post(client, "/setup/create", {"confirmGraphPermissions": True})
    assert response.status_code == 200
    assert response.json()["portalUrl"].startswith("https://portal.azure.com/")
    assert response.headers["cache-control"] == "no-store"
    assert publisher.context.tenant_id == TENANT
    assert publisher.context.subscription_id == SUBSCRIPTION
    assert publisher.context.administrator_id == ADMIN
    assert publisher.parameters["managementSecretName"].startswith("faas-mgmt-")
    for value in vault.values.values():
        assert value not in response.text
        assert value not in json.dumps(list(backend.rows.values()), default=str)
    assert TOKEN not in response.text
    assert adapters[0].closed is True
    replay = post(client, "/setup/create", {"confirmGraphPermissions": True})
    assert replay.status_code == 401
    assert replay.json()["detail"] == "BootstrapSignInExpired"


def test_waiting_and_origin_protection_do_not_run_graph(setup):
    client, device, backend, vault, publisher, adapters = setup
    assert post(client, "/setup/signin", origin="https://attacker.example").status_code == 403
    assert post(client, "/setup/create", {"confirmGraphPermissions": True}).status_code == 401
    assert post(client, "/setup/signin").status_code == 200
    device.pending = True
    assert post(client, "/setup/poll").json() == {"status": "Waiting", "retryAfter": 5}
    assert not adapters and not backend.rows and not vault.values


def test_unknown_inputs_are_rejected_without_directory_calls(setup):
    client, device, backend, vault, publisher, adapters = setup
    post(client, "/setup/signin")
    post(client, "/setup/poll")
    response = post(client, "/setup/create", {"confirmGraphPermissions": True,
                                               "tenantId": uid(99)})
    assert response.status_code == 422
    assert not adapters and not backend.rows


def test_directory_admin_must_match_the_actual_azure_deployment_initiator(setup):
    client, device, backend, vault, publisher, adapters = setup
    device.poll = lambda session: VerifiedAdministrator(TENANT, uid(99), TOKEN)
    post(client, "/setup/signin")
    response = post(client, "/setup/poll")
    assert response.status_code == 403
    assert response.json()["detail"] == "BootstrapIdentityMismatch"
    assert not adapters and not backend.rows and not vault.values
