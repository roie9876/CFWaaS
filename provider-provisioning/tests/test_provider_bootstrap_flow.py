import json
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).parent))
from test_enrollment import Memory
from test_provider_bootstrap_auth import OAuth, ADMIN, CLIENT, ORIGIN, TENANT, uid
from test_provider_bootstrap_graph import Directory
from service.provider_bootstrap import BootstrapContext, BootstrapError, ProviderBootstrap
from service.provider_bootstrap_auth import ProviderBrowserAuth
from service.provider_bootstrap_graph import DelegatedSession, ProviderBootstrapGraph
from service.provider_bootstrap_vault import ProviderBootstrapVault


class PrivateVault:
    def __init__(self):
        self.values = {}

    def set_secret(self, name, value, **kwargs):
        version = "a" * 32
        self.values[(name, version)] = value
        return SimpleNamespace(name=name, value=value, properties=SimpleNamespace(version=version))

    def get_secret(self, name, version, **kwargs):
        return SimpleNamespace(name=name, value=self.values[(name, version)],
                               properties=SimpleNamespace(version=version))


@pytest.fixture
def bootstrap():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keys = SimpleNamespace(get=lambda kid: SimpleNamespace(key=private.public_key()))
    client = OAuth(private)
    browser = ProviderBrowserAuth(TENANT, CLIENT, ORIGIN, lambda: client, keys)
    graph_stub = Directory()
    vault_stub = PrivateVault()
    backend = Memory()
    return browser, client, graph_stub, vault_stub, backend


def test_verified_browser_identity_drives_provider_only_bootstrap_without_secret_outputs(bootstrap):
    browser, client, graph_stub, vault_stub, backend = bootstrap
    challenge = browser.begin()
    admin = browser.complete(challenge.session_id, {"state": client.state, "code": "unit-code"})
    context = BootstrapContext(admin.tenant_id, uid(7), admin.object_id, ORIGIN)
    with httpx.Client(transport=httpx.MockTransport(graph_stub), follow_redirects=False) as transport:
        graph = ProviderBootstrapGraph(
            DelegatedSession(admin.tenant_id, admin.object_id, admin.graph_access_token), transport)
        coordinator = ProviderBootstrap(backend, graph, ProviderBootstrapVault(vault_stub))
        assert coordinator.start(context)["status"] == "Pending"
        assert coordinator.run(context)["status"] == "Ready"
        outputs = coordinator.installation_parameters(context)
    assert outputs["administratorObjectId"] == ADMIN
    assert outputs["providerTenantId"] == TENANT
    assert outputs["managementSecretVersion"] == "a" * 32
    assert len(vault_stub.values) == 2
    assert len(graph_stub.assignments) == 3
    serialized = json.dumps(list(backend.rows.values()), default=str) + json.dumps(outputs)
    for secret in vault_stub.values.values():
        assert secret not in serialized
    assert admin.graph_access_token not in serialized
    assert all(request.url.host == "graph.microsoft.com" for request in graph_stub.requests)


def test_consent_denial_does_not_call_graph_or_create_material(bootstrap):
    browser, client, graph_stub, vault_stub, backend = bootstrap
    challenge = browser.begin()
    with pytest.raises(BootstrapError) as error:
        browser.complete(challenge.session_id, {"state": client.state, "error": "access_denied"})
    assert error.value.code == "BootstrapSignInOrConsentDenied"
    assert not graph_stub.requests
    assert not vault_stub.values
    assert not backend.rows
