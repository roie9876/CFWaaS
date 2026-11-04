import copy
import sys
from pathlib import Path
from unittest.mock import patch
from uuid import UUID

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import register_setup_client as setup


def uid(number):
    return str(UUID(int=number))


class Directory:
    tenant = uid(1)

    def __init__(self):
        self.application = None
        self.principal = None
        self.calls = []
        self.fail = ""

    def request(self, method, path, body=None):
        self.calls.append((method, path, body))
        if self.fail == path:
            raise RuntimeError("unit-no-response")
        if method == "POST" and path == "/applications":
            self.application = {**body, "id": uid(2), "appId": uid(3)}
            return self.application
        if method == "POST" and path == "/servicePrincipals":
            self.principal = {"id": uid(4), "appId": body["appId"]}
            return self.principal
        if method == "GET" and path.startswith("/applications?"):
            return {"value": [self.application] if self.application else []}
        if method == "GET" and path.startswith("/servicePrincipals?"):
            return {"value": [self.principal] if self.principal else []}
        raise AssertionError("Unexpected Graph call")


def test_setup_client_registration_is_secretless_and_grants_no_roles():
    graph = Directory()
    state = {"providerTenantId": uid(1)}
    writes = []
    with patch.object(setup, "save_private", side_effect=lambda path, value: writes.append(copy.deepcopy(value))):
        result = setup.register(graph, state, Path("unit"))
        setup.register(graph, state, Path("unit"))
    assert result["clientId"] == uid(3)
    assert result["principalId"] == uid(4)
    assert graph.application["isFallbackPublicClient"] is True
    assert graph.application["signInAudience"] == "AzureADMultipleOrgs"
    access = graph.application["requiredResourceAccess"]
    assert access[0]["resourceAppId"] == setup.GRAPH_APP
    assert {item["id"] for item in access[0]["resourceAccess"]} == set(setup.SCOPES)
    assert all(item["type"] == "Scope" for item in access[0]["resourceAccess"])
    assert not any("appRoleAssignments" in call[1] for call in graph.calls)
    assert [write["pendingOperation"] for write in writes] == [
        "CreateApplication", "", "CreateServicePrincipal", ""]
    assert sum(call[:2] == ("POST", "/applications") for call in graph.calls) == 1


def test_uncertain_app_write_never_replays():
    graph = Directory()
    graph.fail = "/applications"
    state = {"providerTenantId": uid(1)}
    with patch.object(setup, "save_private"):
        with pytest.raises(RuntimeError):
            setup.register(graph, state, Path("unit"))
        assert state["pendingOperation"] == "CreateApplication"
        with pytest.raises(ValueError):
            setup.register(graph, state, Path("unit"))
    assert sum(call[:2] == ("POST", "/applications") for call in graph.calls) == 1


def test_wrong_tenant_or_changed_permission_contract_fails_closed():
    graph = Directory()
    with patch.object(setup, "save_private"):
        with pytest.raises(ValueError):
            setup.register(graph, {"providerTenantId": uid(9)}, Path("unit"))
        state = {"providerTenantId": uid(1)}
        setup.register(graph, state, Path("unit"))
        graph.application["requiredResourceAccess"][0]["resourceAccess"].pop()
        with pytest.raises(ValueError):
            setup.register(graph, state, Path("unit"))
