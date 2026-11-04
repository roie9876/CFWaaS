import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import httpx
import pytest

from service.provider_bootstrap import Application, BootstrapContext, BootstrapError, GRAPH_PERMISSIONS
from service.provider_bootstrap_graph import (
    GRAPH_APPLICATION_ID, GRAPH_ORIGIN, GRAPH_ROLES, DelegatedSession, ProviderBootstrapGraph,
)


def uid(number):
    return str(UUID(int=number))


CONTEXT = BootstrapContext(uid(1), uid(2), uid(3), "https://unit-admin.azurewebsites.net")
API = Application(uid(10), uid(11), uid(12))
MANAGEMENT = Application(uid(20), uid(21), uid(22))


class Directory:
    def __init__(self):
        self.requests = []
        self.assignments = []
        self.principal_tenant = CONTEXT.tenant_id
        self.response_status = None
        self.api_request = None
        self.management_request = None
        self.implicit_grant = {"enableIdTokenIssuance": True, "enableAccessTokenIssuance": False}

    def __call__(self, request):
        self.requests.append(request)
        if self.response_status:
            return httpx.Response(self.response_status, json={"error": {"message": "unit-private"}})
        path = request.url.path.removeprefix("/v1.0")
        if path == "/me":
            return httpx.Response(200, json={"id": CONTEXT.administrator_id})
        if path == "/applications" and request.method == "POST":
            body = json.loads(request.content)
            if body.get("displayName") == "FaaS Provider API":
                self.api_request = body
                return httpx.Response(201, json={"id": API.object_id, "appId": API.client_id})
            if body.get("displayName") == "FaaS Provider Management":
                self.management_request = body
                return httpx.Response(201, json={"id": MANAGEMENT.object_id, "appId": MANAGEMENT.client_id})
        if path == "/applications/" + API.object_id and request.method == "PATCH":
            assert json.loads(request.content) == {"identifierUris": ["api://" + API.client_id]}
            return httpx.Response(204)
        if path == "/servicePrincipals" and request.method == "POST":
            client_id = json.loads(request.content)["appId"]
            principal = API if client_id == API.client_id else MANAGEMENT
            return httpx.Response(201, json={"id": principal.principal_id, "appId": client_id})
        if path == "/servicePrincipals" and request.method == "GET":
            roles = [{"id": role, "value": name, "isEnabled": True, "allowedMemberTypes": ["Application"]}
                     for name, role in GRAPH_ROLES.items()]
            return httpx.Response(200, json={"value": [{"id": uid(99), "appId": GRAPH_APPLICATION_ID,
                                                         "appRoles": roles}]})
        if path == "/applications/" + MANAGEMENT.object_id:
            return httpx.Response(200, json={
                "id": MANAGEMENT.object_id, "appId": MANAGEMENT.client_id,
                "signInAudience": "AzureADMyOrg",
                "web": {"redirectUris": [CONTEXT.management_origin + "/.auth/login/aad/callback"],
                        "implicitGrantSettings": self.implicit_grant},
                "requiredResourceAccess": [{
                    "resourceAppId": GRAPH_APPLICATION_ID,
                    "resourceAccess": [{"id": GRAPH_ROLES[name], "type": "Role"}
                                       for name in GRAPH_PERMISSIONS],
                }],
            })
        if path == "/applications/" + MANAGEMENT.object_id + "/addPassword":
            return httpx.Response(200, json={
                "keyId": uid(30), "secretText": "unit-password-never-log",
                "endDateTime": json.loads(request.content)["passwordCredential"]["endDateTime"],
            })
        if path == "/servicePrincipals/" + MANAGEMENT.principal_id:
            return httpx.Response(200, json={"id": MANAGEMENT.principal_id,
                                            "appId": MANAGEMENT.client_id,
                                            "appOwnerOrganizationId": self.principal_tenant})
        if path == "/servicePrincipals/" + MANAGEMENT.principal_id + "/appRoleAssignments":
            if request.method == "POST":
                self.assignments.append(json.loads(request.content))
                return httpx.Response(201, json={})
            return httpx.Response(200, json={"value": self.assignments})
        raise AssertionError("Unexpected Graph call")


@pytest.fixture
def graph():
    fake = Directory()
    session = DelegatedSession(CONTEXT.tenant_id, CONTEXT.administrator_id, "unit-fake-token")
    client = httpx.Client(transport=httpx.MockTransport(fake), follow_redirects=False)
    return ProviderBootstrapGraph(session, client), fake


def test_delegated_token_never_appears_in_repr_or_error(graph):
    adapter, fake = graph
    assert "unit-fake-token" not in repr(adapter.session)
    fake.response_status = 403
    with pytest.raises(BootstrapError) as error:
        adapter.verify_administrator(CONTEXT)
    assert error.value.code == "BootstrapGraphAuthorizationRequired"
    assert "unit-fake-token" not in str(error.value)
    assert "unit-private" not in str(error.value)


def test_provider_apps_are_single_tenant_with_exact_role_and_callback(graph):
    adapter, fake = graph
    assert adapter.create_api(CONTEXT, uid(8)) == API
    assert adapter.create_management(CONTEXT, API) == MANAGEMENT
    assert fake.api_request["signInAudience"] == "AzureADMyOrg"
    assert fake.api_request["api"]["requestedAccessTokenVersion"] == 2
    assert fake.api_request["appRoles"][0]["id"] == uid(8)
    assert fake.api_request["appRoles"][0]["allowedMemberTypes"] == ["Application"]
    assert fake.management_request["signInAudience"] == "AzureADMyOrg"
    assert fake.management_request["web"]["redirectUris"] == [
        CONTEXT.management_origin + "/.auth/login/aad/callback"]
    assert fake.management_request["web"]["implicitGrantSettings"] == {
        "enableIdTokenIssuance": True, "enableAccessTokenIssuance": False}
    assert fake.management_request["requiredResourceAccess"][0]["resourceAppId"] == GRAPH_APPLICATION_ID


def test_management_credential_generated_for_verified_app_and_redacted(graph):
    adapter, fake = graph
    expiry = (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0).isoformat()
    credential = adapter.add_management_credential(CONTEXT, MANAGEMENT, expiry)
    assert credential.key_id == uid(30)
    assert credential.secret == "unit-password-never-log"
    assert "unit-password-never-log" not in repr(credential)
    assert len([item for item in fake.requests if item.url.path.endswith("/addPassword")]) == 1


def test_grants_only_exact_approved_provider_graph_roles(graph):
    adapter, fake = graph
    adapter.grant_management_permissions(CONTEXT, MANAGEMENT, GRAPH_PERMISSIONS)
    adapter.verify_management_permissions(CONTEXT, MANAGEMENT, GRAPH_PERMISSIONS)
    assert len(fake.assignments) == 3
    assert {item["appRoleId"] for item in fake.assignments} == set(GRAPH_ROLES.values())
    assert all(item["principalId"] == MANAGEMENT.principal_id for item in fake.assignments)
    assert all(item["resourceId"] == uid(99) for item in fake.assignments)
    assert all(request.url.scheme == "https" and request.url.host == "graph.microsoft.com"
               for request in fake.requests)


def test_unapproved_or_mismatched_management_identity_never_grants(graph):
    adapter, fake = graph
    with pytest.raises(BootstrapError):
        adapter.grant_management_permissions(CONTEXT, MANAGEMENT, GRAPH_PERMISSIONS + ("Directory.ReadWrite.All",))
    assert not fake.assignments
    fake.principal_tenant = uid(4)
    with pytest.raises(BootstrapError) as error:
        adapter.grant_management_permissions(CONTEXT, MANAGEMENT, GRAPH_PERMISSIONS)
    assert error.value.code == "BootstrapGraphBindingMismatch"
    assert not fake.assignments


@pytest.mark.parametrize("settings", [
    {"enableIdTokenIssuance": False, "enableAccessTokenIssuance": False},
    {"enableIdTokenIssuance": True, "enableAccessTokenIssuance": True},
    {},
])
def test_management_signin_settings_must_match_before_graph_grants(graph, settings):
    adapter, fake = graph
    fake.implicit_grant = settings
    with pytest.raises(BootstrapError) as error:
        adapter.grant_management_permissions(CONTEXT, MANAGEMENT, GRAPH_PERMISSIONS)
    assert error.value.code == "BootstrapGraphBindingMismatch"
    assert not fake.assignments


def test_extra_or_missing_grants_are_not_accepted(graph):
    adapter, fake = graph
    adapter.grant_management_permissions(CONTEXT, MANAGEMENT, GRAPH_PERMISSIONS)
    fake.assignments.append({"principalId": MANAGEMENT.principal_id, "resourceId": uid(99),
                             "appRoleId": uid(45)})
    with pytest.raises(BootstrapError) as error:
        adapter.verify_management_permissions(CONTEXT, MANAGEMENT, GRAPH_PERMISSIONS)
    assert error.value.code == "BootstrapGraphPermissionMismatch"


def test_wrong_tenant_or_administrator_never_calls_graph(graph):
    adapter, fake = graph
    other = BootstrapContext(uid(4), CONTEXT.subscription_id, CONTEXT.administrator_id,
                             CONTEXT.management_origin)
    with pytest.raises(BootstrapError):
        adapter.verify_administrator(other)
    assert not fake.requests


def test_graph_rejects_token_controlled_request_paths(graph):
    adapter, fake = graph
    for path in ("https://attacker.example", "//attacker.example", "/x://attacker.example"):
        with pytest.raises(BootstrapError):
            adapter._request("GET", path)
    assert not fake.requests
