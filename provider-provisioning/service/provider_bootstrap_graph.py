"""Provider-only Microsoft Graph adapter for a verified delegated setup session.

The browser sign-in and consent flow is not implemented here. The caller must
validate the signed administrator identity, tenant and subscription before
constructing this adapter, and must never persist the delegated access token.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime
import httpx

from .provider_bootstrap import (
    Application, BootstrapContext, BootstrapError, GRAPH_PERMISSIONS,
    ManagementCredential, ROLE, canonical_guid,
)

logger = logging.getLogger("faas.provider-bootstrap-graph")
GRAPH_ORIGIN = "https://graph.microsoft.com"
GRAPH_APPLICATION_ID = "00000003-0000-0000-c000-000000000000"
GRAPH_ROLES = {
    "Application.ReadWrite.OwnedBy": "18a4783c-866b-4cc7-a460-3d5e5662c884",
    "Application.Read.All": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30",
    "AppRoleAssignment.ReadWrite.All": "06b708a9-e830-4db3-a914-8e69da51d44f",
}


@dataclass(frozen=True)
class DelegatedSession:
    """Produced only after the future browser callback validates the ID token."""

    tenant_id: str
    administrator_id: str
    access_token: str = field(repr=False)

    def __post_init__(self) -> None:
        canonical_guid(self.tenant_id)
        canonical_guid(self.administrator_id)
        if not isinstance(self.access_token, str) or not self.access_token:
            raise ValueError("A delegated Graph token is required")


class ProviderBootstrapGraph:
    def __init__(self, session: DelegatedSession, client: httpx.Client | None = None) -> None:
        self.session = session
        self.client = client or httpx.Client(timeout=httpx.Timeout(20, connect=5),
                                            follow_redirects=False, trust_env=False)

    def _request(self, method: str, path: str, body: dict | None = None,
                 params: dict | None = None) -> dict:
        if not path.startswith("/") or path.startswith("//") or "://" in path:
            raise BootstrapError(400, "BootstrapGraphPathRejected")
        try:
            response = self.client.request(
                method, GRAPH_ORIGIN + "/v1.0" + path, params=params,
                headers={"Authorization": "Bearer " + self.session.access_token},
                json=body,
            )
            if response.status_code not in (200, 201, 204):
                raise BootstrapError(
                    403 if response.status_code in (401, 403) else 502,
                    "BootstrapGraphAuthorizationRequired" if response.status_code in (401, 403)
                    else "BootstrapGraphRequestFailed",
                )
            result = {} if response.status_code == 204 else response.json()
            if not isinstance(result, dict) or "@odata.nextLink" in result:
                raise ValueError("Unexpected Graph response")
            return result
        except BootstrapError:
            raise
        except (httpx.HTTPError, ValueError, TypeError):
            logger.warning("code=BootstrapGraphRequestUnavailable")
            raise BootstrapError(502, "BootstrapGraphRequestFailed") from None

    def verify_administrator(self, context: BootstrapContext) -> None:
        if (context.tenant_id, context.administrator_id) != (
                self.session.tenant_id, self.session.administrator_id):
            raise BootstrapError(403, "BootstrapIdentityMismatch")
        user = self._request("GET", "/me", params={"$select": "id"})
        if user.get("id") != context.administrator_id:
            raise BootstrapError(403, "BootstrapIdentityMismatch")

    @staticmethod
    def _application(result: dict, principal: dict) -> Application:
        try:
            application = Application(
                canonical_guid(result["id"]), canonical_guid(result["appId"]),
                canonical_guid(principal["id"]),
            )
            if principal.get("appId") != application.client_id:
                raise ValueError("Principal does not belong to application")
            return application
        except (KeyError, ValueError, TypeError):
            raise BootstrapError(502, "BootstrapGraphBindingMismatch") from None

    def _create_principal(self, app_id: str) -> dict:
        return self._request("POST", "/servicePrincipals", {"appId": canonical_guid(app_id)})

    def create_api(self, context: BootstrapContext, role_id: str) -> Application:
        self.verify_administrator(context)
        canonical_guid(role_id)
        result = self._request("POST", "/applications", {
            "displayName": "FaaS Provider API",
            "signInAudience": "AzureADMyOrg",
            "api": {"requestedAccessTokenVersion": 2},
            "optionalClaims": {"accessToken": [{"name": "idtyp", "essential": False}]},
            "appRoles": [{"id": role_id, "value": ROLE, "displayName": ROLE,
                          "description": "Request an entitled FaaS environment.",
                          "allowedMemberTypes": ["Application"], "isEnabled": True}],
        })
        object_id, client_id = canonical_guid(result["id"]), canonical_guid(result["appId"])
        self._request("PATCH", "/applications/" + object_id,
                      {"identifierUris": ["api://" + client_id]})
        return self._application(result, self._create_principal(client_id))

    def create_management(self, context: BootstrapContext, api: Application) -> Application:
        self.verify_administrator(context)
        result = self._request("POST", "/applications", {
            "displayName": "FaaS Provider Management",
            "signInAudience": "AzureADMyOrg",
            "web": {
                "redirectUris": [context.management_origin + "/.auth/login/aad/callback"],
                "implicitGrantSettings": {"enableIdTokenIssuance": True, "enableAccessTokenIssuance": False},
            },
            "requiredResourceAccess": [{
                "resourceAppId": GRAPH_APPLICATION_ID,
                "resourceAccess": [{"id": GRAPH_ROLES[name], "type": "Role"}
                                   for name in GRAPH_PERMISSIONS],
            }],
        })
        application = self._application(result, self._create_principal(result["appId"]))
        if application.client_id == api.client_id or application.principal_id == api.principal_id:
            raise BootstrapError(502, "BootstrapGraphBindingMismatch")
        return application

    def _graph_principal(self) -> str:
        result = self._request(
            "GET", "/servicePrincipals",
            params={"$filter": "appId eq '" + GRAPH_APPLICATION_ID + "'",
                    "$select": "id,appId,appRoles"},
        )
        entries = result.get("value")
        if not isinstance(entries, list) or len(entries) != 1:
            raise BootstrapError(502, "BootstrapGraphBindingMismatch")
        principal = entries[0]
        roles = principal.get("appRoles")
        if principal.get("appId") != GRAPH_APPLICATION_ID or not isinstance(roles, list):
            raise BootstrapError(502, "BootstrapGraphBindingMismatch")
        for name, role_id in GRAPH_ROLES.items():
            matches = [role for role in roles if role.get("id") == role_id]
            if (len(matches) != 1 or matches[0].get("value") != name
                    or matches[0].get("isEnabled") is not True
                    or "Application" not in matches[0].get("allowedMemberTypes", [])):
                raise BootstrapError(502, "BootstrapGraphBindingMismatch")
        return canonical_guid(principal["id"])

    def _verify_management(self, context: BootstrapContext, management: Application) -> None:
        principal = self._request(
            "GET", "/servicePrincipals/" + management.principal_id,
            params={"$select": "id,appId,appOwnerOrganizationId"},
        )
        app = self._request(
            "GET", "/applications/" + management.object_id,
            params={"$select": "id,appId,signInAudience,web,requiredResourceAccess"},
        )
        requested = app.get("requiredResourceAccess")
        requested_graph_roles = set()
        if isinstance(requested, list) and len(requested) == 1:
            access = requested[0].get("resourceAccess")
            if requested[0].get("resourceAppId") == GRAPH_APPLICATION_ID and isinstance(access, list):
                requested_graph_roles = {(item.get("id"), item.get("type")) for item in access}
        if (principal.get("id") != management.principal_id
                or principal.get("appId") != management.client_id
                or principal.get("appOwnerOrganizationId") != context.tenant_id
                or app.get("id") != management.object_id
                or app.get("appId") != management.client_id
                or app.get("signInAudience") != "AzureADMyOrg"
                or (app.get("web") or {}).get("redirectUris") !=
                   [context.management_origin + "/.auth/login/aad/callback"]
                or ((app.get("web") or {}).get("implicitGrantSettings") or {}).get("enableIdTokenIssuance") is not True
                or ((app.get("web") or {}).get("implicitGrantSettings") or {}).get("enableAccessTokenIssuance") is not False
                or requested_graph_roles != {(value, "Role") for value in GRAPH_ROLES.values()}
                or len(requested[0]["resourceAccess"]) != len(GRAPH_ROLES)):
            raise BootstrapError(502, "BootstrapGraphBindingMismatch")

    def grant_management_permissions(self, context: BootstrapContext, management: Application,
                                     permissions: tuple[str, ...]) -> None:
        self.verify_administrator(context)
        if permissions != GRAPH_PERMISSIONS:
            raise BootstrapError(403, "BootstrapGraphPermissionMismatch")
        self._verify_management(context, management)
        graph_id = self._graph_principal()
        for name in permissions:
            self._request("POST", "/servicePrincipals/" + management.principal_id + "/appRoleAssignments", {
                "principalId": management.principal_id,
                "resourceId": graph_id,
                "appRoleId": GRAPH_ROLES[name],
            })

    def verify_management_permissions(self, context: BootstrapContext, management: Application,
                                      permissions: tuple[str, ...]) -> None:
        self.verify_administrator(context)
        if permissions != GRAPH_PERMISSIONS:
            raise BootstrapError(403, "BootstrapGraphPermissionMismatch")
        self._verify_management(context, management)
        graph_id = self._graph_principal()
        result = self._request(
            "GET", "/servicePrincipals/" + management.principal_id + "/appRoleAssignments",
            params={"$select": "principalId,resourceId,appRoleId"},
        )
        assignments = result.get("value")
        if not isinstance(assignments, list):
            raise BootstrapError(502, "BootstrapGraphBindingMismatch")
        expected = {(management.principal_id, graph_id, GRAPH_ROLES[name]) for name in permissions}
        actual = {(item.get("principalId"), item.get("resourceId"), item.get("appRoleId"))
                  for item in assignments}
        if actual != expected or len(assignments) != len(expected):
            raise BootstrapError(502, "BootstrapGraphPermissionMismatch")

    def add_management_credential(self, context: BootstrapContext, management: Application,
                                  expires_at: str) -> ManagementCredential:
        self.verify_administrator(context)
        self._verify_management(context, management)
        result = self._request("POST", "/applications/" + management.object_id + "/addPassword", {
            "passwordCredential": {"displayName": "faas-management-bootstrap",
                                   "endDateTime": expires_at},
        })
        try:
            actual = datetime.fromisoformat(result["endDateTime"].replace("Z", "+00:00"))
            expected = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
            if actual != expected:
                raise ValueError("Credential expiry mismatch")
            return ManagementCredential(canonical_guid(result["keyId"]), result["secretText"], expires_at)
        except (KeyError, ValueError, TypeError):
            raise BootstrapError(502, "BootstrapGraphCredentialInvalid") from None

    def close(self) -> None:
        self.client.close()
