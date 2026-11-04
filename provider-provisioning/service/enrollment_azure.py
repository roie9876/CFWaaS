"""Provider-tenant-only adapters. No ARM calls and no Azure RBAC grants.

The management app requires Application.ReadWrite.OwnedBy,
Application.Read.All and AppRoleAssignment.ReadWrite.All (admin consent).
Its credential is separate from every customer API credential. Explicit,
reconciled service-principal and role-assignment denials may be retried; ambiguous
writes, including timeouts, are never retried or reconciled by display name.
Application uniqueName is documented as immutable/read-only, not a
verified create-only input, so it is deliberately not used for reconciliation:
https://learn.microsoft.com/en-us/graph/api/resources/application?view=graph-rest-1.0
"""

from dataclasses import dataclass, field
from datetime import datetime
import time
from typing import Any
from uuid import UUID

import httpx
from azure.identity import AzureAuthorityHosts, ClientSecretCredential
from azure.keyvault.secrets import SecretClient

from .enrollment import (
    ApplicationIdentity, Credential, CustomerBinding, EnrollmentError,
    VaultReference, canonical_guid,
)

GRAPH_ORIGIN = "https://graph.microsoft.com"
GRAPH_SCOPE = GRAPH_ORIGIN + "/.default"
API_ROLE = "FirewallDeployment.Request"


@dataclass(frozen=True)
class GraphSettings:
    provider_tenant: str
    management_client_id: str
    management_principal_id: str
    management_secret: str = field(repr=False)
    provider_api_client_id: str
    provider_api_principal_id: str
    provider_role_id: str

    def __post_init__(self) -> None:
        identifiers = (
            self.provider_tenant, self.management_client_id, self.management_principal_id,
            self.provider_api_client_id, self.provider_api_principal_id, self.provider_role_id,
        )
        for value in identifiers:
            canonical_guid(value)
            if UUID(value).int == 0:
                raise ValueError("Invalid Graph configuration")
        if (not self.management_secret
                or self.management_client_id == self.provider_api_client_id
                or self.management_principal_id == self.provider_api_principal_id):
            raise ValueError("Management and API identities must be separate")

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.provider_tenant}/v2.0"


class GraphDirectory:
    def __init__(self, settings: GraphSettings) -> None:
        self.settings = settings
        self.credential = ClientSecretCredential(
            settings.provider_tenant, settings.management_client_id,
            settings.management_secret, authority=AzureAuthorityHosts.AZURE_PUBLIC_CLOUD,
            logging_enable=False, retry_total=0, connection_timeout=5, read_timeout=20,
        )
        self.client = httpx.Client(
            timeout=httpx.Timeout(20, connect=5), follow_redirects=False,
            transport=httpx.HTTPTransport(retries=0),
        )

    def _request(self, method: str, path: str, body: dict | None = None,
                 *, missing_ok: bool = False, retry_not_found: bool = False,
                 diagnostic_operation: str = "") -> dict[str, Any]:
        # Paths are constructed exclusively below, never from Graph/token response URLs.
        if (not path.startswith("/") or "://" in path or path.startswith("//")
                or (retry_not_found and method != "GET")):
            raise EnrollmentError(502, "GraphRequestRejected")
        try:
            deadline, delay = time.monotonic() + 30, 1
            while True:
                token = self.credential.get_token(GRAPH_SCOPE)
                response = self.client.request(
                    method, GRAPH_ORIGIN + "/v1.0" + path,
                    headers={"Authorization": "Bearer " + token.token},
                    json=body,
                )
                if response.status_code == 404 and retry_not_found:
                    remaining = deadline - time.monotonic()
                    if remaining > 0:
                        time.sleep(min(delay, remaining))
                        delay = min(delay * 2, 8)
                        continue
                if missing_ok and method == "GET" and response.status_code == 404:
                    raise EnrollmentError(404, "GraphResourceNotFound")
                if response.status_code not in (200, 201, 204):
                    reason = ""
                    try:
                        document = response.json()
                        if isinstance(document, dict) and isinstance(document.get("error"), dict):
                            candidate = document["error"].get("code")
                            if candidate in {"Authorization_RequestDenied", "Request_BadRequest",
                                             "Request_ResourceNotFound", "Authentication_RequestFromUnsupportedUserRole",
                                             "AccessDenied", "Forbidden", "InsufficientPrivileges"}:
                                reason = candidate
                    except (TypeError, ValueError):
                        pass
                    raise EnrollmentError(502, "GraphRequestFailed", response.status_code,
                                          diagnostic_operation, reason)
                result = {} if response.status_code == 204 else response.json()
                if not isinstance(result, dict) or "@odata.nextLink" in result:
                    raise ValueError()
                return result
        except EnrollmentError:
            raise
        except Exception:
            raise EnrollmentError(502, "GraphRequestFailed") from None

    @staticmethod
    def _id(value: str) -> str:
        try:
            return canonical_guid(value)
        except (ValueError, TypeError, AttributeError):
            raise EnrollmentError(502, "GraphIdentityInvalid") from None

    def _provider(self) -> None:
        s = self.settings
        management = self._request(
            "GET", f"/servicePrincipals/{s.management_principal_id}"
            "?$select=id,appId,appOwnerOrganizationId")
        api = self._request(
            "GET", f"/servicePrincipals/{s.provider_api_principal_id}"
            "?$select=id,appId,appOwnerOrganizationId,appRoles")
        role = next((role for role in api.get("appRoles", [])
                     if role.get("id") == s.provider_role_id), None)
        if (management.get("id") != s.management_principal_id
                or management.get("appId") != s.management_client_id
                or management.get("appOwnerOrganizationId") != s.provider_tenant
                or api.get("id") != s.provider_api_principal_id
                or api.get("appId") != s.provider_api_client_id
                or api.get("appOwnerOrganizationId") != s.provider_tenant
                or not role or role.get("value") != API_ROLE
                or role.get("isEnabled") is not True
                or role.get("allowedMemberTypes") != ["Application"]):
            raise EnrollmentError(502, "GraphProviderBindingMismatch")

    def _owners(self) -> list[str]:
        return [GRAPH_ORIGIN + "/v1.0/servicePrincipals/"
                + self.settings.management_principal_id]

    def create_application(self, customer_id: str) -> ApplicationIdentity:
        customer_id = self._id(customer_id)
        self._provider()
        result = self._request("POST", "/applications", {
            "displayName": "faas-customer-" + customer_id,
            "signInAudience": "AzureADMyOrg",
            "tags": ["faas-customer:" + customer_id],
            "owners@odata.bind": self._owners(),
            "requiredResourceAccess": [{
                "resourceAppId": self.settings.provider_api_client_id,
                "resourceAccess": [{"id": self.settings.provider_role_id, "type": "Role"}],
            }],
        })
        return ApplicationIdentity(self._id(result.get("id")), self._id(result.get("appId")))

    def create_principal(self, client_id: str) -> str:
        client_id = self._id(client_id)
        if client_id in (self.settings.management_client_id, self.settings.provider_api_client_id):
            raise EnrollmentError(502, "GraphIdentityInvalid")
        app = self._request("GET", f"/applications(appId='{client_id}')?$select=id,appId",
                            retry_not_found=True, diagnostic_operation="ReadNewApplication")
        if app.get("appId") != client_id or not app.get("id"):
            raise EnrollmentError(502, "GraphBindingMismatch")
        application_id = self._id(app["id"])
        deadline, delay = time.monotonic() + 45, 2
        while True:
            try:
                result = self._request("POST", "/servicePrincipals", {
                    "appId": client_id, "accountEnabled": False,
                    "appRoleAssignmentRequired": True, "owners@odata.bind": self._owners(),
                }, diagnostic_operation="CreateServicePrincipal")
                return self._id(result.get("id"))
            except EnrollmentError as error:
                if (error.code != "GraphRequestFailed" or error.dependency_status != 403
                        or error.dependency_reason != "Authorization_RequestDenied"
                        or time.monotonic() >= deadline):
                    raise
                owners = self._request("GET", f"/applications/{application_id}/owners?$select=id",
                                       retry_not_found=True)
                if self.settings.management_principal_id not in [
                        item.get("id") for item in owners.get("value", [])]:
                    raise EnrollmentError(502, "GraphBindingMismatch")
                try:
                    self._request("GET", f"/servicePrincipals(appId='{client_id}')?$select=id,appId",
                                  missing_ok=True)
                except EnrollmentError as lookup:
                    if lookup.status != 404 or lookup.code != "GraphResourceNotFound":
                        raise
                else:
                    raise EnrollmentError(409, "PrincipalCreationUncertain")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(delay, remaining))
                delay = min(delay * 2, 15)
                if time.monotonic() >= deadline:
                    raise

    def find_principal(self, client_id: str) -> str | None:
        client_id = self._id(client_id)
        try:
            result = self._request(
                "GET", f"/servicePrincipals(appId='{client_id}')?$select=id,appId",
                missing_ok=True, retry_not_found=True)
        except EnrollmentError as exc:
            if exc.status == 404 and exc.code == "GraphResourceNotFound":
                return None
            raise
        if result.get("appId") != client_id:
            raise EnrollmentError(502, "GraphBindingMismatch")
        return self._id(result.get("id"))

    def verify_application(self, customer_id: str, application: ApplicationIdentity) -> None:
        application_id = self._id(application.object_id)
        client_id, customer_id = self._id(application.client_id), self._id(customer_id)
        self._provider()
        if client_id in (self.settings.management_client_id, self.settings.provider_api_client_id):
            raise EnrollmentError(502, "GraphBindingMismatch")
        app = self._request(
            "GET", f"/applications/{application_id}"
            "?$select=id,appId,displayName,tags,signInAudience,requiredResourceAccess",
            retry_not_found=True)
        owners = self._request("GET", f"/applications/{application_id}/owners?$select=id",
                               retry_not_found=True)
        expected_access = [{
            "resourceAppId": self.settings.provider_api_client_id,
            "resourceAccess": [{"id": self.settings.provider_role_id, "type": "Role"}],
        }]
        if (app.get("id") != application_id or app.get("appId") != client_id
                or app.get("displayName") != "faas-customer-" + customer_id
                or app.get("tags") != ["faas-customer:" + customer_id]
                or app.get("signInAudience") != "AzureADMyOrg"
                or app.get("requiredResourceAccess") != expected_access
                or self.settings.management_principal_id not in
                [item.get("id") for item in owners.get("value", [])]):
            raise EnrollmentError(502, "GraphBindingMismatch")

    def verify(self, binding: CustomerBinding, application_id: str) -> None:
        application_id = self._id(application_id)
        client_id, principal_id = self._id(binding.client), self._id(binding.principal)
        self.verify_application(binding.customer_id, ApplicationIdentity(application_id, client_id))
        if principal_id in (self.settings.management_principal_id,
                            self.settings.provider_api_principal_id):
            raise EnrollmentError(502, "GraphBindingMismatch")
        principal = self._request(
            "GET", f"/servicePrincipals/{principal_id}"
            "?$select=id,appId,appOwnerOrganizationId", retry_not_found=True)
        principal_owners = self._request(
            "GET", f"/servicePrincipals/{principal_id}/owners?$select=id", retry_not_found=True)
        assignments = self._assignments(principal_id)
        if (principal.get("id") != principal_id
                or principal.get("appId") != client_id
                or principal.get("appOwnerOrganizationId") != self.settings.provider_tenant
                or self.settings.management_principal_id not in
                [item.get("id") for item in principal_owners.get("value", [])]
                or any(item.get("resourceId") != self.settings.provider_api_principal_id
                       or item.get("appRoleId") != self.settings.provider_role_id
                       or item.get("principalId") != principal_id
                       for item in assignments)):
            raise EnrollmentError(502, "GraphBindingMismatch")

    def grant_role(self, principal_id: str) -> None:
        principal_id = self._id(principal_id)
        self._provider()
        expected = {"principalId": principal_id, "resourceId": self.settings.provider_api_principal_id,
                    "appRoleId": self.settings.provider_role_id}
        deadline, delay = time.monotonic() + 45, 2
        while True:
            try:
                self._request("POST", f"/servicePrincipals/{principal_id}/appRoleAssignments", expected)
                return
            except EnrollmentError as error:
                if (error.code != "GraphRequestFailed" or error.dependency_status != 404
                        or error.dependency_reason != "Request_ResourceNotFound"
                        or time.monotonic() >= deadline):
                    raise
                assignments = self._assignments(principal_id)
                if (len(assignments) > 1
                        or any({key: item.get(key) for key in expected} != expected for item in assignments)):
                    raise EnrollmentError(502, "GraphBindingMismatch")
                if assignments:
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(delay, remaining))
                delay = min(delay * 2, 15)
                if time.monotonic() >= deadline:
                    raise

    def _assignments(self, principal_id: str) -> list[dict]:
        result = self._request(
            "GET", f"/servicePrincipals/{self._id(principal_id)}/appRoleAssignments"
            "?$select=resourceId,appRoleId,principalId", retry_not_found=True)
        if not isinstance(result.get("value"), list):
            raise EnrollmentError(502, "GraphBindingMismatch")
        return result["value"]

    def ensure_role(self, principal_id: str) -> None:
        principal_id = self._id(principal_id)
        self._provider()
        assignments = self._assignments(principal_id)
        if any(item.get("resourceId") != self.settings.provider_api_principal_id
               or item.get("appRoleId") != self.settings.provider_role_id
               or item.get("principalId") != principal_id for item in assignments):
            raise EnrollmentError(502, "GraphBindingMismatch")
        if not assignments:
            self.grant_role(principal_id)

    def password_keys(self, application_id: str, customer_id: str) -> list[str]:
        application_id, customer_id = self._id(application_id), self._id(customer_id)
        result = self._request(
            "GET", f"/applications/{application_id}?$select=id,passwordCredentials")
        if result.get("id") != application_id or not isinstance(
                result.get("passwordCredentials"), list):
            raise EnrollmentError(502, "GraphBindingMismatch")
        prefix = f"faas-enrollment:{customer_id}:"
        keys = []
        for credential in result["passwordCredentials"]:
            marker = credential.get("displayName")
            if isinstance(marker, str) and marker.startswith(prefix):
                suffix = marker.removeprefix(prefix)
                if len(suffix) == 64 and all(char in "0123456789abcdef" for char in suffix):
                    keys.append(self._id(credential.get("keyId")))
        if len(keys) > 100 or len(keys) != len(set(keys)):
            raise EnrollmentError(502, "GraphPasswordListInvalid")
        return keys

    def add_password(self, application_id: str, expires_at: str, marker: str) -> Credential:
        application_id = self._id(application_id)
        try:
            prefix, customer_id, suffix = marker.split(":")
            self._id(customer_id)
            if (prefix != "faas-enrollment" or len(suffix) != 64
                    or any(char not in "0123456789abcdef" for char in suffix)):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise EnrollmentError(502, "GraphPasswordMarkerInvalid") from None
        result = self._request("POST", f"/applications/{application_id}/addPassword", {
            "passwordCredential": {"displayName": marker, "endDateTime": expires_at},
        })
        secret = result.get("secretText")
        try:
            if (not isinstance(secret, str) or not secret
                    or datetime.fromisoformat(result["endDateTime"].replace("Z", "+00:00"))
                    != datetime.fromisoformat(expires_at)):
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise EnrollmentError(502, "GraphCredentialInvalid") from None
        return Credential(self._id(result.get("keyId")), secret, expires_at)

    def remove_password(self, application_id: str, key_id: str) -> None:
        application_id, key_id = self._id(application_id), self._id(key_id)
        deadline = time.monotonic() + 30
        for attempt in range(4):
            try:
                self._request("POST", f"/applications/{application_id}/removePassword",
                              {"keyId": key_id})
                return
            except EnrollmentError as error:
                if error.code != "GraphRequestFailed" or error.dependency_status != 409:
                    raise
                if time.monotonic() >= deadline:
                    raise
                application = self._request(
                    "GET", f"/applications/{application_id}?$select=id,passwordCredentials")
                credentials = application.get("passwordCredentials")
                if (application.get("id") != application_id or not isinstance(credentials, list)
                        or any(not isinstance(item, dict) for item in credentials)):
                    raise EnrollmentError(502, "GraphBindingMismatch") from None
                if key_id not in [self._id(item.get("keyId")) for item in credentials]:
                    return
                delay = 2 ** attempt
                if attempt == 3 or time.monotonic() + delay >= deadline:
                    raise
                time.sleep(delay)

    def set_enabled(self, principal_id: str, enabled: bool) -> None:
        self._request("PATCH", f"/servicePrincipals/{self._id(principal_id)}",
                      {"accountEnabled": enabled})

    def close(self) -> None:
        try:
            self.client.close()
        finally:
            self.credential.close()


class EnrollmentVault:
    """Only enrollment-owned names; the caller owns/closes the borrowed client."""

    def __init__(self, client: SecretClient) -> None:
        self.client = client

    @staticmethod
    def _name(customer_id: str) -> str:
        try:
            return "customer-" + canonical_guid(customer_id)
        except (ValueError, TypeError, AttributeError):
            raise EnrollmentError(502, "VaultNameInvalid") from None

    def write(self, customer_id: str, secret: str, expires: str) -> VaultReference:
        name = self._name(customer_id)
        try:
            result = self.client.set_secret(
                name, secret, expires_on=datetime.fromisoformat(expires),
                content_type="application/x-faas-client-secret",
                logging_enable=False, retry_total=0,
            )
            if result.name != name or not result.properties.version:
                raise ValueError()
            return {"name": name, "version": result.properties.version}
        except Exception:
            raise EnrollmentError(502, "VaultWriteFailed") from None

    def read(self, name: str, version: str) -> str:
        if not isinstance(name, str) or not name.startswith("customer-"):
            raise EnrollmentError(502, "VaultNameInvalid")
        self._name(name.removeprefix("customer-"))
        if (not isinstance(version, str) or len(version) != 32
                or any(char not in "0123456789abcdef" for char in version)):
            raise EnrollmentError(502, "VaultVersionInvalid")
        try:
            value = self.client.get_secret(
                name, version, logging_enable=False, retry_total=0).value
            if not value:
                raise ValueError()
            return value
        except Exception:
            raise EnrollmentError(502, "VaultReadFailed") from None
