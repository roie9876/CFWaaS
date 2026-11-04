import base64
import hashlib
import json
import logging
import os
import re
import threading
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID

import httpx
from azure.identity import ClientSecretCredential, ManagedIdentityCredential
from azure.core.exceptions import ClientAuthenticationError
from azure.keyvault.secrets import SecretClient
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse

from .auth import TrustedKeys
from .azure_data import TableBackend
from .config import endpoint, uuid_text
from .decommission import EnvironmentDecommissions
from .connection_details import CheckpointAccess, ConnectionDetails
from .enrollment import (EnrollmentError, EnrollmentRegistry, EnrollmentRequest,
                         EnrollmentService, RotationRequest)
from .enrollment_azure import EnrollmentVault, GraphDirectory, GraphSettings
from .management_auth import Administrator, ManagementAuthenticator, ProviderRelayAuthenticator
from .models import RoutingAddress
from .admin_access import normalize_admin_sources
from .profiles import ProfilePublisher

logger = logging.getLogger("faas.management")


@dataclass(frozen=True)
class ManagementSettings:
    tenant: str
    client_id: str
    secret: str = field(repr=False)
    administrators: frozenset[str]
    origin: str
    table_endpoint: str
    vault_url: str
    artifact_url: str
    api_url: str
    api_application: str
    api_role: str
    admin_allowed_sources: list[str] = field(default_factory=list)
    checkpoint_relay_client_id: str = ""
    checkpoint_relay_principal_id: str = ""
    checkpoint_relay_identity_id: str = ""

    @classmethod
    def from_env(cls) -> "ManagementSettings":
        administrators = json.loads(os.environ["FAAS_ADMIN_OBJECT_IDS"])
        if not isinstance(administrators, list) or not 1 <= len(administrators) <= 50:
            raise ValueError("An explicit administrator allowlist is required")
        secret = os.environ["FAAS_MANAGEMENT_CLIENT_SECRET"]
        if not secret or secret.startswith("@Microsoft.KeyVault("):
            raise ValueError("Management credential is unavailable")
        return cls(
            uuid_text(os.environ["FAAS_MANAGEMENT_TENANT_ID"]),
            uuid_text(os.environ["FAAS_MANAGEMENT_CLIENT_ID"]),
            secret,
            frozenset(uuid_text(value) for value in administrators),
            endpoint(os.environ["FAAS_MANAGEMENT_ORIGIN"], ".azurewebsites.net"),
            endpoint(os.environ["FAAS_TABLE_ENDPOINT"], ".table.core.windows.net"),
            endpoint(os.environ["FAAS_MANAGEMENT_VAULT_URL"], ".vault.azure.net"),
            endpoint(os.environ["FAAS_ARTIFACT_ACCOUNT_URL"], ".blob.core.windows.net"),
            endpoint(os.environ["FAAS_API_URL"], ".azurewebsites.net"),
            uuid_text(os.environ["FAAS_API_APPLICATION_ID"]),
            uuid_text(os.environ["FAAS_API_ROLE_ID"]),
            normalize_admin_sources(json.loads(os.getenv("FAAS_ADMIN_ALLOWED_SOURCES", "[]"))),
            os.getenv("FAAS_CHECKPOINT_RELAY_CLIENT_ID", ""),
            os.getenv("FAAS_CHECKPOINT_RELAY_PRINCIPAL_ID", ""),
            os.getenv("FAAS_CHECKPOINT_RELAY_IDENTITY_ID", ""),
        )


def directory_settings(settings: ManagementSettings) -> GraphSettings:
    credential = ClientSecretCredential(settings.tenant, settings.client_id, settings.secret,
                                        logging_enable=False)
    try:
        token = credential.get_token("https://graph.microsoft.com/.default").token
        identities = []
        with httpx.Client(timeout=15, follow_redirects=False, trust_env=False) as client:
            for app in (settings.client_id, settings.api_application):
                response = client.get(
                    "https://graph.microsoft.com/v1.0/servicePrincipals",
                    params={"$filter": f"appId eq '{app}'", "$select": "id,appId"},
                    headers={"Authorization": "Bearer " + token},
                )
                response.raise_for_status()
                document = response.json()
                records = document.get("value", [])
                if (document.get("@odata.nextLink") or len(records) != 1
                        or records[0].get("appId") != app):
                    raise EnrollmentError(503, "ProviderIdentitySetupRequired")
                identities.append(uuid_text(records[0]["id"]))
            response = client.get(
                "https://graph.microsoft.com/v1.0/applications",
                params={"$filter": f"appId eq '{settings.api_application}'",
                        "$select": "appId,api,optionalClaims,identifierUris"},
                headers={"Authorization": "Bearer " + token},
            )
            response.raise_for_status()
            applications = response.json()
            records = applications.get("value", [])
            if applications.get("@odata.nextLink") or len(records) != 1:
                raise EnrollmentError(503, "ProviderApiSetupRequired")
            api = records[0]
            optional = (api.get("optionalClaims") or {}).get("accessToken") or []
            if (api.get("appId") != settings.api_application
                    or (api.get("api") or {}).get("requestedAccessTokenVersion") != 2
                    or "api://" + settings.api_application not in (api.get("identifierUris") or [])
                    or not any(claim.get("name") == "idtyp" for claim in optional)):
                raise EnrollmentError(503, "ProviderApiTokenConfigurationRequired")
        return GraphSettings(
            provider_tenant=settings.tenant, management_client_id=settings.client_id,
            management_principal_id=identities[0], management_secret=settings.secret,
            provider_api_client_id=settings.api_application,
            provider_api_principal_id=identities[1], provider_role_id=settings.api_role,
        )
    except ClientAuthenticationError:
        raise EnrollmentError(503, "ProviderManagementCredentialUnavailable") from None
    except httpx.HTTPStatusError:
        raise EnrollmentError(503, "ProviderGraphConsentOrPermissionRequired") from None
    finally:
        credential.close()


def create_app(service: EnrollmentService | None = None,
               authenticator: ManagementAuthenticator | None = None,
               decommissions: EnvironmentDecommissions | None = None,
               connection_details: ConnectionDetails | None = None,
               relay_authenticator: ProviderRelayAuthenticator | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if service is not None:
            if authenticator is None:
                raise ValueError("Test services require an explicit authenticator")
            app.state.service, app.state.auth = service, authenticator
            app.state.registry = service.registry
            app.state.decommissions = decommissions
            app.state.connection_details = connection_details
            app.state.relay_auth = relay_authenticator
            app.state.service_lock = threading.Lock()
            yield
            return
        configured = ManagementSettings.from_env()
        identity = ManagedIdentityCredential(logging_enable=False)
        backend = TableBackend(configured.table_endpoint, identity, "Customers")
        operations = TableBackend(configured.table_endpoint, identity, "Operations")
        secrets = SecretClient(configured.vault_url, identity, logging_enable=False,
                               retry_total=2, connection_timeout=5, read_timeout=20)
        keys = TrustedKeys(configured.tenant)
        registry = EnrollmentRegistry(backend)
        resources = []
        app.state.service = None
        app.state.registry = registry
        app.state.decommissions = EnvironmentDecommissions(registry, operations, configured.tenant)
        app.state.connection_details = ConnectionDetails(app.state.decommissions, secrets)
        relay = (configured.checkpoint_relay_client_id, configured.checkpoint_relay_principal_id,
                 configured.checkpoint_relay_identity_id)
        if any(relay) and not all(relay):
            raise ValueError("Incomplete Check Point relay identity")
        app.state.relay_auth = (ProviderRelayAuthenticator(
            configured.tenant, configured.api_application, *relay, keys) if all(relay) else None)
        app.state.service_lock = threading.Lock()
        def initialize():
            graph = GraphDirectory(directory_settings(configured))
            try:
                publisher = ProfilePublisher(identity, configured.artifact_url, configured.api_url,
                                             "api://" + configured.api_application, configured.tenant,
                                             admin_allowed_sources=configured.admin_allowed_sources)
            except Exception:
                graph.close()
                raise
            resources.extend([graph, publisher])
            return EnrollmentService(registry, graph, EnrollmentVault(secrets), publisher)
        app.state.initialize = initialize
        app.state.auth = ManagementAuthenticator(configured.tenant, configured.client_id,
                                               set(configured.administrators), configured.origin, keys)
        try:
            yield
        finally:
            for resource in reversed(resources):
                resource.close()
            keys.close()
            secrets.close()
            operations.close()
            backend.close()
            identity.close()

    app = FastAPI(title="FaaS Provider Administration", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    logging.getLogger("azure").setLevel(logging.WARNING)

    def administrator(request: Request) -> Administrator:
        return app.state.auth.authenticate(request)

    def enrollment_service() -> EnrollmentService:
        with app.state.service_lock:
            if app.state.service is None:
                app.state.service = app.state.initialize()
            return app.state.service

    @app.middleware("http")
    async def protected_responses(request: Request, call_next):
        try:
            response = await call_next(request)
        except Exception as error:
            logger.error("code=ManagementDependencyUnavailable type=%s", type(error).__name__)
            response = JSONResponse({"detail": "ManagementDependencyUnavailable"}, status_code=503)
        response.headers.update({
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        })
        return response

    @app.exception_handler(EnrollmentError)
    async def enrollment_error(request, error: EnrollmentError):
        return JSONResponse({"detail": error.code}, status_code=error.status)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, error):
        return JSONResponse({"detail": "InvalidRequest"}, status_code=422)

    @app.exception_handler(Exception)
    async def dependency_error(request, error):
        logger.error("code=ManagementDependencyUnavailable type=%s", type(error).__name__)
        return JSONResponse({"detail": "ManagementDependencyUnavailable"}, status_code=503)

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def console(request: Request):
        try:
            administrator(request)
        except HTTPException as error:
            if error.status_code != 401 or error.detail != "AdministratorSignInRequired":
                raise
            return HTMLResponse(
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                "<title>Provider sign-in required</title></head><body>"
                "<h1>Sign in again</h1><p>Your provider administrator session is missing or expired.</p>"
                "<p><a href=\"/.auth/login/aad?post_login_redirect_uri=%2F\">"
                "Sign in to provider administration</a></p></body></html>",
                status_code=401,
                headers={"Content-Security-Policy":
                         "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"},
            )
        html = (Path(__file__).parent / "static/management.html").read_text()
        hashes = ["'sha256-" + base64.b64encode(hashlib.sha256(code.encode()).digest()).decode() + "'"
                  for code in re.findall(r"<script>(.*?)</script>", html, re.DOTALL)]
        return HTMLResponse(html, headers={
            "Content-Security-Policy": "default-src 'self'; script-src " + " ".join(hashes)
                + "; style-src 'self' 'unsafe-inline'; connect-src 'self'; "
                  "frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'",
        })

    @app.get("/admin/session")
    def session(admin: Administrator = Depends(administrator)):
        return {"name": admin.name, "objectId": admin.oid}

    @app.get("/admin/readiness")
    def readiness(admin: Administrator = Depends(administrator)):
        app.state.registry.list_customers()
        enrollment_service()
        return {"status": "Registry and Graph identity/API configuration verified. Credential-write permissions and artifact publishing are tested during onboarding."}

    @app.get("/admin/customers")
    def customers(admin: Administrator = Depends(administrator)):
        return {"customers": app.state.registry.list_customers()}

    @app.post("/admin/customers")
    def onboard(body: EnrollmentRequest, admin: Administrator = Depends(administrator),
                key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128)):
        return enrollment_service().onboard(body, admin.oid, key)

    def customer_id(value: str) -> str:
        try:
            return str(UUID(value))
        except ValueError:
            raise HTTPException(422, "InvalidCustomerId") from None

    @app.post("/admin/customers/{identifier}/rotate")
    def rotate(identifier: str, body: RotationRequest | None = None,
               admin: Administrator = Depends(administrator),
               key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128)):
        return enrollment_service().rotate(
            customer_id(identifier), admin.oid, key, body.credentialHours if body else None)

    @app.post("/admin/customers/{identifier}/revoke")
    def revoke(identifier: str, admin: Administrator = Depends(administrator),
               key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128)):
        return enrollment_service().revoke(customer_id(identifier), admin.oid, key)

    @app.post("/admin/customers/{identifier}/archive")
    def archive(identifier: str, admin: Administrator = Depends(administrator),
                key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128)):
        return enrollment_service().archive(customer_id(identifier), admin.oid, key)

    @app.post("/admin/customers/{identifier}/recover")
    def recover(identifier: str, admin: Administrator = Depends(administrator),
                key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128)):
        return enrollment_service().recover(customer_id(identifier), admin.oid, key)

    @app.post("/admin/customers/{identifier}/reveal")
    def reveal(identifier: str, admin: Administrator = Depends(administrator)):
        identifier = customer_id(identifier)
        result = enrollment_service().reveal(identifier, admin.oid)
        if app.state.connection_details is not None:
            result["connectionDetails"] = app.state.connection_details.reveal(identifier, admin.oid)
        return result

    @app.post("/admin/customers/{identifier}/environments/{environment}/routing")
    def register_customer_routing(identifier: str, environment: UUID, body: RoutingAddress,
                                  admin: Administrator = Depends(administrator)):
        if app.state.connection_details is None:
            raise EnrollmentError(503, "ConnectionDetailsUnavailable")
        return app.state.connection_details.register_routing(
            customer_id(identifier), str(environment), body, admin.oid)

    @app.post("/internal/checkpoint-access")
    def publish_checkpoint_access(body: CheckpointAccess, request: Request):
        if app.state.relay_auth is None or app.state.connection_details is None:
            raise EnrollmentError(503, "ProviderRelayUnavailable")
        actor = app.state.relay_auth.authenticate(request)
        return app.state.connection_details.publish(body, actor)

    @app.post("/admin/customers/{identifier}/deployment")
    def deployment(identifier: str, admin: Administrator = Depends(administrator)):
        return enrollment_service().deployment(customer_id(identifier), admin.oid)

    def decommission_service() -> EnvironmentDecommissions:
        if app.state.decommissions is None:
            raise EnrollmentError(503, "DecommissionUnavailable")
        return app.state.decommissions

    @app.get("/admin/customers/{identifier}/environments")
    def environments(identifier: str, admin: Administrator = Depends(administrator)):
        return {"environments": decommission_service().environments(customer_id(identifier))}

    @app.post("/admin/customers/{identifier}/environments/{environment}/decommission")
    def decommission(identifier: str, environment: str, admin: Administrator = Depends(administrator),
                     key: str = Header(alias="Idempotency-Key", min_length=1, max_length=128)):
        try:
            environment_id = str(UUID(environment))
        except ValueError:
            raise HTTPException(422, "InvalidEnvironmentId") from None
        return decommission_service().request(customer_id(identifier), environment_id, admin.oid)

    return app


app = create_app()
