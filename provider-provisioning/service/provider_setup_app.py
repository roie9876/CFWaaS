"""Provider setup UI. This app is separate from the public provisioning API."""
import hashlib
import logging
import os
import re
import threading
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.concurrency import run_in_threadpool

from .auth import TrustedKeys
from .azure_data import TableBackend
from .config import endpoint
from .provider_bootstrap import BootstrapContext, BootstrapError, ProviderBootstrap, canonical_guid
from .provider_bootstrap_auth import msal_public_client_factory
from .provider_bootstrap_graph import DelegatedSession, ProviderBootstrapGraph
from .provider_bootstrap_release import BootstrapReleasePublisher
from .provider_bootstrap_vault import ProviderBootstrapVault
from .provider_device_auth import DevicePending, ProviderDeviceAuth

logger = logging.getLogger("faas.provider-setup")
COOKIE = "__Host-faas-setup"


@dataclass(frozen=True)
class SetupSettings:
    tenant_id: str
    subscription_id: str
    client_id: str
    administrator_id: str
    origin: str
    management_origin: str
    table_endpoint: str
    vault_url: str
    release_account_url: str
    release_group: str
    vault_name: str
    vault_group: str
    package_uri: str
    package_sha256: str
    template_sha256: str

    def __post_init__(self) -> None:
        for value in (self.tenant_id, self.subscription_id, self.client_id, self.administrator_id):
            canonical_guid(value)

    @classmethod
    def from_env(cls) -> "SetupSettings":
        environment = os.environ
        return cls(
            canonical_guid(environment["FAAS_SETUP_TENANT_ID"]),
            canonical_guid(environment["FAAS_SETUP_SUBSCRIPTION_ID"]),
            canonical_guid(environment["FAAS_SETUP_CLIENT_ID"]),
            canonical_guid(environment["FAAS_SETUP_ADMINISTRATOR_ID"]),
            endpoint(environment["FAAS_SETUP_ORIGIN"], ".azurewebsites.net"),
            endpoint(environment["FAAS_SETUP_MANAGEMENT_ORIGIN"], ".azurewebsites.net"),
            endpoint(environment["FAAS_SETUP_TABLE_ENDPOINT"], ".table.core.windows.net"),
            endpoint(environment["FAAS_SETUP_VAULT_URL"], ".vault.azure.net"),
            endpoint(environment["FAAS_SETUP_RELEASE_ACCOUNT_URL"], ".blob.core.windows.net"),
            environment["FAAS_SETUP_RELEASE_GROUP"],
            environment["FAAS_SETUP_VAULT_NAME"],
            environment["FAAS_SETUP_VAULT_GROUP"],
            environment["FAAS_SETUP_PACKAGE_URI"],
            environment["FAAS_SETUP_PACKAGE_SHA256"],
            environment["FAAS_SETUP_TEMPLATE_SHA256"],
        )


class CreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    confirmGraphPermissions: bool


class SetupSessions:
    """Short-lived Graph tokens are held only in this process, never in cookies."""

    def __init__(self) -> None:
        self._active: dict[str, tuple[float, object]] = {}
        self._lock = threading.Lock()

    def add(self, session_id: str, administrator) -> None:
        now = time.monotonic()
        with self._lock:
            self._active = {key: value for key, value in self._active.items() if value[0] > now}
            if len(self._active) >= 100:
                raise BootstrapError(429, "BootstrapSessionCapacityExceeded")
            self._active[session_id] = (now + 300, administrator)

    def consume(self, session_id: str):
        with self._lock:
            entry = self._active.pop(session_id, None)
        if entry is None or entry[0] <= time.monotonic():
            raise BootstrapError(401, "BootstrapSignInExpired")
        return entry[1]


def create_app(settings: SetupSettings | None = None, device=None, backend=None, vault=None,
               publisher=None, graph_factory=ProviderBootstrapGraph) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        owned = settings is None
        configured = SetupSettings.from_env() if owned else settings
        identity = keys = state = secret_client = release = None
        if owned:
            identity = ManagedIdentityCredential(logging_enable=False)
            keys = TrustedKeys(configured.tenant_id)
            state = TableBackend(configured.table_endpoint, identity, "Bootstrap")
            secret_client = SecretClient(configured.vault_url, identity, logging_enable=False,
                                         retry_total=0, connection_timeout=5, read_timeout=20)
            release = BootstrapReleasePublisher(
                identity, configured.release_account_url, configured.release_group,
                configured.vault_name, configured.vault_group, configured.package_uri,
                configured.package_sha256, configured.template_sha256,
            )
            device_auth = ProviderDeviceAuth(
                configured.tenant_id, configured.client_id,
                msal_public_client_factory(configured.tenant_id, configured.client_id), keys,
            )
            app.state.device, app.state.backend = device_auth, state
            app.state.vault, app.state.publisher = ProviderBootstrapVault(secret_client), release
        else:
            if any(value is None for value in (device, backend, vault, publisher)):
                raise ValueError("Test services must be explicitly supplied")
            app.state.device, app.state.backend = device, backend
            app.state.vault, app.state.publisher = vault, publisher
        if owned and canonical_guid(os.environ["FAAS_SETUP_ADMINISTRATOR_TENANT_ID"]) != configured.tenant_id:
            raise ValueError("The deployment administrator must belong to the provider tenant")
        app.state.settings = configured
        app.state.sessions = SetupSessions()
        try:
            yield
        finally:
            if owned:
                release.close()
                secret_client.close()
                state.close()
                keys.close()
                identity.close()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    logging.getLogger("azure").setLevel(logging.WARNING)

    @app.middleware("http")
    async def safe_response(request: Request, call_next):
        try:
            response = await call_next(request)
        except Exception as error:
            logger.error("code=BootstrapDependencyUnavailable type=%s", type(error).__name__)
            response = JSONResponse({"detail": "BootstrapDependencyUnavailable"}, status_code=503)
        response.headers.update({
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
        })
        return response

    @app.exception_handler(BootstrapError)
    async def bootstrap_error(request: Request, error: BootstrapError):
        return JSONResponse({"detail": error.code}, status_code=error.status)

    def check_origin(request: Request) -> None:
        if request.headers.get("origin") != app.state.settings.origin:
            raise BootstrapError(403, "InvalidRequestOrigin")
        if request.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise BootstrapError(415, "JsonRequired")

    def cookie(request: Request) -> str:
        value = request.cookies.get(COOKIE, "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value):
            raise BootstrapError(401, "BootstrapSignInRequired")
        return value

    @app.get("/healthz")
    def health():
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def index():
        html = (Path(__file__).parent / "static/provider-setup.html").read_text()
        import base64
        hashes = ["'sha256-" + base64.b64encode(hashlib.sha256(code.encode()).digest()).decode() + "'"
                  for code in re.findall(r"<script>(.*?)</script>", html, re.DOTALL)]
        return HTMLResponse(html, headers={
            "Content-Security-Policy": "default-src 'self'; script-src " + " ".join(hashes)
                + "; style-src 'self' 'unsafe-inline'; connect-src 'self'; "
                  "frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'",
        })

    @app.post("/setup/signin")
    def signin(request: Request):
        check_origin(request)
        challenge = app.state.device.begin()
        response = JSONResponse({"userCode": challenge.user_code,
                                 "verificationUri": challenge.verification_uri,
                                 "expiresIn": challenge.expires_in})
        response.set_cookie(COOKIE, challenge.session_id, secure=True, httponly=True,
                            samesite="lax", max_age=challenge.expires_in, path="/")
        return response

    @app.post("/setup/poll")
    def poll(request: Request):
        check_origin(request)
        session_id = cookie(request)
        result = app.state.device.poll(session_id)
        if isinstance(result, DevicePending):
            return {"status": "Waiting", "retryAfter": result.retry_after}
        if (result.tenant_id != app.state.settings.tenant_id
                or result.object_id != app.state.settings.administrator_id):
            raise BootstrapError(403, "BootstrapIdentityMismatch")
        app.state.sessions.add(session_id, result)
        return {"status": "SignedIn"}

    @app.post("/setup/create")
    async def create(request: Request, body: CreateRequest):
        check_origin(request)
        if body.confirmGraphPermissions is not True:
            raise BootstrapError(400, "BootstrapGraphApprovalRequired")
        administrator = app.state.sessions.consume(cookie(request))
        configured = app.state.settings
        context = BootstrapContext(configured.tenant_id, configured.subscription_id,
                                   administrator.object_id, configured.management_origin)
        graph = graph_factory(DelegatedSession(administrator.tenant_id, administrator.object_id,
                                               administrator.graph_access_token))
        try:
            coordinator = ProviderBootstrap(app.state.backend, graph, app.state.vault)
            await run_in_threadpool(coordinator.start, context)
            await run_in_threadpool(coordinator.run, context)
            parameters = await run_in_threadpool(coordinator.installation_parameters, context)
            result = await run_in_threadpool(app.state.publisher.publish, context, parameters)
            return result
        finally:
            graph.close()

    return app


app = create_app()
