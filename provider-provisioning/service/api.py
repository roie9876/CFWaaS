from contextlib import asynccontextmanager
import logging
from uuid import UUID

from azure.identity import ManagedIdentityCredential
from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.exceptions import RequestValidationError
from starlette.concurrency import run_in_threadpool

from .auth import Authenticator, Owner, TrustedKeys
from .azure_data import TableBackend, Vault, secret_names
from .config import Settings
from .customer_stores import CustomerStores
from .enrollment import EnrollmentRegistry
from .models import EnvironmentRequest, RoutingAddress, parse_stored_environment_request
from .store import DomainError, Store

logger = logging.getLogger("faas.api")


def public_operation(row: dict) -> dict:
    import json
    return {
        "operationId": row["environmentId"], "environmentId": row["environmentId"],
        "status": row["status"], "createdAt": row["createdAt"], "updatedAt": row["updatedAt"],
        "connectionManifest": json.loads(str(row["manifest"])),
        "error": ({"code": row["errorCode"], "message": row["errorMessage"]}
                  if row["errorCode"] else None),
    }


def create_app(settings: Settings | None = None, store: Store | CustomerStores | None = None,
               authenticator: Authenticator | None = None, vault: Vault | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if settings is None:
            configured = Settings.from_env()
            credential = ManagedIdentityCredential(retry_total=2, connection_timeout=5,
                                                   read_timeout=10)
            backend = TableBackend(configured.table_endpoint, credential)
            exchange = Vault(configured.vault_url, credential)
            keys = TrustedKeys(configured.authority_tenant)
            customers = None
            registry = None
            if configured.auth_mode == "provider-api-registry":
                customers = TableBackend(configured.table_endpoint, credential, "Customers")
                registry = EnrollmentRegistry(customers)
                app.state.store = CustomerStores(backend, configured, registry)
            else:
                app.state.store = Store(backend, configured)
            app.state.auth = Authenticator(configured, keys, registry)
            app.state.settings = configured
            app.state.vault = exchange
            try:
                yield
            finally:
                keys.close()
                backend.close()
                exchange.close()
                credential.close()
                if customers is not None:
                    customers.close()
        else:
            if store is None or authenticator is None or vault is None:
                raise ValueError("All test dependencies must be supplied")
            app.state.store, app.state.auth, app.state.vault = store, authenticator, vault
            app.state.settings = settings
            yield

    app = FastAPI(title="Provider Provisioning", docs_url=None, redoc_url=None,
                  openapi_url=None, lifespan=lifespan)
    # SDK HTTP/body logging must not be enabled, including on exchange endpoints.
    logging.getLogger("azure").setLevel(logging.WARNING)

    def caller(authorization: str | None = Header(default=None)) -> Owner:
        return app.state.auth.authenticate(authorization)

    def customer_store(owner: Owner) -> Store:
        selected = app.state.store
        return selected.for_owner(owner) if isinstance(selected, CustomerStores) else selected

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc: RequestValidationError):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "InvalidRequest"}, status_code=422,
                            headers={"Cache-Control": "no-store"})

    @app.exception_handler(DomainError)
    async def domain_error(request, exc: DomainError):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": exc.code}, status_code=exc.status,
                            headers={"Cache-Control": "no-store"})

    @app.exception_handler(Exception)
    async def dependency_error(request, exc: Exception):
        from fastapi.responses import JSONResponse
        # Never echo SDK exception details (ARM can include secure parameters).
        logger.error("code=ApiDependencyUnavailable type=%s", type(exc).__name__)
        return JSONResponse({"detail": "ServiceUnavailable"}, status_code=503,
                            headers={"Cache-Control": "no-store"})

    @app.middleware("http")
    async def no_cache(request, call_next):
        try:
            response = await call_next(request)
        except Exception as exc:
            # Catch before ServerErrorMiddleware can re-raise an SDK exception into
            # Uvicorn's error logger, including customer/secure parameter details.
            from fastapi.responses import JSONResponse
            logger.error("code=ApiDependencyUnavailable type=%s", type(exc).__name__)
            response = JSONResponse({"detail": "ServiceUnavailable"}, status_code=503)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/healthz")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/v1/readiness")
    def readiness(owner: Owner = Depends(caller)) -> dict:
        import re
        try:
            selected = customer_store(owner)
            selected.backend.get(selected.partition, "__readiness__")
        except Exception as exc:
            code = getattr(getattr(exc, "error", None), "code", None)
            code = code if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_]{1,64}", code) else "DependencyUnavailable"
            status = getattr(exc, "status_code", None)
            logger.error("code=OperationStoreUnavailable type=%s", type(exc).__name__)
            raise HTTPException(503, {"component": "operation-store", "code": code,
                                      "type": type(exc).__name__,
                                      "status": status if type(status) is int else None}) from None
        return {"status": "ready"}

    @app.get("/v1/firewall-types/checkpoint-byol/readiness")
    def checkpoint_readiness(owner: Owner = Depends(caller)) -> dict:
        # Settings are loaded in lifespan in production; the create_app argument is test-only.
        if not app.state.settings.checkpoint_enabled:
            raise HTTPException(409, "CheckpointDeploymentUnavailable")
        return {"firewallType": "checkpoint-byol", "status": "ready"}

    @app.post("/v1/environments", status_code=202)
    def provision(body: EnvironmentRequest, response: Response,
                  owner: Owner = Depends(caller),
                  idempotency_key: str = Header(alias="Idempotency-Key", min_length=1,
                                                max_length=128)) -> dict:
        row = customer_store(owner).reserve(owner, idempotency_key, body)
        response.headers["Location"] = f"/v1/operations/{row['environmentId']}"
        return public_operation(row)

    @app.get("/v1/operations/{operation_id}")
    def operation(operation_id: UUID, owner: Owner = Depends(caller)) -> dict:
        return public_operation(customer_store(owner).owned(owner, str(operation_id)))

    @app.post("/v1/operations/{operation_id}/routing")
    def register_routing(operation_id: UUID, body: RoutingAddress,
                         owner: Owner = Depends(caller)) -> dict:
        return customer_store(owner).register_routing(
            owner, str(operation_id), body.routingApplianceIp)

    @app.post("/v1/operations/{operation_id}/retry-group", status_code=202)
    def retry_group(operation_id: UUID, owner: Owner = Depends(caller)) -> dict:
        return public_operation(customer_store(owner).retry_failed_group(owner, str(operation_id)))

    @app.get("/v1/environments/{environment_id}/connection-material")
    async def material(environment_id: UUID, owner: Owner = Depends(caller)) -> dict:
        row = await run_in_threadpool(customer_store(owner).owned, owner, str(environment_id))
        if row["status"] != "Ready":
            raise HTTPException(409, "EnvironmentNotReady")
        if parse_stored_environment_request(str(row["request"]))[0].mode != "network":
            raise HTTPException(409, "ProofHasNoConnectionMaterial")
        ingress, delivery = secret_names(str(environment_id))
        import json
        versions = json.loads(str(row["secretVersions"]))
        if set(versions) != {"ingress", "delivery"}:
            raise HTTPException(503, "ConnectionMaterialUnavailable")
        first = await run_in_threadpool(app.state.vault.read, ingress, versions["ingress"])
        second = await run_in_threadpool(app.state.vault.read, delivery, versions["delivery"])
        return {"environmentId": str(environment_id), "ingressSharedKey": first,
                "deliverySharedKey": second}

    return app


app = create_app()
