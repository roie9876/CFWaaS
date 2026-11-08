"""Durable provider enrollment; incomplete external writes require operator repair.

The backend must provide atomic, create-only/ETag transactions and bounded
``list_rows(partition, prefix, limit)``. Only explicit recovery may replace an
expired operation fence; it reconciles known identities and retires marked
passwords rather than replaying uncertain application/password creation.
"""

import hashlib
import json
import logging
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Protocol, TypeVar, TypedDict
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .store import Backend, Change, Conflict, Row
from .deployment_scope import ScopeMode, ScopeSelectionError, scope_mode

PARTITION = "enrollments"
ATTEMPTS = 8
LIST_LIMIT = 1000
LEASE_SECONDS = 120
T = TypeVar("T")
logger = logging.getLogger("faas.enrollment")


class EnrollmentError(Exception):
    def __init__(self, status: int, code: str, dependency_status: int | None = None,
                 dependency_operation: str = "", dependency_reason: str = "") -> None:
        self.status, self.code, self.dependency_status = status, code, dependency_status
        self.dependency_operation, self.dependency_reason = dependency_operation, dependency_reason
        super().__init__(code)


def canonical_guid(value: str) -> str:
    if str(UUID(value)) != value:
        raise ValueError("Expected a canonical GUID")
    return value


def customer_name_key(tenant: str, name: str) -> str:
    normalized = unicodedata.normalize("NFKC", name).strip().casefold()
    return "name:" + hashlib.sha256((tenant + "\0" + normalized).encode()).hexdigest()


class EnrollmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    name: str = Field(min_length=1, max_length=100)
    tenantId: str
    subscriptionId: str
    credentialHours: int = Field(default=24, ge=1, le=8760)
    maxEnvironments: int = Field(default=3, ge=0)
    scopeMode: ScopeMode = "customer"
    providerLabAcknowledged: bool = False

    @field_validator("tenantId", "subscriptionId")
    @classmethod
    def guid(cls, value: str) -> str:
        return canonical_guid(value)

    @field_validator("name")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip() or any(ord(char) < 32 for char in value):
            raise ValueError("Expected a customer name")
        return value

    @model_validator(mode="after")
    def acknowledged_scope(self) -> "EnrollmentRequest":
        if self.scopeMode == "provider-lab" and not self.providerLabAcknowledged:
            raise ValueError("ProviderLabAcknowledgementRequired")
        if self.scopeMode == "customer" and self.providerLabAcknowledged:
            raise ValueError("ProviderLabAcknowledgementRequiresLabMode")
        return self

    def enrollment_fields(self) -> dict:
        values = self.model_dump()
        if self.scopeMode == "customer":
            values.pop("scopeMode")
            values.pop("providerLabAcknowledged")
        return values


class RotationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    credentialHours: int | None = Field(default=None, ge=1, le=8760)


@dataclass(frozen=True)
class CustomerBinding:
    customer_id: str
    name: str
    tenant: str
    subscription: str
    principal: str
    client: str
    max_environments: int
    status: str
    allocation_key: str = ""
    scope_mode: ScopeMode = "customer"
    provider_lab_acknowledged: bool = False


@dataclass(frozen=True)
class ApplicationIdentity:
    object_id: str
    client_id: str


@dataclass(frozen=True)
class Credential:
    key_id: str
    secret: str = field(repr=False)
    expires_at: str


class VaultReference(TypedDict):
    name: str
    version: str


class DeploymentLink(TypedDict):
    portalUrl: str
    expiresAt: str


class EnrollmentBackend(Backend, Protocol):
    def list_rows(self, partition: str, prefix: str, limit: int) -> list[Row]: ...


class Directory(Protocol):
    def create_application(self, customer_id: str) -> ApplicationIdentity: ...
    def create_principal(self, client_id: str) -> str: ...
    def find_principal(self, client_id: str) -> str | None: ...
    def verify_application(self, customer_id: str, application: ApplicationIdentity) -> None: ...
    def verify(self, binding: CustomerBinding, application_id: str) -> None: ...
    def grant_role(self, principal_id: str) -> None: ...
    def ensure_role(self, principal_id: str) -> None: ...
    def password_keys(self, application_id: str, customer_id: str) -> list[str]: ...
    def add_password(self, application_id: str, expires_at: str, marker: str) -> Credential: ...
    def remove_password(self, application_id: str, key_id: str) -> None: ...
    def set_enabled(self, principal_id: str, enabled: bool) -> None: ...


class CredentialVault(Protocol):
    def write(self, customer_id: str, secret: str, expires: str) -> VaultReference: ...
    def read(self, name: str, version: str) -> str: ...


class Publisher(Protocol):
    def publish(self, binding: CustomerBinding) -> DeploymentLink: ...


def _row(key: str, **values: object) -> Row:
    return {"PartitionKey": PARTITION, "RowKey": key, **values}


def _change(row: Row) -> Change:
    return Change(row, str(row["_etag"]) if row.get("_etag") else None)


def _expiry(hours: int) -> str:
    return datetime.fromtimestamp(
        time.time() + hours * 3600, timezone.utc).replace(microsecond=0).isoformat()


def _expired(expires: str) -> bool:
    return datetime.fromisoformat(expires).timestamp() <= time.time()


class EnrollmentRegistry:
    def __init__(self, backend: EnrollmentBackend) -> None:
        self.backend = backend

    def _get(self, key: str) -> Row | None:
        try:
            return self.backend.get(PARTITION, key)
        except Exception:
            raise EnrollmentError(503, "EnrollmentStoreUnavailable") from None

    def _transact(self, changes: list[Change]) -> None:
        try:
            self.backend.transact(changes)
        except Conflict:
            raise
        except Exception:
            raise EnrollmentError(503, "EnrollmentStoreUnavailable") from None

    def _customer(self, customer_id: str) -> Row:
        try:
            canonical_guid(customer_id)
        except (ValueError, TypeError, AttributeError):
            raise EnrollmentError(404, "CustomerNotFound") from None
        row = self._get("customer:" + customer_id)
        if not row:
            raise EnrollmentError(404, "CustomerNotFound")
        return row

    def _customers(self) -> list[Row]:
        try:
            rows = self.backend.list_rows(PARTITION, "customer:", LIST_LIMIT + 1)
        except Exception:
            raise EnrollmentError(503, "EnrollmentStoreUnavailable") from None
        if len(rows) > LIST_LIMIT:
            raise EnrollmentError(503, "EnrollmentListLimit")
        return rows

    @staticmethod
    def _scope(row: Row) -> tuple[ScopeMode, bool]:
        try:
            mode = scope_mode(row.get("scopeMode", "customer"))
            acknowledged = row.get("providerLabAcknowledged", False) is True
            if mode == "provider-lab" and not acknowledged:
                raise ScopeSelectionError("ProviderLabAcknowledgementRequired")
        except ScopeSelectionError:
            raise EnrollmentError(503, "EnrollmentStoreUnavailable") from None
        return mode, acknowledged

    @staticmethod
    def _safe(row: Row) -> dict:
        EnrollmentRegistry._scope(row)
        fields = ("customerId", "name", "tenantId", "subscriptionId", "principalId",
                  "clientId", "status", "credentialHours", "credentialExpiresAt",
                  "revealed", "errorCode", "failureStage", "dependencyOperation",
                  "dependencyReason", "recoveryGuidance", "scopeMode")
        safe = {key: row[key] for key in fields if key in row}
        if row.get("operation"):
            safe["recoveryAvailableAt"] = datetime.fromtimestamp(
                float(row.get("leaseUntil", 0)), timezone.utc).isoformat()
        return safe

    def _binding(self, row: Row) -> CustomerBinding:
        tenant = str(row["tenantId"])
        customer_id = str(row["customerId"])
        allocation_key = str(row.get("allocationKey") or tenant)
        mode, acknowledged = self._scope(row)
        if allocation_key not in (tenant, "customer:" + customer_id):
            raise EnrollmentError(503, "EnrollmentStoreUnavailable")
        return CustomerBinding(
            customer_id, str(row["name"]), tenant,
            str(row["subscriptionId"]), str(row["principalId"]), str(row["clientId"]),
            int(row["maxEnvironments"]), str(row["status"]), allocation_key, mode, acknowledged,
        )

    def list_customers(self) -> list[dict]:
        return [self._safe(row) for row in self._customers() if row.get("status") != "Archived"]

    def get(self, customer_id: str) -> dict:
        return self._safe(self._customer(customer_id))

    def lookup(self, client_id: str, principal_id: str) -> CustomerBinding | None:
        try:
            canonical_guid(client_id)
            canonical_guid(principal_id)
        except (ValueError, TypeError, AttributeError):
            return None
        index = self._get("client:" + client_id)
        if not index:
            return None
        row = self._customer(str(index["customerId"]))
        if (row["status"] != "Ready" or row.get("principalId") != principal_id
                or row.get("clientId") != client_id
                or _expired(str(row["credentialExpiresAt"]))):
            return None
        return self._binding(row)

    def worker_customers(self) -> list[CustomerBinding]:
        return [self._binding(row) for row in self._customers()
                if row["status"] in ("Ready", "Revoked", "Archived") and row.get("principalId")]

    def binding(self, customer_id: str) -> CustomerBinding | None:
        row = self._customer(customer_id)
        return self._binding(row) if row.get("principalId") and row.get("clientId") else None

    def decommission_requests(self, customer_id: str | None = None) -> list[Row]:
        try:
            rows = self.backend.list_rows(PARTITION, "decommission:", LIST_LIMIT + 1)
        except Exception:
            raise EnrollmentError(503, "EnrollmentStoreUnavailable") from None
        if len(rows) > LIST_LIMIT:
            raise EnrollmentError(503, "EnrollmentListLimit")
        valid = []
        for row in rows:
            try:
                environment_id = canonical_guid(str(row.get("environmentId")))
                canonical_guid(str(row.get("customerId")))
                attempt = int(row.get("attempt", 0))
            except (ValueError, TypeError, AttributeError):
                continue
            if row.get("RowKey") != "decommission:" + environment_id or attempt < 1:
                continue
            if customer_id is None or row["customerId"] == customer_id:
                valid.append(row)
        return valid


class EnrollmentService:
    def __init__(self, registry: EnrollmentRegistry, graph: Directory,
                 vault: CredentialVault, publisher: Publisher) -> None:
        self.registry, self.graph = registry, graph
        self.vault, self.publisher = vault, publisher

    @staticmethod
    def _actor(actor: str) -> None:
        try:
            canonical_guid(actor)
        except (ValueError, TypeError, AttributeError):
            raise EnrollmentError(400, "InvalidActor") from None

    @staticmethod
    def _operation(actor: str, key: str, action: str, target: object) -> tuple[str, str]:
        if (not isinstance(key, str) or not 1 <= len(key) <= 128
                or any(ord(c) < 33 or ord(c) > 126 for c in key)):
            raise EnrollmentError(400, "InvalidIdempotencyKey")
        identity = hashlib.sha256(f"{actor}:{key}".encode()).hexdigest()
        digest = hashlib.sha256(json.dumps(
            [action, target], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return "idem:" + identity, digest

    @staticmethod
    def _audit(customer_id: str, actor: str, event: str) -> Change:
        return Change(_row("audit:" + str(uuid4()), customerId=customer_id,
                           actorOid=actor, event=event, timestamp=time.time()))

    def _replay(self, key: str, digest: str) -> dict | None:
        previous = self.registry._get(key)
        if not previous:
            return None
        if previous["digest"] != digest:
            raise EnrollmentError(409, "IdempotencyConflict")
        if previous["state"] == "Failed":
            raise EnrollmentError(409, "EnrollmentNeedsAttention")
        if previous["state"] != "Done":
            raise EnrollmentError(409, "EnrollmentInProgress")
        return self.registry.get(str(previous["customerId"]))

    def _save(self, customer_id: str, operation: str, **updates: object) -> Row:
        for _ in range(ATTEMPTS):
            row = self._checked(customer_id, operation)
            row.update(updates)
            row["leaseUntil"] = time.time() + LEASE_SECONDS
            try:
                self.registry._transact([_change(row)])
                return self.registry._customer(customer_id)
            except Conflict:
                continue
        raise EnrollmentError(409, "EnrollmentContention")

    def _checked(self, customer_id: str, operation: str) -> Row:
        row = self.registry._customer(customer_id)
        if (row.get("operation") != operation
                or float(row.get("leaseUntil", 0)) <= time.time()):
            raise EnrollmentError(409, "EnrollmentFenceLost")
        return row

    def _external(self, customer_id: str, operation: str, call: Callable[[], T]) -> T:
        self._save(customer_id, operation)
        result = call()
        self._checked(customer_id, operation)
        return result

    def _finish(self, customer_id: str, actor: str, operation: str,
                status: str, failed: bool = False, error_code: str = "",
                guidance: str = "", failure_stage: str = "",
                dependency_operation: str = "", dependency_reason: str = "") -> dict:
        for _ in range(ATTEMPTS):
            row = self.registry._customer(customer_id)
            idem = self.registry._get(operation)
            if row.get("operation") != operation or not idem:
                raise EnrollmentError(409, "EnrollmentFenceLost")
            if not failed:
                self._checked(customer_id, operation)
            row.update(status=status, operation="", leaseUntil=0.0, errorCode=(
                error_code or ("EnrollmentDependencyFailed" if failed else "")),
                       failureStage=failure_stage if failed else "",
                       dependencyOperation=dependency_operation if failed else "",
                       dependencyReason=dependency_reason if failed else "",
                       recoveryGuidance=guidance or (
                           "Use Recover to verify this enrollment, disable its client, "
                           "retire enrollment-marked credentials and issue a fresh credential. "
                           "If application identity cannot be verified, follow the Entra "
                           "portal instructions returned by Recover."
                           if failed else ""))
            idem["state"] = "Failed" if failed else "Done"
            try:
                self.registry._transact([
                    _change(row), _change(idem),
                    self._audit(customer_id, actor, status),
                ])
                return self.registry._safe(row)
            except Conflict:
                continue
        raise EnrollmentError(409, "EnrollmentContention")

    def _fail(self, customer_id: str, actor: str, operation: str,
              error: Exception, stage: str = "") -> None:
        safe_codes = {
            "GraphRequestFailed", "GraphBindingMismatch", "GraphProviderBindingMismatch",
            "GraphIdentityInvalid", "GraphCredentialInvalid", "GraphPasswordListInvalid",
            "GraphPasswordMarkerInvalid", "VaultWriteFailed", "VaultReadFailed",
            "EnrollmentStoreUnavailable", "EnrollmentFenceLost", "EnrollmentContention",
            "ClientAlreadyBound", "InvalidCredential", "InvalidVaultReference", "PrincipalCreationUncertain",
        }
        code = error.code if isinstance(error, EnrollmentError) and error.code in safe_codes else "EnrollmentDependencyFailed"
        if (isinstance(error, EnrollmentError) and error.code == "GraphRequestFailed"
                and type(error.dependency_status) is int and 400 <= error.dependency_status <= 599):
            code += "Http" + str(error.dependency_status)
        operation_labels = {"ReadNewApplication", "CreateServicePrincipal"}
        graph_reasons = {"Authorization_RequestDenied", "Request_BadRequest",
                         "Request_ResourceNotFound", "Authentication_RequestFromUnsupportedUserRole",
                         "AccessDenied", "Forbidden", "InsufficientPrivileges"}
        dependency_operation = (error.dependency_operation
                                if isinstance(error, EnrollmentError)
                                and error.dependency_operation in operation_labels else "")
        dependency_reason = (error.dependency_reason
                             if isinstance(error, EnrollmentError)
                             and error.dependency_reason in graph_reasons else "")
        logger.error("code=%s stage=%s type=%s", code, stage or "unknown", type(error).__name__)
        try:
            self._finish(customer_id, actor, operation, "NeedsAttention", failed=True,
                         error_code=code, failure_stage=stage,
                         dependency_operation=dependency_operation, dependency_reason=dependency_reason)
        except Exception as persistence_error:
            # A failed store remains fenced/in-progress, never eligible for takeover.
            logger.error("code=EnrollmentFailurePersistenceUnavailable type=%s",
                         type(persistence_error).__name__)
        raise EnrollmentError(502, "EnrollmentDependencyFailed") from None

    def onboard(self, request: EnrollmentRequest, actor_oid: str,
                idempotency_key: str) -> dict:
        if "maxEnvironments" in request.model_fields_set:
            logger.warning("Legacy customer environment allocation limit is ignored")
        self._actor(actor_oid)
        operation, digest = self._operation(
            actor_oid, idempotency_key, "onboard", request.enrollment_fields())
        customer_id = str(uuid4())
        name_key = customer_name_key(request.tenantId, request.name)
        for _ in range(ATTEMPTS):
            replay = self._replay(operation, digest)
            if replay is not None:
                return replay
            owner = self.registry._get("owner:" + request.tenantId)
            if self.registry._get(name_key):
                raise EnrollmentError(409, "CustomerNameAlreadyEnrolled")
            if owner:
                if not owner.get("customerId"):
                    raise EnrollmentError(503, "EnrollmentStoreUnavailable")
                original = self.registry._customer(str(owner["customerId"]))
                if original["tenantId"] != request.tenantId:
                    raise EnrollmentError(503, "EnrollmentStoreUnavailable")
                if customer_name_key(request.tenantId, str(original["name"])) == name_key:
                    raise EnrollmentError(409, "CustomerNameAlreadyEnrolled")
            row = _row(
                "customer:" + customer_id, customerId=customer_id,
                **request.enrollment_fields(), status="Onboarding", operation=operation,
                allocationKey=request.tenantId if not owner else "customer:" + customer_id,
                revealed=False, errorCode="", credentialVersion=0,
                leaseUntil=time.time() + LEASE_SECONDS,
            )
            try:
                changes = [
                    Change(row),
                    Change(_row(name_key, customerId=customer_id)),
                    Change(_row(operation, digest=digest, customerId=customer_id,
                                state="Busy")),
                    self._audit(customer_id, actor_oid, "Onboarding"),
                ]
                if not owner:
                    changes.append(Change(_row("owner:" + request.tenantId, customerId=customer_id,
                                               subscriptionId=request.subscriptionId)))
                self.registry._transact(changes)
                break
            except Conflict:
                continue
        else:
            raise EnrollmentError(409, "EnrollmentContention")
        stage = "CreateApplication"
        try:
            app = self._external(customer_id, operation,
                                 lambda: self.graph.create_application(customer_id))
            canonical_guid(app.object_id)
            canonical_guid(app.client_id)
            self._save(customer_id, operation, applicationId=app.object_id,
                       clientId=app.client_id)
            stage = "CreatePrincipal"
            principal = self._external(customer_id, operation,
                                       lambda: self.graph.create_principal(app.client_id))
            canonical_guid(principal)
            row = self._save(customer_id, operation, principalId=principal)
            stage = "IndexClient"
            self._index(row, operation)
            stage = "VerifyIdentity"
            self._external(customer_id, operation,
                           lambda: self.graph.verify(self.registry._binding(row), app.object_id))
            stage = "GrantApiRole"
            self._external(customer_id, operation, lambda: self.graph.grant_role(principal))
            stage = "CreateCredential"
            self._password(customer_id, operation)
            stage = "EnableClient"
            self._external(customer_id, operation, lambda: self.graph.set_enabled(principal, True))
            return self._finish(customer_id, actor_oid, operation, "Ready")
        except Exception as error:
            self._fail(customer_id, actor_oid, operation, error, stage)

    def _index(self, row: Row, operation: str) -> None:
        for _ in range(ATTEMPTS):
            current = self._checked(str(row["customerId"]), operation)
            try:
                self.registry._transact([
                    _change(current),
                    Change(_row("client:" + str(row["clientId"]),
                                customerId=row["customerId"])),
                ])
                return
            except Conflict:
                if self.registry._get("client:" + str(row["clientId"])):
                    raise EnrollmentError(409, "ClientAlreadyBound") from None
        raise EnrollmentError(409, "EnrollmentContention")

    def _password(self, customer_id: str, operation: str) -> None:
        row = self.registry._customer(customer_id)
        expires = _expiry(int(row["credentialHours"]))
        marker = f"faas-enrollment:{customer_id}:{operation.removeprefix('idem:')}"
        credential = self._external(customer_id, operation, lambda: self.graph.add_password(
            str(row["applicationId"]), expires, marker))
        canonical_guid(credential.key_id)
        if not credential.secret or credential.expires_at != expires:
            raise EnrollmentError(502, "InvalidCredential")
        self._save(customer_id, operation, pendingPasswordKeyId=credential.key_id)
        reference = self._external(
            customer_id, operation, lambda: self.vault.write(customer_id, credential.secret, expires))
        version = reference["version"]
        if (reference["name"] != "customer-" + customer_id
                or not isinstance(version, str) or len(version) != 32
                or any(char not in "0123456789abcdef" for char in version)):
            raise EnrollmentError(502, "InvalidVaultReference")
        self._save(
            customer_id, operation, vaultName=reference["name"],
            vaultVersion=reference["version"], credentialExpiresAt=expires,
            credentialVersion=int(row["credentialVersion"]) + 1, revealed=False,
        )
        if row.get("passwordKeyId"):
            self._external(customer_id, operation, lambda: self.graph.remove_password(
                str(row["applicationId"]), str(row["passwordKeyId"])))
        self._save(customer_id, operation, passwordKeyId=credential.key_id,
                   pendingPasswordKeyId="")

    def _begin(self, customer_id: str, actor: str, key: str,
               action: str, credential_hours: int | None = None) -> tuple[str, dict | None]:
        self._actor(actor)
        target = (customer_id if credential_hours is None else
                  {"customerId": customer_id, "credentialHours": credential_hours})
        operation, digest = self._operation(actor, key, action, target)
        for _ in range(ATTEMPTS):
            replay = self._replay(operation, digest)
            if replay is not None:
                return operation, replay
            row = self.registry._customer(customer_id)
            previous_operation = str(row.get("operation", ""))
            if previous_operation and (
                    action != "recover" or float(row.get("leaseUntil", 0)) > time.time()):
                raise EnrollmentError(409, "EnrollmentInProgress")
            allowed = {
                "rotate": ("Ready",),
                "revoke": ("Ready", "NeedsAttention", "Revoked"),
                "archive": ("Revoked",),
                "recover": ("Ready", "NeedsAttention", "Revoked", "Onboarding",
                            "Rotating", "Revoking", "Recovering"),
            }[action]
            if (row["status"] not in allowed
                    or (action != "recover" and not row.get("principalId"))):
                raise EnrollmentError(409, "EnrollmentNotReady")
            row.update(operation=operation, leaseUntil=time.time() + LEASE_SECONDS,
                       status={"rotate": "Rotating", "revoke": "Revoking",
                           "archive": "Archiving",
                               "recover": "Recovering"}[action])
            if credential_hours is not None:
                row["credentialHours"] = credential_hours
            changes = [
                _change(row), Change(_row(operation, digest=digest,
                                          customerId=customer_id, state="Busy")),
                self._audit(customer_id, actor, str(row["status"])),
            ]
            if previous_operation:
                previous = self.registry._get(previous_operation)
                if not previous:
                    raise EnrollmentError(409, "EnrollmentFenceLost")
                previous["state"] = "Failed"
                changes.append(_change(previous))
            try:
                self.registry._transact(changes)
                return operation, None
            except Conflict:
                continue
        raise EnrollmentError(409, "EnrollmentContention")

    def rotate(self, customer_id: str, actor_oid: str, idempotency_key: str,
               credential_hours: int | None = None) -> dict:
        RotationRequest(credentialHours=credential_hours)
        operation, replay = self._begin(customer_id, actor_oid, idempotency_key, "rotate",
                                        credential_hours)
        if replay is not None:
            return replay
        try:
            row = self.registry._customer(customer_id)
            self._external(customer_id, operation, lambda: self.graph.verify(
                self.registry._binding(row), str(row["applicationId"])))
            self._external(customer_id, operation,
                           lambda: self.graph.set_enabled(str(row["principalId"]), False))
            self._password(customer_id, operation)
            self._external(customer_id, operation,
                           lambda: self.graph.set_enabled(str(row["principalId"]), True))
            return self._finish(customer_id, actor_oid, operation, "Ready")
        except Exception as error:
            self._fail(customer_id, actor_oid, operation, error, "Rotate")

    def revoke(self, customer_id: str, actor_oid: str, idempotency_key: str) -> dict:
        operation, replay = self._begin(customer_id, actor_oid, idempotency_key, "revoke")
        if replay is not None:
            return replay
        try:
            row = self.registry._customer(customer_id)
            self._external(customer_id, operation, lambda: self.graph.verify(
                self.registry._binding(row), str(row["applicationId"])))
            self._external(customer_id, operation,
                           lambda: self.graph.set_enabled(str(row["principalId"]), False))
            return self._finish(customer_id, actor_oid, operation, "Revoked")
        except Exception as error:
            self._fail(customer_id, actor_oid, operation, error, "Revoke")

    def archive(self, customer_id: str, actor_oid: str, idempotency_key: str) -> dict:
        operation, replay = self._begin(customer_id, actor_oid, idempotency_key, "archive")
        if replay is not None:
            return replay
        return self._finish(customer_id, actor_oid, operation, "Archived")

    def recover(self, customer_id: str, actor_oid: str, idempotency_key: str) -> dict:
        """Explicit reset, not a replay: verify, disable, retire marked keys, mint once."""
        operation, replay = self._begin(customer_id, actor_oid, idempotency_key, "recover")
        if replay is not None:
            return replay
        stage = "VerifyApplication"
        try:
            row = self._checked(customer_id, operation)
            if not row.get("applicationId") or not row.get("clientId"):
                return self._finish(
                    customer_id, actor_oid, operation, "NeedsAttention", failed=True,
                    error_code="ApplicationIdentityUnverified",
                    guidance=(
                        "Open https://entra.microsoft.com/ in the provider tenant. "
                        "Go to App registrations > All applications and inspect "
                        f"faas-customer-{customer_id}. Do not adopt it by display name "
                        "or create a replacement. Verify its object ID, client ID and "
                        "onboarding management-app owner; in Enterprise applications "
                        "disable the corresponding verified service principal while "
                        "investigating. This UI cannot safely bind lost application "
                        "IDs. Contact the provider's recovery administrator for a "
                        "verified identity-binding workflow; then use Recover."
                    ),
                )
            application = ApplicationIdentity(
                str(row["applicationId"]), str(row["clientId"]))
            self._external(customer_id, operation, lambda: self.graph.verify_application(
                customer_id, application))
            stage = "FindPrincipal"
            principal = str(row.get("principalId", ""))
            if not principal:
                principal = self._external(customer_id, operation, lambda: self.graph.find_principal(
                    application.client_id)) or ""
                if not principal:
                    stage = "CreatePrincipal"
                    principal = self._external(
                        customer_id, operation,
                        lambda: self.graph.create_principal(application.client_id))
                canonical_guid(principal)
                row = self._save(customer_id, operation, principalId=principal)
            index = self.registry._get("client:" + application.client_id)
            stage = "IndexClient"
            if index:
                if index["customerId"] != customer_id:
                    raise EnrollmentError(409, "ClientAlreadyBound")
            else:
                self._index(row, operation)
            stage = "VerifyIdentity"
            self._external(customer_id, operation, lambda: self.graph.verify(
                self.registry._binding(row), application.object_id))
            stage = "DisableClient"
            self._external(customer_id, operation,
                           lambda: self.graph.set_enabled(principal, False))
            stage = "EnsureApiRole"
            self._external(customer_id, operation, lambda: self.graph.ensure_role(principal))
            stage = "RetireCredentials"
            keys = self._external(customer_id, operation, lambda: self.graph.password_keys(
                application.object_id, customer_id))
            if len(keys) > 100 or len(set(keys)) != len(keys):
                raise EnrollmentError(502, "GraphPasswordListInvalid")
            for key in keys:
                canonical_guid(key)
                self._external(customer_id, operation, lambda key=key: self.graph.remove_password(
                    application.object_id, key))
            self._save(customer_id, operation, passwordKeyId="", pendingPasswordKeyId="")
            stage = "CreateCredential"
            self._password(customer_id, operation)
            stage = "EnableClient"
            self._external(customer_id, operation, lambda: self.graph.set_enabled(principal, True))
            return self._finish(customer_id, actor_oid, operation, "Ready")
        except Exception as error:
            self._fail(customer_id, actor_oid, operation, error, stage)

    def reveal(self, customer_id: str, actor_oid: str) -> dict:
        self._actor(actor_oid)
        for _ in range(ATTEMPTS):
            row = self.registry._customer(customer_id)
            if (row["status"] != "Ready" or row.get("operation")
                    or _expired(str(row["credentialExpiresAt"]))):
                raise EnrollmentError(409, "CredentialUnavailable")
            row["revealed"] = True
            try:
                self.registry._transact([
                    _change(row), self._audit(customer_id, actor_oid, "RevealClaimed"),
                ])
                break
            except Conflict:
                continue
        else:
            raise EnrollmentError(409, "EnrollmentContention")
        try:
            secret = self.vault.read(str(row["vaultName"]), str(row["vaultVersion"]))
        except EnrollmentError as error:
            if error.code not in ("VaultNameInvalid", "VaultVersionInvalid", "VaultReadFailed"):
                raise
            raise EnrollmentError(502, "CredentialReadFailed") from None
        current = self.registry._customer(customer_id)
        if (not secret or current["status"] != "Ready" or current.get("operation")
                or current["credentialVersion"] != row["credentialVersion"]
                or _expired(str(row["credentialExpiresAt"]))):
            raise EnrollmentError(409, "CredentialUnavailable")
        return {"secret": secret, "expiresAt": row["credentialExpiresAt"]}

    def deployment(self, customer_id: str, actor_oid: str) -> dict:
        self._actor(actor_oid)
        for _ in range(ATTEMPTS):
            row = self.registry._customer(customer_id)
            if row["status"] != "Ready" or row.get("operation"):
                raise EnrollmentError(409, "EnrollmentNotReady")
            try:
                self.registry._transact([
                    _change(row), self._audit(customer_id, actor_oid, "DeploymentRequested"),
                ])
                break
            except Conflict:
                continue
        else:
            raise EnrollmentError(409, "EnrollmentContention")
        try:
            link = self.publisher.publish(self.registry._binding(row))
            current = self.registry._customer(customer_id)
            if (current["status"] != "Ready" or current.get("operation")
                    or _expired(link["expiresAt"])):
                raise EnrollmentError(502, "DeploymentUnavailable")
            return {"portalUrl": link["portalUrl"], "expiresAt": link["expiresAt"]}
        except Exception:
            raise EnrollmentError(502, "DeploymentPublishFailed") from None
