"""Provider setup coordinator; adapters must establish real authorization.

This module is not exposed as an HTTP endpoint. The future browser bootstrap
must validate its administrator identity and obtain explicit Graph consent
before constructing the directory adapter.
"""
import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .store import Change, Conflict, Row

PARTITION = "provider-bootstrap"
ROLE = "FirewallDeployment.Request"
GRAPH_PERMISSIONS = (
    "Application.ReadWrite.OwnedBy",
    "Application.Read.All",
    "AppRoleAssignment.ReadWrite.All",
)
logger = logging.getLogger("faas.provider-bootstrap")


class BootstrapError(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status, self.code = status, code
        super().__init__(code)


def canonical_guid(value: str) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value or UUID(value).int == 0:
        raise ValueError("Expected a nonzero canonical UUID")
    return value


@dataclass(frozen=True)
class BootstrapContext:
    tenant_id: str
    subscription_id: str
    administrator_id: str
    management_origin: str

    def __post_init__(self) -> None:
        from .config import endpoint
        for value in (self.tenant_id, self.subscription_id, self.administrator_id):
            canonical_guid(value)
        endpoint(self.management_origin, ".azurewebsites.net")

    @property
    def installation_id(self) -> str:
        return hashlib.sha256(
            (self.tenant_id + ":" + self.subscription_id + ":" + self.management_origin).encode()
        ).hexdigest()


@dataclass(frozen=True)
class Application:
    object_id: str
    client_id: str
    principal_id: str

    def __post_init__(self) -> None:
        for value in (self.object_id, self.client_id, self.principal_id):
            canonical_guid(value)


@dataclass(frozen=True, repr=False)
class ManagementCredential:
    key_id: str
    secret: str = field(repr=False)
    expires_at: str

    def __post_init__(self) -> None:
        canonical_guid(self.key_id)
        expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        if not self.secret or expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise ValueError("Invalid management credential")


class BootstrapBackend(Protocol):
    def get(self, partition: str, key: str) -> Row | None: ...
    def transact(self, changes: list[Change]) -> None: ...


class ProviderDirectory(Protocol):
    def verify_administrator(self, context: BootstrapContext) -> None: ...
    def create_api(self, context: BootstrapContext, role_id: str) -> Application: ...
    def create_management(self, context: BootstrapContext, api: Application) -> Application: ...
    def grant_management_permissions(self, context: BootstrapContext, management: Application,
                                     permissions: tuple[str, ...]) -> None: ...
    def verify_management_permissions(self, context: BootstrapContext, management: Application,
                                      permissions: tuple[str, ...]) -> None: ...
    def add_management_credential(self, context: BootstrapContext, management: Application,
                                  expires_at: str) -> ManagementCredential: ...


class BootstrapVault(Protocol):
    def write(self, name: str, value: str, expires_at: str | None = None) -> str: ...
    def verify(self, name: str, version: str) -> None: ...


def _app(row: Row, prefix: str) -> Application:
    return Application(str(row[prefix + "ObjectId"]), str(row[prefix + "ClientId"]),
                       str(row[prefix + "PrincipalId"]))


class ProviderBootstrap:
    """Fenced, provider-only setup. Uncertain external writes are never replayed."""

    def __init__(self, backend: BootstrapBackend, directory: ProviderDirectory,
                 vault: BootstrapVault) -> None:
        self.backend, self.directory, self.vault = backend, directory, vault

    def _read(self, key: str) -> Row | None:
        try:
            return self.backend.get(PARTITION, key)
        except Exception:
            raise BootstrapError(503, "BootstrapStateUnavailable") from None

    def _write(self, row: Row) -> None:
        etag = str(row["_etag"]) if row.get("_etag") else None
        try:
            self.backend.transact([Change(row, etag)])
        except Conflict:
            raise BootstrapError(409, "BootstrapConcurrentOperation") from None
        except Exception:
            raise BootstrapError(503, "BootstrapStateUnavailable") from None

    def _verify_administrator(self, context: BootstrapContext) -> None:
        try:
            self.directory.verify_administrator(context)
        except BootstrapError:
            raise
        except Exception:
            logger.warning("code=BootstrapAdministratorVerificationUnavailable")
            raise BootstrapError(503, "BootstrapAdministratorVerificationUnavailable") from None

    @staticmethod
    def _owned(row: Row, context: BootstrapContext) -> None:
        if (row.get("tenantId"), row.get("subscriptionId"), row.get("administratorId"),
                row.get("managementOrigin")) != (
                context.tenant_id, context.subscription_id, context.administrator_id,
                context.management_origin):
            raise BootstrapError(403, "BootstrapIdentityMismatch")

    def start(self, context: BootstrapContext) -> dict:
        key = "setup:" + context.installation_id
        row = self._read(key)
        if row is not None:
            self._owned(row, context)
            return self.status(context)
        self._verify_administrator(context)
        self._write({
            "PartitionKey": PARTITION, "RowKey": key, "status": "Pending",
            "tenantId": context.tenant_id, "subscriptionId": context.subscription_id,
            "administratorId": context.administrator_id,
            "managementOrigin": context.management_origin,
            "roleId": str(uuid4()), "pendingOperation": "",
            "createdAt": time.time(), "updatedAt": time.time(),
        })
        return self.status(context)

    def status(self, context: BootstrapContext) -> dict:
        row = self._read("setup:" + context.installation_id)
        if row is None:
            raise BootstrapError(404, "BootstrapNotFound")
        self._owned(row, context)
        return {key: row[key] for key in ("status", "pendingOperation", "createdAt", "updatedAt")}

    def _run_step(self, context: BootstrapContext, name: str, action) -> None:
        key = "setup:" + context.installation_id
        row = self._read(key)
        if row is None:
            raise BootstrapError(404, "BootstrapNotFound")
        self._owned(row, context)
        if row.get("pendingOperation"):
            raise BootstrapError(409, "BootstrapNeedsOperatorReview")
        row.update(status="Running", pendingOperation=name, updatedAt=time.time())
        self._write(row)
        try:
            values = action(row)
            if not isinstance(values, dict) or any(
                    key.lower().endswith(("secret", "privatekey", "token")) for key in values):
                raise ValueError("Invalid public bootstrap output")
            latest = self._read(key)
            if latest is None or latest.get("pendingOperation") != name:
                raise BootstrapError(409, "BootstrapFenceLost")
            self._owned(latest, context)
            latest.update(values)
            latest.update(status="Pending", pendingOperation="", updatedAt=time.time())
            self._write(latest)
        except Exception as error:
            try:
                latest = self._read(key)
                if latest is not None and latest.get("pendingOperation") == name:
                    latest.update(status="NeedsAttention", updatedAt=time.time())
                    self._write(latest)
            except BootstrapError:
                logger.error("code=BootstrapFailureStateUnavailable")
            if isinstance(error, BootstrapError):
                raise
            raise BootstrapError(503, "BootstrapNeedsOperatorReview") from None

    def run(self, context: BootstrapContext) -> dict:
        key = "setup:" + context.installation_id
        row = self._read(key)
        if row is None:
            raise BootstrapError(404, "BootstrapNotFound")
        self._owned(row, context)
        if row.get("pendingOperation"):
            raise BootstrapError(409, "BootstrapNeedsOperatorReview")
        if row.get("status") == "Ready":
            return self.status(context)
        self._verify_administrator(context)

        if not row.get("apiClientId"):
            def create_api(current):
                api = self.directory.create_api(context, str(current["roleId"]))
                return {"apiObjectId": api.object_id, "apiClientId": api.client_id,
                        "apiPrincipalId": api.principal_id}
            self._run_step(context, "CreateApi", create_api)
        row = self._read(key)
        if not row.get("managementClientId"):
            def create_management(current):
                app = self.directory.create_management(context, _app(current, "api"))
                if app.client_id == current["apiClientId"] or app.principal_id == current["apiPrincipalId"]:
                    raise ValueError("Provider identities must differ")
                return {"managementObjectId": app.object_id, "managementClientId": app.client_id,
                        "managementPrincipalId": app.principal_id}
            self._run_step(context, "CreateManagement", create_management)
        row = self._read(key)
        if row.get("permissionsVerified") is not True:
            def grant_permissions(current):
                app = _app(current, "management")
                self.directory.grant_management_permissions(context, app, GRAPH_PERMISSIONS)
                self.directory.verify_management_permissions(context, app, GRAPH_PERMISSIONS)
                return {"permissionsVerified": True}
            self._run_step(context, "GrantGraphPermissions", grant_permissions)
        row = self._read(key)
        if not row.get("managementCredentialVersion"):
            def create_credential(current):
                expires = (datetime.now(timezone.utc) + timedelta(days=30)).replace(microsecond=0).isoformat()
                credential = self.directory.add_management_credential(
                    context, _app(current, "management"), expires)
                if credential.expires_at != expires:
                    raise ValueError("Unexpected credential expiry")
                name = "faas-mgmt-" + credential.key_id.replace("-", "")
                version = self.vault.write(name, credential.secret, expires)
                self.vault.verify(name, version)
                return {"managementCredentialKeyId": credential.key_id,
                        "managementSecretName": name,
                        "managementCredentialExpiresOn": credential.expires_at,
                        "managementCredentialVersion": version}
            self._run_step(context, "CreateManagementCredential", create_credential)
        row = self._read(key)
        if not row.get("nvaSshPublicKey"):
            def create_ssh(current):
                private = Ed25519PrivateKey.generate()
                public = private.public_key().public_bytes(
                    serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
                material = private.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                    serialization.NoEncryption()).decode()
                name = "faas-ssh-" + context.installation_id[:24]
                version = self.vault.write(name, material)
                self.vault.verify(name, version)
                return {"nvaSshPublicKey": public, "sshSecretName": name,
                        "sshCredentialVersion": version}
            self._run_step(context, "CreateSshKey", create_ssh)
        row = self._read(key)
        try:
            self.directory.verify_management_permissions(context, _app(row, "management"), GRAPH_PERMISSIONS)
            self.vault.verify(str(row["managementSecretName"]), str(row["managementCredentialVersion"]))
            self.vault.verify(str(row["sshSecretName"]), str(row["sshCredentialVersion"]))
        except BootstrapError:
            raise
        except Exception:
            logger.warning("code=BootstrapFinalVerificationUnavailable")
            raise BootstrapError(503, "BootstrapFinalVerificationUnavailable") from None
        row.update(status="Ready", updatedAt=time.time())
        self._write(row)
        return self.status(context)

    def installation_parameters(self, context: BootstrapContext) -> dict:
        row = self._read("setup:" + context.installation_id)
        if row is None:
            raise BootstrapError(404, "BootstrapNotFound")
        self._owned(row, context)
        if row.get("status") != "Ready" or row.get("pendingOperation"):
            raise BootstrapError(409, "BootstrapNotReady")
        return {
            "providerTenantId": context.tenant_id,
            "providerSubscriptionId": context.subscription_id,
            "administratorObjectId": context.administrator_id,
            "apiApplicationId": row["apiClientId"],
            "apiRoleId": row["roleId"],
            "managementApplicationId": row["managementClientId"],
            "managementAppName": context.management_origin.removeprefix("https://").split(".")[0],
            "managementCredentialExpiresOn": row["managementCredentialExpiresOn"],
            "managementSecretName": row["managementSecretName"],
            "managementSecretVersion": row["managementCredentialVersion"],
            "nvaSshPublicKey": row["nvaSshPublicKey"],
        }
