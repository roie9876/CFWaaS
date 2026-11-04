"""Provider-only Check Point credential persistence; not wired into the live worker."""
import hashlib
import hmac
import json
import re
from dataclasses import dataclass

from azure.core.exceptions import AzureError, ResourceNotFoundError
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import KeyVaultSecret, SecretClient
from azure.mgmt.resource import ResourceManagementClient

from .checkpoint_credential_journal import CheckpointCredentialJournal
from .checkpoint_credentials import CheckpointCredentials, generate_checkpoint_credentials
from .checkpoint_private_data import (
    CheckpointPrivateDataReferences, validate_checkpoint_private_data_outputs,
    validate_checkpoint_vault_evidence,
)
from .config import uuid_text
from .store import Lease


CONTENT_TYPE = "application/vnd.faas.checkpoint-credentials+json"


class CheckpointVaultError(Exception):
    pass


class CheckpointCredentialPending(CheckpointVaultError):
    pass


@dataclass(frozen=True)
class CheckpointCredentialReference:
    vault_id: str
    name: str
    version: str


def decode_checkpoint_credential(secret: KeyVaultSecret, name: str, version: str, environment_id: str,
                                 fingerprint: str) -> CheckpointCredentials:
    properties = getattr(secret, "properties", None)
    value_text = getattr(secret, "value", None)
    if (getattr(secret, "name", None) != name or getattr(properties, "version", None) != version
            or getattr(properties, "enabled", None) is not True
            or getattr(properties, "content_type", None) != CONTENT_TYPE
            or getattr(properties, "tags", None) != {"purpose": "checkpoint-management-credentials",
                                                     "environmentId": environment_id}
            or not isinstance(value_text, str) or len(value_text) > 1024):
        raise CheckpointVaultError("Invalid Check Point credential version")
    try:
        digest = hashlib.sha256(value_text.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:
        raise CheckpointVaultError("Invalid Check Point credential version") from None
    if not hmac.compare_digest(digest, fingerprint):
        raise CheckpointVaultError("Check Point credential fingerprint mismatch")
    try:
        value = json.loads(value_text)
    except (TypeError, ValueError):
        raise CheckpointVaultError("Invalid Check Point credential version") from None
    if (not isinstance(value, dict) or set(value) != {"managementPassword", "sicKey"}
            or not isinstance(value["managementPassword"], str)
            or not 16 <= len(value["managementPassword"]) <= 72
            or not re.fullmatch(r"[A-Za-z0-9!@#%_+-]+", value["managementPassword"])
            or not all(re.search(pattern, value["managementPassword"])
                       for pattern in (r"[A-Z]", r"[a-z]", r"[0-9]", r"[!@#%_+-]"))
            or not isinstance(value["sicKey"], str)
            or not re.fullmatch(r"[0-9a-f]{48}", value["sicKey"])):
        raise CheckpointVaultError("Invalid Check Point credential version")
    return CheckpointCredentials(value["managementPassword"], value["sicKey"])


class CheckpointCredentialVault:
    def __init__(self, journal: CheckpointCredentialJournal, provider_tenant: str,
                 resources: ResourceManagementClient, credential: ManagedIdentityCredential) -> None:
        self.journal = journal
        self.provider_tenant = uuid_text(provider_tenant)
        self.resources = resources
        self.credential = credential

    def _verify_vault(self, lease: Lease, outputs: dict) -> CheckpointPrivateDataReferences:
        group_name = self.journal.group_name(lease)
        references = validate_checkpoint_private_data_outputs(
            outputs, self.journal.subscription, group_name, lease.environment_id)
        self.journal.store.checked_job(lease)
        try:
            vault = self.resources.resources.get_by_id(references.vault_id, "2023-07-01")
            endpoint = self.resources.resources.get_by_id(references.vault_endpoint_id, "2025-05-01")
        except AzureError:
            raise CheckpointVaultError("Check Point private vault evidence is unavailable") from None
        result = validate_checkpoint_vault_evidence(
            outputs, self.journal.subscription, self.provider_tenant, group_name, lease.environment_id,
            vault.as_dict(), endpoint.as_dict())
        self.journal.store.checked_job(lease)
        return result

    @staticmethod
    def _version(secret: KeyVaultSecret, name: str) -> str:
        version = getattr(getattr(secret, "properties", None), "version", None)
        if (getattr(secret, "name", None) != name or not isinstance(version, str)
                or not re.fullmatch(r"[0-9a-f]{32}", version)):
            raise CheckpointVaultError("Invalid Check Point credential version")
        return version

    def _client(self, references: CheckpointPrivateDataReferences) -> SecretClient:
        return SecretClient(references.vault_uri, self.credential, logging_enable=False,
                            retry_total=0, connection_timeout=5, read_timeout=20)

    def ensure(self, lease: Lease, outputs: dict) -> CheckpointCredentialReference:
        references = self._verify_vault(lease, outputs)
        reservation = self.journal.reserve(lease, references.vault_id)
        client = self._client(references)
        try:
            self.journal.store.checked_job(lease)
            if reservation.may_write_once:
                credentials = generate_checkpoint_credentials()
                value = json.dumps({"managementPassword": credentials.management_password,
                                    "sicKey": credentials.sic_key}, separators=(",", ":"))
                # Persist only a digest of high-entropy material before the single write.
                fingerprint = hashlib.sha256(value.encode()).hexdigest()
                self.journal.prepare(lease, references.vault_id, reservation.name, fingerprint)
                self.journal.store.checked_job(lease)
                secret = client.set_secret(
                    reservation.name, value, enabled=True, content_type=CONTENT_TYPE,
                    tags={"purpose": "checkpoint-management-credentials",
                          "environmentId": lease.environment_id},
                    logging_enable=False, retry_total=0, tracing_options={"enabled": False})
                version = self._version(secret, reservation.name)
            elif reservation.version is None:
                fingerprint = reservation.fingerprint
                if fingerprint is None:
                    raise CheckpointCredentialPending("Check Point credential write is not yet resolved")
                versions = iter(client.list_properties_of_secret_versions(
                    reservation.name, logging_enable=False, retry_total=0, tracing_options={"enabled": False}))
                first = next(versions, None)
                if first is None:
                    raise CheckpointCredentialPending("Check Point credential write is not yet resolved")
                if next(versions, None) is not None:
                    raise CheckpointVaultError("Multiple Check Point credential versions require review")
                version = first.version
                if not isinstance(version, str) or not re.fullmatch(r"[0-9a-f]{32}", version):
                    raise CheckpointVaultError("Invalid Check Point credential version")
                secret = client.get_secret(reservation.name, version, logging_enable=False, retry_total=0,
                                           tracing_options={"enabled": False})
            else:
                version = reservation.version
                fingerprint = reservation.fingerprint
                if fingerprint is None:
                    raise CheckpointVaultError("Check Point credential fingerprint is missing")
                secret = client.get_secret(reservation.name, version, logging_enable=False, retry_total=0,
                                           tracing_options={"enabled": False})
            decode_checkpoint_credential(secret, reservation.name, version, lease.environment_id, fingerprint)
            self.journal.bind(lease, references.vault_id, reservation.name, version)
            return CheckpointCredentialReference(references.vault_id, reservation.name, version)
        except ResourceNotFoundError:
            raise CheckpointCredentialPending("Check Point credential write is not yet resolved") from None
        except AzureError:
            raise CheckpointVaultError("Check Point credential vault operation failed; reconcile before retry") from None
        finally:
            client.close()

    def read(self, lease: Lease, outputs: dict) -> CheckpointCredentials:
        references = self._verify_vault(lease, outputs)
        reservation = self.journal.bound(lease, references.vault_id)
        version = reservation.version
        fingerprint = reservation.fingerprint
        if version is None or fingerprint is None:
            raise CheckpointVaultError("Check Point credential version is not bound")
        client = self._client(references)
        try:
            self.journal.store.checked_job(lease)
            secret = client.get_secret(reservation.name, version, logging_enable=False, retry_total=0,
                                       tracing_options={"enabled": False})
            credentials = decode_checkpoint_credential(secret, reservation.name, version, lease.environment_id, fingerprint)
            self.journal.store.checked_job(lease)
            return credentials
        except AzureError:
            raise CheckpointVaultError("Check Point credential vault read failed") from None
        finally:
            client.close()
