import json
import re
import time
from dataclasses import dataclass, field
from uuid import uuid4

from .config import uuid_text
from .models import environment_resource_group_name, parse_stored_environment_request
from .store import Conflict, Lease, LostLease, Row, Store


class CheckpointCredentialStateError(ValueError):
    pass


@dataclass(frozen=True)
class CheckpointCredentialReservation:
    name: str
    version: str | None
    vault_id: str
    fingerprint: str | None = field(repr=False)
    may_write_once: bool


class CheckpointCredentialJournal:
    """Lease-fenced, one-shot reservation of non-secret credential references."""

    def __init__(self, store: Store, provider_subscription: str) -> None:
        self.store = store
        self.subscription = uuid_text(provider_subscription)

    def _operation(self, lease: Lease) -> tuple[Row, Row]:
        job = self.store.checked_job(lease)
        operation = self.store.operation(lease)
        group_name = operation.get("providerGroupName")
        try:
            request, _, isolated = parse_stored_environment_request(str(operation["request"]))
            if (not isinstance(group_name, str) or not group_name.startswith("rg-faas-env-")
                    or environment_resource_group_name(group_name.removeprefix("rg-faas-env-")) != group_name):
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise CheckpointCredentialStateError("Invalid Check Point credential operation") from None
        expected = f"/subscriptions/{self.subscription}/resourceGroups/{group_name}"
        if (operation.get("environmentId") != lease.environment_id
                or operation.get("status") != "Running"
                or request.mode != "network" or request.firewallType != "checkpoint-byol"
                or not isolated or operation.get("providerGroupMode") != "isolated"
                or operation.get("providerGroupState") != "created"
                or str(operation.get("providerGroupId", "")).lower() != expected.lower()):
            raise CheckpointCredentialStateError("Invalid Check Point credential operation")
        return job, operation

    @staticmethod
    def _reference(operation: Row) -> dict | None:
        raw = operation.get("checkpointCredentialRef")
        if raw is None:
            return None
        try:
            value = json.loads(str(raw))
        except (TypeError, ValueError):
            raise CheckpointCredentialStateError("Invalid Check Point credential reference") from None
        if (not isinstance(value, dict)
                or set(value) != {"name", "state", "version", "vaultId", "fingerprint", "writerFence"}
                or not isinstance(value["name"], str)
                or not re.fullmatch(r"cp-credentials-[0-9a-f]{32}", value["name"])
                or not isinstance(value["vaultId"], str)
                or not isinstance(value["state"], str)
                or value["state"] not in {"reserved", "bound"}
                or not isinstance(value["version"], str)
                or not isinstance(value["fingerprint"], str)
                or type(value["writerFence"]) is not int or value["writerFence"] < 1
                or (value["fingerprint"] != "" and not re.fullmatch(r"[0-9a-f]{64}", value["fingerprint"]))
                or (value["state"] == "reserved" and value["version"] != "")
                or (value["state"] == "bound" and
                    (not re.fullmatch(r"[0-9a-f]{32}", value["version"]) or not value["fingerprint"]))):
            raise CheckpointCredentialStateError("Invalid Check Point credential reference")
        return value

    @staticmethod
    def _vault_id(operation: Row, vault_id: str) -> str:
        prefix = str(operation["providerGroupId"]).lower() + "/providers/microsoft.keyvault/vaults/"
        if (not isinstance(vault_id, str) or not vault_id.lower().startswith(prefix)
                or not re.fullmatch(r"kvcp[a-z0-9]{13}", vault_id.lower()[len(prefix):])):
            raise CheckpointCredentialStateError("Invalid Check Point credential vault scope")
        return vault_id.lower()

    def group_name(self, lease: Lease) -> str:
        _, operation = self._operation(lease)
        return str(operation["providerGroupName"])

    def scoped_operation(self, lease: Lease) -> tuple[Row, Row]:
        return self._operation(lease)

    def reserve(self, lease: Lease, vault_id: str) -> CheckpointCredentialReservation:
        for _ in range(8):
            job, operation = self._operation(lease)
            vault_id = self._vault_id(operation, vault_id)
            reference = self._reference(operation)
            if reference is not None:
                if reference["vaultId"] != vault_id:
                    raise CheckpointCredentialStateError("Check Point credential vault mismatch")
                if reference["writerFence"] > lease.fence:
                    raise CheckpointCredentialStateError("Invalid Check Point credential writer fence")
                if (reference["state"] == "reserved" and not reference["fingerprint"]
                        and reference["writerFence"] < lease.fence):
                    reference["writerFence"] = lease.fence
                    operation["checkpointCredentialRef"] = json.dumps(reference, sort_keys=True, separators=(",", ":"))
                    operation["updatedAt"] = time.time()
                    try:
                        self.store.backend.transact([self.store._change(job), self.store._change(operation)])
                        return CheckpointCredentialReservation(reference["name"], None, vault_id, None, True)
                    except Conflict:
                        continue
                return CheckpointCredentialReservation(
                    reference["name"], reference["version"] or None, vault_id,
                    reference["fingerprint"] or None, False)
            reference = {"name": "cp-credentials-" + uuid4().hex, "state": "reserved",
                         "version": "", "vaultId": vault_id, "fingerprint": "", "writerFence": lease.fence}
            operation["checkpointCredentialRef"] = json.dumps(reference, sort_keys=True, separators=(",", ":"))
            operation["updatedAt"] = time.time()
            try:
                self.store.backend.transact([self.store._change(job), self.store._change(operation)])
                return CheckpointCredentialReservation(reference["name"], None, vault_id, None, True)
            except Conflict:
                continue
        raise LostLease()

    def bound(self, lease: Lease, vault_id: str) -> CheckpointCredentialReservation:
        _, operation = self._operation(lease)
        vault_id = self._vault_id(operation, vault_id)
        reference = self._reference(operation)
        if reference is None or reference["vaultId"] != vault_id or reference["state"] != "bound":
            raise CheckpointCredentialStateError("Check Point credential version is not bound")
        return CheckpointCredentialReservation(
            reference["name"], reference["version"], vault_id, reference["fingerprint"], False)

    def prepare(self, lease: Lease, vault_id: str, name: str, fingerprint: str) -> None:
        if (not isinstance(name, str) or not re.fullmatch(r"cp-credentials-[0-9a-f]{32}", name)
                or not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)):
            raise CheckpointCredentialStateError("Invalid Check Point credential preparation")
        for _ in range(8):
            job, operation = self._operation(lease)
            vault_id = self._vault_id(operation, vault_id)
            reference = self._reference(operation)
            if (reference is None or reference["name"] != name or reference["vaultId"] != vault_id
                    or reference["state"] != "reserved" or reference["writerFence"] != lease.fence):
                raise CheckpointCredentialStateError("Check Point credential reservation mismatch")
            if reference["fingerprint"]:
                if reference["fingerprint"] != fingerprint:
                    raise CheckpointCredentialStateError("Check Point credential fingerprint mismatch")
                return
            reference["fingerprint"] = fingerprint
            operation["checkpointCredentialRef"] = json.dumps(reference, sort_keys=True, separators=(",", ":"))
            operation["updatedAt"] = time.time()
            try:
                self.store.backend.transact([self.store._change(job), self.store._change(operation)])
                return
            except Conflict:
                continue
        raise LostLease()

    def bind(self, lease: Lease, vault_id: str, name: str, version: str) -> None:
        if (not isinstance(name, str) or not re.fullmatch(r"cp-credentials-[0-9a-f]{32}", name)
                or not isinstance(version, str) or not re.fullmatch(r"[0-9a-f]{32}", version)):
            raise CheckpointCredentialStateError("Invalid Check Point credential reference")
        for _ in range(8):
            job, operation = self._operation(lease)
            vault_id = self._vault_id(operation, vault_id)
            reference = self._reference(operation)
            if (reference is None or reference["name"] != name or reference["vaultId"] != vault_id
                    or not reference["fingerprint"]):
                raise CheckpointCredentialStateError("Check Point credential reservation mismatch")
            if reference["state"] == "bound":
                if reference["version"] != version:
                    raise CheckpointCredentialStateError("Check Point credential version mismatch")
                return
            reference.update(state="bound", version=version)
            operation["checkpointCredentialRef"] = json.dumps(reference, sort_keys=True, separators=(",", ":"))
            operation["updatedAt"] = time.time()
            try:
                self.store.backend.transact([self.store._change(job), self.store._change(operation)])
                return
            except Conflict:
                continue
        raise LostLease()
