"""Lease-fenced, one-shot reservation of a Check Point Terraform apply."""
import json
import re
import time
from dataclasses import dataclass, field

from .checkpoint_credential_journal import CheckpointCredentialJournal
from .config import uuid_text
from .store import Conflict, Lease, LostLease, Row


def checkpoint_runner_resource_id(group_id: str, environment_id: str) -> str:
    uuid_text(environment_id)
    return (group_id + "/providers/Microsoft.ContainerInstance/containerGroups/cg-cp-runner-" + environment_id)


def checkpoint_runner_job_id(operation: Row, lease: Lease) -> str:
    return checkpoint_runner_resource_id(str(operation["providerGroupId"]), lease.environment_id)


class CheckpointApplyStateError(ValueError):
    pass


@dataclass(frozen=True)
class CheckpointApplyReservation:
    job_id: str
    plan_sha256: str = field(repr=False)
    state: str
    may_start_once: bool


class CheckpointApplyJournal:
    def __init__(self, scope: CheckpointCredentialJournal) -> None:
        self.scope = scope
        self.store = scope.store

    @staticmethod
    def _inputs(operation: Row, lease: Lease, job_id: str, plan_sha256: str) -> tuple[str, str]:
        expected = checkpoint_runner_job_id(operation, lease)
        if (not isinstance(job_id, str) or job_id.lower() != expected.lower()
                or not isinstance(plan_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", plan_sha256)):
            raise CheckpointApplyStateError("Invalid Check Point apply reference")
        return expected.lower(), plan_sha256

    @staticmethod
    def _reference(operation: Row) -> dict | None:
        raw = operation.get("checkpointApplyRef")
        if raw is None:
            return None
        try:
            value = json.loads(str(raw))
        except (TypeError, ValueError):
            raise CheckpointApplyStateError("Invalid Check Point apply state") from None
        if (not isinstance(value, dict) or set(value) != {"jobId", "planSha256", "state"}
                or not isinstance(value["jobId"], str)
                or not isinstance(value["planSha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", value["planSha256"])
                or not isinstance(value["state"], str) or value["state"] not in {"starting", "succeeded"}):
            raise CheckpointApplyStateError("Invalid Check Point apply state")
        return value

    def reserve(self, lease: Lease, job_id: str, plan_sha256: str) -> CheckpointApplyReservation:
        for _ in range(8):
            job, operation = self.scope.scoped_operation(lease)
            job_id, plan_sha256 = self._inputs(operation, lease, job_id, plan_sha256)
            reference = self._reference(operation)
            if reference is not None:
                if reference["jobId"] != job_id or reference["planSha256"] != plan_sha256:
                    raise CheckpointApplyStateError("Check Point apply reference mismatch")
                return CheckpointApplyReservation(job_id, plan_sha256, reference["state"], False)
            reference = {"jobId": job_id, "planSha256": plan_sha256, "state": "starting"}
            operation["checkpointApplyRef"] = json.dumps(reference, sort_keys=True, separators=(",", ":"))
            operation["updatedAt"] = time.time()
            try:
                self.store.backend.transact([self.store._change(job), self.store._change(operation)])
                return CheckpointApplyReservation(job_id, plan_sha256, "starting", True)
            except Conflict:
                continue
        raise LostLease()

    def succeed(self, lease: Lease, job_id: str, plan_sha256: str, exit_code: int) -> None:
        if type(exit_code) is not int or exit_code != 0:
            raise CheckpointApplyStateError("Check Point apply did not complete successfully")
        for _ in range(8):
            job, operation = self.scope.scoped_operation(lease)
            job_id, plan_sha256 = self._inputs(operation, lease, job_id, plan_sha256)
            reference = self._reference(operation)
            if (reference is None or reference["jobId"] != job_id
                    or reference["planSha256"] != plan_sha256):
                raise CheckpointApplyStateError("Check Point apply reference mismatch")
            if reference["state"] == "succeeded":
                return
            reference["state"] = "succeeded"
            operation["checkpointApplyRef"] = json.dumps(reference, sort_keys=True, separators=(",", ":"))
            operation["updatedAt"] = time.time()
            try:
                self.store.backend.transact([self.store._change(job), self.store._change(operation)])
                return
            except Conflict:
                continue
        raise LostLease()
