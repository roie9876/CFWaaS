"""Lease-fenced single-launch state for a Check Point container job."""
import json
import re
import time
from dataclasses import dataclass, field

from .checkpoint_apply_journal import checkpoint_runner_job_id
from .checkpoint_credential_journal import CheckpointCredentialJournal
from .store import Conflict, Lease, LostLease, Row


class CheckpointRunnerStateError(ValueError):
    pass


@dataclass(frozen=True)
class CheckpointRunnerReservation:
    job_id: str
    spec_sha256: str = field(repr=False)
    state: str
    exit_code: int | None
    may_prepare: bool


class CheckpointRunnerJournal:
    def __init__(self, scope: CheckpointCredentialJournal) -> None:
        self.scope = scope
        self.store = scope.store

    @staticmethod
    def _inputs(operation: Row, lease: Lease, job_id: str, spec_sha256: str) -> tuple[str, str]:
        try:
            expected = checkpoint_runner_job_id(operation, lease)
        except (KeyError, ValueError, TypeError):
            raise CheckpointRunnerStateError("Invalid Check Point runner scope") from None
        if (not isinstance(job_id, str) or job_id.lower() != expected.lower()
                or not isinstance(spec_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", spec_sha256)):
            raise CheckpointRunnerStateError("Invalid Check Point runner reference")
        return expected.lower(), spec_sha256

    @staticmethod
    def _reference(operation: Row) -> dict | None:
        raw = operation.get("checkpointRunnerRef")
        if raw is None:
            return None
        try:
            value = json.loads(str(raw))
        except (TypeError, ValueError):
            raise CheckpointRunnerStateError("Invalid Check Point runner state") from None
        if (not isinstance(value, dict)
                or set(value) != {"jobId", "specSha256", "state", "writerFence", "exitCode"}
                or not isinstance(value["jobId"], str)
                or not isinstance(value["specSha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", value["specSha256"])
                or not isinstance(value["state"], str)
                or value["state"] not in {"reserved", "launching", "running", "succeeded", "failed"}
                or type(value["writerFence"]) is not int or value["writerFence"] < 1
                or (value["state"] in {"reserved", "launching", "running"} and value["exitCode"] is not None)
                or (value["state"] == "succeeded" and
                    (type(value["exitCode"]) is not int or value["exitCode"] != 0))
                or (value["state"] == "failed" and
                    (value["exitCode"] is not None
                     and (type(value["exitCode"]) is not int or not 1 <= value["exitCode"] <= 255)))):
            raise CheckpointRunnerStateError("Invalid Check Point runner state")
        return value

    def reserve(self, lease: Lease, job_id: str, spec_sha256: str) -> CheckpointRunnerReservation:
        for _ in range(8):
            job, operation = self.scope.scoped_operation(lease)
            job_id, spec_sha256 = self._inputs(operation, lease, job_id, spec_sha256)
            reference = self._reference(operation)
            if reference is not None:
                if reference["jobId"] != job_id or reference["specSha256"] != spec_sha256:
                    raise CheckpointRunnerStateError("Check Point runner reference mismatch")
                if reference["writerFence"] > lease.fence:
                    raise CheckpointRunnerStateError("Invalid Check Point runner fence")
                if reference["state"] == "reserved" and reference["writerFence"] < lease.fence:
                    reference["writerFence"] = lease.fence
                    operation["checkpointRunnerRef"] = json.dumps(reference, sort_keys=True, separators=(",", ":"))
                    operation["updatedAt"] = time.time()
                    try:
                        self.store.backend.transact([self.store._change(job), self.store._change(operation)])
                        return CheckpointRunnerReservation(job_id, spec_sha256, "reserved", None, True)
                    except Conflict:
                        continue
                return CheckpointRunnerReservation(
                    job_id, spec_sha256, reference["state"], reference["exitCode"], False)
            reference = {"jobId": job_id, "specSha256": spec_sha256, "state": "reserved",
                         "writerFence": lease.fence, "exitCode": None}
            operation["checkpointRunnerRef"] = json.dumps(reference, sort_keys=True, separators=(",", ":"))
            operation["updatedAt"] = time.time()
            try:
                self.store.backend.transact([self.store._change(job), self.store._change(operation)])
                return CheckpointRunnerReservation(job_id, spec_sha256, "reserved", None, True)
            except Conflict:
                continue
        raise LostLease()

    def read(self, lease: Lease, job_id: str, spec_sha256: str) -> CheckpointRunnerReservation:
        _, operation = self.scope.scoped_operation(lease)
        job_id, spec_sha256 = self._inputs(operation, lease, job_id, spec_sha256)
        reference = self._reference(operation)
        if (reference is None or reference["jobId"] != job_id
                or reference["specSha256"] != spec_sha256):
            raise CheckpointRunnerStateError("Check Point runner reference mismatch")
        if reference["writerFence"] > lease.fence:
            raise CheckpointRunnerStateError("Invalid Check Point runner fence")
        return CheckpointRunnerReservation(
            job_id, spec_sha256, reference["state"], reference["exitCode"], False)

    def begin_launch(self, lease: Lease, job_id: str, spec_sha256: str) -> bool:
        for _ in range(8):
            job, operation = self.scope.scoped_operation(lease)
            job_id, spec_sha256 = self._inputs(operation, lease, job_id, spec_sha256)
            reference = self._reference(operation)
            if (reference is None or reference["jobId"] != job_id
                    or reference["specSha256"] != spec_sha256):
                raise CheckpointRunnerStateError("Check Point runner reference mismatch")
            if reference["state"] != "reserved":
                return False
            if reference["writerFence"] != lease.fence:
                raise CheckpointRunnerStateError("Check Point runner reservation is not owned")
            reference["state"] = "launching"
            operation["checkpointRunnerRef"] = json.dumps(reference, sort_keys=True, separators=(",", ":"))
            operation["updatedAt"] = time.time()
            try:
                self.store.backend.transact([self.store._change(job), self.store._change(operation)])
                return True
            except Conflict:
                continue
        raise LostLease()

    def observe_running(self, lease: Lease, job_id: str, spec_sha256: str) -> None:
        self._transition(lease, job_id, spec_sha256, "running", None)

    def finish(self, lease: Lease, job_id: str, spec_sha256: str, exit_code: int) -> None:
        if type(exit_code) is not int or not 0 <= exit_code <= 255:
            raise CheckpointRunnerStateError("Invalid Check Point runner exit code")
        self._transition(lease, job_id, spec_sha256, "succeeded" if exit_code == 0 else "failed", exit_code)

    def fail_provisioning(self, lease: Lease, job_id: str, spec_sha256: str) -> None:
        self._transition(lease, job_id, spec_sha256, "failed", None)

    def _transition(self, lease: Lease, job_id: str, spec_sha256: str,
                    state: str, exit_code: int | None) -> None:
        for _ in range(8):
            job, operation = self.scope.scoped_operation(lease)
            job_id, spec_sha256 = self._inputs(operation, lease, job_id, spec_sha256)
            reference = self._reference(operation)
            if (reference is None or reference["jobId"] != job_id
                    or reference["specSha256"] != spec_sha256):
                raise CheckpointRunnerStateError("Check Point runner reference mismatch")
            if reference["state"] == state and reference["exitCode"] == exit_code:
                return
            if reference["state"] not in {"launching", "running"}:
                raise CheckpointRunnerStateError("Invalid Check Point runner transition")
            reference.update(state=state, exitCode=exit_code)
            operation["checkpointRunnerRef"] = json.dumps(reference, sort_keys=True, separators=(",", ":"))
            operation["updatedAt"] = time.time()
            try:
                self.store.backend.transact([self.store._change(job), self.store._change(operation)])
                return
            except Conflict:
                continue
        raise LostLease()
