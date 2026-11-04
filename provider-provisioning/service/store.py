import hashlib
import json
import time
from dataclasses import dataclass
from typing import Protocol
from uuid import NAMESPACE_URL, uuid4, uuid5

from .auth import Owner
from .config import Settings
from .models import (
    EnvironmentRequest, environment_resource_group_name, parse_stored_environment_request,
    stored_environment_request,
)

Row = dict[str, object]

# Provider-side validation failures whose stages are idempotent: the retained group, foundation,
# keys and runner journal are reused, and a launched runner is observed, never relaunched.
RESUMABLE_CHECKPOINT_CODES = frozenset({
    "InvalidCheckpointFoundation", "InvalidCheckpointRunner", "CheckpointRunnerUnconfirmed"})


class Conflict(Exception):
    pass


class StoreUnavailable(Exception):
    pass


class DomainError(Exception):
    def __init__(self, status: int, code: str) -> None:
        self.status, self.code = status, code


class LostLease(Exception):
    pass


@dataclass
class Change:
    row: Row
    etag: str | None = None


class Backend(Protocol):
    def get(self, partition: str, key: str) -> Row | None: ...
    def transact(self, changes: list[Change]) -> None: ...
    def jobs(self, partition: str) -> list[Row]: ...


@dataclass(frozen=True)
class Lease:
    environment_id: str
    owner: str
    fence: int


class Store:
    def __init__(self, backend: Backend, settings: Settings) -> None:
        if settings.customer is None:
            raise ValueError("Operation stores require a bound customer")
        self.backend, self.settings = backend, settings
        self.allocation_key = settings.customer_allocation_key or settings.customer.tenant
        self.partition = ("registry:" + str(settings.authority_tenant)
                          if settings.auth_mode == "provider-api-registry" else settings.customer.tenant)

    def _row(self, key: str, **values: object) -> Row:
        return {"PartitionKey": self.partition, "RowKey": key, **values}

    def _quota(self) -> Row:
        return self.backend.get(self.partition, "quota") or self._row(
            "quota", allocated=0, active=0, callers="{}", running="{}", allocations="{}")

    @staticmethod
    def _change(row: Row) -> Change:
        etag = row.get("_etag")
        return Change(row, str(etag) if etag else None)

    @staticmethod
    def _counter(row: Row, field: str, caller: str, delta: int) -> int:
        counters = json.loads(str(row[field]))
        counters[caller] = max(0, counters.get(caller, 0) + delta)
        row[field] = json.dumps(counters, sort_keys=True)
        return counters[caller]

    def reserve(self, owner: Owner, key: str, body: EnvironmentRequest) -> Row:
        expected = self.settings.customer
        if expected is None:
            raise StoreUnavailable("Bound customer unavailable")
        if ((self.settings.auth_mode != "provider-api-registry" and owner.tenant != self.partition)
                or (self.settings.auth_mode == "provider-api-registry"
                    and (owner.tenant, owner.principal, owner.client) !=
                    (expected.tenant, expected.principal, expected.client))):
            raise DomainError(404, "NotFound")
        if not 1 <= len(key) <= 128 or any(ord(c) < 33 or ord(c) > 126 for c in key):
            raise DomainError(400, "InvalidIdempotencyKey")
        checkpoint = body.firewallType != "ubuntu"
        if checkpoint and not (self.settings.checkpoint_enabled and body.mode == "network"
                               and body.region == "eastus2"):
            raise DomainError(409, "CheckpointDeploymentUnavailable")
        identity = f"{owner.tenant}:{owner.key}:{key}"
        digest = hashlib.sha256(identity.encode()).hexdigest()
        environment_id = str(uuid5(NAMESPACE_URL, "faas:" + digest))
        idem_key = "idem:" + digest
        for attempt in range(8):
            existing = self.backend.get(self.partition, idem_key)
            if existing:
                if existing["digest"] != body.digest():
                    raise DomainError(409, "IdempotencyConflict")
                operation = self.owned(owner, environment_id)
                if self._checkpoint_resumable(operation, owner):
                    return self._resume_checkpoint(owner, environment_id)
                return operation
            quota = self._quota()
            count = json.loads(str(quota["callers"])).get(owner.key, 0)
            quota.setdefault("allocations", "{}")
            if count >= self.settings.max_caller_active:
                raise DomainError(429, "CallerActiveLimit")
            quota["allocated"] = int(quota["allocated"]) + 1
            quota["active"] = int(quota["active"]) + 1
            self._counter(quota, "callers", owner.key, 1)
            self._counter(quota, "allocations", self.allocation_key, 1)
            group_mode = self.settings.provider_group_mode if body.mode == "network" else "shared"
            operation = self._row(
                "op:" + environment_id, environmentId=environment_id,
                tenant=owner.tenant, principal=owner.principal, client=owner.client,
                allocationKey=self.allocation_key,
                providerGroupMode=group_mode,
                providerGroupName=(environment_resource_group_name(str(uuid4()))
                                   if group_mode == "isolated" else ""),
                caller=owner.key, status="Pending",
                request=stored_environment_request(
                    body, self.settings.parallel_provider_networking and body.mode == "network" and not checkpoint,
                    group_mode == "isolated"),
                createdAt=time.time(), updatedAt=time.time(), manifest="{}",
                errorCode="", errorMessage="", secretVersions="{}",
            )
            changes = [
                self._change(quota),
                Change(self._row(idem_key, digest=body.digest(), environmentId=environment_id)),
                Change(operation),
                Change(self._row("job:" + environment_id, environmentId=environment_id,
                                 status="pending", leaseOwner="", leaseUntil=0.0,
                                 fence=0, attempts=0, nextAttempt=0.0)),
            ]
            try:
                self.backend.transact(changes)
                return operation
            except Conflict:
                time.sleep(min(0.005 * 2**attempt, 0.2))
        raise StoreUnavailable("Reservation contention")

    def owned(self, owner: Owner, environment_id: str) -> Row:
        row = self.backend.get(self.partition, "op:" + environment_id)
        if not row or (row["tenant"], row["principal"], row["client"]) != (
                owner.tenant, owner.principal, owner.client):
            raise DomainError(404, "NotFound")
        return row

    def retry_failed_group(self, owner: Owner, environment_id: str) -> Row:
        for _ in range(8):
            operation = self.owned(owner, environment_id)
            if self.settings.auth_mode != "provider-api-registry" or not self._belongs(operation):
                raise DomainError(404, "NotFound")
            # Concurrent or repeated requests for an in-flight retry are idempotent; a retry that
            # failed again may be retried, still bounded by the job's attempt limit.
            if operation.get("groupRetryRequested") is True and operation["status"] != "Failed":
                return operation
            if (operation["status"] != "Failed" or operation["errorCode"] != "GroupOwnershipError"
                    or operation.get("decommissionState")
                    or operation.get("providerGroupMode") != "isolated"
                    # "new" failed before any application was requested; the worker rechecks that
                    # neither the application nor the group exists before creating them.
                    or operation.get("providerGroupState", "new") not in ("new", "creating")
                    or operation.get("providerGroupId")
                    or operation.get("caller") != owner.key
                    or operation.get("secretVersions") != "{}"):
                raise DomainError(409, "GroupRetryNotEligible")
            try:
                request, _, isolated = parse_stored_environment_request(str(operation["request"]))
                name = str(operation["providerGroupName"])
                if (not isolated or request.mode != "network"
                        or not name.startswith("rg-faas-env-")
                        or environment_resource_group_name(name.removeprefix("rg-faas-env-")) != name):
                    raise ValueError()
            except (KeyError, TypeError, ValueError):
                raise DomainError(409, "GroupRetryNotEligible") from None
            job = self.backend.get(self.partition, "job:" + environment_id)
            quota = self.backend.get(self.partition, "quota")
            if (not job or not quota or job.get("status") != "done"
                    or job.get("leaseOwner") or float(job.get("leaseUntil", 0)) != 0
                    or int(job["attempts"]) >= self.settings.max_attempts):
                raise DomainError(409, "GroupRetryNotEligible")
            callers = json.loads(str(quota["callers"]))
            allocations = json.loads(str(quota["allocations"]))
            if (int(quota["allocated"]) < 1
                    or allocations.get(str(operation.get("allocationKey")), 0) < 1):
                raise DomainError(409, "GroupRetryNotEligible")
            if callers.get(owner.key, 0) >= self.settings.max_caller_active:
                raise DomainError(429, "CallerActiveLimit")
            quota["active"] = int(quota["active"]) + 1
            self._counter(quota, "callers", owner.key, 1)
            job.update(status="pending", leaseOwner="", leaseUntil=0.0, nextAttempt=0.0)
            operation.update(status="Pending", errorCode="", errorMessage="",
                             groupRetryRequested=True, updatedAt=time.time())
            try:
                self.backend.transact([self._change(quota), self._change(job),
                                       self._change(operation)])
                return operation
            except Conflict:
                continue
        raise StoreUnavailable("Group retry contention")

    def _checkpoint_resumable(self, operation: Row, owner: Owner) -> bool:
        """A Check Point environment whose provider-side validation failed after its retained
        group and foundation were created resumes from those resources on the same request."""
        if (operation.get("status") != "Failed"
                or operation.get("errorCode") not in RESUMABLE_CHECKPOINT_CODES
                or operation.get("decommissionState") or operation.get("allocationReleased")
                or operation.get("providerGroupMode") != "isolated"
                or operation.get("providerGroupState") != "created"
                or not operation.get("providerGroupId")
                or operation.get("caller") != owner.key):
            return False
        try:
            request, _, _ = parse_stored_environment_request(str(operation["request"]))
        except (KeyError, TypeError, ValueError):
            return False
        return request.firewallType == "checkpoint-byol" and request.mode == "network"

    def _resume_checkpoint(self, owner: Owner, environment_id: str) -> Row:
        for _ in range(8):
            operation = self.owned(owner, environment_id)
            if not self._checkpoint_resumable(operation, owner):
                return operation
            job = self.backend.get(self.partition, "job:" + environment_id)
            quota = self.backend.get(self.partition, "quota")
            if (not job or not quota or job.get("status") != "done"
                    or job.get("leaseOwner") or float(job.get("leaseUntil", 0)) != 0
                    or int(job["attempts"]) >= self.settings.max_attempts):
                return operation
            if json.loads(str(quota["callers"])).get(owner.key, 0) >= self.settings.max_caller_active:
                raise DomainError(429, "CallerActiveLimit")
            quota["active"] = int(quota["active"]) + 1
            self._counter(quota, "callers", owner.key, 1)
            job.update(status="pending", leaseOwner="", leaseUntil=0.0, nextAttempt=0.0)
            operation.update(status="Pending", errorCode="", errorMessage="", updatedAt=time.time())
            try:
                self.backend.transact([self._change(quota), self._change(job), self._change(operation)])
                return operation
            except Conflict:
                continue
        raise StoreUnavailable("Check Point resume contention")

    def candidates(self) -> list[Row]:
        jobs = self.backend.jobs(self.partition)
        if self.settings.auth_mode != "provider-api-registry":
            return jobs
        return [job for job in jobs if self._belongs(
            self.backend.get(self.partition, "op:" + str(job["environmentId"])))]

    def _belongs(self, operation: Row | None) -> bool:
        customer = self.settings.customer
        return bool(operation and customer and
                    (operation["tenant"], operation["principal"], operation["client"]) ==
                    (customer.tenant, customer.principal, customer.client))

    def claim(self, environment_id: str, worker_id: str, now: float | None = None) -> Lease | None:
        now = time.time() if now is None else now
        for _ in range(8):
            job = self.backend.get(self.partition, "job:" + environment_id)
            operation = self.backend.get(self.partition, "op:" + environment_id)
            if self.settings.auth_mode == "provider-api-registry" and not self._belongs(operation):
                return None
            if (not job or not operation or job["status"] not in ("pending", "retry", "busy")
                    or float(job["nextAttempt"]) > now
                    or (job["status"] == "busy" and float(job["leaseUntil"]) > now)):
                return None
            quota = self._quota()
            # A crashed busy claim already owns its running slot.
            if job["status"] != "busy":
                running = json.loads(str(quota["running"])).get(str(operation["caller"]), 0)
                if running >= self.settings.max_caller_running:
                    return None
                self._counter(quota, "running", str(operation["caller"]), 1)
            job.update(status="busy", leaseOwner=worker_id,
                       leaseUntil=now + self.settings.lease_seconds,
                       fence=int(job["fence"]) + 1, attempts=int(job["attempts"]) + 1)
            operation.update(status="Running", updatedAt=now)
            try:
                self.backend.transact([self._change(quota), self._change(job),
                                       self._change(operation)])
                return Lease(environment_id, worker_id, int(job["fence"]))
            except Conflict:
                continue
        return None

    def checked_job(self, lease: Lease, now: float | None = None) -> Row:
        job = self.backend.get(self.partition, "job:" + lease.environment_id)
        now = time.time() if now is None else now
        if (not job or job["status"] != "busy" or job["leaseOwner"] != lease.owner
                or job["fence"] != lease.fence or float(job["leaseUntil"]) <= now):
            raise LostLease()
        return job

    def renew(self, lease: Lease) -> None:
        for _ in range(8):
            job = self.checked_job(lease)
            job["leaseUntil"] = time.time() + self.settings.lease_seconds
            try:
                self.backend.transact([self._change(job)])
                return
            except Conflict:
                continue
        raise LostLease()

    def operation(self, lease: Lease) -> Row:
        self.checked_job(lease)
        operation = self.backend.get(self.partition, "op:" + lease.environment_id)
        if not operation:
            raise LostLease()
        return operation

    def begin_provider_group(self, lease: Lease) -> None:
        for _ in range(8):
            job = self.checked_job(lease)
            operation = self.operation(lease)
            if (operation.get("providerGroupMode") != "isolated"
                    or operation.get("providerGroupState", "new") != "new"
                    or not operation.get("providerGroupName")):
                raise LostLease()
            operation["providerGroupState"] = "creating"
            try:
                self.backend.transact([self._change(job), self._change(operation)])
                return
            except Conflict:
                continue
        raise LostLease()

    def bind_provider_group(self, lease: Lease, subscription: str, scope: str) -> None:
        from uuid import UUID

        if str(UUID(subscription)) != subscription:
            raise ValueError("Invalid provider subscription")
        for _ in range(8):
            job = self.checked_job(lease)
            operation = self.operation(lease)
            expected = (f"/subscriptions/{subscription}/resourceGroups/"
                        + str(operation.get("providerGroupName", "")))
            if (operation.get("providerGroupMode") != "isolated"
                    or scope.lower() != expected.lower()):
                raise LostLease()
            if operation.get("providerGroupState") == "created":
                if str(operation.get("providerGroupId", "")).lower() != expected.lower():
                    raise LostLease()
                return
            if operation.get("providerGroupState") != "creating":
                raise LostLease()
            operation.update(providerGroupState="created", providerGroupId=expected)
            try:
                self.backend.transact([self._change(job), self._change(operation)])
                return
            except Conflict:
                continue
        raise LostLease()

    def bind_secret_versions(self, lease: Lease, versions: dict[str, str]) -> None:
        if set(versions) != {"ingress", "delivery"} or not all(versions.values()):
            raise ValueError("Both secret versions are required")
        for _ in range(8):
            job = self.checked_job(lease)
            operation = self.operation(lease)
            current = json.loads(str(operation["secretVersions"]))
            if current:
                if current != versions:
                    raise LostLease()
                return
            # Persist only nonsecret version identifiers. This fixes the selected
            # versions even if an expired worker's in-flight KV write arrives late.
            operation["secretVersions"] = json.dumps(versions, sort_keys=True)
            try:
                self.backend.transact([self._change(job), self._change(operation)])
                return
            except Conflict:
                continue
        raise LostLease()

    def register_routing(self, owner, environment_id: str, address: str) -> dict:
        from .models import RoutingAddress
        value = RoutingAddress(routingApplianceIp=address).routingApplianceIp
        for _ in range(8):
            operation = self.owned(owner, environment_id)
            if operation.get("decommissionState") in ("Deleting", "Decommissioned"):
                raise DomainError(409, "EnvironmentDecommissioned")
            request, _, _ = parse_stored_environment_request(str(operation["request"]))
            if request.mode != "network":
                raise DomainError(409, "NetworkEnvironmentRequired")
            operation.update(customerRoutingApplianceIp=value, routingRegisteredAt=time.time())
            try:
                self.backend.transact([self._change(operation)])
                return {"status": "registered"}
            except Conflict:
                continue
        raise DomainError(409, "RoutingRegistrationContention")

    def finish(self, lease: Lease, status: str, manifest: dict | None = None,
               code: str = "", release: bool = False) -> None:
        if status not in ("Ready", "Failed", "Retry"):
            raise ValueError("Invalid final state")
        for _ in range(8):
            job = self.checked_job(lease)
            operation = self.operation(lease)
            quota = self._quota()
            self._counter(quota, "running", str(operation["caller"]), -1)
            if status != "Retry":
                quota["active"] = max(0, int(quota["active"]) - 1)
                self._counter(quota, "callers", str(operation["caller"]), -1)
                # Failures with ambiguous or retained ARM resources keep their allocation.
                if release:
                    quota["allocated"] = max(0, int(quota["allocated"]) - 1)
                    quota.setdefault("allocations", "{}")
                    self._counter(quota, "allocations",
                                  str(operation.get("allocationKey", operation["tenant"])), -1)
                    operation["allocationReleased"] = True
            job.update(status="retry" if status == "Retry" else "done",
                       leaseOwner="", leaseUntil=0.0,
                       nextAttempt=time.time() + min(300, 2 ** min(int(job["attempts"]), 8)))
            operation.update(
                status="Pending" if status == "Retry" else status,
                manifest=json.dumps(manifest or {}, sort_keys=True),
                errorCode=code,
                errorMessage="Provider operation requires retry or operator review." if code else "",
                updatedAt=time.time(),
            )
            try:
                self.backend.transact([self._change(quota), self._change(job),
                                       self._change(operation)])
                return
            except Conflict:
                continue
        raise LostLease()

    def _decommission_rows(self, environment_id: str) -> tuple[Row, Row] | None:
        operation = self.backend.get(self.partition, "op:" + environment_id)
        job = self.backend.get(self.partition, "job:" + environment_id)
        if not job or not self._belongs(operation) or operation.get("providerGroupMode") != "isolated":
            return None
        return operation, job

    def decommission_operation(self, environment_id: str, attempt: int) -> Row | None:
        """Return an operation whose provider resources may be removed now, else None."""
        rows = self._decommission_rows(environment_id)
        if rows is None:
            return None
        operation, job = rows
        state = operation.get("decommissionState", "")
        if state == "Decommissioned" or job.get("status") in ("pending", "retry", "busy"):
            return None
        if state == "Failed" and int(operation.get("decommissionAttempt", 0)) >= attempt:
            return None
        return operation

    def mark_decommission(self, environment_id: str, state: str, attempt: int, code: str = "") -> None:
        if state not in ("Deleting", "Failed"):
            raise ValueError("Invalid decommission state")
        for _ in range(8):
            rows = self._decommission_rows(environment_id)
            if rows is None:
                raise LostLease()
            operation, job = rows
            if (operation.get("decommissionState") == "Decommissioned"
                    or job.get("status") in ("pending", "retry", "busy")):
                raise LostLease()
            operation.update(decommissionState=state, decommissionAttempt=attempt,
                             decommissionError=code, updatedAt=time.time())
            try:
                # The unchanged job ETag fences against a concurrent provisioning claim.
                self.backend.transact([self._change(job), self._change(operation)])
                return
            except Conflict:
                continue
        raise StoreUnavailable("Decommission contention")

    def finish_decommission(self, environment_id: str) -> None:
        for _ in range(8):
            rows = self._decommission_rows(environment_id)
            if rows is None:
                raise LostLease()
            operation, job = rows
            if operation.get("decommissionState") == "Decommissioned":
                return
            if operation.get("decommissionState") != "Deleting" or job.get("status") != "done":
                raise LostLease()
            quota = self._quota()
            if not operation.get("allocationReleased"):
                quota["allocated"] = max(0, int(quota["allocated"]) - 1)
                quota.setdefault("allocations", "{}")
                self._counter(quota, "allocations",
                              str(operation.get("allocationKey", operation["tenant"])), -1)
            now = time.time()
            operation.update(status="Decommissioned", decommissionState="Decommissioned",
                             decommissionError="", allocationReleased=True,
                             decommissionedAt=now, updatedAt=now)
            try:
                self.backend.transact([self._change(quota), self._change(job), self._change(operation)])
                return
            except Conflict:
                continue
        raise StoreUnavailable("Decommission contention")
