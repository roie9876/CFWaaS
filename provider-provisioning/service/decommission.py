"""Administrator requests to decommission provider-side environment groups.

The management app only reads Operations and records requests in its own
Customers registry. The worker, the sole identity excluded from the managed
host's deny assignment, performs the deletion and records the outcome.
"""

import time
from uuid import uuid4

from .enrollment import (LIST_LIMIT, PARTITION, EnrollmentError, EnrollmentRegistry,
                         canonical_guid)
from .models import environment_resource_group_name
from .store import Change, Conflict, Row

ATTEMPTS = 8
BUSY = ("Pending", "Running")


class EnvironmentDecommissions:
    def __init__(self, registry: EnrollmentRegistry, operations, authority_tenant: str) -> None:
        self.registry, self.operations = registry, operations
        self.partition = "registry:" + canonical_guid(authority_tenant)

    @staticmethod
    def _identity(customer: Row) -> tuple[str, str, str] | None:
        values = (customer.get("tenantId"), customer.get("principalId"), customer.get("clientId"))
        return values if all(isinstance(value, str) and value for value in values) else None

    @staticmethod
    def _isolated(operation: Row) -> bool:
        name = str(operation.get("providerGroupName", ""))
        return (operation.get("providerGroupMode") == "isolated" and name.startswith("rg-faas-env-")
                and environment_resource_group_name(name.removeprefix("rg-faas-env-")) == name)

    def _owned(self, operation: Row | None, identity) -> bool:
        return bool(operation and identity and self._isolated(operation)
                    and (operation.get("tenant"), operation.get("principal"),
                         operation.get("client")) == identity)

    @staticmethod
    def _view(operation: Row, request: Row | None) -> dict:
        state = str(operation.get("decommissionState", ""))
        if request and (not state or (state == "Failed" and int(request.get("attempt", 0))
                                      > int(operation.get("decommissionAttempt", 0)))):
            state = "Requested"
        return {"environmentId": operation["environmentId"],
                "providerGroupName": operation["providerGroupName"],
                "status": operation.get("status", ""),
                "createdAt": operation.get("createdAt"),
                "decommissionState": state,
                "decommissionError": str(operation.get("decommissionError", "")) if state == "Failed" else ""}

    def environments(self, customer_id: str) -> list[dict]:
        identity = self._identity(self.registry._customer(customer_id))
        if identity is None:
            return []
        try:
            rows = self.operations.list_rows(self.partition, "op:", LIST_LIMIT + 1)
        except Exception:
            raise EnrollmentError(503, "OperationsStoreUnavailable") from None
        if len(rows) > LIST_LIMIT:
            raise EnrollmentError(503, "OperationsListLimit")
        requests = {row["environmentId"]: row for row in self.registry.decommission_requests(customer_id)}
        owned = [row for row in rows if self._owned(row, identity)]
        owned.sort(key=lambda row: float(row.get("createdAt") or 0), reverse=True)
        return [self._view(row, requests.get(row["environmentId"])) for row in owned]

    def request(self, customer_id: str, environment_id: str, actor: str) -> dict:
        try:
            canonical_guid(actor)
            canonical_guid(environment_id)
        except (ValueError, TypeError, AttributeError):
            raise EnrollmentError(400, "InvalidRequest") from None
        for _ in range(ATTEMPTS):
            identity = self._identity(self.registry._customer(customer_id))
            try:
                operation = self.operations.get(self.partition, "op:" + environment_id)
            except Exception:
                raise EnrollmentError(503, "OperationsStoreUnavailable") from None
            if not self._owned(operation, identity):
                raise EnrollmentError(404, "EnvironmentNotFound")
            state = operation.get("decommissionState", "")
            existing = self.registry._get("decommission:" + environment_id)
            if existing and existing.get("customerId") != customer_id:
                raise EnrollmentError(404, "EnvironmentNotFound")
            if state in ("Deleting", "Decommissioned"):
                return self._view(operation, existing)
            if operation.get("status") in BUSY:
                raise EnrollmentError(409, "EnvironmentBusy")
            if existing:
                if state != "Failed" or int(existing.get("attempt", 0)) > int(
                        operation.get("decommissionAttempt", 0)):
                    return self._view(operation, existing)
                existing.update(attempt=int(existing["attempt"]) + 1, requestedBy=actor,
                                requestedAt=time.time())
                request = Change(existing, str(existing["_etag"]))
            else:
                existing = {"PartitionKey": PARTITION, "RowKey": "decommission:" + environment_id,
                            "customerId": customer_id, "environmentId": environment_id,
                            "providerGroupName": operation["providerGroupName"], "attempt": 1,
                            "requestedBy": actor, "requestedAt": time.time()}
                request = Change(existing)
            audit = Change({"PartitionKey": PARTITION, "RowKey": "audit:" + str(uuid4()),
                            "customerId": customer_id, "actorOid": actor,
                            "event": "DecommissionRequested", "environmentId": environment_id,
                            "timestamp": time.time()})
            try:
                self.registry._transact([request, audit])
                return self._view(operation, existing)
            except Conflict:
                continue
        raise EnrollmentError(409, "DecommissionContention")
