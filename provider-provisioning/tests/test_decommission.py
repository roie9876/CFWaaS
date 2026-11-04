import copy
import json
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest
from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from fastapi.testclient import TestClient

from service.config import Settings
from service.customer_stores import CustomerStores
from service.decommission import EnvironmentDecommissions
from service.enrollment import EnrollmentError, EnrollmentRegistry
from service.environment_groups import GroupOwnershipError
from service.management import create_app
from service.models import EnvironmentRequest
from service.auth import Owner
from service.store import Conflict, LostLease
from service.worker import RegistryWorker

from test_managed_environment_groups import APP_ID, GROUP, GROUP_SCOPE, fixture  # noqa: F401
from test_management import ADMIN, ORIGIN, authentication, identity, signing  # noqa: F401


def uid(number):
    return str(UUID(int=number))


AUTHORITY, TENANT, PRINCIPAL, CLIENT, CUSTOMER = uid(30), uid(31), uid(32), uid(33), uid(34)
OTHER_CUSTOMER = uid(35)
NETWORK = {"mode": "network",
           "customerIngress": {"publicIp": "8.8.8.8", "bgpAddress": "10.0.0.4", "asn": 64512},
           "customerDelivery": {"publicIp": "1.1.1.1", "bgpAddress": "10.0.0.4", "asn": 64512}}


class Memory:
    def __init__(self):
        self.rows, self.version = {}, 0
        self.lock = threading.RLock()

    def get(self, partition, key):
        with self.lock:
            return copy.deepcopy(self.rows.get((partition, key)))

    def list_rows(self, partition, prefix="", limit=100):
        with self.lock:
            return [copy.deepcopy(row) for (part, key), row in sorted(self.rows.items())
                    if part == partition and key.startswith(prefix)][:limit]

    def jobs(self, partition):
        with self.lock:
            return [copy.deepcopy(row) for (part, key), row in self.rows.items()
                    if part == partition and key.startswith("job:")
                    and row["status"] in ("pending", "retry", "busy")]

    def transact(self, changes):
        with self.lock:
            for change in changes:
                current = self.rows.get((change.row["PartitionKey"], change.row["RowKey"]))
                if ((change.etag is None and current is not None)
                        or (change.etag is not None and (current or {}).get("_etag") != change.etag)):
                    raise Conflict()
            for change in changes:
                self.version += 1
                row = copy.deepcopy(change.row)
                row["_etag"] = str(self.version)
                self.rows[(row["PartitionKey"], row["RowKey"])] = row


def customer_row(customer_id=CUSTOMER, client=CLIENT, status="Ready"):
    return {"PartitionKey": "enrollments", "RowKey": "customer:" + customer_id,
            "customerId": customer_id, "name": "unit", "tenantId": TENANT,
            "subscriptionId": uid(36), "principalId": PRINCIPAL, "clientId": client,
            "maxEnvironments": 0, "status": status, "credentialExpiresAt": "2099-01-01T00:00:00+00:00"}


@pytest.fixture
def world():
    customers, operations = Memory(), Memory()
    customers.transact([SimpleNamespace(row=customer_row(), etag=None)])
    customers.transact([SimpleNamespace(row=customer_row(OTHER_CUSTOMER, uid(37)), etag=None)])
    registry = EnrollmentRegistry(customers)
    settings = Settings(CLIENT, None, "https://unit.table.core.windows.net", "https://unit.vault.azure.net",
                        auth_mode="provider-api-registry", authority_tenant=AUTHORITY,
                        provider_group_mode="isolated")
    stores = CustomerStores(operations, settings, registry)
    store = stores.bound(registry.binding(CUSTOMER))
    operation = store.reserve(Owner(TENANT, PRINCIPAL, CLIENT), "one", EnvironmentRequest.model_validate(NETWORK))
    environment_id = str(operation["environmentId"])
    lease = store.claim(environment_id, "worker")
    store.finish(lease, "Ready")
    service = EnvironmentDecommissions(registry, operations, AUTHORITY)
    return SimpleNamespace(customers=customers, operations=operations, registry=registry, stores=stores,
                           store=store, environment_id=environment_id, service=service,
                           group=str(operation["providerGroupName"]))


def quota(world):
    return world.operations.get("registry:" + AUTHORITY, "quota")


def test_request_lists_and_records_an_audited_request(world):
    [listed] = world.service.environments(CUSTOMER)
    assert listed["providerGroupName"] == world.group
    assert listed["decommissionState"] == ""
    assert world.service.environments(OTHER_CUSTOMER) == []
    result = world.service.request(CUSTOMER, world.environment_id, ADMIN)
    assert result["decommissionState"] == "Requested"
    assert world.service.request(CUSTOMER, world.environment_id, ADMIN)["decommissionState"] == "Requested"
    [request] = world.registry.decommission_requests()
    assert (request["customerId"], request["providerGroupName"], request["attempt"]) == (
        CUSTOMER, world.group, 1)
    audits = [row for (_, key), row in world.customers.rows.items() if key.startswith("audit:")]
    assert len(audits) == 1 and audits[0]["event"] == "DecommissionRequested"
    assert world.operations.get("registry:" + AUTHORITY, "op:" + world.environment_id)["status"] == "Ready"


def test_request_rejects_foreign_unknown_and_busy_environments(world):
    with pytest.raises(EnrollmentError) as foreign:
        world.service.request(OTHER_CUSTOMER, world.environment_id, ADMIN)
    assert foreign.value.code == "EnvironmentNotFound"
    with pytest.raises(EnrollmentError) as unknown:
        world.service.request(CUSTOMER, uid(99), ADMIN)
    assert unknown.value.code == "EnvironmentNotFound"
    key = ("registry:" + AUTHORITY, "op:" + world.environment_id)
    world.operations.rows[key]["status"] = "Running"
    with pytest.raises(EnrollmentError) as busy:
        world.service.request(CUSTOMER, world.environment_id, ADMIN)
    assert busy.value.code == "EnvironmentBusy"
    assert world.registry.decommission_requests() == []


def worker(world, groups):
    instance = RegistryWorker(world.stores, Mock(), groups, Mock())
    return instance


def test_worker_deletes_then_releases_allocation_exactly_once(world):
    groups = Mock()
    groups.decommission.side_effect = [False, True]
    runner = worker(world, groups)
    runner.decommission()
    assert groups.decommission.call_count == 0
    world.service.request(CUSTOMER, world.environment_id, ADMIN)
    before = quota(world)
    runner.next_decommission = 0
    runner.decommission()
    operation = world.operations.get("registry:" + AUTHORITY, "op:" + world.environment_id)
    assert operation["decommissionState"] == "Deleting"
    assert world.service.environments(CUSTOMER)[0]["decommissionState"] == "Deleting"
    runner.next_decommission = 0
    runner.decommission()
    operation = world.operations.get("registry:" + AUTHORITY, "op:" + world.environment_id)
    assert (operation["status"], operation["decommissionState"]) == ("Decommissioned", "Decommissioned")
    after = quota(world)
    assert after["allocated"] == before["allocated"] - 1
    assert json.loads(after["allocations"])[TENANT] == json.loads(before["allocations"])[TENANT] - 1
    runner.next_decommission = 0
    runner.decommission()
    world.store.finish_decommission(world.environment_id)
    assert quota(world)["allocated"] == after["allocated"]
    assert groups.decommission.call_count == 2


def test_worker_waits_for_active_provisioning_and_is_throttled(world):
    groups = Mock()
    world.service.request(CUSTOMER, world.environment_id, ADMIN)
    world.operations.rows[("registry:" + AUTHORITY, "job:" + world.environment_id)]["status"] = "retry"
    runner = worker(world, groups)
    runner.decommission()
    groups.decommission.assert_not_called()
    world.operations.rows[("registry:" + AUTHORITY, "job:" + world.environment_id)]["status"] = "done"
    runner.decommission()
    groups.decommission.assert_not_called()


@pytest.mark.parametrize("error,code", [
    (GroupOwnershipError("GroupBindingMismatch"), "GroupOwnershipError"),
    (HttpResponseError(response=SimpleNamespace(status_code=403, reason="Forbidden", headers={},
                                                text=lambda: "", content_type="")),
     "DecommissionNotAuthorized"),
])
def test_failures_are_recorded_and_retried_only_on_new_request(world, error, code):
    if isinstance(error, HttpResponseError):
        error.status_code = 403
    groups = Mock()
    groups.decommission.side_effect = error
    world.service.request(CUSTOMER, world.environment_id, ADMIN)
    runner = worker(world, groups)
    runner.decommission()
    [view] = world.service.environments(CUSTOMER)
    assert (view["decommissionState"], view["decommissionError"]) == ("Failed", code)
    runner.next_decommission = 0
    runner.decommission()
    assert groups.decommission.call_count == 1
    assert world.service.request(CUSTOMER, world.environment_id, ADMIN)["decommissionState"] == "Requested"
    groups.decommission.side_effect = [True]
    runner.next_decommission = 0
    runner.decommission()
    assert world.service.environments(CUSTOMER)[0]["decommissionState"] == "Decommissioned"


def test_decommissioning_blocks_group_retry_and_claims(world):
    world.service.request(CUSTOMER, world.environment_id, ADMIN)
    world.store.mark_decommission(world.environment_id, "Deleting", 1)
    assert world.store.claim(world.environment_id, "worker") is None
    with pytest.raises(LostLease):
        world.stores.bound(world.registry.binding(OTHER_CUSTOMER)).mark_decommission(
            world.environment_id, "Deleting", 1)


def test_managed_group_decommission_deletes_only_the_bound_application(fixture):
    fixture.objects[APP_ID], fixture.groups[GROUP] = fixture.app, fixture.group
    deleted = []

    def delete(resource_id, _api, **kwargs):
        assert kwargs["polling"] is False
        deleted.append(resource_id)
        fixture.app.properties["provisioningState"] = "Deleting"

    fixture.resources.resources.begin_delete_by_id.side_effect = delete
    assert fixture.manager.decommission(fixture.operation, lambda: None) is False
    assert fixture.manager.decommission(fixture.operation, lambda: None) is False
    assert deleted == [APP_ID]
    del fixture.objects[APP_ID]
    assert fixture.manager.decommission(fixture.operation, lambda: None) is False
    del fixture.groups[GROUP]
    assert fixture.manager.decommission(fixture.operation, lambda: None) is True
    fixture.resources.resource_groups.begin_delete.assert_not_called()


@pytest.mark.parametrize("unsafe", ["foreign_group", "orphan_group", "tags", "partition"])
def test_managed_group_decommission_rejects_unowned_targets(fixture, unsafe):
    fixture.objects[APP_ID], fixture.groups[GROUP] = fixture.app, fixture.group
    if unsafe == "foreign_group":
        fixture.group.managed_by = APP_ID + "-other"
    elif unsafe == "orphan_group":
        del fixture.objects[APP_ID]
        fixture.group.managed_by = None
    elif unsafe == "tags":
        fixture.app.tags["faasClientId"] = uid(99)
    else:
        fixture.operation["PartitionKey"] = "registry:" + uid(99)
    with pytest.raises(GroupOwnershipError):
        fixture.manager.decommission(fixture.operation, lambda: None)
    fixture.resources.resources.begin_delete_by_id.assert_not_called()


def test_management_routes_require_administrator(signing):  # noqa: F811
    service, decommissions = Mock(), Mock()
    service.registry.list_customers.return_value = []
    decommissions.environments.return_value = [{"environmentId": uid(5)}]
    decommissions.request.return_value = {"decommissionState": "Requested"}
    with TestClient(create_app(service, authentication(signing), decommissions), base_url=ORIGIN) as client:
        headers = {"x-ms-token-aad-id-token": identity(signing), "Origin": ORIGIN,
                   "Idempotency-Key": str(uuid4())}
        assert client.get(f"/admin/customers/{CUSTOMER}/environments").status_code == 401
        listed = client.get(f"/admin/customers/{CUSTOMER}/environments", headers=headers)
        assert listed.json() == {"environments": [{"environmentId": uid(5)}]}
        path = f"/admin/customers/{CUSTOMER}/environments/{uid(5)}/decommission"
        assert client.post(path, json={}).status_code == 401
        assert client.post(path, json={}, headers=headers).json() == {"decommissionState": "Requested"}
        decommissions.request.assert_called_once_with(CUSTOMER, uid(5), ADMIN)
        bad = client.post(f"/admin/customers/{CUSTOMER}/environments/not-a-guid/decommission",
                          json={}, headers=headers)
        assert bad.status_code == 422
