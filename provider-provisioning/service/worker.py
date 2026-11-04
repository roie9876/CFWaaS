import logging
import json
import threading
import time
from uuid import uuid4
from typing import TYPE_CHECKING

from azure.core.exceptions import HttpResponseError

from .models import InvalidStoredNetworkingMode, parse_stored_environment_request
from .environment_groups import (
    GroupCreationUnavailable, GroupCreationUncertain, GroupDeploymentFailed, GroupOwnershipError,
)
from .enrollment import EnrollmentError
from .provisioner import ProvisionError, Provisioner
from .store import Lease, LostLease, Store
if TYPE_CHECKING:
    from .customer_stores import CustomerStores

logger = logging.getLogger("faas.worker")
DECOMMISSION_SECONDS = 30.0


class Stopping(Exception):
    pass


class Worker:
    def __init__(self, store: Store, provisioner: Provisioner,
                 environment_groups=None, isolated_arm_factory=None, checkpoint=None) -> None:
        self.store, self.provisioner = store, provisioner
        self.environment_groups, self.isolated_arm_factory = environment_groups, isolated_arm_factory
        self.checkpoint = checkpoint
        self.worker_id = str(uuid4())
        self.stop = threading.Event()
        self.last_tick = time.monotonic()

    def _check(self, lease: Lease, lost: threading.Event) -> None:
        if self.stop.is_set():
            raise Stopping()
        if lost.is_set():
            raise LostLease()
        self.store.checked_job(lease)

    def process(self, lease: Lease) -> None:
        heartbeat_stop, lost = threading.Event(), threading.Event()

        def heartbeat() -> None:
            while not heartbeat_stop.wait(self.store.settings.lease_seconds / 3):
                try:
                    self.store.renew(lease)
                except Exception:
                    logger.warning("operation=%s code=LeaseRenewUnavailable",
                                   lease.environment_id)
                    lost.set()
                    return

        thread = threading.Thread(target=heartbeat, name="faas-lease", daemon=False)
        thread.start()
        status, manifest, code, release = "Retry", {}, "", False
        isolated_arm = None
        try:
            operation = self.store.operation(lease)
            try:
                request, parallel, isolated_mode = parse_stored_environment_request(str(operation["request"]))
            except InvalidStoredNetworkingMode:
                raise ProvisionError("InvalidProviderNetworkingMode", False) from None
            mode = operation.get("providerGroupMode", "shared")
            if request.firewallType != "ubuntu":
                if self.checkpoint is None or mode != "isolated" or not isolated_mode or parallel:
                    raise ProvisionError("CheckpointDeploymentUnavailable", False)
            if isolated_mode != (mode == "isolated"):
                raise ProvisionError("InvalidProviderGroupMode", False)
            if request.firewallType != "ubuntu":
                manifest = self.checkpoint.provision(
                    lease, self.store, operation, request, lambda: self._check(lease, lost))
                status = "Ready"
            elif mode == "isolated":
                if request.mode != "network" or not self.environment_groups or not self.isolated_arm_factory:
                    raise ProvisionError("IsolatedProvisioningNotConfigured", False)
                if self.provisioner.templates.network is None:
                    raise ProvisionError("NetworkTemplateNotConfigured", False, True)
                group = self.environment_groups.ensure(
                    operation, request.region, lambda: self._check(lease, lost),
                    lambda: self.store.begin_provider_group(lease),
                    lambda scope: self.store.bind_provider_group(
                        lease, self.environment_groups.subscription, scope))
                isolated_arm = self.isolated_arm_factory(group)
            elif mode != "shared":
                raise ProvisionError("InvalidProviderGroupMode", False)
            if request.firewallType == "ubuntu":
                arguments = (lease.environment_id, request, lambda: self._check(lease, lost),
                             json.loads(str(operation["secretVersions"])),
                             lambda versions: self.store.bind_secret_versions(lease, versions))
                if isolated_arm is not None:
                    manifest = self.provisioner.provision(
                        *arguments, arm=isolated_arm, parallel_networking=parallel)
                elif parallel:
                    manifest = self.provisioner.provision(*arguments, parallel_networking=True)
                else:
                    manifest = self.provisioner.provision(*arguments)
                status = "Ready"
        except (GroupOwnershipError, GroupCreationUncertain,
                GroupCreationUnavailable, GroupDeploymentFailed) as exc:
            status, code = "Failed", type(exc).__name__
            if isinstance(exc, GroupOwnershipError):
                reason = str(exc)
                if reason not in {"HostMismatch", "ApplicationMismatch", "GroupBindingMismatch", "GroupRoleMismatch",
                                  "GroupDenyMismatch", "GroupPermissionsNotReady"}:
                    reason = "OtherOwnershipCheck"
                logger.warning("operation=%s code=%s reason=%s", lease.environment_id, code, reason)
        except ProvisionError as exc:
            code, release = exc.code, exc.release
            attempts = int(self.store.checked_job(lease)["attempts"])
            status = ("Retry" if exc.retryable and attempts < self.store.settings.max_attempts
                      else "Failed")
        except (LostLease, Stopping):
            return
        except Exception:
            code = "WorkerDependencyUnavailable"
            logger.warning("operation=%s code=%s", lease.environment_id, code)
            try:
                attempts = int(self.store.checked_job(lease)["attempts"])
                status = "Retry" if attempts < self.store.settings.max_attempts else "Failed"
            except LostLease:
                return
        finally:
            heartbeat_stop.set()
            thread.join()
            if isolated_arm is not None:
                try:
                    isolated_arm.close()
                except Exception:
                    logger.warning("operation=%s code=IsolatedArmCloseFailed", lease.environment_id)
        try:
            self._check(lease, lost)
            self.store.finish(lease, status, manifest, code, release and status == "Failed")
            logger.info("operation=%s state=%s code=%s", lease.environment_id, status, code)
        except (LostLease, Stopping):
            pass

    def tick(self) -> bool:
        self.last_tick = time.monotonic()
        for job in self.store.candidates():
            if self.stop.is_set():
                return False
            lease = self.store.claim(str(job["environmentId"]), self.worker_id)
            if lease:
                self.process(lease)
                self.last_tick = time.monotonic()
                return True
        return False

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                if not self.tick():
                    self.stop.wait(self.store.settings.poll_seconds)
            except Exception:
                logger.warning("code=WorkerPollUnavailable")
                self.stop.wait(self.store.settings.poll_seconds)


class RegistryWorker:
    """One bounded worker, round-robin between enrolled customer partitions."""

    def __init__(self, stores: "CustomerStores", provisioner: Provisioner,
                 environment_groups=None, isolated_arm_factory=None, checkpoint=None) -> None:
        self.stores, self.provisioner = stores, provisioner
        self.environment_groups, self.isolated_arm_factory = environment_groups, isolated_arm_factory
        self.checkpoint = checkpoint
        self.stop = threading.Event()
        self.last_tick = time.monotonic()
        self.offset = 0
        self.next_decommission = 0.0

    def _stopping(self) -> None:
        if self.stop.is_set():
            raise Stopping()

    def decommission(self) -> None:
        """Advance administrator-requested deletions without blocking provisioning."""
        groups = self.environment_groups
        if groups is None or not hasattr(groups, "decommission"):
            return
        now = time.monotonic()
        if now < self.next_decommission:
            return
        self.next_decommission = now + DECOMMISSION_SECONDS
        for request in self.stores.registry.decommission_requests():
            self._stopping()
            environment_id, attempt = str(request["environmentId"]), int(request["attempt"])
            try:
                binding = self.stores.registry.binding(str(request["customerId"]))
            except EnrollmentError:
                continue
            if binding is None:
                continue
            store = self.stores.bound(binding)
            operation = store.decommission_operation(environment_id, attempt)
            if (operation is None
                    or operation.get("providerGroupName") != request.get("providerGroupName")):
                continue
            try:
                if operation.get("decommissionState") != "Deleting":
                    store.mark_decommission(environment_id, "Deleting", attempt)
                if groups.decommission(operation, self._stopping):
                    store.finish_decommission(environment_id)
                    logger.info("operation=%s state=Decommissioned", environment_id)
            except (GroupOwnershipError, GroupCreationUncertain) as exc:
                code = type(exc).__name__
                logger.warning("operation=%s code=Decommission%s", environment_id, code)
                store.mark_decommission(environment_id, "Failed", attempt, code)
            except HttpResponseError as exc:
                if exc.status_code not in (401, 403):
                    raise
                logger.warning("operation=%s code=DecommissionNotAuthorized", environment_id)
                store.mark_decommission(environment_id, "Failed", attempt, "DecommissionNotAuthorized")
            except LostLease:
                continue

    def tick(self) -> bool:
        self.last_tick = time.monotonic()
        try:
            self.decommission()
        except Stopping:
            return False
        except Exception:
            logger.warning("code=DecommissionPollUnavailable")
        customers = self.stores.registry.worker_customers()
        if not customers:
            return False
        start = self.offset % len(customers)
        for index in range(len(customers)):
            binding = customers[(start + index) % len(customers)]
            worker = Worker(self.stores.bound(binding), self.provisioner,
                            self.environment_groups, self.isolated_arm_factory, self.checkpoint)
            worker.stop = self.stop
            if worker.tick():
                self.offset = start + index + 1
                self.last_tick = time.monotonic()
                return True
        self.offset = start + 1
        return False

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                if not self.tick():
                    self.stop.wait(self.stores.settings.poll_seconds)
            except Exception:
                logger.warning("code=RegistryWorkerPollUnavailable")
                self.stop.wait(self.stores.settings.poll_seconds)
