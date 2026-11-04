from contextlib import asynccontextmanager
from dataclasses import replace
import logging
import threading

from azure.identity import ManagedIdentityCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.locks import ManagementLockClient
from fastapi import FastAPI

from .azure_data import TableBackend, Vault
from .checkpoint_provisioner import CheckpointProvisioner, load_checkpoint_settings
from .config import CheckpointWorkerSettings, Settings, WorkerSettings
from .customer_stores import CustomerStores
from .enrollment import EnrollmentRegistry
from .environment_groups import EnvironmentGroups
from .managed_environment_groups import CHECKPOINT_PUBLISHER_ROLES, ManagedEnvironmentGroups
from .provisioner import AzureArm, Provisioner
from .store import Store
from .templates import Templates
from .worker import RegistryWorker, Stopping, Worker


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings, target = Settings.from_env(), WorkerSettings.from_env()
    if target.managed_host_group and (
            settings.auth_mode != "provider-api-registry" or settings.authority_tenant is None):
        raise ValueError("Managed host requires the provider customer registry")
    if settings.provider_group_mode == "isolated" and (
            not target.managed_host_group or not target.managed_host_allow_azure_condition):
        raise ValueError("Isolated mode requires the approved managed host configuration")
    templates = Templates(target)
    checkpoint_config = CheckpointWorkerSettings.from_env(target)
    if checkpoint_config is not None and (not settings.checkpoint_enabled or not target.group_subscription):
        raise ValueError("Check Point worker requires the enabled isolated API configuration")
    checkpoint_settings = load_checkpoint_settings(checkpoint_config) if checkpoint_config else None
    credential = ManagedIdentityCredential(retry_total=2, connection_timeout=5, read_timeout=10)
    backend = TableBackend(settings.table_endpoint, credential)
    vault = Vault(settings.vault_url, credential)
    arm = AzureArm(target, credential)
    customers = None
    provisioner = Provisioner(arm, vault, templates, target)
    group_identity = deployment_identity = group_resources = group_authorization = group_locks = groups = None
    arm_factory = checkpoint = checkpoint_identity = checkpoint_resources = None
    if target.group_subscription:
        group_identity = ManagedIdentityCredential(client_id=target.group_provisioner_client_id,
                                                   retry_total=0, connection_timeout=5, read_timeout=10)
        deployment_identity = ManagedIdentityCredential(client_id=target.group_deployer_client_id,
                                                        retry_total=2, connection_timeout=5, read_timeout=10)
        group_resources = ResourceManagementClient(group_identity, target.group_subscription,
                                                   logging_enable=False, retry_total=0,
                                                   connection_timeout=5, read_timeout=30)
        group_authorization = AuthorizationManagementClient(group_identity, target.group_subscription,
                                                            logging_enable=False, retry_total=0,
                                                            connection_timeout=5, read_timeout=30)
        if target.managed_host_group:
            authority_tenant = settings.authority_tenant
            if authority_tenant is None:
                raise ValueError("Managed host requires the provider authority")
            group_locks = ManagementLockClient(group_identity, target.group_subscription,
                                               logging_enable=False, retry_total=0,
                                               connection_timeout=5, read_timeout=30)
            groups = ManagedEnvironmentGroups(
                group_resources, group_authorization, group_locks, target.group_subscription,
                target.group_deployer_principal_id, authority_tenant,
                target.managed_host_group, target.managed_host_parent_group,
                target.managed_host_application, target.managed_host_definition,
                allow_azure_managed_condition=target.managed_host_allow_azure_condition)
        else:
            groups = EnvironmentGroups(group_resources, group_authorization, target.group_subscription,
                                       target.group_deployer_principal_id)
        arm_factory = lambda group: AzureArm(
            replace(target, subscription=target.group_subscription, resource_group=group),
            deployment_identity)
        if checkpoint_settings is not None and checkpoint_config is not None:
            authority_tenant = settings.authority_tenant
            if group_locks is None or authority_tenant is None:
                raise ValueError("Check Point requires the managed host")
            # Separate identity: the Check Point group deny admits only its own publisher principal.
            checkpoint_identity = ManagedIdentityCredential(client_id=checkpoint_config.client_id, retry_total=2,
                                                            connection_timeout=5, read_timeout=10)
            checkpoint_resources = ResourceManagementClient(checkpoint_identity, target.group_subscription,
                                                            logging_enable=False, retry_total=2,
                                                            connection_timeout=5, read_timeout=30)
            checkpoint_groups = ManagedEnvironmentGroups(
                group_resources, group_authorization, group_locks, target.group_subscription,
                checkpoint_config.principal_id, authority_tenant,
                target.managed_host_group, target.managed_host_parent_group,
                target.managed_host_application, checkpoint_config.definition,
                allow_azure_managed_condition=target.managed_host_allow_azure_condition,
                publisher_roles=CHECKPOINT_PUBLISHER_ROLES,
                host_principal=target.group_deployer_principal_id)
            checkpoint = CheckpointProvisioner(
                checkpoint_settings, checkpoint_groups,
                lambda group: AzureArm(replace(target, subscription=target.group_subscription, resource_group=group),
                                       checkpoint_identity),
                checkpoint_resources, vault, target.group_subscription, authority_tenant)
    if settings.auth_mode == "provider-api-registry":
        customers = TableBackend(settings.table_endpoint, credential, "Customers")
        registry = EnrollmentRegistry(customers)
        worker = RegistryWorker(CustomerStores(backend, settings, registry), provisioner, groups, arm_factory,
                                checkpoint)
    else:
        worker = Worker(Store(backend, settings), provisioner, groups, arm_factory, checkpoint)

    def interruptible_wait(seconds: float) -> None:
        if worker.stop.wait(seconds):
            raise Stopping()

    worker.provisioner.wait = interruptible_wait
    if checkpoint is not None:
        checkpoint.wait = interruptible_wait
        checkpoint.groups.wait = interruptible_wait
    if isinstance(groups, ManagedEnvironmentGroups):
        groups.wait = interruptible_wait
    thread = threading.Thread(target=worker.run, name="faas-durable-worker", daemon=False)
    app.state.worker, app.state.thread = worker, thread
    thread.start()
    try:
        yield
    finally:
        worker.stop.set()
        # SDK calls have bounded transport/retry timeouts. Never leave a worker orphan.
        import asyncio
        await asyncio.to_thread(thread.join)
        arm.close()
        vault.close()
        backend.close()
        credential.close()
        if customers is not None:
            customers.close()
        if group_authorization is not None:
            group_authorization.close()
        if group_locks is not None:
            group_locks.close()
        if group_resources is not None:
            group_resources.close()
        if group_identity is not None:
            group_identity.close()
        if deployment_identity is not None:
            deployment_identity.close()
        if checkpoint_resources is not None:
            checkpoint_resources.close()
        if checkpoint_identity is not None:
            checkpoint_identity.close()


logging.getLogger("azure").setLevel(logging.WARNING)
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


@app.get("/healthz")
def health() -> dict:
    from fastapi import HTTPException
    if not app.state.thread.is_alive() or app.state.worker.stop.is_set():
        raise HTTPException(503, "WorkerUnavailable")
    return {"status": "ok"}
