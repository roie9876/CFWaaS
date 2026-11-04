from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from azure.core.exceptions import ResourceNotFoundError
from azure.mgmt.authorization.v2022_04_01.models import DenyAssignment

from service.environment_groups import GroupCreationUncertain, GroupDeploymentFailed, GroupOwnershipError
from service.config import WorkerSettings
from service.managed_environment_groups import (
    CHECKPOINT_PUBLISHER_ROLES, EVERYONE, NETWORK_CONTRIBUTOR, VM_CONTRIBUTOR, ManagedEnvironmentGroups,
)
from service.models import EnvironmentRequest, stored_environment_request
from service.store import Lease, LostLease
from service.worker import Worker

SUBSCRIPTION = "00000000-0000-0000-0000-000000000001"
PUBLISHER = "00000000-0000-0000-0000-000000000002"
AUTHORITY = "00000000-0000-0000-0000-000000000003"
ENVIRONMENT = "00000000-0000-0000-0000-000000000004"
TENANT = "00000000-0000-0000-0000-000000000005"
CALLER = "00000000-0000-0000-0000-000000000006"
CLIENT = "00000000-0000-0000-0000-000000000007"
GROUP = "rg-faas-env-00000000-0000-0000-0000-000000000008"
HOST_GROUP = "rg-faas-host"
PARENT_GROUP = "rg-faas-control"
HOST_APPLICATION = "faas-host"
DEFINITION = "faas-environment-definition"
BASE = f"/subscriptions/{SUBSCRIPTION}"
HOST_SCOPE = f"{BASE}/resourceGroups/{HOST_GROUP}"
HOST_ID = f"{BASE}/resourceGroups/{PARENT_GROUP}/providers/Microsoft.Solutions/applications/{HOST_APPLICATION}"
DEFINITION_ID = (f"{BASE}/resourceGroups/{PARENT_GROUP}/providers/Microsoft.Solutions/"
                 f"applicationDefinitions/{DEFINITION}")
APP_ID = f"{HOST_SCOPE}/providers/Microsoft.Solutions/applications/faas-env-{ENVIRONMENT}"
GROUP_SCOPE = f"{BASE}/resourceGroups/{GROUP}"
TAGS = {"purpose": "provider-provisioning-environment", "faasEnvironmentId": ENVIRONMENT,
        "faasClientId": CLIENT, "faasTenantId": TENANT, "faasPrincipalId": CALLER}


def deny(scope):
    permission = SimpleNamespace(actions=["*"], not_actions=["*/read"], data_actions=["*"],
                                 not_data_actions=["*/read"])
    return SimpleNamespace(
        scope=scope, is_system_protected=True, do_not_apply_to_child_scopes=False,
        condition=None,
        principals=[SimpleNamespace(id=EVERYONE, type="SystemDefined")],
        exclude_principals=[SimpleNamespace(id=PUBLISHER, type="ServicePrincipal")],
        permissions=[permission],
    )


@pytest.fixture
def fixture():
    resources, authorization, locks = Mock(), Mock(), Mock()
    host = SimpleNamespace(
        id=HOST_ID, kind="ServiceCatalog", properties={
            "provisioningState": "Succeeded", "managedResourceGroupId": HOST_SCOPE,
        })
    definition = SimpleNamespace(id=DEFINITION_ID, properties={
        "lockLevel": "ReadOnly", "deploymentPolicy": {"deploymentMode": "Incremental"},
        "authorizations": [
            {"principalId": PUBLISHER, "roleDefinitionId": NETWORK_CONTRIBUTOR},
            {"principalId": PUBLISHER, "roleDefinitionId": VM_CONTRIBUTOR},
        ],
    })
    app = SimpleNamespace(id=APP_ID, kind="ServiceCatalog", location="centralus", tags=TAGS.copy(),
                          properties={"provisioningState": "Succeeded",
                                      "applicationDefinitionId": DEFINITION_ID,
                                      "managedResourceGroupId": GROUP_SCOPE})
    host_group = SimpleNamespace(id=HOST_SCOPE, managed_by=HOST_ID, location="centralus",
                                 properties=SimpleNamespace(provisioning_state="Succeeded"))
    group = SimpleNamespace(id=GROUP_SCOPE, managed_by=APP_ID, location="centralus",
                            properties=SimpleNamespace(provisioning_state="Succeeded"))
    objects = {HOST_ID: host, DEFINITION_ID: definition}
    groups = {HOST_GROUP: host_group}

    def get_resource(resource_id, _api):
        if resource_id not in objects:
            raise ResourceNotFoundError()
        return objects[resource_id]

    def get_group(name):
        if name not in groups:
            raise ResourceNotFoundError()
        return groups[name]

    def create(resource_id, _api, _resource, **_kwargs):
        objects[resource_id], groups[GROUP] = app, group

    resources.resources.get_by_id.side_effect = get_resource
    resources.resource_groups.get.side_effect = get_group
    resources.resources.begin_create_or_update_by_id.side_effect = create
    locks.management_locks.list_by_scope.side_effect = lambda scope: [
        SimpleNamespace(id=scope + "/providers/Microsoft.Authorization/locks/readonly",
                        level="ReadOnly")]
    authorization.deny_assignments.list_for_scope.side_effect = lambda scope: [deny(scope)]
    authorization.permissions.list_for_resource_group.return_value = [
        SimpleNamespace(actions=["Microsoft.Resources/subscriptions/resourceGroups/read",
                                 "Microsoft.Solutions/applications/read",
                                 "Microsoft.Solutions/applications/write"],
                        not_actions=[], data_actions=[], not_data_actions=[])]
    authorization.role_assignments.list_for_scope.return_value = [
        SimpleNamespace(scope=GROUP_SCOPE, principal_id=PUBLISHER,
                        role_definition_id=f"{BASE}/providers/Microsoft.Authorization/roleDefinitions/{role}")
        for role in (NETWORK_CONTRIBUTOR, VM_CONTRIBUTOR)]
    manager = ManagedEnvironmentGroups(
        resources, authorization, locks, SUBSCRIPTION, PUBLISHER, AUTHORITY,
        HOST_GROUP, PARENT_GROUP, HOST_APPLICATION, DEFINITION, wait=lambda _: None, timeout=1,
    )
    operation = {"PartitionKey": "registry:" + AUTHORITY, "RowKey": "op:" + ENVIRONMENT,
                 "providerGroupMode": "isolated", "environmentId": ENVIRONMENT,
                 "tenant": TENANT, "principal": CALLER, "client": CLIENT,
                 "providerGroupName": GROUP}
    return SimpleNamespace(resources=resources, authorization=authorization, locks=locks,
                           manager=manager, operation=operation, objects=objects, groups=groups,
                           app=app, group=group, definition=definition)


def test_new_group_is_created_and_bound(fixture):
    begin, bind = Mock(), Mock()
    assert fixture.manager.ensure(fixture.operation, "centralus", lambda: None, begin, bind) == GROUP
    begin.assert_called_once_with()
    bind.assert_called_once_with(GROUP_SCOPE)
    args, kwargs = fixture.resources.resources.begin_create_or_update_by_id.call_args
    assert args[0] == APP_ID
    assert args[2].properties["managedResourceGroupId"] == GROUP_SCOPE
    assert args[2].tags == TAGS
    assert kwargs["polling"] is False
    fixture.resources.resource_groups.create_or_update.assert_not_called()
    fixture.authorization.role_assignments.create.assert_not_called()


@pytest.mark.parametrize("existing", ["application", "group"])
def test_new_operation_never_adopts_an_existing_target(fixture, existing):
    if existing == "application":
        fixture.objects[APP_ID] = fixture.app
    else:
        fixture.groups[GROUP] = fixture.group
    begin, bind = Mock(), Mock()
    with pytest.raises(GroupOwnershipError):
        fixture.manager.ensure(fixture.operation, "centralus", lambda: None, begin, bind)
    begin.assert_not_called()
    bind.assert_not_called()
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


@pytest.mark.parametrize("unsafe", ["unlocked", "unlocked_definition", "other_exclusion", "conditional_deny", "broad_role",
                                    "complete_mode", "unexpected_publisher", "wrong_partition"])
def test_unsafe_host_is_rejected_before_creation(fixture, unsafe):
    if unsafe == "unlocked":
        fixture.locks.management_locks.list_by_scope.side_effect = lambda _: []
    elif unsafe == "unlocked_definition":
        fixture.locks.management_locks.list_by_scope.side_effect = lambda scope: (
            [SimpleNamespace(id=scope + "/providers/Microsoft.Authorization/locks/readonly",
                             level="ReadOnly")] if scope == HOST_ID else [])
    elif unsafe == "other_exclusion":
        entry = deny(HOST_SCOPE)
        entry.exclude_principals.append(SimpleNamespace(id=CLIENT, type="ServicePrincipal"))
        fixture.authorization.deny_assignments.list_for_scope.side_effect = lambda _: [entry]
    elif unsafe == "conditional_deny":
        entry = deny(HOST_SCOPE)
        entry.condition = "@Subject[ResourceId] StringNotStartsWithIgnoreCase 'host/'"
        fixture.authorization.deny_assignments.list_for_scope.side_effect = lambda _: [entry]
    elif unsafe == "broad_role":
        fixture.authorization.permissions.list_for_resource_group.return_value[0].actions.append("*")
    elif unsafe == "complete_mode":
        fixture.definition.properties["deploymentPolicy"]["deploymentMode"] = "Complete"
    elif unsafe == "unexpected_publisher":
        fixture.definition.properties["authorizations"].append(
            {"principalId": CLIENT, "roleDefinitionId": NETWORK_CONTRIBUTOR})
    elif unsafe == "wrong_partition":
        fixture.operation["PartitionKey"] = TENANT
    with pytest.raises(GroupOwnershipError):
        fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), Mock())
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


def test_lease_loss_after_creation_intent_prevents_the_put(fixture):
    begin = Mock()

    def check():
        if begin.called:
            raise LostLease()

    with pytest.raises(LostLease):
        fixture.manager.ensure(fixture.operation, "centralus", check, begin, Mock())
    begin.assert_called_once_with()
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


def test_sdk_conditional_deny_is_not_treated_as_exclusive(fixture):
    observed = DenyAssignment.deserialize({"properties": {
        "scope": HOST_SCOPE, "isSystemProtected": True, "doNotApplyToChildScopes": False,
        "condition": f"@Subject[ResourceId] StringNotStartsWithIgnoreCase '{HOST_SCOPE}/'",
        "conditionVersion": "1.0",
        "principals": [{"id": EVERYONE, "type": "SystemDefined"}],
        "excludePrincipals": [{"id": PUBLISHER, "type": "ServicePrincipal"}],
        "permissions": [{"actions": ["*"], "notActions": ["*/read"],
                         "dataActions": ["*"], "notDataActions": ["*/read"]}],
    }})
    fixture.authorization.deny_assignments.list_for_scope.side_effect = lambda _: [observed]
    with pytest.raises(GroupOwnershipError):
        fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), Mock())
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


def test_exact_azure_conditions_require_explicit_lab_opt_in(fixture):
    def conditional(scope):
        entry = deny(scope)
        entry.condition = f"@Subject[ResourceId] StringNotStartsWithIgnoreCase '{scope}/'"
        entry.condition_version = "1.0"
        return [entry]

    fixture.authorization.deny_assignments.list_for_scope.side_effect = conditional
    with pytest.raises(GroupOwnershipError):
        fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), Mock())

    fixture.manager.allow_azure_managed_condition = True
    bind = Mock()
    assert fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), bind) == GROUP
    bind.assert_called_once_with(GROUP_SCOPE)


@pytest.mark.parametrize("change", ["different_scope", "extra_expression", "wrong_version"])
def test_lab_opt_in_rejects_other_deny_conditions(fixture, change):
    entry = deny(HOST_SCOPE)
    entry.condition = f"@Subject[ResourceId] StringNotStartsWithIgnoreCase '{HOST_SCOPE}/'"
    entry.condition_version = "1.0"
    if change == "different_scope":
        entry.condition = entry.condition.replace(HOST_SCOPE, HOST_SCOPE + "-other")
    elif change == "extra_expression":
        entry.condition += " || true"
    else:
        entry.condition_version = "2.0"
    fixture.manager.allow_azure_managed_condition = True
    fixture.authorization.deny_assignments.list_for_scope.side_effect = lambda _: [entry]
    with pytest.raises(GroupOwnershipError):
        fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), Mock())
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


def test_recovery_reads_owned_application_without_replaying_put(fixture):
    fixture.operation["providerGroupState"] = "creating"
    fixture.objects[APP_ID], fixture.groups[GROUP] = fixture.app, fixture.group
    bind = Mock()
    assert fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), bind) == GROUP
    bind.assert_called_once_with(GROUP_SCOPE)
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


def test_recovery_waits_for_bound_group_and_application_to_finish(fixture):
    fixture.operation["providerGroupState"] = "creating"
    fixture.objects[APP_ID], fixture.groups[GROUP] = fixture.app, fixture.group
    fixture.app.properties["provisioningState"] = "Accepted"
    fixture.group.properties.provisioning_state = "Updating"

    def finish(_seconds):
        fixture.app.properties["provisioningState"] = "Succeeded"
        fixture.group.properties.provisioning_state = "Succeeded"

    fixture.manager.wait = Mock(side_effect=finish)
    bind = Mock()
    assert fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), bind) == GROUP
    fixture.manager.wait.assert_called_once()
    bind.assert_called_once_with(GROUP_SCOPE)
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


def test_new_group_waits_for_owner_metadata_only_while_creating(fixture):
    fixture.operation["providerGroupState"] = "creating"
    fixture.objects[APP_ID], fixture.groups[GROUP] = fixture.app, fixture.group
    fixture.group.managed_by = None
    fixture.group.properties.provisioning_state = "Creating"

    def finish(_seconds):
        fixture.group.managed_by = APP_ID
        fixture.group.properties.provisioning_state = "Succeeded"

    fixture.manager.wait = Mock(side_effect=finish)
    bind = Mock()
    assert fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), bind) == GROUP
    fixture.manager.wait.assert_called_once()
    bind.assert_called_once_with(GROUP_SCOPE)
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


@pytest.mark.parametrize("owner,state", [(None, "Succeeded"), (HOST_ID, "Creating")])
def test_new_group_never_accepts_an_unbound_or_wrong_owner(fixture, owner, state):
    fixture.operation["providerGroupState"] = "creating"
    fixture.objects[APP_ID], fixture.groups[GROUP] = fixture.app, fixture.group
    fixture.group.managed_by = owner
    fixture.group.properties.provisioning_state = state
    fixture.manager.wait = Mock()
    bind = Mock()
    with pytest.raises(GroupOwnershipError, match="GroupBindingMismatch"):
        fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), bind)
    fixture.manager.wait.assert_not_called()
    bind.assert_not_called()
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


@pytest.mark.parametrize("missing", ["deny", "role"])
def test_new_group_waits_for_missing_permissions_without_binding(fixture, missing):
    fixture.operation["providerGroupState"] = "creating"
    fixture.objects[APP_ID], fixture.groups[GROUP] = fixture.app, fixture.group
    bind = Mock()
    roles = fixture.authorization.role_assignments.list_for_scope.return_value
    if missing == "role":
        fixture.authorization.role_assignments.list_for_scope.return_value = roles[:1]
    else:
        fixture.authorization.deny_assignments.list_for_scope.side_effect = (
            lambda scope: [deny(scope)] if scope == HOST_SCOPE else [])

    def finish(_seconds):
        bind.assert_not_called()
        fixture.authorization.role_assignments.list_for_scope.return_value = roles
        fixture.authorization.deny_assignments.list_for_scope.side_effect = lambda scope: [deny(scope)]

    fixture.manager.wait = Mock(side_effect=finish)
    assert fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), bind) == GROUP
    fixture.manager.wait.assert_called_once()
    bind.assert_called_once_with(GROUP_SCOPE)
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


def test_new_group_fails_closed_when_permissions_never_arrive(fixture):
    fixture.operation["providerGroupState"] = "creating"
    fixture.objects[APP_ID], fixture.groups[GROUP] = fixture.app, fixture.group
    fixture.authorization.role_assignments.list_for_scope.return_value = []
    fixture.manager.timeout = 0.01
    bind = Mock()
    with pytest.raises(GroupOwnershipError, match="GroupPermissionsNotReady"):
        fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), bind)
    bind.assert_not_called()
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


def test_new_group_rejects_unexpected_roles_without_waiting(fixture):
    fixture.operation["providerGroupState"] = "creating"
    fixture.objects[APP_ID], fixture.groups[GROUP] = fixture.app, fixture.group
    fixture.authorization.role_assignments.list_for_scope.return_value.append(
        SimpleNamespace(scope=GROUP_SCOPE, principal_id=PUBLISHER,
                        role_definition_id=f"{BASE}/providers/Microsoft.Authorization/roleDefinitions/{CLIENT}"))
    fixture.manager.wait = Mock()
    bind = Mock()
    with pytest.raises(GroupOwnershipError, match="GroupRoleMismatch"):
        fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), bind)
    fixture.manager.wait.assert_not_called()
    bind.assert_not_called()


def test_missing_application_after_uncertain_creation_is_not_replayed(fixture):
    fixture.operation["providerGroupState"] = "creating"
    with pytest.raises(GroupCreationUncertain):
        fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), Mock())
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


@pytest.mark.parametrize("state", ["Failed", "Canceled"])
def test_failed_managed_application_is_not_bound_or_recreated(fixture, state):
    fixture.operation["providerGroupState"] = "creating"
    fixture.app.properties["provisioningState"] = state
    fixture.objects[APP_ID], fixture.groups[GROUP] = fixture.app, fixture.group
    bind = Mock()
    with pytest.raises(GroupDeploymentFailed):
        fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), bind)
    bind.assert_not_called()
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


@pytest.mark.parametrize("bad", ["tags", "group_owner", "missing_role", "extra_role", "wrong_binding"])
def test_recovery_rejects_mismatched_ownership_or_permissions(fixture, bad):
    fixture.operation["providerGroupState"] = "created"
    fixture.operation["providerGroupId"] = GROUP_SCOPE
    fixture.objects[APP_ID], fixture.groups[GROUP] = fixture.app, fixture.group
    if bad == "tags":
        fixture.app.tags["faasClientId"] = CALLER
    elif bad == "group_owner":
        fixture.group.managed_by = HOST_ID
    elif bad == "missing_role":
        fixture.authorization.role_assignments.list_for_scope.return_value.pop()
    elif bad == "extra_role":
        fixture.authorization.role_assignments.list_for_scope.return_value.append(
            SimpleNamespace(scope=GROUP_SCOPE, principal_id=PUBLISHER,
                            role_definition_id=f"{BASE}/providers/Microsoft.Authorization/roleDefinitions/{CLIENT}"))
    elif bad == "wrong_binding":
        fixture.operation["providerGroupId"] = HOST_SCOPE
    with pytest.raises(GroupOwnershipError):
        fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), Mock())
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


@pytest.fixture
def worker_environment(monkeypatch):
    settings = {
        "FAAS_PROVIDER_SUBSCRIPTION_ID": SUBSCRIPTION,
        "FAAS_PROVIDER_RESOURCE_GROUP": PARENT_GROUP,
        "FAAS_GROUP_SUBSCRIPTION_ID": SUBSCRIPTION,
        "FAAS_GROUP_PROVISIONER_CLIENT_ID": CLIENT,
        "FAAS_GROUP_DEPLOYER_CLIENT_ID": CLIENT,
        "FAAS_GROUP_DEPLOYER_PRINCIPAL_ID": PUBLISHER,
        "FAAS_MANAGED_HOST_GROUP": HOST_GROUP,
        "FAAS_MANAGED_HOST_PARENT_GROUP": PARENT_GROUP,
        "FAAS_MANAGED_HOST_APPLICATION": HOST_APPLICATION,
        "FAAS_MANAGED_HOST_DEFINITION": DEFINITION,
    }
    for key, value in settings.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("FAAS_MANAGED_HOST_ALLOW_AZURE_CONDITION", raising=False)
    return settings


def test_worker_requires_complete_managed_host_configuration(worker_environment):
    configured = WorkerSettings.from_env()
    assert configured.managed_host_group == HOST_GROUP
    assert configured.managed_host_parent_group == PARENT_GROUP
    assert configured.managed_host_application == HOST_APPLICATION
    assert configured.managed_host_definition == DEFINITION
    assert configured.managed_host_allow_azure_condition is False


def test_worker_lab_condition_opt_in_is_explicit(worker_environment, monkeypatch):
    monkeypatch.setenv("FAAS_MANAGED_HOST_ALLOW_AZURE_CONDITION", "true")
    assert WorkerSettings.from_env().managed_host_allow_azure_condition is True


@pytest.mark.parametrize("key,value", [
    ("FAAS_MANAGED_HOST_DEFINITION", ""),
    ("FAAS_GROUP_SUBSCRIPTION_ID", ""),
    ("FAAS_GROUP_DEPLOYER_CLIENT_ID", CALLER),
    ("FAAS_MANAGED_HOST_GROUP", "../other-group"),
    ("FAAS_MANAGED_HOST_GROUP", PARENT_GROUP.upper()),
    ("FAAS_MANAGED_HOST_ALLOW_AZURE_CONDITION", "yes"),
])
def test_worker_rejects_unsafe_managed_host_configuration(
        worker_environment, monkeypatch, key, value):
    monkeypatch.setenv(key, value)
    with pytest.raises(ValueError):
        WorkerSettings.from_env()


@pytest.mark.parametrize("safe", [True, False])
def test_worker_uses_the_protected_allocator_only_after_host_validation(fixture, safe):
    endpoint = {"publicIp": "8.8.8.8", "bgpAddress": "10.0.0.4", "asn": 64512}
    request = EnvironmentRequest.model_validate({
        "mode": "network", "customerIngress": endpoint,
        "customerDelivery": {**endpoint, "publicIp": "1.1.1.1"},
    })
    fixture.operation["request"] = stored_environment_request(request, False, True)
    fixture.operation["secretVersions"] = "{}"
    fixture.app.location = request.region
    fixture.group.location = request.region
    if not safe:
        fixture.locks.management_locks.list_by_scope.side_effect = lambda _: []
    store, provisioner, arm, factory = Mock(), Mock(), Mock(), Mock()
    store.settings.lease_seconds = 90
    store.operation.return_value = fixture.operation
    provisioner.templates.network = object()
    provisioner.provision.return_value = {}
    factory.return_value = arm
    lease = Lease(ENVIRONMENT, "worker", 1)

    Worker(store, provisioner, fixture.manager, factory).process(lease)

    if safe:
        factory.assert_called_once_with(GROUP)
        store.bind_provider_group.assert_called_once_with(lease, SUBSCRIPTION, GROUP_SCOPE)
        assert provisioner.provision.call_args.kwargs["arm"] is arm
        assert store.finish.call_args.args[1] == "Ready"
    else:
        factory.assert_not_called()
        provisioner.provision.assert_not_called()
        assert store.finish.call_args.args[1] == "Failed"
        assert store.finish.call_args.args[3] == "GroupOwnershipError"


def test_worker_reports_a_failed_managed_application_without_starting_deployment(fixture):
    endpoint = {"publicIp": "8.8.8.8", "bgpAddress": "10.0.0.4", "asn": 64512}
    request = EnvironmentRequest.model_validate({
        "mode": "network", "customerIngress": endpoint,
        "customerDelivery": {**endpoint, "publicIp": "1.1.1.1"},
    })
    fixture.operation.update(providerGroupState="creating",
                             request=stored_environment_request(request, False, True),
                             secretVersions="{}")
    fixture.app.location = fixture.group.location = request.region
    fixture.app.properties["provisioningState"] = "Failed"
    fixture.objects[APP_ID], fixture.groups[GROUP] = fixture.app, fixture.group
    store, provisioner, factory = Mock(), Mock(), Mock()
    store.settings.lease_seconds = 90
    store.operation.return_value = fixture.operation
    provisioner.templates.network = object()

    Worker(store, provisioner, fixture.manager, factory).process(Lease(ENVIRONMENT, "worker", 1))

    factory.assert_not_called()
    provisioner.provision.assert_not_called()
    assert store.finish.call_args.args[1] == "Failed"
    assert store.finish.call_args.args[3] == "GroupDeploymentFailed"


def checkpoint_manager(fixture, roles):
    fixture.definition.properties["authorizations"] = [
        {"principalId": PUBLISHER, "roleDefinitionId": role} for role in roles]
    fixture.authorization.role_assignments.list_for_scope.return_value = [
        SimpleNamespace(scope=GROUP_SCOPE, principal_id=PUBLISHER,
                        role_definition_id=f"{BASE}/providers/Microsoft.Authorization/roleDefinitions/{role}")
        for role in roles]
    return ManagedEnvironmentGroups(
        fixture.resources, fixture.authorization, fixture.locks, SUBSCRIPTION, PUBLISHER, AUTHORITY,
        HOST_GROUP, PARENT_GROUP, HOST_APPLICATION, DEFINITION, wait=lambda _: None, timeout=1,
        publisher_roles=CHECKPOINT_PUBLISHER_ROLES)


def test_checkpoint_definition_requires_its_exact_separate_role_set(fixture):
    manager = checkpoint_manager(fixture, CHECKPOINT_PUBLISHER_ROLES)
    assert manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), Mock()) == GROUP


def test_ubuntu_allocator_rejects_a_broader_checkpoint_definition(fixture):
    checkpoint_manager(fixture, CHECKPOINT_PUBLISHER_ROLES)
    with pytest.raises(GroupOwnershipError):
        fixture.manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), Mock())
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


def test_checkpoint_allocator_rejects_missing_or_extra_definition_roles(fixture):
    manager = checkpoint_manager(fixture, CHECKPOINT_PUBLISHER_ROLES[:-1])
    with pytest.raises(GroupOwnershipError):
        manager.ensure(fixture.operation, "centralus", lambda: None, Mock(), Mock())
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()


@pytest.mark.parametrize("roles", [(), (NETWORK_CONTRIBUTOR,), (NETWORK_CONTRIBUTOR, NETWORK_CONTRIBUTOR),
                                   ["not-a-tuple"]])
def test_allocator_rejects_unsupported_publisher_role_sets(fixture, roles):
    with pytest.raises(ValueError):
        ManagedEnvironmentGroups(
            fixture.resources, fixture.authorization, fixture.locks, SUBSCRIPTION, PUBLISHER, AUTHORITY,
            HOST_GROUP, PARENT_GROUP, HOST_APPLICATION, DEFINITION, publisher_roles=roles)


def test_checkpoint_allocator_checks_host_deny_against_the_host_publisher(fixture):
    checkpoint = "00000000-0000-0000-0000-000000000077"

    def denies(scope):
        item = deny(scope)
        if scope == GROUP_SCOPE:
            item.exclude_principals = [SimpleNamespace(id=checkpoint, type="ServicePrincipal")]
        return [item]

    fixture.authorization.deny_assignments.list_for_scope.side_effect = denies
    fixture.definition.properties["authorizations"] = [
        {"principalId": checkpoint, "roleDefinitionId": role} for role in CHECKPOINT_PUBLISHER_ROLES]
    fixture.authorization.role_assignments.list_for_scope.return_value = [
        SimpleNamespace(scope=GROUP_SCOPE, principal_id=checkpoint,
                        role_definition_id=f"{BASE}/providers/Microsoft.Authorization/roleDefinitions/{role}")
        for role in CHECKPOINT_PUBLISHER_ROLES]

    def manager(host_principal=None):
        return ManagedEnvironmentGroups(
            fixture.resources, fixture.authorization, fixture.locks, SUBSCRIPTION, checkpoint, AUTHORITY,
            HOST_GROUP, PARENT_GROUP, HOST_APPLICATION, DEFINITION, wait=lambda _: None, timeout=1,
            publisher_roles=CHECKPOINT_PUBLISHER_ROLES, host_principal=host_principal)

    with pytest.raises(GroupOwnershipError):
        manager().ensure(fixture.operation, "centralus", lambda: None, Mock(), Mock())
    fixture.resources.resources.begin_create_or_update_by_id.assert_not_called()
    assert manager(PUBLISHER).ensure(fixture.operation, "centralus", lambda: None, Mock(), Mock()) == GROUP
