import re
import time
from typing import Callable
from uuid import UUID

from azure.core.exceptions import ResourceNotFoundError
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.locks import ManagementLockClient
from azure.mgmt.resource.resources.models import GenericResource

from .environment_groups import (
    GroupCreationUncertain, GroupCreationUnavailable, GroupDeploymentFailed, GroupOwnershipError,
)
from .models import environment_resource_group_name

APPLICATION_API = "2021-07-01"
NETWORK_CONTRIBUTOR = "4d97b98b-1d4f-4787-a291-c67834d212e7"
VM_CONTRIBUTOR = "9980e02c-c2be-4d73-94e8-173b1dc7cf3c"
UBUNTU_PUBLISHER_ROLES = (NETWORK_CONTRIBUTOR, VM_CONTRIBUTOR)
# Separate Check Point definition only; the Ubuntu definition keeps the two roles above.
CHECKPOINT_PUBLISHER_ROLES = UBUNTU_PUBLISHER_ROLES + (
    "f25e0fa2-a7c8-4377-a976-54943a77a395",  # Key Vault Contributor
    "b86a8fe4-44ce-4948-aee5-eccb2c155cd7",  # Key Vault Secrets Officer
    "17d1049b-9a84-46fb-8f53-869881c3d3ab",  # Storage Account Contributor
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe",  # Storage Blob Data Contributor
    "b12aa53e-6015-4669-85d0-8515ebb3ae7f",  # Private DNS Zone Contributor
    "5d977122-f97e-4b4d-a52f-6b43003ddb4d",  # Azure Container Instances Contributor
)
EVERYONE = "00000000-0000-0000-0000-000000000000"
HOST_ACTIONS = {
    "*/read",
    "microsoft.authorization/denyassignments/read",
    "microsoft.authorization/locks/read",
    "microsoft.authorization/permissions/read",
    "microsoft.authorization/roleassignments/read",
    "microsoft.authorization/roledefinitions/read",
    "microsoft.resources/subscriptions/resourcegroups/read",
    "microsoft.solutions/applications/read",
    "microsoft.solutions/applications/write",
    "microsoft.solutions/applications/delete",
}


def _uuid(value: str) -> str:
    if str(UUID(value)) != value:
        raise ValueError("Invalid identity")
    return value


def _name(value: str) -> str:
    if not re.fullmatch(r"[a-zA-Z0-9_.()-]{1,90}", value) or value.endswith("."):
        raise ValueError("Invalid resource name")
    return value


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and left.lower() == right.lower()


class ManagedEnvironmentGroups:
    """Experimental managed-application group allocator; startup remains gated."""

    def __init__(
        self, resources: ResourceManagementClient, authorization: AuthorizationManagementClient,
        locks: ManagementLockClient, subscription: str, principal: str, authority_tenant: str,
        host_group: str, host_parent_group: str, host_application: str, definition: str,
        wait: Callable[[float], None] = time.sleep, timeout: float = 600,
        allow_azure_managed_condition: bool = False,
        publisher_roles: tuple[str, ...] = UBUNTU_PUBLISHER_ROLES,
        host_principal: str | None = None,
    ) -> None:
        self.resources, self.authorization, self.locks = resources, authorization, locks
        self.subscription, self.principal = _uuid(subscription), _uuid(principal)
        # The shared host group's deny excludes the identity of the definition that created it,
        # which differs from this allocator's publisher when it uses a separate definition.
        self.host_principal = _uuid(host_principal) if host_principal is not None else self.principal
        self.authority_tenant = _uuid(authority_tenant)
        self.host_group, self.host_parent_group = _name(host_group), _name(host_parent_group)
        if self.host_group.lower() == self.host_parent_group.lower():
            raise ValueError("Managed host must use a separate parent group")
        self.host_application, self.definition = _name(host_application), _name(definition)
        self.host_scope = f"/subscriptions/{self.subscription}/resourceGroups/{self.host_group}"
        self.host_id = (f"/subscriptions/{self.subscription}/resourceGroups/{self.host_parent_group}"
                        f"/providers/Microsoft.Solutions/applications/{self.host_application}")
        self.definition_id = (f"/subscriptions/{self.subscription}/resourceGroups/{self.host_parent_group}"
                              f"/providers/Microsoft.Solutions/applicationDefinitions/{self.definition}")
        if timeout <= 0:
            raise ValueError("Invalid group timeout")
        if type(allow_azure_managed_condition) is not bool:
            raise ValueError("Invalid managed deny condition setting")
        self.wait, self.timeout = wait, timeout
        self.allow_azure_managed_condition = allow_azure_managed_condition
        if (not isinstance(publisher_roles, tuple) or not publisher_roles
                or len(set(publisher_roles)) != len(publisher_roles)
                or publisher_roles not in (UBUNTU_PUBLISHER_ROLES, CHECKPOINT_PUBLISHER_ROLES)):
            raise ValueError("Unsupported managed publisher role set")
        self.publisher_roles = publisher_roles

    def _resource(self, resource_id: str):
        try:
            return self.resources.resources.get_by_id(resource_id, APPLICATION_API)
        except ResourceNotFoundError:
            return None

    def _group(self, name: str):
        try:
            return self.resources.resource_groups.get(name)
        except ResourceNotFoundError:
            return None

    def _deny_is_acceptable(self, scope: str, denies=None, principal: str | None = None) -> bool:
        principal = principal or self.principal
        if denies is None:
            denies = self.authorization.deny_assignments.list_for_scope(scope)
        for deny in denies:
            if (not _same(deny.scope, scope) or not deny.is_system_protected
                    or deny.do_not_apply_to_child_scopes):
                continue
            if deny.condition:
                expected = f"@Subject[ResourceId] StringNotStartsWithIgnoreCase '{scope}/'"
                if (not self.allow_azure_managed_condition
                        or deny.condition_version != "1.0"
                        or not _same(deny.condition, expected)):
                    continue
            principals = {(str(p.id).lower(), str(p.type).lower()) for p in deny.principals or []}
            excluded = {(str(p.id).lower(), str(p.type).lower()) for p in deny.exclude_principals or []}
            if principals != {(EVERYONE, "systemdefined")} or excluded != {
                    (principal, "serviceprincipal")}:
                continue
            for permission in deny.permissions or []:
                if ({str(action).lower() for action in permission.actions or []} == {"*"}
                        and {str(action).lower() for action in permission.not_actions or []} == {"*/read"}
                        and {str(action).lower() for action in permission.data_actions or []} == {"*"}
                        and {str(action).lower() for action in permission.not_data_actions or []} == {"*/read"}):
                    return True
        return False

    def _host_is_safe(self, check: Callable[[], None]) -> None:
        check()
        host = self._resource(self.host_id)
        group = self._group(self.host_group)
        properties = host.properties if host and isinstance(host.properties, dict) else {}
        if (host is None or group is None or not _same(host.id, self.host_id)
                or not _same(host.kind, "ServiceCatalog")
                or properties.get("provisioningState") != "Succeeded"
                or not _same(properties.get("managedResourceGroupId"), self.host_scope)
                or not _same(group.id, self.host_scope) or not _same(group.managed_by, self.host_id)
                or group.properties is None or group.properties.provisioning_state != "Succeeded"):
            raise GroupOwnershipError("HostMismatch")
        check()
        for resource_id in (self.host_id, self.definition_id):
            lock_prefix = resource_id.lower() + "/providers/microsoft.authorization/locks/"
            if not any(
                    str(lock.level).lower() == "readonly"
                    and str(lock.id).lower().startswith(lock_prefix)
                    for lock in self.locks.management_locks.list_by_scope(resource_id)):
                raise GroupOwnershipError()
            check()
        check()
        if not self._deny_is_acceptable(self.host_scope, principal=self.host_principal):
            raise GroupOwnershipError()
        permissions = list(self.authorization.permissions.list_for_resource_group(self.host_group))
        if not permissions:
            raise GroupOwnershipError()
        actions: set[str] = set()
        for permission in permissions:
            if permission.not_actions or permission.data_actions or permission.not_data_actions:
                raise GroupOwnershipError()
            actions.update(str(action).lower() for action in permission.actions or [])
        if (not actions.issubset(HOST_ACTIONS)
                or "microsoft.solutions/applications/write" not in actions):
            raise GroupOwnershipError()
        check()
        definition = self._resource(self.definition_id)
        properties = definition.properties if definition and isinstance(definition.properties, dict) else {}
        authorizations = properties.get("authorizations")
        expected = {(self.principal, role) for role in self.publisher_roles}
        if (definition is None or not _same(definition.id, self.definition_id)
                or properties.get("lockLevel") != "ReadOnly"
                or not isinstance(properties.get("deploymentPolicy"), dict)
                or properties["deploymentPolicy"].get("deploymentMode") != "Incremental"
                or not isinstance(authorizations, list)
                or any(not isinstance(item, dict) for item in authorizations)
                or {(str(item.get("principalId", "")).lower(),
                     str(item.get("roleDefinitionId", "")).lower()) for item in authorizations} != expected
                or len(authorizations) != len(expected)):
            raise GroupOwnershipError()

    def _validate_application(self, app, app_id: str, group_scope: str, location: str, tags: dict) -> str:
        properties = app.properties if isinstance(app.properties, dict) else {}
        if (not _same(app.id, app_id) or not _same(app.kind, "ServiceCatalog")
                or not _same(app.location, location)
                or not _same(properties.get("applicationDefinitionId"), self.definition_id)
                or not _same(properties.get("managedResourceGroupId"), group_scope)
                or not isinstance(app.tags, dict)
                or any(app.tags.get(key) != value for key, value in tags.items())):
            raise GroupOwnershipError("ApplicationMismatch")
        state = properties.get("provisioningState")
        if not isinstance(state, str) or not state:
            raise GroupCreationUncertain()
        return state

    def _group_is_bound(self, group, scope: str, app_id: str, location: str) -> bool:
        return bool(group and _same(group.id, scope) and _same(group.location, location)
                    and _same(group.managed_by, app_id))

    def decommission(self, operation: dict, check) -> bool:
        """Delete one bound environment application; True once the app and group are gone.

        Never deletes a resource group directly. Azure deletes the managed group with
        its application, so an unbound or foreign group is rejected rather than removed.
        """
        try:
            environment_id = _uuid(str(operation["environmentId"]))
            name = str(operation["providerGroupName"])
            if (operation.get("PartitionKey") != "registry:" + self.authority_tenant
                    or operation.get("RowKey") != "op:" + environment_id
                    or operation.get("providerGroupMode") != "isolated"
                    or not name.startswith("rg-faas-env-")
                    or environment_resource_group_name(name.removeprefix("rg-faas-env-")) != name):
                raise ValueError()
            tags = {"purpose": "provider-provisioning-environment", "faasEnvironmentId": environment_id,
                    "faasClientId": _uuid(str(operation["client"])),
                    "faasTenantId": _uuid(str(operation["tenant"])),
                    "faasPrincipalId": _uuid(str(operation["principal"]))}
        except (KeyError, ValueError, TypeError):
            raise GroupOwnershipError() from None
        app_id = f"{self.host_scope}/providers/Microsoft.Solutions/applications/faas-env-{environment_id}"
        scope = f"/subscriptions/{self.subscription}/resourceGroups/{name}"
        self._host_is_safe(check)
        check()
        app, group = self._resource(app_id), self._group(name)
        if app is not None:
            state = self._validate_application(app, app_id, scope, str(app.location), tags)
            if group is not None and not self._group_is_bound(group, scope, app_id, str(app.location)):
                raise GroupOwnershipError("GroupBindingMismatch")
            if state != "Deleting":
                check()
                self.resources.resources.begin_delete_by_id(app_id, APPLICATION_API, polling=False)
            return False
        if group is not None:
            if not _same(group.id, scope) or not _same(group.managed_by, app_id):
                raise GroupOwnershipError("GroupBindingMismatch")
            return False
        return True

    def ensure(self, operation: dict, location: str, check, begin=None, bind=None) -> str:
        try:
            environment_id = _uuid(str(operation["environmentId"]))
            client = _uuid(str(operation["client"]))
            tenant = _uuid(str(operation["tenant"]))
            principal = _uuid(str(operation["principal"]))
            name = str(operation["providerGroupName"])
            if (operation.get("PartitionKey") != "registry:" + self.authority_tenant
                    or operation.get("RowKey") != "op:" + environment_id
                    or operation.get("providerGroupMode") != "isolated"
                    or not name.startswith("rg-faas-env-")
                    or environment_resource_group_name(name.removeprefix("rg-faas-env-")) != name
                    or not re.fullmatch(r"[a-z0-9]{1,30}", location)):
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise GroupOwnershipError() from None
        app_id = f"{self.host_scope}/providers/Microsoft.Solutions/applications/faas-env-{environment_id}"
        scope = f"/subscriptions/{self.subscription}/resourceGroups/{name}"
        tags = {"purpose": "provider-provisioning-environment", "faasEnvironmentId": environment_id,
                "faasClientId": client, "faasTenantId": tenant, "faasPrincipalId": principal}
        self._host_is_safe(check)
        state = operation.get("providerGroupState", "new")
        check()
        app, group = self._resource(app_id), self._group(name)
        if state == "new":
            if app is not None or group is not None:
                raise GroupOwnershipError()
            if begin is None or bind is None:
                raise GroupCreationUnavailable()
            begin()
            check()
            self.resources.resources.begin_create_or_update_by_id(
                app_id, APPLICATION_API,
                GenericResource(
                    location=location, kind="ServiceCatalog", tags=tags,
                    properties={"applicationDefinitionId": self.definition_id,
                                "managedResourceGroupId": scope}),
                polling=False,
            )
            state = "creating"
        elif state not in ("creating", "created"):
            raise GroupOwnershipError()

        deadline = time.monotonic() + self.timeout
        permission_deadline = None
        expected = {
            f"/subscriptions/{self.subscription}/providers/microsoft.authorization/roledefinitions/{role}"
            for role in self.publisher_roles
        }
        while True:
            check()
            app, group = self._resource(app_id), self._group(name)
            if app is None:
                raise GroupCreationUncertain()
            app_state = self._validate_application(app, app_id, scope, location, tags)
            group_state = group.properties.provisioning_state if group and group.properties else None
            if group is not None and (not isinstance(group_state, str) or not group_state):
                raise GroupCreationUncertain()
            if group is not None and not self._group_is_bound(group, scope, app_id, location):
                awaiting_owner = (state == "creating" and not group.managed_by
                                  and _same(group.id, scope) and _same(group.location, location)
                                  and group_state in ("Creating", "Updating"))
                if not awaiting_owner:
                    raise GroupOwnershipError("GroupBindingMismatch")
            if app_state in ("Failed", "Canceled", "Cancelled"):
                raise GroupDeploymentFailed()
            if group_state in ("Failed", "Canceled", "Cancelled"):
                raise GroupDeploymentFailed()
            if app_state == "Succeeded" and group_state == "Succeeded":
                check()
                denies = list(self.authorization.deny_assignments.list_for_scope(scope))
                acceptable = self._deny_is_acceptable(scope, denies)
                assignments = self.authorization.role_assignments.list_for_scope(scope)
                actual = {
                    str(assignment.role_definition_id).lower()
                    for assignment in assignments
                    if _same(assignment.scope, scope) and _same(assignment.principal_id, self.principal)
                }
                if actual - expected:
                    raise GroupOwnershipError("GroupRoleMismatch")
                if not acceptable and any(_same(deny.scope, scope) for deny in denies):
                    raise GroupOwnershipError("GroupDenyMismatch")
                if acceptable and actual == expected:
                    break
                if state != "creating":
                    raise GroupOwnershipError("GroupPermissionsNotReady")
                if permission_deadline is None:
                    permission_deadline = min(deadline, time.monotonic() + 60)
                if time.monotonic() >= permission_deadline:
                    raise GroupOwnershipError("GroupPermissionsNotReady")
            if time.monotonic() >= deadline:
                raise GroupCreationUncertain()
            self.wait(5)

        if state == "created":
            if not _same(operation.get("providerGroupId"), scope):
                raise GroupOwnershipError()
        elif bind is None:
            raise GroupCreationUncertain()
        else:
            check()
            bind(scope)
        check()
        return name
