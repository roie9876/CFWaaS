from uuid import NAMESPACE_URL, UUID, uuid5

from azure.core.exceptions import ResourceNotFoundError

from .models import environment_resource_group_name


class GroupOwnershipError(Exception):
    pass


class GroupCreationUncertain(Exception):
    pass


class GroupCreationUnavailable(Exception):
    pass


class GroupDeploymentFailed(Exception):
    pass


class EnvironmentGroups:
    def __init__(self, resources, authorization, subscription: str, principal: str):
        if str(UUID(subscription)) != subscription or str(UUID(principal)) != principal:
            raise ValueError("Invalid provider identity")
        self.resources, self.authorization = resources, authorization
        self.subscription, self.principal = subscription, principal

    def ensure(self, operation: dict, location: str, check, begin=None, bind=None) -> str:
        environment_id = str(operation["environmentId"])
        client = str(operation["client"])
        name = str(operation["providerGroupName"])
        try:
            if (str(UUID(environment_id)) != environment_id or str(UUID(client)) != client
                    or not name.startswith("rg-faas-env-") or environment_resource_group_name(
                        name.removeprefix("rg-faas-env-")) != name):
                raise ValueError()
        except (ValueError, TypeError, AttributeError):
            raise GroupOwnershipError() from None
        scope = f"/subscriptions/{self.subscription}/resourceGroups/{name}"
        tags = {"purpose": "provider-provisioning-environment",
                "faasEnvironmentId": environment_id, "faasClientId": client}
        check()
        try:
            group = self.resources.resource_groups.get(name)
        except ResourceNotFoundError:
            group = None
        state = operation.get("providerGroupState", "new")
        if state == "new":
            if group is not None:
                raise GroupOwnershipError()
            # ARM's create-or-update is not an atomic create-only operation.
            raise GroupCreationUnavailable()
        elif state == "creating":
            raise GroupCreationUncertain()
        elif state == "created":
            if (group is None or str(group.id).lower() != scope.lower()
                    or group.location.lower() != location.lower()
                    or any((group.tags or {}).get(key) != value for key, value in tags.items())
                    or str(operation.get("providerGroupId", "")).lower() != scope.lower()):
                raise GroupOwnershipError()
        else:
            raise GroupOwnershipError()

        role = f"/subscriptions/{self.subscription}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c"
        assignment_id = str(uuid5(NAMESPACE_URL, "faas-role:" + scope.lower() + ":" + self.principal))
        check()
        try:
            assignment = self.authorization.role_assignments.get(scope, assignment_id)
        except ResourceNotFoundError:
            assignment = self.authorization.role_assignments.create(
                scope, assignment_id,
                {"role_definition_id": role, "principal_id": self.principal,
                 "principal_type": "ServicePrincipal"}, retry_total=0)
        if (str(assignment.principal_id).lower() != self.principal
                or str(assignment.role_definition_id).lower() != role.lower()
                or str(assignment.scope).lower() != scope.lower()):
            raise GroupOwnershipError()
        check()
        return name