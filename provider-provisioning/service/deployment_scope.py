from dataclasses import dataclass
import re
from typing import Literal

from .config import uuid_text

ScopeMode = Literal["customer", "provider-lab"]
SCOPE_MODES = ("customer", "provider-lab")
SCOPE_LABELS = {
    "customer": "Customer tenant/subscription (separate)",
    "provider-lab": "Provider tenant/subscription (lab only)",
}


class ScopeSelectionError(ValueError):
    pass


def scope_mode(value: object) -> ScopeMode:
    if value == "customer":
        return "customer"
    if value == "provider-lab":
        return "provider-lab"
    raise ScopeSelectionError("InvalidEnrollmentScopeMode")


@dataclass(frozen=True)
class ProviderScope:
    tenant: str
    subscription: str
    protected_groups: tuple[str, ...]

    def __post_init__(self) -> None:
        uuid_text(self.tenant)
        uuid_text(self.subscription)
        if not self.protected_groups:
            raise ValueError("Provider protected resource groups are required")
        prefix = f"/subscriptions/{self.subscription}/resourcegroups/"
        for group in self.protected_groups:
            if (not isinstance(group, str) or not group.lower().startswith(prefix)
                    or not re.fullmatch(r"[\w().-]{1,90}", group[len(prefix):])):
                raise ValueError("Invalid provider protected resource group")

    def validate(self, mode: ScopeMode, acknowledged: bool, tenant: str, subscription: str) -> None:
        if mode == "provider-lab":
            if not acknowledged:
                raise ScopeSelectionError("ProviderLabAcknowledgementRequired")
            if (tenant, subscription) != (self.tenant, self.subscription):
                raise ScopeSelectionError("ProviderLabScopeMismatch")
        elif tenant == self.tenant or subscription == self.subscription:
            raise ScopeSelectionError("ProviderLabModeRequired")

    def public(self) -> dict:
        return {"available": True, "tenantId": self.tenant, "subscriptionId": self.subscription}


def bind_scope(parameters: dict, fields: dict, mode: ScopeMode,
               tenant: str, subscription: str, protected_groups: tuple[str, ...] = ()) -> None:
    if "scopeMode" not in parameters:
        if mode == "provider-lab":
            raise ValueError("Provider lab customer release is incomplete")
        return
    if ("scopeMode" not in fields or "deploymentScopeNotice" not in fields
            or "providerProtectedResourceGroupIds" not in parameters):
        raise ValueError("Customer scope wizard is incomplete")
    parameters["scopeMode"].update(defaultValue=mode, allowedValues=[mode])
    fields["scopeMode"]["defaultValue"] = SCOPE_LABELS[mode]
    fields["scopeMode"]["constraints"]["allowedValues"] = [{"label": SCOPE_LABELS[mode], "value": mode}]
    fields["deploymentScopeNotice"]["options"]["text"] = (
        f"Approved tenant: {tenant}. Approved subscription: {subscription}. "
        "Select this scope in Azure Portal and use a separate customer resource group. "
        + ("Provider-only lab: this does not test cross-tenant organizational isolation. "
           if mode == "provider-lab" else "")
        + "To change scope, create a new enrollment; this deployment link cannot rebind an existing customer.")
    parameters["providerProtectedResourceGroupIds"]["defaultValue"] = list(protected_groups)
