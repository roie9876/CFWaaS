#!/usr/bin/env python3
"""Publisher engineering: register the reusable, secretless Entra setup client.

This requests no consent and grants no permissions. The provider administrator
will separately review the delegated Graph permissions during device sign-in.
"""
import argparse
from pathlib import Path

from bootstrap_identity import Graph, find_exact
from common import ROOT, load_private, save_private, uuid_value

GRAPH_APP = "00000003-0000-0000-c000-000000000000"
SCOPES = (
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d",  # User.Read
    "bdfbf15f-ee85-4955-8675-146e8e5296b5",  # Application.ReadWrite.All
    "c79f8feb-a9db-4090-85f9-90d820caa0eb",  # Application.Read.All
    "84bccea3-f856-4a8a-967b-dbe0a3d53a64",  # AppRoleAssignment.ReadWrite.All
)


def register(graph, state: dict, path: Path) -> dict:
    if state.get("pendingOperation"):
        raise ValueError("An uncertain setup client write requires directory audit review")
    if state.get("providerTenantId") != graph.tenant:
        raise ValueError("Setup client journal belongs to another tenant")
    client_id = state.get("clientId")
    if not client_id:
        state["pendingOperation"] = "CreateApplication"
        save_private(path, state)
        app = graph.request("POST", "/applications", {
            "displayName": "FaaS Provider Setup",
            "signInAudience": "AzureADMultipleOrgs",
            "isFallbackPublicClient": True,
            "requiredResourceAccess": [{
                "resourceAppId": GRAPH_APP,
                "resourceAccess": [{"id": scope, "type": "Scope"} for scope in SCOPES],
            }],
        })
        state.update(applicationObjectId=uuid_value(app["id"]), clientId=uuid_value(app["appId"]),
                     pendingOperation="")
        save_private(path, state)
        client_id = state["clientId"]
    app = find_exact(graph, "applications", uuid_value(client_id))
    expected = {(scope, "Scope") for scope in SCOPES}
    access = app.get("requiredResourceAccess", []) if app else []
    if (not app or app.get("id") != state.get("applicationObjectId")
            or app.get("signInAudience") != "AzureADMultipleOrgs"
            or app.get("isFallbackPublicClient") is not True
            or len(access) != 1 or access[0].get("resourceAppId") != GRAPH_APP
            or {(entry.get("id"), entry.get("type")) for entry in access[0].get("resourceAccess", [])} != expected
            or len(access[0].get("resourceAccess", [])) != len(expected)):
        raise ValueError("Setup public client does not match the approved permission contract")
    principal = find_exact(graph, "servicePrincipals", client_id)
    if principal is None:
        if state.get("principalId"):
            raise ValueError("Bound setup service principal is missing")
        state["pendingOperation"] = "CreateServicePrincipal"
        save_private(path, state)
        principal = graph.request("POST", "/servicePrincipals", {"appId": client_id})
        state.update(principalId=uuid_value(principal["id"]), pendingOperation="")
        save_private(path, state)
    if (principal.get("id") != state.get("principalId")
            or principal.get("appId") != client_id):
        raise ValueError("Setup client service principal differs from the journal")
    return state


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider-tenant-id", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    tenant = uuid_value(args.provider_tenant_id)
    if not args.execute:
        print("DRY RUN: no Entra operations performed.")
        return
    path = ROOT / ".local/provider-setup-client.json"
    state = load_private(path) if path.exists() else {"providerTenantId": tenant}
    register(Graph(tenant), state, path)
    print("Provider setup public client registered. No admin consent or application permission was granted.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Setup client registration stopped; inspect provider directory audit before retrying.") from None
