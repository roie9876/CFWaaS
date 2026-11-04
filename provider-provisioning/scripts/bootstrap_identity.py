#!/usr/bin/env python3
"""Explicit directory bootstrap. Imports and default invocations perform no cloud calls."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import shlex
from pathlib import Path
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import uuid

from common import ROOT, cli, config_digest, digest, load_private, save_private, uuid_value, validate_config, verify_account

ROLE = "FirewallDeployment.Request"
GRAPH = "https://graph.microsoft.com/v1.0"


class DirectoryDenied(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Graph:
    def __init__(self, tenant: str):
        self.tenant = tenant
        # Explicit tenant; token is captured in memory, never argv or logs.
        result = subprocess.run(
            ["az", "account", "get-access-token", "--tenant", tenant,
             "--scope", "https://graph.microsoft.com/.default", "--query", "accessToken", "--output", "tsv",
             "--only-show-errors"], capture_output=True, text=True, check=True)
        self._token = result.stdout.strip()
        if not self._token:
            raise ValueError("No tenant-scoped Graph token")

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        if not path.startswith("/") or "://" in path:
            raise ValueError("Graph path must be relative")
        request = urllib.request.Request(
            GRAPH + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Authorization": "Bearer " + self._token, "Content-Type": "application/json"})
        try:
            with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response:
                data = response.read()
                return json.loads(data) if data else {}
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                # Never print the response body or authorization header.
                raise DirectoryDenied(
                    f"Graph {method} {path} denied in tenant {self.tenant}. "
                    "An already-authorized directory administrator must run this same "
                    "command after signing into that tenant; no directory role is granted "
                    "by this script. Required Graph operation/body are saved in the private journal."
                ) from None
            raise RuntimeError(f"Graph {method} failed HTTP {exc.code}; inspect tenant audit logs") from None


def find_exact(graph: Graph, collection: str, app_id: str) -> dict | None:
    uuid_value(app_id)
    query = urllib.parse.urlencode({"$filter": f"appId eq '{app_id}'"})
    matches = graph.request("GET", f"/{collection}?{query}").get("value", [])
    if len(matches) > 1:
        raise ValueError("Ambiguous application ID; refusing display-name fallback")
    return matches[0] if matches else None


def graph_write(graph: Graph, method: str, path: str, body: dict, journal: dict, journal_path: Path) -> dict:
    journal["pendingAdminOperation"] = {"tenantId": graph.tenant, "method": method, "path": path, "body": body}
    save_private(journal_path, journal)
    result = graph.request(method, path, body)
    journal.pop("pendingAdminOperation", None)
    return result


def provider(config: dict, journal: dict, path: Path) -> None:
    if (config.get("apiApplicationId") and journal.get("apiApplicationId")
            and config["apiApplicationId"] != journal["apiApplicationId"]):
        raise ValueError("Configured API application differs from the bound ownership journal")
    graph = Graph(config["provider"]["tenantId"])
    app_id = config.get("apiApplicationId") or journal.get("apiApplicationId")
    app = find_exact(graph, "applications", app_id) if app_id else None
    if app_id and not app:
        raise ValueError("Configured appId does not exist in provider tenant; refusing replacement")
    redirect = config.get("consentRedirectUri")
    if redirect:
        parsed = urllib.parse.urlsplit(redirect)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.fragment:
            raise ValueError("Consent redirect must be an explicitly configured HTTPS URL")
    role_id = journal.setdefault("appRoleId", str(uuid.uuid4()))
    save_private(path, journal)
    if not app:
        if journal.get("applicationCreateAttempted"):
            raise ValueError("Previous create may have succeeded. Recover exact appId from directory audit into config; no display-name matching.")
        journal["applicationCreateAttempted"] = True
        save_private(path, journal)
        try:
            app = graph_write(graph, "POST", "/applications", {
            "displayName": "faas-provider-" + config["runId"],
            "signInAudience": "AzureADMultipleOrgs",
            "requiredResourceAccess": [],
            "api": {"requestedAccessTokenVersion": 2},
            "optionalClaims": {"accessToken": [{"name": "idtyp", "essential": False}]},
            "appRoles": [{"id": role_id, "value": ROLE, "displayName": ROLE,
                          "description": "Request an entitled firewall environment",
                          "allowedMemberTypes": ["Application"], "isEnabled": True}],
            "web": {"redirectUris": [redirect] if redirect else []},
            }, journal, path)
        except DirectoryDenied:
            journal["applicationCreateAttempted"] = False
            save_private(path, journal)
            raise
        journal.update(apiApplicationId=app["appId"], applicationObjectId=app["id"], applicationCreated=True)
        save_private(path, journal)
    else:
        roles = [r for r in app.get("appRoles", []) if r.get("value") == ROLE]
        if len(roles) != 1 or roles[0].get("allowedMemberTypes") != ["Application"] or not roles[0].get("isEnabled"):
            raise ValueError("Existing app role differs; administrator must reconcile explicitly")
        role_id = roles[0]["id"]
        if app.get("signInAudience") != "AzureADMultipleOrgs" or app.get("api", {}).get("requestedAccessTokenVersion") != 2:
            raise ValueError("Existing application is not approved multitenant v2 configuration")
        if app.get("requiredResourceAccess"):
            raise ValueError("API application must not request additional directory/application permissions")
        if not any(claim.get("name") == "idtyp" for claim in app.get("optionalClaims", {}).get("accessToken", [])):
            raise ValueError("Existing application is missing the required idtyp access-token claim")
        journal.update(apiApplicationId=app["appId"], applicationObjectId=app["id"], appRoleId=role_id)
        save_private(path, journal)
    desired_uri = "api://" + app["appId"]
    uris = app.get("identifierUris", [])
    if uris and uris != [desired_uri]:
        raise ValueError("Unexpected existing identifier URI")
    if not uris:
        graph_write(graph, "PATCH", "/applications/" + app["id"],
                    {"identifierUris": [desired_uri]}, journal, path)
    journal["apiAudience"] = app["appId"]  # v2 access-token aud is the API client ID
    journal["apiResource"] = desired_uri
    if redirect:
        if app.get("web", {}).get("redirectUris", []) != [redirect]:
            raise ValueError("Consent redirect does not match registered application")
        journal["adminConsentUrl"] = (
            "https://login.microsoftonline.com/" + config["customer"]["tenantId"] + "/v2.0/adminconsent?"
            + urllib.parse.urlencode({"client_id": app["appId"], "redirect_uri": redirect,
                                     "scope": desired_uri + "/.default", "state": digest(config)}))
    save_private(path, journal)


def customer(config: dict, journal: dict, path: Path) -> None:
    if (config.get("apiApplicationId") and journal.get("apiApplicationId")
            and config["apiApplicationId"] != journal["apiApplicationId"]):
        raise ValueError("Configured API application differs from the bound ownership journal")
    app_id = uuid_value(config.get("apiApplicationId") or journal["apiApplicationId"])
    role_id = uuid_value(journal["appRoleId"])
    context = config["customer"]
    identity = cli("identity", "show", "--subscription", context["subscriptionId"],
                   "--resource-group", context["bootstrapResourceGroup"], "--name", config["customerIdentityName"])
    if identity.get("tenantId") != context["tenantId"]:
        raise ValueError("Managed identity tenant mismatch")
    principal_id = uuid_value(identity["principalId"])
    graph = Graph(context["tenantId"])
    sp = find_exact(graph, "servicePrincipals", app_id)
    if not sp:
        sp = graph_write(graph, "POST", "/servicePrincipals", {"appId": app_id}, journal, path)
        journal["customerEnterpriseSpCreated"] = True
        journal["customerEnterpriseSpObjectId"] = sp["id"]
        save_private(path, journal)
    roles = [r for r in sp.get("appRoles", []) if r.get("id") == role_id and r.get("value") == ROLE]
    if not roles or roles[0].get("allowedMemberTypes") != ["Application"] or not roles[0].get("isEnabled"):
        raise ValueError("Customer enterprise application does not expose the exact approved app-only role")
    assignments = graph.request("GET", f"/servicePrincipals/{principal_id}/appRoleAssignments").get("value", [])
    existing = [r for r in assignments if r.get("resourceId") == sp["id"] and r.get("appRoleId") == role_id]
    if len(existing) > 1:
        raise ValueError("Duplicate role assignments")
    assignment = existing[0] if existing else graph_write(
        graph, "POST", f"/servicePrincipals/{principal_id}/appRoleAssignments",
        {"principalId": principal_id, "resourceId": sp["id"], "appRoleId": role_id}, journal, path)
    journal.update(customerEnterpriseSpObjectId=sp["id"], appRoleAssignmentId=assignment["id"],
                   customerPrincipalId=principal_id, customerClientId=identity["clientId"],
                   appRoleAssignmentCreated=journal.get("appRoleAssignmentCreated", False) or not bool(existing))
    save_private(path, journal)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["provider", "customer"])
    parser.add_argument("--config", required=True, help="0600 .local JSON; approved tenant/subscription/group contexts")
    parser.add_argument("--journal", default=str(ROOT / ".local/identity-journal.json"))
    parser.add_argument("--execute", action="store_true", help="Perform explicit directory writes; default is offline validation only")
    args = parser.parse_args(argv)
    config = validate_config(load_private(args.config))
    if not args.execute:
        print(f"DRY RUN: validate {args.phase} app-only identity bootstrap; no Azure calls or writes.")
        return 0
    verify_account(config[args.phase])
    path = Path(args.journal).resolve()
    if not path.is_relative_to(ROOT / ".local"):
        raise ValueError("Journal must be in project .local")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        journal = load_private(path) if path.exists() else {"configDigest": config_digest(config)}
        if journal["configDigest"] != config_digest(config):
            raise ValueError("Journal belongs to a different exact configuration")
        try:
            (provider if args.phase == "provider" else customer)(config, journal, path)
        except DirectoryDenied:
            print("No privileges were granted or changed to bypass denial. An already-authorized tenant administrator can run:")
            print("az login --tenant " + shlex.quote(config[args.phase]["tenantId"]))
            print("python3 scripts/bootstrap_identity.py " + shlex.quote(args.phase)
                  + " --config " + shlex.quote(args.config) + " --journal " + shlex.quote(str(path)) + " --execute")
            print("Exact denied Graph method/path/body is pendingAdminOperation in the private journal; no token is recorded.")
            raise
    print("Bootstrap completed; non-secret IDs recorded in private ownership journal.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        raise SystemExit(str(exc)) from None
