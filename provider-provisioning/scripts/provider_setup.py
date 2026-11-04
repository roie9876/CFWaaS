#!/usr/bin/env python3
"""Provider-only setup. Offline by default; --execute authorizes one cloud phase.

Customer tenant/subscription/group values are enrollment metadata, not evidence of
ownership. No customer-directory consent, customer Azure access or client Azure
RBAC is performed. Recover uncertain Graph writes by exact IDs and audit logs;
never delete/recreate an application or silently rotate a credential.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import zipfile
import urllib.parse
import time

import bootstrap
import bootstrap_identity as identity_bootstrap
from common import (ROOT, cli, config_digest, digest, group_id, load_private,
                    operator_cidr, public_key, save_private, uuid_value,
                    validate_config, verify_account)

PHASES = ("groups", "api", "api-client", "control-plane", "code-deploy")
MODE = "provider-api-client"
ROLE = identity_bootstrap.ROLE


@contextmanager
def locked(path: Path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def bound_journal(config: dict, path: Path) -> dict:
    value = load_private(path) if path.exists() else {"configDigest": config_digest(config)}
    if value.get("configDigest") != config_digest(config):
        raise ValueError("Journal does not match the approved configuration")
    return value


def provider_feature_preflight(config: dict) -> None:
    """Read only the provider subscription; never register a feature."""
    provider = config["provider"]
    verify_account(provider)
    feature = cli("feature", "show", "--subscription", provider["subscriptionId"],
                  "--namespace", "Microsoft.Compute", "--name", "EncryptionAtHost")
    if feature.get("properties", {}).get("state") != "Registered":
        raise ValueError("Provider EncryptionAtHost must already be Registered")


def groups(config: dict, journal: dict, path: Path) -> None:
    provider = config["provider"]
    for field, location in (("controlPlaneResourceGroup", "centralus"),
                            ("dataPlaneResourceGroup", "eastus2")):
        group = provider[field]
        if cli("group", "exists", "--subscription", provider["subscriptionId"], "--name", group):
            bootstrap.assert_owned_group(provider, group, config["runId"])
        else:
            result = cli("group", "create", "--subscription", provider["subscriptionId"],
                         "--name", group, "--location", location,
                         "--tags", "purpose=provider-provisioning", "labRun=" + config["runId"])
            if result.get("id", "").lower() != group_id(provider["subscriptionId"], group).lower():
                raise ValueError("Unexpected provider group response")
            journal.setdefault("createdResourceGroups", []).append(result["id"])
            save_private(path, journal)


def api(config: dict, identity: dict, path: Path) -> None:
    # The legacy helper's provider branch is provider-Graph-only. Suppress its
    # optional customer-admin-consent URL entirely in this mode.
    provider_config = {key: value for key, value in config.items() if key != "consentRedirectUri"}
    identity.pop("adminConsentUrl", None)
    identity_bootstrap.provider(provider_config, identity, path)
    identity.pop("adminConsentUrl", None)
    save_private(path, identity)


def validate_identity(config: dict, identity: dict, client: bool = True) -> None:
    if identity.get("configDigest") != config_digest(config):
        raise ValueError("Provider identity belongs to a different configuration")
    for key in ("apiApplicationId", "apiAudience", "appRoleId"):
        uuid_value(identity[key])
    if (identity["apiAudience"] != identity["apiApplicationId"]
            or identity["apiResource"] != "api://" + identity["apiApplicationId"]):
        raise ValueError("Invalid provider API resource/audience")
    if identity.get("pendingClientOperation") or identity.get("pendingAdminOperation"):
        raise ValueError("Uncertain Graph operation; reconcile exact IDs using provider audit logs")
    if client:
        for key in ("providerApiServicePrincipalId", "customerApiClientId", "customerApiPrincipalId",
                    "customerApiClientApplicationObjectId"):
            uuid_value(identity[key])


def client_write(graph, method: str, resource: str, body: dict, identity: dict,
                 path: Path, fields: dict | None = None) -> dict:
    # Persist intent before network I/O; after an uncertain result no retry can
    # issue a second create/addPassword, including an explicit rotation.
    identity["pendingClientOperation"] = {"method": method, "path": resource}
    save_private(path, identity)
    result = graph.request(method, resource, body)
    if fields:
        for target, source in fields.items():
            identity[target] = uuid_value(result[source])
    identity.pop("pendingClientOperation")
    save_private(path, identity)
    return result


def api_client(config: dict, identity: dict, path: Path, rotate: bool = False) -> None:
    validate_identity(config, identity, client=False)
    graph = identity_bootstrap.Graph(config["provider"]["tenantId"])
    app = identity_bootstrap.find_exact(graph, "applications", identity["apiApplicationId"])
    if not app:
        raise ValueError("Provider API application missing; refusing replacement")
    roles = [role for role in app.get("appRoles", []) if role.get("id") == identity["appRoleId"]]
    if (len(roles) != 1 or roles[0].get("value") != ROLE
            or roles[0].get("allowedMemberTypes") != ["Application"]
            or roles[0].get("isEnabled") is not True):
        raise ValueError("API role must be exactly FirewallDeployment.Request for Applications")
    resource = identity_bootstrap.find_exact(graph, "servicePrincipals", identity["apiApplicationId"])
    if not resource:
        if identity.get("providerApiServicePrincipalId"):
            raise ValueError("Bound API service principal is missing")
        resource = client_write(graph, "POST", "/servicePrincipals",
                                {"appId": identity["apiApplicationId"]}, identity, path,
                                {"providerApiServicePrincipalId": "id"})
    resource_id = uuid_value(resource["id"])
    if identity.get("providerApiServicePrincipalId", resource_id) != resource_id:
        raise ValueError("Provider API service principal changed")
    identity["providerApiServicePrincipalId"] = resource_id
    resource_roles = [role for role in resource.get("appRoles", [])
                      if role.get("id") == identity["appRoleId"]]
    if (len(resource_roles) != 1 or resource_roles[0].get("value") != ROLE
            or resource_roles[0].get("allowedMemberTypes") != ["Application"]
            or resource_roles[0].get("isEnabled") is not True):
        raise ValueError("Provider API service principal role differs from the application")
    access = [{"resourceAppId": identity["apiApplicationId"],
               "resourceAccess": [{"id": identity["appRoleId"], "type": "Role"}]}]
    client_id = identity.get("customerApiClientId")
    if client_id:
        client = identity_bootstrap.find_exact(graph, "applications", client_id)
        if not client or client["id"] != identity["customerApiClientApplicationObjectId"]:
            raise ValueError("Bound client application missing or changed; no replacement")
    else:
        client = client_write(graph, "POST", "/applications", {
            "displayName": "faas-customer-api-" + config["runId"],
            "signInAudience": "AzureADMyOrg", "requiredResourceAccess": access,
        }, identity, path, {"customerApiClientId": "appId",
                           "customerApiClientApplicationObjectId": "id"})
    if (client.get("signInAudience") != "AzureADMyOrg"
            or client.get("requiredResourceAccess") != access):
        raise ValueError("Client must request only the provider API application role")
    principal = identity_bootstrap.find_exact(graph, "servicePrincipals", identity["customerApiClientId"])
    if not principal:
        if identity.get("customerApiPrincipalId"):
            raise ValueError("Bound client service principal missing; no replacement")
        principal = client_write(graph, "POST", "/servicePrincipals",
                                 {"appId": identity["customerApiClientId"]}, identity, path,
                                 {"customerApiPrincipalId": "id"})
    principal_id = uuid_value(principal["id"])
    if identity.get("customerApiPrincipalId", principal_id) != principal_id:
        raise ValueError("Client service principal changed")
    identity["customerApiPrincipalId"] = principal_id
    save_private(path, identity)
    endpoint = "/servicePrincipals/" + principal_id + "/appRoleAssignments"
    grants = graph.request("GET", endpoint)
    if grants.get("@odata.nextLink"):
        raise ValueError("Unexpected paginated role grants; reconcile explicitly")
    assignments = grants.get("value", [])
    expected = {"principalId": principal_id, "resourceId": resource_id, "appRoleId": identity["appRoleId"]}
    if any(any(item.get(key) != value for key, value in expected.items()) for item in assignments):
        raise ValueError("Client has unexpected application role grants; reconcile explicitly")
    if len(assignments) > 1:
        raise ValueError("Duplicate client application role grants")
    if not assignments:
        client_write(graph, "POST", endpoint, expected, identity, path)
    issue_credential(graph, identity, path, rotate)


def issue_credential(graph, identity: dict, path: Path, rotate: bool) -> None:
    credential_path = ROOT / ".local/customer-api-credential.json"
    credential = load_private(credential_path) if credential_path.exists() else None
    if credential and not rotate:
        if (credential.get("clientId") != identity["customerApiClientId"]
                or digest(credential) != identity.get("credentialDigest")):
            raise ValueError("Credential does not match the identity journal; explicit rotation required")
        expiry = datetime.fromisoformat(credential["expiresAt"].replace("Z", "+00:00"))
        if expiry > datetime.now(timezone.utc) and credential.get("secret"):
            return
        raise ValueError("Credential expired; use --rotate-credential explicitly")
    if identity.get("credentialKeyId") and not rotate:
        raise ValueError("Credential file missing; use --rotate-credential explicitly")
    if credential and rotate and credential.get("clientId") != identity["customerApiClientId"]:
        raise ValueError("Refusing to overwrite another application's credential")
    expiry = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    endpoint = "/applications/" + identity["customerApiClientApplicationObjectId"] + "/addPassword"
    identity["pendingClientOperation"] = {"method": "POST", "path": endpoint}
    save_private(path, identity)
    password = graph.request("POST", endpoint, {"passwordCredential": {
        "displayName": "faas-api-poc-24h", "endDateTime": expiry}})
    # Keep the pending marker until the credential AND journal are durable.
    credential = {"clientId": identity["customerApiClientId"], "secret": password["secretText"],
                  "expiresAt": password["endDateTime"]}
    returned_expiry = datetime.fromisoformat(credential["expiresAt"].replace("Z", "+00:00"))
    if (not isinstance(credential["secret"], str) or not credential["secret"]
            or returned_expiry <= datetime.now(timezone.utc)
            or returned_expiry > datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            + timedelta(seconds=1)):
        raise ValueError("Unexpected credential response; reconcile provider audit logs")
    key_id = uuid_value(password["keyId"])
    save_private(credential_path, credential)
    old_key = identity.get("credentialKeyId")
    identity.update(credentialKeyId=key_id, credentialDigest=digest(credential))
    identity.pop("pendingClientOperation")
    save_private(path, identity)
    if rotate and old_key:
        client_write(graph, "POST", "/applications/" + identity["customerApiClientApplicationObjectId"]
                     + "/removePassword", {"keyId": uuid_value(old_key)}, identity, path)


def package_metadata() -> dict:
    metadata = load_private(ROOT / ".local/apps.metadata.json")
    for key in ("providerTemplateSha256", "packageSha256"):
        if not re.fullmatch(r"[a-f0-9]{64}", metadata[key]):
            raise ValueError("Invalid package SHA256")
    package = ROOT / ".local/apps.zip"
    if (Path(metadata["packagePath"]).resolve() != package.resolve()
            or package.is_symlink()
            or hashlib.sha256(package.read_bytes()).hexdigest() != metadata["packageSha256"]):
        raise ValueError("Current .local/apps.zip does not match package metadata")
    with zipfile.ZipFile(package) as archive:
        if hashlib.sha256(archive.read("service/templates/provider.json")).hexdigest() != metadata["providerTemplateSha256"]:
            raise ValueError("Provider template in ZIP differs from package metadata")
    return metadata


def control_plane(config: dict, journal: dict, path: Path, identity: dict, approved: bool) -> None:
    if not approved:
        raise ValueError("--approve-scm-bootstrap-exception is required")
    operator_cidr(config["deploymentOperatorCidr"])
    if config.get("nvaSshPublicKey"):
        public_key(config["nvaSshPublicKey"])
    validate_identity(config, identity)
    metadata = package_metadata()
    provider = config["provider"]
    bootstrap.assert_owned_group(provider, provider["dataPlaneResourceGroup"], config["runId"])
    result = bootstrap.deploy(provider, provider["controlPlaneResourceGroup"], "main.bicep", {
        "runId": config["runId"], "namePrefix": config["namePrefix"],
        "providerDataPlaneResourceGroupId": group_id(provider["subscriptionId"], provider["dataPlaneResourceGroup"]),
        "trustedTenantId": config["customer"]["tenantId"],
        "trustedPrincipalId": identity["customerApiPrincipalId"],
        "trustedClientId": identity["customerApiClientId"], "apiAudience": identity["apiAudience"],
        "apiAuthMode": MODE, "nvaSshPublicKey": config.get("nvaSshPublicKey", ""),
        "providerTemplateSha256": metadata["providerTemplateSha256"],
        "deploymentOperatorCidr": config["deploymentOperatorCidr"],
        "approveScmBootstrapException": True,
    }, config["runId"])
    journal.update(controlPlane=bootstrap.outputs(result), apiAuthMode=MODE,
                   providerTemplateSha256=metadata["providerTemplateSha256"])
    # A configuration redeploy is not evidence that the current ZIP was published.
    if journal.get("codePackageSha256") != metadata["packageSha256"]:
        journal.pop("codePackageSha256", None)
    save_private(path, journal)


def wait_for_publish(provider: dict, app: str, started: datetime, timeout: int = 900) -> None:
    url = ("https://management.azure.com" + group_id(provider["subscriptionId"], provider["controlPlaneResourceGroup"])
           + f"/providers/Microsoft.Web/sites/{app}/deployments?api-version=2023-12-01")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = cli("rest", "--method", "get", "--url", url)
        recent = []
        for item in result.get("value", []):
            properties = item.get("properties", {})
            timestamp = properties.get("start_time") or properties.get("startTime")
            if timestamp and datetime.fromisoformat(timestamp.replace("Z", "+00:00")) >= started:
                recent.append((timestamp, properties))
        if recent:
            properties = max(recent, key=lambda row: row[0])[1]
            if properties.get("status") == 4 and properties.get("active") is True:
                return
            if properties.get("status") == 3:
                raise ValueError("Provider remote build failed; inspect sanitized ARM deployment logs")
        time.sleep(5)
    raise TimeoutError("Provider publishing did not reach a successful active deployment")


def code_deploy(config: dict, journal: dict, path: Path, package_uri_file: str | None = None) -> None:
    provider = config["provider"]
    bootstrap.assert_owned_group(provider, provider["controlPlaneResourceGroup"], config["runId"])
    version = cli("version")["azure-cli"]
    if tuple(int(part) for part in version.split(".")[:3]) < (2, 48, 1):
        raise ValueError("Entra publishing requires Azure CLI >= 2.48.1")
    metadata = package_metadata()
    if (journal.get("apiAuthMode") != MODE
            or metadata["providerTemplateSha256"] != journal.get("providerTemplateSha256")):
        raise ValueError("Configure current provider template and API auth mode before code publishing")
    apps = [journal["controlPlane"][mode + "AppName"] for mode in ("api", "worker")]
    if len(set(apps)) != 2 or any(not re.fullmatch(r"[A-Za-z0-9-]{2,60}", name) for name in apps):
        raise ValueError("Invalid provider app names")
    for app in apps:
        policy = cli("resource", "show", "--subscription", provider["subscriptionId"],
                     "--ids", group_id(provider["subscriptionId"], provider["controlPlaneResourceGroup"])
                     + f"/providers/Microsoft.Web/sites/{app}/basicPublishingCredentialsPolicies/scm",
                     "--api-version", "2023-12-01")
        if policy.get("properties", {}).get("allow") is not False:
            raise ValueError("SCM basic publishing must remain disabled")
    if package_uri_file:
        blob = load_private(package_uri_file)
        host = load_private(ROOT / ".local/artifact-host.json")
        parsed = urllib.parse.urlsplit(blob["uri"])
        query = urllib.parse.parse_qs(parsed.query)
        expiry = datetime.fromisoformat(blob["expiresAt"].replace("Z", "+00:00"))
        if (host.get("configDigest") != config_digest(config)
                or parsed.scheme != "https" or parsed.hostname != host["host"]["accountName"] + ".blob.core.windows.net"
                or parsed.username or parsed.password or parsed.fragment
                or query.get("sp") != ["r"] or query.get("sr") != ["b"]
                or blob["sha256"] != metadata["packageSha256"]
                or expiry <= datetime.now(timezone.utc) + timedelta(minutes=10)):
            raise ValueError("Invalid, expired or unpinned provider package URI")
        journal.pop("codePackageSha256", None)
        save_private(path, journal)
        # A successful ARM extension call only starts the asynchronous build.
        # Finish one site's build before starting another on the small shared plan.
        for app in apps:
            body = ROOT / ".local" / f"provider-code-{app}.json"
            save_private(body, {"properties": {"packageUri": blob["uri"], "type": "zip",
                                               "clean": True, "restart": True}})
            started = datetime.now(timezone.utc) - timedelta(seconds=2)
            url = ("https://management.azure.com"
                   + group_id(provider["subscriptionId"], provider["controlPlaneResourceGroup"])
                   + f"/providers/Microsoft.Web/sites/{app}/extensions/onedeploy?api-version=2024-11-01")
            cli("rest", "--method", "put", "--url", url, "--body", "@" + str(body))
            wait_for_publish(provider, app, started)
    else:
        for app in apps:
            cli("webapp", "deploy", "--subscription", provider["subscriptionId"],
                "--resource-group", provider["controlPlaneResourceGroup"], "--name", app,
                "--src-path", str(ROOT / ".local/apps.zip"), "--type", "zip",
                "--track-status", "false", "--timeout", "600000")
    journal["codePackageSha256"] = metadata["packageSha256"]
    save_private(path, journal)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=PHASES)
    parser.add_argument("--config", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--approve-scm-bootstrap-exception", action="store_true")
    parser.add_argument("--rotate-credential", action="store_true",
                        help="Explicitly replace a known API-client credential (api-client only)")
    parser.add_argument("--package-uri-file", help="0600 provider blob URI metadata for ARM OneDeploy; code-deploy only")
    args = parser.parse_args(argv)
    config = validate_config(load_private(args.config))
    if args.rotate_credential and args.phase != "api-client":
        parser.error("--rotate-credential applies only to api-client")
    if args.package_uri_file and args.phase != "code-deploy":
        parser.error("--package-uri-file applies only to code-deploy")
    if not args.execute:
        print(f"DRY RUN {args.phase}: approved metadata validated; no cloud requests or writes.")
        return 0
    path = ROOT / ".local/provider-journal.json"
    identity_path = ROOT / ".local/provider-identity.json"
    with locked(path):
        journal = bound_journal(config, path)
        identity = bound_journal(config, identity_path)
        verify_account(config["provider"])
        if args.phase == "groups":
            groups(config, journal, path)
        elif args.phase == "api":
            api(config, identity, identity_path)
        elif args.phase == "api-client":
            api_client(config, identity, identity_path, args.rotate_credential)
        elif args.phase == "control-plane":
            control_plane(config, journal, path, identity, args.approve_scm_bootstrap_exception)
        else:
            validate_identity(config, identity)
            code_deploy(config, journal, path, args.package_uri_file)
        journal["configDigest"] = config_digest(config)
        save_private(path, journal)
    print(f"Completed provider {args.phase}; private provider state updated.")
    return 0


def entrypoint():
    try:
        raise SystemExit(main())
    except Exception:
        # CLI/Graph exception text can include request or response content.
        raise SystemExit("Provider setup stopped; inspect private state and provider audit logs. "
                         "No response bodies or credentials are logged.") from None


if __name__ == "__main__":
    entrypoint()
