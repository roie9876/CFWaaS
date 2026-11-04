#!/usr/bin/env python3
"""Provider artifact host/upload; offline unless --execute. SAS values are saved, never logged.

host requires --publisher-principal-id UUID --publisher-principal-type User|ServicePrincipal.
upload requires --file .local/apps.zip (or generated azuredeploy.json/uiFormDefinition.json),
--blob-name immutable/name and --uri-output .local/private-uri.json.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import parse_qs, quote, urlsplit

import bootstrap
from common import (ROOT, cli, config_digest, digest, group_id, load_private,
                    save_private, uuid_value, validate_config, verify_account)
from provider_setup import bound_journal, locked

CONTAINER = "deployment-artifacts"
ROLE = "ba92f5b4-2d11-453d-a403-e96b0029c9fe"


def storage(*args):
    """Retry only an explicit RBAC propagation denial, with a 180-second total budget."""
    deadline = time.monotonic() + 180
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("Artifact data operation timed out; response suppressed")
        result = subprocess.run(["az", "storage", *args, "--output", "json", "--only-show-errors"],
                                capture_output=True, text=True, timeout=remaining)
        if result.returncode == 0:
            return json.loads(result.stdout) if result.stdout.strip() else {}
        if (not re.search(r"\b403\b", result.stderr)
                or not re.search(r"\bAuthorizationPermissionMismatch\b", result.stderr)
                or deadline - time.monotonic() <= 5):
            raise ValueError("Artifact data operation failed; response suppressed")
        time.sleep(5)


def private_path(value, source=False) -> Path:
    path = Path(os.path.abspath(value))
    local = ROOT / ".local"
    if not path.is_relative_to(local) or path == local:
        raise ValueError("Artifact paths must be under project .local")
    for part in (local, *path.relative_to(local).parents, path):
        candidate = part if part.is_absolute() else local / part
        if candidate.is_symlink():
            raise ValueError("Artifact paths must not contain symlinks")
    if source or path.exists():
        stat = path.stat()
        if not path.is_file() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
            raise ValueError("Artifact file must be private and user-owned")
    return path


def blob_name(value: str) -> str:
    if (not value or len(value) > 500 or ".." in value or "\\" in value
            or value.startswith("/") or not re.fullmatch(r"[A-Za-z0-9._/-]+", value)):
        raise ValueError("Invalid immutable artifact blob name")
    return value


def source_file(value, config) -> tuple[Path, str]:
    path = private_path(value, source=True)
    if path.name == "apps.zip":
        metadata = load_private(private_path(path.with_suffix(".metadata.json"), source=True))
        if (Path(metadata.get("packagePath", "")).resolve() != path
                or metadata.get("includesManagement") is not True):
            raise ValueError("Package metadata does not bind this release")
        expected = metadata["packageSha256"]
    elif path.name in {"azuredeploy.json", "uiFormDefinition.json"}:
        metadata = load_private(private_path(path.parent / "profile.json", source=True))
        if metadata.get("configDigest") != config_digest(config):
            raise ValueError("Generated customer artifact configuration mismatch")
        key = "templateSha256" if path.name == "azuredeploy.json" else "formSha256"
        if digest(json.loads(path.read_text())) != metadata[key]:
            raise ValueError("Generated customer artifact hash mismatch")
        expected = None
    else:
        raise ValueError("Only apps.zip or generated customer ARM/Form JSON may be uploaded")
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    if expected is not None and sha != expected:
        raise ValueError("Package hash mismatch")
    return path, sha


def host_outputs(config, value):
    if set(value) != {"accountName", "blobEndpoint", "containerName", "accountId"}:
        raise ValueError("Unexpected artifact host outputs")
    name = value["accountName"]
    provider = config["provider"]
    account_id = (group_id(provider["subscriptionId"], provider["controlPlaneResourceGroup"])
                  + "/providers/Microsoft.Storage/storageAccounts/" + name)
    if (not re.fullmatch(r"stfaasart[a-z0-9]{13}", name) or value["accountId"] != account_id
            or value["containerName"] != CONTAINER
            or value["blobEndpoint"] != f"https://{name}.blob.core.windows.net/"):
        raise ValueError("Artifact host is not the dedicated provider account")
    return value


def owned_account(config, account_id):
    result = cli("resource", "show", "--subscription", config["provider"]["subscriptionId"],
                 "--ids", account_id, "--api-version", "2023-05-01")
    if (result.get("id", "").lower() != account_id.lower()
            or result.get("tags", {}).get("purpose") != "provider-provisioning"
            or result.get("tags", {}).get("labRun") != config["runId"]
            or result.get("tags", {}).get("SecurityControl") != "Ignore"):
        raise ValueError("Existing artifact account is not owned by this run")
    return result


def preview(config, changes, principal, principal_type):
    provider = config["provider"]
    prefix = (group_id(provider["subscriptionId"], provider["controlPlaneResourceGroup"])
              + "/providers/Microsoft.Storage/storageAccounts/")
    accounts = []
    for change in changes:
        if change["changeType"] == "Ignore":
            continue  # Incremental deployments leave unrelated existing resources alone.
        resource_id = change["resourceId"]
        if not resource_id.startswith(prefix):
            raise ValueError("What-if escaped the provider artifact account")
        name, _, child = resource_id[len(prefix):].partition("/")
        if not re.fullmatch(r"stfaasart[a-z0-9]{13}", name):
            raise ValueError("What-if targets a non-artifact storage account")
        accounts.append(prefix + name)
        if change["changeType"] not in {"Create", "Modify", "NoChange"}:
            raise ValueError("Unexpected artifact what-if change")
        properties = (change.get("after") or {}).get("properties", {})
        if child.startswith("providers/Microsoft.Authorization/roleAssignments/"):
            uuid_value(child.rsplit("/", 1)[1])
            role = properties.get("roleDefinitionId", "")
            role_uri = urlsplit(role)
            if role_uri.scheme:
                if (role_uri.scheme != "https" or role_uri.netloc != "management.azure.com"
                        or role_uri.query or role_uri.fragment):
                    raise ValueError("Unexpected artifact publisher role URI")
                role = role_uri.path
            allowed_roles = {
                f"/subscriptions/{provider['subscriptionId']}/providers/microsoft.authorization/roledefinitions/{ROLE}",
                f"/providers/microsoft.authorization/roledefinitions/{ROLE}",
            }
            if (properties.get("principalId") != principal
                    or properties.get("principalType") not in {None, principal_type}
                    or role.lower() not in allowed_roles):
                raise ValueError("Unexpected artifact publisher grant")
        elif child not in {"", "blobServices/default", "blobServices/default/containers/" + CONTAINER}:
            raise ValueError("Unexpected artifact resource")
        if change["changeType"] != "Create":
            owned_account(config, prefix + name)
    if len(set(accounts)) != 1:
        raise ValueError("What-if must target exactly one artifact account")
    return accounts[0]


def publisher(config, principal, principal_type):
    principal = uuid_value(principal)
    identity = load_private(private_path(ROOT / ".local/provider-identity.json", source=True))
    if identity.get("configDigest") != config_digest(config):
        raise ValueError("Provider identity configuration mismatch")
    if principal == uuid_value(identity["customerApiPrincipalId"]):
        raise ValueError("API-only client must never receive Azure RBAC")
    if principal_type not in {"User", "ServicePrincipal"}:
        raise ValueError("Invalid publisher principal type")


def host(config, state, state_path, principal, principal_type):
    publisher(config, principal, principal_type)
    provider = config["provider"]
    base = ("--subscription", provider["subscriptionId"], "--resource-group",
            provider["controlPlaneResourceGroup"], "--name", "faas-provider-artifacts",
            "--template-file", str(ROOT / "infra/provider-artifacts.bicep"), "--mode", "Incremental",
            "--parameters", "runId=" + config["runId"], "publisherPrincipalId=" + principal,
            "publisherPrincipalType=" + principal_type)
    plan = cli("deployment", "group", "what-if", *base, "--no-pretty-print", "--result-format", "FullResourcePayloads")
    account_id = preview(config, plan["changes"], principal, principal_type)
    if state.get("host") and state["host"]["accountId"] != account_id:
        raise ValueError("Artifact account changed")
    result = cli("deployment", "group", "create", *base)
    value = host_outputs(config, bootstrap.outputs(result))
    if value["accountId"] != account_id:
        raise ValueError("Deployment differs from artifact preview")
    state.update(host=value, publisherPrincipalId=principal, publisherPrincipalType=principal_type)
    save_private(state_path, state)
    if owned_account(config, value["accountId"])["properties"].get("publicNetworkAccess") != "Enabled":
        raise ValueError("Provider governance blocks artifact network reachability; no policy bypass attempted")


def upload(config, state, source, sha, name, output):
    value = host_outputs(config, state["host"])
    account = owned_account(config, value["accountId"])
    properties = account["properties"]
    if properties.get("publicNetworkAccess") != "Enabled":
        raise ValueError("Provider governance blocks artifact network reachability; no policy bypass attempted")
    if properties.get("allowSharedKeyAccess") is not False or properties.get("allowBlobPublicAccess") is not False:
        raise ValueError("Artifact account must disable shared keys and public blobs")
    base = ("--subscription", config["provider"]["subscriptionId"], "--account-name", value["accountName"],
            "--container-name", CONTAINER, "--name", name, "--auth-mode", "login")
    container = storage("container", "show", "--subscription", config["provider"]["subscriptionId"],
                    "--account-name", value["accountName"], "--name", CONTAINER, "--auth-mode", "login")
    if container.get("properties", {}).get("publicAccess") not in {None, "None", "Off"}:
        raise ValueError("Artifact container must be private")
    exists = storage("blob", "exists", *base)
    if type(exists.get("exists")) is not bool:
        raise ValueError("Unexpected blob existence response")
    if not exists["exists"]:
        storage("blob", "upload", *base, "--file", str(source), "--overwrite", "false",
            "--metadata", "sha256=" + sha)
    blob = storage("blob", "show", *base)
    if blob.get("metadata", {}).get("sha256") != sha:
        raise ValueError("Existing blob hash mismatch; refusing overwrite or SAS")
    expiry = (datetime.now(timezone.utc) + timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
    uri = storage("blob", "generate-sas", *base, "--permissions", "r", "--https-only",
              "--as-user", "--expiry", expiry, "--full-uri")
    parsed, query = urlsplit(uri), parse_qs(urlsplit(uri).query)
    if (parsed.scheme != "https" or parsed.netloc != urlsplit(value["blobEndpoint"]).netloc
            or parsed.path != f"/{CONTAINER}/{quote(name, safe='/')}"
            or parsed.fragment or query.get("sp") != ["r"] or query.get("sr") != ["b"]
            or query.get("spr") != ["https"] or not query.get("sig") or not query.get("skoid")):
        raise ValueError("Unexpected user-delegation SAS response")
    # Exclusive creation prevents a URI-output race from truncating another private file.
    output = private_path(output)
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump({"uri": uri, "expiresAt": expiry, "sha256": sha}, stream)
        stream.flush()
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("host", "upload"))
    parser.add_argument("--config", type=Path, default=ROOT / ".local/config.json")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--publisher-principal-id")
    parser.add_argument("--publisher-principal-type", choices=("User", "ServicePrincipal"))
    parser.add_argument("--file", type=Path)
    parser.add_argument("--blob-name")
    parser.add_argument("--uri-output", type=Path)
    args = parser.parse_args(argv)
    config = validate_config(load_private(private_path(args.config, source=True)))
    if args.phase == "host":
        if not args.publisher_principal_id or not args.publisher_principal_type:
            parser.error("host requires publisher principal ID and type")
        publisher(config, args.publisher_principal_id, args.publisher_principal_type)
    else:
        if not args.file or not args.blob_name or not args.uri_output:
            parser.error("upload requires --file, --blob-name and --uri-output")
        # Refuse credential/journal inputs before opening any candidate source.
        if args.file.name not in {"apps.zip", "azuredeploy.json", "uiFormDefinition.json"}:
            raise ValueError("Unsupported artifact input")
        source, sha = source_file(args.file, config)
        name, output = blob_name(args.blob_name), private_path(args.uri_output)
        if output.exists():
            raise ValueError("URI output must be a new private file")
    if not args.execute:
        print(f"DRY RUN provider artifact {args.phase}; no cloud requests or writes.")
        return 0
    path = private_path(ROOT / ".local/artifact-host.json")
    with locked(path):
        state = bound_journal(config, path)
        verify_account(config["provider"])
        bootstrap.assert_owned_group(config["provider"], config["provider"]["controlPlaneResourceGroup"], config["runId"])
        if args.phase == "host":
            host(config, state, path, args.publisher_principal_id, args.publisher_principal_type)
        else:
            upload(config, state, source, sha, name, output)
    print(f"Completed provider artifact {args.phase}; private .local files updated (URLs suppressed).")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # Azure CLI exception bodies may contain SAS URLs; never propagate their text.
        raise SystemExit("Provider artifacts stopped; no response bodies or credentials are logged.") from None
