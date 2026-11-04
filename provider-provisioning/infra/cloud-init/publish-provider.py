"""Runs inside the provider-owned Azure deployment script, never on an admin laptop."""
import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit


class ProviderPublishRequestError(RuntimeError):
    pass


def request_error(stderr):
    codes = ("AuthorizationFailed", "AuthorizationPermissionMismatch", "Forbidden",
             "ResourceNotFound", "TooManyRequests", "ServiceUnavailable", "GatewayTimeout",
             "InternalServerError", "Conflict", "BadRequest")
    found = [code for code in codes if re.search(r"\b" + code + r"\b", stderr)]
    status = re.search(r"\b(?:403|404|409|429|500|502|503|504)\b", stderr)
    return "Azure request failed (code: {}, HTTP: {}).".format(
        ",".join(found) if found else "unclassified", status.group() if status else "unknown")


def cli(*args):
    deadline = time.monotonic() + 180
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("ProviderPublishingRolePropagationTimedOut")
        result = subprocess.run(["az", *args, "--output", "json", "--only-show-errors"],
                                capture_output=True, text=True, timeout=min(90, remaining))
        if not result.returncode:
            return json.loads(result.stdout) if result.stdout.strip() else {}
        if (re.search(r"\b(?:AuthorizationFailed|AuthorizationPermissionMismatch)\b", result.stderr)
                and "403" in result.stderr and remaining > 5):
            time.sleep(5)
            continue
        raise ProviderPublishRequestError(request_error(result.stderr))


def main():
    uri = os.environ["FAAS_PACKAGE_URI"]
    parsed = urlsplit(uri)
    query = parse_qs(parsed.query)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.fragment or parsed.port not in (None, 443)
            or not parsed.hostname.endswith(".blob.core.windows.net")):
        raise ValueError("AzureBlobPackageRequired")
    release_account = os.environ.get("FAAS_RELEASE_STORAGE_ACCOUNT", "")
    if not query:
        if (not re.fullmatch(r"[a-z0-9]{3,24}", release_account)
                or parsed.hostname != release_account + ".blob.core.windows.net"):
            raise ValueError("ApprovedReleaseAccountRequired")
        path = parsed.path.lstrip("/").split("/", 1)
        if len(path) != 2 or not all(path):
            raise ValueError("ReleaseBlobPathRequired")
        expiry = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        print("Provider publish stage: generate package access", flush=True)
        uri = cli("storage", "blob", "generate-sas", "--account-name", release_account,
                  "--container-name", unquote(path[0]), "--name", unquote(path[1]),
                  "--permissions", "r", "--https-only", "--as-user", "--auth-mode", "login",
                  "--expiry", expiry, "--full-uri")
        parsed, query = urlsplit(uri), parse_qs(urlsplit(uri).query)
        if parsed.hostname != release_account + ".blob.core.windows.net":
            raise ValueError("UnexpectedReleaseBlobHost")
    if (query.get("sp") != ["r"] or query.get("sr") != ["b"] or query.get("spr") != ["https"]
            or not query.get("skoid") or not query.get("sig")):
        raise ValueError("ReadOnlyAzureBlobPackageRequired")
    expected = os.environ["FAAS_PACKAGE_SHA256"]
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise ValueError("InvalidPackagePin")
    digest, size = hashlib.sha256(), 0
    print("Provider publish stage: verify package", flush=True)
    try:
        with urllib.request.urlopen(uri, timeout=60) as response:
            while chunk := response.read(65536):
                size += len(chunk)
                if size > 20_000_000:
                    raise ValueError("PackageTooLarge")
                digest.update(chunk)
    except urllib.error.HTTPError as error:
        raise ProviderPublishRequestError("Provider package download failed (HTTP {}).".format(error.code)) from None
    except urllib.error.URLError:
        raise ProviderPublishRequestError("Provider package download unavailable.") from None
    if digest.hexdigest() != expected:
        raise ValueError("PackagePinMismatch")
    print("Provider publish stage: verify subscription", flush=True)
    account = cli("account", "show")
    if account["id"] != os.environ["FAAS_PROVIDER_SUBSCRIPTION"]:
        raise ValueError("ProviderSubscriptionMismatch")
    group = os.environ["FAAS_PROVIDER_CONTROL_GROUP"]
    apps = json.loads(os.environ["FAAS_PROVIDER_APPS"])
    if not isinstance(apps, list) or not 1 <= len(apps) <= 3 or len(set(apps)) != len(apps):
        raise ValueError("OneToThreeDistinctProviderAppsRequired")
    for app in apps:
        if not isinstance(app, str) or not app or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-" for char in app):
            raise ValueError("InvalidProviderApp")
        prefix = ("https://management.azure.com/subscriptions/" + account["id"]
                  + "/resourceGroups/" + group + "/providers/Microsoft.Web/sites/" + app)
        started = datetime.now(timezone.utc) - timedelta(seconds=2)
        descriptor, name = tempfile.mkstemp(prefix="provider-publish-", suffix=".json")
        try:
            with os.fdopen(descriptor, "w") as stream:
                os.fchmod(stream.fileno(), 0o600)
                json.dump({"properties": {"packageUri": uri, "type": "zip",
                                          "clean": True, "restart": True}}, stream)
            print("Provider publish stage: submit app build " + app, flush=True)
            cli("rest", "--method", "put", "--url",
                prefix + "/extensions/onedeploy?api-version=2024-11-01", "--body", "@" + name)
        finally:
            Path(name).unlink(missing_ok=True)
        deadline = time.monotonic() + 1200
        print("Provider publish stage: verify app build " + app, flush=True)
        while time.monotonic() < deadline:
            deployments = cli("rest", "--method", "get", "--url",
                              prefix + "/deployments?api-version=2023-12-01")
            recent = []
            for entry in deployments.get("value", []):
                properties = entry.get("properties", {})
                timestamp = properties.get("start_time") or properties.get("startTime")
                if timestamp and datetime.fromisoformat(timestamp.replace("Z", "+00:00")) >= started:
                    recent.append((timestamp, properties))
            if recent:
                deployment = max(recent, key=lambda value: value[0])[1]
                if deployment.get("status") == 3:
                    raise RuntimeError("ProviderRemoteBuildFailed")
                if deployment.get("status") == 4 and deployment.get("active") is True:
                    print("Provider app build verified: " + app, flush=True)
                    break
            time.sleep(10)
        else:
            raise TimeoutError("ProviderRemoteBuildTimedOut")
    Path(os.environ["AZ_SCRIPTS_OUTPUT_PATH"]).write_text(json.dumps({"status": "Published"}))


if __name__ == "__main__":
    try:
        main()
    except ProviderPublishRequestError as error:
        raise SystemExit("Provider installation stopped: " + str(error)) from None
    except Exception as error:
        raise SystemExit("Provider installation stopped: " + type(error).__name__) from None
