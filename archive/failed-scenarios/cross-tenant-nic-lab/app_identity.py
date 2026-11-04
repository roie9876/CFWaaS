#!/usr/bin/env python3
"""Run the approved lab with a disposable certificate-based multitenant app."""

import argparse
import base64
import hashlib
import json
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request

from lab import ACCOUNTS, ARM, RESOURCE_API, ArmError, Lab, api_url, sanitize


GRAPH = "https://graph.microsoft.com/v1.0"
CONTRIBUTOR = "b24988ac-6180-42a0-ab88-20f7382dd24c"
ROLE_API = "2022-04-01"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_claims(token):
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def validate_application_claims(claims, account, client_id, principal_id):
    if (
        claims.get("tid") != ACCOUNTS[account]["tenant"]
        or (claims.get("appid") or claims.get("azp")) != client_id
        or claims.get("oid") != principal_id
    ):
        raise RuntimeError(f"Entra returned unexpected application identity metadata for {account}")
    if claims.get("aud") not in {
        ARM, ARM + "/", "https://management.core.windows.net/",
        "https://management.core.windows.net",
        "797f4846-ba00-4fd7-ba43-dac1f8f63013",
    }:
        raise RuntimeError("Entra returned an unexpected ARM token audience")


class AppIdentity:
    def __init__(self, lab, temporary, home_account="A"):
        if home_account not in ACCOUNTS:
            raise ValueError("Application home account must be A or B")
        self.lab = lab
        self.arm = lab.arm
        self.home_account = home_account
        self.temporary = Path(temporary)
        self.graph_tokens = {}
        self.app_tokens = {}
        self.application = None
        self.principals = {}
        self.roles = []
        self.cleanup_results = []
        self.key = self.temporary / "application-key.pem"
        self.certificate = self.temporary / "application-cert.pem"
        self.der = None
        self.save()

    def save(self):
        payload = {
            "runId": self.lab.run_id, "homeTenant": self.home_account,
            "application": self.application, "servicePrincipals": self.principals,
            "roleAssignments": self.roles, "cleanup": self.cleanup_results,
            "credential": "temporary local RSA certificate; no private key saved in workspace",
            "graphApiPermissionsGrantedToApp": [],
        }
        (self.lab.directory / "identity.json").write_text(json.dumps(sanitize(payload), indent=2) + "\n")

    def graph_token(self, account):
        cached = self.graph_tokens.get(account)
        if cached and cached["expires"] > time.time() + 300:
            return cached["token"]
        result = subprocess.run([
            "az", "account", "get-access-token", "--subscription",
            ACCOUNTS[account]["subscription"], "--resource", "https://graph.microsoft.com/",
            "--output", "json",
        ], capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise RuntimeError(f"Existing Graph authentication failed in {account}: {sanitize(result.stderr)}")
        payload = json.loads(result.stdout)
        if payload.get("tenant") != ACCOUNTS[account]["tenant"]:
            raise RuntimeError("Graph token was issued for an unexpected tenant")
        self.graph_tokens[account] = {
            "token": payload["accessToken"], "expires": int(payload["expires_on"]),
        }
        return payload["accessToken"]

    def graph(self, method, path, account, body=None, allow_404=False):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Graph requests must use a fixed-host relative path")
        url = GRAPH + path
        if urlsplit(url).hostname != "graph.microsoft.com":
            raise ValueError("Refusing an unapproved Graph host")
        client_id = str(uuid.uuid4())
        request = Request(
            url, data=None if body is None else json.dumps(body).encode(), method=method,
            headers={
                "Authorization": "Bearer " + self.graph_token(account),
                "Content-Type": "application/json", "client-request-id": client_id,
            },
        )
        try:
            response = self.arm.opener.open(request, timeout=90)
        except HTTPError as error:
            response = error
        except (URLError, TimeoutError) as error:
            self.arm.record({
                "service": "Graph", "method": method, "url": url,
                "account": account, "transportError": str(error),
            })
            raise RuntimeError(f"Graph transport failure: {sanitize(str(error))}") from error
        with response:
            status = response.code
            headers = {key.lower(): value for key, value in response.headers.items()}
            raw = response.read().decode()
        payload = json.loads(raw) if raw.strip() else {}
        self.arm.record({
            "service": "Graph", "startedAt": datetime.now(timezone.utc).isoformat(),
            "method": method, "url": url, "account": account,
            "clientRequestId": client_id, "requestBody": body, "httpStatus": status,
            "responseHeaders": {
                key: value for key, value in headers.items()
                if key in {"request-id", "client-request-id", "date"}
            },
            "responseBody": payload,
        })
        if not 200 <= status < 300 and not (allow_404 and status == 404):
            raise ArmError(status, payload)
        return status, payload

    def provision(self):
        for account in ACCOUNTS:
            self.graph_token(account)
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=xtnic-" + self.lab.run_id,
            "-keyout", str(self.key), "-out", str(self.certificate),
        ], check=True, capture_output=True)
        self.key.chmod(0o600)
        self.der = subprocess.run([
            "openssl", "x509", "-in", str(self.certificate), "-outform", "DER",
        ], check=True, capture_output=True).stdout
        _, app = self.graph("POST", "/applications", self.home_account, {
            "displayName": "xtnic-lab-" + self.lab.run_id,
            "signInAudience": "AzureADMultipleOrgs",
            "requiredResourceAccess": [],
            "keyCredentials": [{
                "type": "AsymmetricX509Cert", "usage": "Verify",
                "displayName": "disposable-lab-certificate",
                "key": base64.b64encode(self.der).decode(),
            }],
        })
        self.application = {"objectId": app["id"], "clientId": app["appId"]}
        self.save()
        print(f"Created disposable application: {app['appId']}", flush=True)
        for account in (self.home_account, "B" if self.home_account == "A" else "A"):
            principal = self.create_principal(account, app["appId"])
            self.principals[account] = {"objectId": principal["id"], "clientId": principal["appId"]}
            self.save()
            print(f"Created lab application service principal in tenant {account}", flush=True)

    def create_principal(self, account, client_id):
        deadline = time.monotonic() + 180
        while True:
            try:
                _, principal = self.graph(
                    "POST", "/servicePrincipals", account, {"appId": client_id},
                )
                return principal
            except ArmError as error:
                details = error.body.get("error", {}).get("details", [])
                replication_pending = any(item.get("code") == "NoBackingApplicationObject" for item in details)
                if error.status != 400 or not replication_pending or time.monotonic() >= deadline:
                    raise
                print(f"Waiting for new backing application replication in tenant {account}", flush=True)
                time.sleep(10)

    def assertion(self, account):
        endpoint = f"https://login.microsoftonline.com/{ACCOUNTS[account]['tenant']}/oauth2/v2.0/token"
        client = self.application["clientId"]
        now = int(time.time())
        header = {"alg": "PS256", "typ": "JWT", "x5t#S256": b64url(hashlib.sha256(self.der).digest())}
        payload = {
            "aud": endpoint, "iss": client, "sub": client,
            "jti": str(uuid.uuid4()), "nbf": now - 30, "iat": now, "exp": now + 300,
        }
        unsigned = ".".join(b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, payload))
        signature = subprocess.run([
            "openssl", "dgst", "-sha256", "-sign", str(self.key),
            "-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:digest",
        ], input=unsigned.encode(), check=True, capture_output=True).stdout
        return endpoint, unsigned + "." + b64url(signature)

    def token(self, account):
        cached = self.app_tokens.get(account)
        if cached and cached["expires"] > time.time() + 300:
            return cached["token"]
        deadline = time.monotonic() + 180
        while True:
            endpoint, assertion = self.assertion(account)
            data = urlencode({
                "client_id": self.application["clientId"],
                "scope": ARM + "/.default", "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
            }).encode()
            request = Request(endpoint, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
            try:
                response = self.arm.opener.open(request, timeout=60)
            except HTTPError as error:
                response = error
            with response:
                status = response.code
                payload = json.loads(response.read())
            if status != 200:
                self.arm.record({
                    "service": "Entra", "stage": "application-token", "account": account,
                    "httpStatus": status, "responseBody": payload,
                })
                if 700016 in payload.get("error_codes", []) and time.monotonic() < deadline:
                    print(f"Waiting for new application replication in tenant {account}", flush=True)
                    time.sleep(10)
                    continue
                raise ArmError(status, payload)
            token = payload["access_token"]
            claims = decode_claims(token)
            validate_application_claims(
                claims, account, self.application["clientId"], self.principals[account]["objectId"],
            )
            self.app_tokens[account] = {"token": token, "expires": int(claims["exp"])}
            self.arm.record({
                "service": "Entra", "stage": "application-token", "account": account,
                "httpStatus": status,
                "identityMetadata": {key: claims.get(key) for key in ("tid", "appid", "azp", "oid", "aud", "exp")},
            })
            return token

    def assign_roles(self):
        for account, group in self.lab.groups.items():
            role_id = group + "/providers/Microsoft.Authorization/roleAssignments/" + str(uuid.uuid4())
            self.roles.append({"account": account, "id": role_id, "scope": group, "role": "Contributor"})
            self.save()
            definition = (
                "/subscriptions/" + ACCOUNTS[account]["subscription"]
                + "/providers/Microsoft.Authorization/roleDefinitions/" + CONTRIBUTOR
            )
            self.arm.request("PUT", api_url(role_id, ROLE_API), account, {"properties": {
                "roleDefinitionId": definition,
                "principalId": self.principals[account]["objectId"],
                "principalType": "ServicePrincipal",
            }})
            print(f"Granted Contributor only on lab resource group in {account}", flush=True)

    def bootstrap(self, lab):
        self.provision()
        lab.create_groups()
        self.assign_roles()
        lab.arm.token_provider = self.token
        for account, group in lab.groups.items():
            deadline = time.monotonic() + 300
            while True:
                try:
                    lab.arm.request("GET", api_url(group, RESOURCE_API), account)
                    break
                except ArmError as error:
                    code = error.body.get("error", {}).get("code")
                    if error.status != 403 or code != "AuthorizationFailed" or time.monotonic() >= deadline:
                        raise
                    print(f"Waiting for lab-scoped RBAC propagation in {account}", flush=True)
                    time.sleep(10)
        lab.arm.request("GET", api_url(lab.groups["A"], RESOURCE_API), "A", auxiliary="B")
        result = {
            "test": "auxiliary-auth-preflight", "readOnly": True,
            "status": "authentication-verified", "identityType": "same-multitenant-application",
            "clientId": self.application["clientId"],
        }
        lab.results.append(result)
        lab.save()
        print(json.dumps(result), flush=True)

    def cleanup(self):
        failures = []
        for role in self.roles:
            try:
                self.arm.delete(role["id"], ROLE_API, role["account"])
                self.cleanup_results.append({"id": role["id"], "status": "absent-verified"})
            except (ArmError, RuntimeError, TimeoutError) as error:
                failures.append({"id": role["id"], "error": str(error)})
        objects = [
            (account, "/servicePrincipals/" + item["objectId"])
            for account, item in reversed(list(self.principals.items()))
        ]
        if self.application:
            objects.append((self.home_account, "/applications/" + self.application["objectId"]))
        for account, path in objects:
            try:
                self.graph("DELETE", path, account, allow_404=True)
                status, _ = self.graph("GET", path, account, allow_404=True)
                if status != 404:
                    raise RuntimeError("Directory object still exists after DELETE")
                self.cleanup_results.append({
                    "account": account, "id": path, "status": "deleted-and-404-verified",
                    "note": "Active directory object absent; Entra soft-delete retention may apply.",
                })
            except (ArmError, RuntimeError, TimeoutError) as error:
                failures.append({"account": account, "id": path, "error": str(error)})
        self.cleanup_results.extend(dict(item, status="cleanup-failed") for item in failures)
        self.save()
        if failures:
            raise RuntimeError("Identity cleanup incomplete: " + json.dumps(sanitize(failures)))
        print("Identity cleanup verified: scoped roles and active lab directory objects absent.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    if not arguments.execute:
        print(json.dumps({
            "mode": "dry-run; no Azure calls",
            "identity": "new multitenant app in A with certificate and service principal in A/B",
            "permissions": "Contributor only on new lab resource groups; no Graph app permissions",
            "tests": "same matrix as lab.py, with shared application identity",
            "cleanup": "resource groups, scoped roles, service principals, app and local certificate key",
            "salWrites": False,
        }, indent=2))
        return
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6] + "-app"
    directory = Path(__file__).resolve().parent / "results" / run_id
    directory.mkdir(parents=True, exist_ok=False)
    print(f"Evidence directory: {directory}", flush=True)
    lab = Lab(directory, run_id)
    lab.save()
    with tempfile.TemporaryDirectory(prefix="xtnic-app-certificate-") as temporary:
        identity = AppIdentity(lab, temporary)
        try:
            lab.run(bootstrap=identity.bootstrap)
        finally:
            identity.cleanup()


if __name__ == "__main__":
    main()
