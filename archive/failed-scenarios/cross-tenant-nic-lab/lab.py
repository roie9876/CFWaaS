#!/usr/bin/env python3
"""Disposable, token-safe cross-tenant NIC experiment using raw ARM requests."""

import argparse
import json
import os
import re
import subprocess
import tempfile
import time
import uuid
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


ARM = "https://management.azure.com"


class AccountProfiles(Mapping):
    """Load explicit, local account selection only when it is needed."""

    def _load(self):
        path = Path(os.environ.get(
            "FAAS_ACCOUNT_PROFILE", str(Path(__file__).resolve().parents[3] / ".local/accounts.json"),
        )).expanduser()
        if not path.is_file():
            raise RuntimeError(
                "Missing local account profile. Copy accounts.example.json to "
                ".local/accounts.json, fill the approved identities, or set FAAS_ACCOUNT_PROFILE."
            )
        profiles = json.loads(path.read_text())
        if not isinstance(profiles, dict) or set(profiles) != {"A", "B"}:
            raise ValueError("Account profile must contain exactly provider A and customer B")
        for account, entry in profiles.items():
            if not isinstance(entry, dict) or set(entry) != {"tenant", "subscription"}:
                raise ValueError("Each account profile requires tenant and subscription")
            for value in entry.values():
                try:
                    parsed = uuid.UUID(value)
                except (ValueError, TypeError, AttributeError) as error:
                    raise ValueError("Account profile identities must be explicit UUIDs, not placeholders") from error
                if parsed.int == 0 or str(parsed) != value:
                    raise ValueError("Account profile identities must be nonzero canonical UUIDs")
        if profiles["A"]["tenant"] == profiles["B"]["tenant"] or (
            profiles["A"]["subscription"] == profiles["B"]["subscription"]
        ):
            raise ValueError("This cross-tenant lab requires distinct tenants and subscriptions")
        return profiles

    def __getitem__(self, account):
        return self._load()[account]

    def __iter__(self):
        return iter(self._load())

    def __len__(self):
        return len(self._load())


ACCOUNTS = AccountProfiles()
COMPUTE_API = "2025-04-01"
NETWORK_API = "2025-05-01"
RESOURCE_API = "2022-09-01"
REGION = "israelcentral"
IMAGE_VERSION = "24.04.202609040"
SIZE = "Standard_B2s"
TERMINAL_FAILURES = {"failed", "canceled", "cancelled"}
SAFE_RESPONSE_HEADERS = {
    "azure-asyncoperation", "location", "retry-after", "x-ms-request-id",
    "x-ms-correlation-request-id", "x-ms-routing-request-id", "date",
}


def sanitize(value):
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if key.lower() in {
                    "authorization", "x-ms-authorization-auxiliary", "accesstoken",
                    "access_token", "refresh_token", "client_secret", "adminpassword",
                    "secrettext", "client_assertion", "id_token",
                }
                else sanitize(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [REDACTED]", value)
        value = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[JWT REDACTED]", value)
        return re.sub(
            r"(?i)([?&](?!api-version=)[A-Za-z0-9._~-]+=)[^&\s\"<>]+",
            r"\1[REDACTED]",
            value,
        )
    return value


def approved_url(url):
    url = urljoin(ARM + "/", url)
    parts = urlsplit(url)
    if (
        parts.scheme != "https" or parts.hostname != "management.azure.com"
        or parts.port not in (None, 443) or parts.username or parts.password
        or parts.fragment
    ):
        raise ValueError("Refusing credentials to an unapproved ARM URL")
    return url


def api_url(resource_id, version):
    return approved_url(resource_id + "?api-version=" + version)


def same_id(left, right):
    return isinstance(left, str) and left.rstrip("/").lower() == right.rstrip("/").lower()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ArmError(RuntimeError):
    def __init__(self, status, body):
        self.status = status
        self.body = sanitize(body)
        super().__init__(json.dumps({"httpStatus": status, "response": self.body}))


class Arm:
    def __init__(self, directory, token_provider=None):
        self.directory = directory
        self.tokens = {}
        self.opener = build_opener(NoRedirect())
        self.sequence = 0
        self.token_provider = token_provider

    def token(self, account):
        if self.token_provider is not None:
            return self.token_provider(account)
        cached = self.tokens.get(account)
        if cached and cached["expires"] > time.time() + 300:
            return cached["token"]
        config = ACCOUNTS[account]
        command = [
            "az", "account", "get-access-token", "--subscription",
            config["subscription"], "--resource", ARM + "/", "--output", "json",
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        if result.returncode:
            raise RuntimeError(f"Token acquisition failed for {account}: {sanitize(result.stderr)}")
        payload = json.loads(result.stdout)
        if payload.get("tenant") != config["tenant"]:
            raise RuntimeError(f"Unexpected token tenant for {account}")
        expires = payload.get("expires_on")
        if expires is None:
            raise RuntimeError("Azure CLI did not return expires_on; cannot safely cache token")
        self.tokens[account] = {"token": payload["accessToken"], "expires": int(expires)}
        return payload["accessToken"]

    def request(self, method, url, account, body=None, auxiliary=None, allow_404=False):
        url = approved_url(url)
        client_id = str(uuid.uuid4())
        headers = {
            "Authorization": "Bearer " + self.token(account),
            "Content-Type": "application/json",
            "x-ms-client-request-id": client_id,
        }
        if auxiliary:
            headers["x-ms-authorization-auxiliary"] = "Bearer " + self.token(auxiliary)
        data = None if body is None else json.dumps(body).encode()
        request = Request(url, data=data, headers=headers, method=method)
        started = datetime.now(timezone.utc).isoformat()
        try:
            response = self.opener.open(request, timeout=90)
        except HTTPError as error:
            response = error
        except (URLError, TimeoutError) as error:
            self.record({
                "startedAt": started, "method": method, "url": url,
                "account": account, "auxiliaryAccount": auxiliary,
                "clientRequestId": client_id, "transportError": str(error),
            })
            raise RuntimeError(f"ARM transport failure: {sanitize(str(error))}") from error
        with response:
            status = response.code
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            raw = response.read().decode("utf-8")
        try:
            payload = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            self.record({"method": method, "url": url, "httpStatus": status, "nonJsonBody": raw})
            raise RuntimeError(f"ARM returned non-JSON HTTP {status}")
        self.record({
            "startedAt": started, "method": method, "url": url,
            "account": account, "auxiliaryAccount": auxiliary,
            "clientRequestId": client_id, "requestHeaderNames": sorted(headers),
            "requestBody": body, "httpStatus": status,
            "responseHeaders": {
                key: value for key, value in response_headers.items()
                if key in SAFE_RESPONSE_HEADERS
            },
            "responseBody": payload,
        })
        if not 200 <= status < 300 and not (allow_404 and status == 404):
            raise ArmError(status, payload)
        return status, response_headers, payload

    def record(self, event):
        self.sequence += 1
        event["sequence"] = self.sequence
        with (self.directory / "events.jsonl").open("a") as stream:
            stream.write(json.dumps(sanitize(event)) + "\n")

    def operation(self, response, account, auxiliary=None, timeout=900):
        status, headers, payload = response
        async_url = headers.get("azure-asyncoperation")
        location = headers.get("location")
        poll_url = async_url or location
        if not poll_url:
            if status == 202:
                raise RuntimeError("ARM accepted an operation without a documented polling URL")
            return payload
        poll_url = approved_url(poll_url)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                delay = min(30, max(2, int(headers.get("retry-after", "5"))))
            except ValueError:
                delay = 5
            time.sleep(delay)
            status, headers, payload = self.request("GET", poll_url, account, auxiliary=auxiliary)
            if status == 202 and payload is None:
                continue
            if not isinstance(payload, dict):
                raise RuntimeError(f"ARM polling returned an invalid HTTP {status} result shape")
            state = str(payload.get("status", "")).lower()
            if state in TERMINAL_FAILURES:
                raise ArmError(status, payload)
            if state == "succeeded":
                if async_url and location and approved_url(location) != poll_url:
                    result = self.request("GET", location, account, auxiliary=auxiliary)
                    if result[0] in (200, 201, 204):
                        result_state = str(result[2].get("status", "")).lower()
                        if result_state in TERMINAL_FAILURES:
                            raise ArmError(result[0], result[2])
                        if result_state not in {"accepted", "running", "inprogress"}:
                            return result[2]
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("ARM final-result retrieval exceeded the operation timeout")
                    return self.operation(result, account, auxiliary, remaining)
                return payload
            if not async_url and status in (200, 201, 204) and not state:
                return payload
        raise TimeoutError(f"ARM operation did not finish within {timeout} seconds")

    def resource(self, resource_id, version, account, body, auxiliary=None):
        url = api_url(resource_id, version)
        response = self.request("PUT", url, account, body, auxiliary)
        self.operation(response, account, auxiliary)
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            _, _, payload = self.request("GET", url, account, auxiliary=auxiliary)
            state = payload.get("properties", {}).get("provisioningState", "").lower()
            if state in TERMINAL_FAILURES:
                raise ArmError(200, payload)
            if state == "succeeded":
                return payload
            if not state:
                raise RuntimeError(f"Resource response has no provisioningState: {resource_id}")
            time.sleep(5)
        raise TimeoutError(f"Resource did not reach a terminal state: {resource_id}")

    def delete(self, resource_id, version, account, auxiliary=None, timeout=900):
        response = self.request(
            "DELETE", api_url(resource_id, version), account,
            auxiliary=auxiliary, allow_404=True,
        )
        if response[0] == 404:
            return
        self.operation(response, account, auxiliary, timeout)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, _, _ = self.request(
                "GET", api_url(resource_id, version), account, auxiliary=auxiliary, allow_404=True,
            )
            if status == 404:
                return
            time.sleep(5)
        raise TimeoutError(f"Deletion not verified: {resource_id}")


class Lab:
    def __init__(self, directory, run_id):
        self.directory = directory
        self.run_id = run_id
        self.arm = Arm(directory)
        self.groups = {}
        self.manifest = []
        self.results = []
        self.public_key = None
        self.test_deadline = time.monotonic() + 2700

    def save(self):
        for name, payload in (
            ("manifest.json", {"runId": self.run_id, "resources": self.manifest}),
            ("results.json", {"runId": self.run_id, "region": REGION, "tests": self.results}),
        ):
            (self.directory / name).write_text(json.dumps(sanitize(payload), indent=2) + "\n")

    def track(self, account, resource_id, purpose):
        self.manifest.append({"account": account, "id": resource_id, "purpose": purpose})
        self.save()

    def authenticate(self):
        for account, config in ACCOUNTS.items():
            _, _, subscription = self.arm.request(
                "GET", api_url("/subscriptions/" + config["subscription"], "2022-12-01"), account,
            )
            if subscription.get("tenantId") != config["tenant"] or subscription.get("state") != "Enabled":
                raise RuntimeError(f"Subscription/tenant mapping or state changed for {account}")
        result = {
            "test": "auxiliary-auth-preflight", "readOnly": True,
            "description": "Read subscription A with primary A and auxiliary B tokens",
        }
        try:
            self.arm.request(
                "GET", api_url("/subscriptions/" + ACCOUNTS["A"]["subscription"], "2022-12-01"),
                "A", auxiliary="B",
            )
        except ArmError as error:
            result.update({"status": "rejected", "httpStatus": error.status, "error": error.body})
            self.results.append(result)
            self.save()
            print(json.dumps(sanitize(result)), flush=True)
            raise
        result["status"] = "authentication-verified"
        self.results.append(result)
        self.save()
        print(json.dumps(result), flush=True)

    def resource_id(self, account, resource_type, name):
        return self.groups[account] + "/providers/" + resource_type + "/" + name

    def create_groups(self):
        for account, config in ACCOUNTS.items():
            group = f"rg-xtnic-{self.run_id}-{account.lower()}"
            resource_id = f"/subscriptions/{config['subscription']}/resourceGroups/{group}"
            status, _, _ = self.arm.request(
                "GET", api_url(resource_id, RESOURCE_API), account, allow_404=True,
            )
            if status != 404:
                raise RuntimeError(f"Refusing to reuse pre-existing group {resource_id}")
            self.groups[account] = resource_id
            self.track(account, resource_id, "disposable lab resource group")
            self.arm.resource(resource_id, RESOURCE_API, account, {
                "location": REGION,
                "tags": {"purpose": "cross-tenant-nic-lab", "labRun": self.run_id},
            })

    def network(self, account, cidr):
        nsg = self.resource_id(account, "Microsoft.Network/networkSecurityGroups", "nsg-lab")
        self.track(account, nsg, "block inbound access to disposable lab")
        self.arm.resource(nsg, NETWORK_API, account, {
            "location": REGION,
            "properties": {"securityRules": [{
                "name": "DenyAllInbound",
                "properties": {
                    "priority": 100, "protocol": "*", "access": "Deny", "direction": "Inbound",
                    "sourceAddressPrefix": "*", "sourcePortRange": "*",
                    "destinationAddressPrefix": "*", "destinationPortRange": "*",
                },
            }]},
        })
        vnet = self.resource_id(account, "Microsoft.Network/virtualNetworks", "vnet-lab")
        self.track(account, vnet, "isolated lab virtual network")
        self.arm.resource(vnet, NETWORK_API, account, {
            "location": REGION,
            "properties": {
                "addressSpace": {"addressPrefixes": [cidr + ".0.0/16"]},
                "subnets": [{
                    "name": "lab",
                    "properties": {
                        "addressPrefix": cidr + ".0.0/24",
                        "networkSecurityGroup": {"id": nsg},
                        "defaultOutboundAccess": False,
                    },
                }],
            },
        })
        return vnet + "/subnets/lab"

    def public_ip(self, account, name):
        resource_id = self.resource_id(account, "Microsoft.Network/publicIPAddresses", "pip-" + name)
        self.track(account, resource_id, "explicit outbound connectivity; inbound blocked by subnet NSG")
        self.arm.resource(resource_id, NETWORK_API, account, {
            "location": REGION, "sku": {"name": "Standard"},
            "properties": {"publicIPAllocationMethod": "Static", "publicIPAddressVersion": "IPv4"},
        })
        return resource_id

    def nic(self, account, name, subnet, auxiliary=None):
        public_ip = self.public_ip(account, name)
        resource_id = self.resource_id(account, "Microsoft.Network/networkInterfaces", "nic-" + name)
        self.track(account, resource_id, "test NIC; may be rejected")
        payload = self.arm.resource(resource_id, NETWORK_API, account, {
            "location": REGION,
            "properties": {"ipConfigurations": [{
                "name": "ipconfig1",
                "properties": {
                    "privateIPAllocationMethod": "Dynamic", "subnet": {"id": subnet},
                    "publicIPAddress": {"id": public_ip},
                },
            }]},
        }, auxiliary)
        return resource_id, payload

    def vm_body(self, name, nic):
        return {
            "location": REGION,
            "tags": {"purpose": "cross-tenant-nic-lab", "labRun": self.run_id},
            "properties": {
                "hardwareProfile": {"vmSize": SIZE},
                "storageProfile": {
                    "imageReference": {
                        "publisher": "Canonical", "offer": "ubuntu-24_04-lts",
                        "sku": "server", "version": IMAGE_VERSION,
                    },
                    "osDisk": {
                        "name": name + "-os", "createOption": "FromImage",
                        "caching": "ReadWrite", "diskSizeGB": 32, "deleteOption": "Delete",
                        "managedDisk": {"storageAccountType": "StandardSSD_LRS"},
                    },
                },
                "osProfile": {
                    "computerName": name, "adminUsername": "labuser",
                    "linuxConfiguration": {
                        "disablePasswordAuthentication": True,
                        "ssh": {"publicKeys": [{
                            "path": "/home/labuser/.ssh/authorized_keys", "keyData": self.public_key,
                        }]},
                    },
                },
                "securityProfile": {
                    "securityType": "TrustedLaunch",
                    "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True},
                },
                "networkProfile": {"networkInterfaces": [{
                    "id": nic, "properties": {"primary": True, "deleteOption": "Detach"},
                }]},
                "diagnosticsProfile": {"bootDiagnostics": {"enabled": True}},
            },
        }

    def runtime(self, vm_id, expected_ip):
        deadline = time.monotonic() + 300
        instance = {}
        while time.monotonic() < deadline:
            _, _, instance = self.arm.request(
                "GET", api_url(vm_id + "/instanceView", COMPUTE_API), "A",
            )
            agent_states = instance.get("vmAgent", {}).get("statuses", [])
            if any(state.get("code", "").lower() == "provisioningstate/succeeded" for state in agent_states):
                break
            time.sleep(10)
        else:
            raise TimeoutError("VM guest agent did not become ready")
        response = self.arm.request(
            "POST", api_url(vm_id + "/runCommand", COMPUTE_API), "A",
            {"commandId": "RunShellScript", "script": [
                "set -eu",
                "printf 'LAB_ADDRESSES_BEGIN\\n'",
                "ip -j address",
                "printf 'LAB_ADDRESSES_END\\n'",
                "printf 'LAB_ROUTES_BEGIN\\n'",
                "ip -j route",
                "printf 'LAB_ROUTES_END\\n'",
            ]},
        )
        output = self.arm.operation(response, "A", timeout=600)
        messages = "\n".join(item.get("message", "") for item in output.get("value", []))
        match = re.search(r"LAB_ADDRESSES_BEGIN\s*\n(.*?)\nLAB_ADDRESSES_END", messages, re.S)
        if not match:
            raise RuntimeError("Run Command did not return the expected guest-address output")
        addresses = json.loads(match.group(1))
        guest_ips = {
            address["local"]
            for interface in addresses for address in interface.get("addr_info", [])
        }
        if expected_ip not in guest_ips:
            raise RuntimeError(f"Expected NIC private IP {expected_ip} was not present in guest")
        power_states = [item.get("code") for item in instance.get("statuses", [])]
        if "PowerState/running" not in power_states:
            raise RuntimeError(f"VM was not reported running: {power_states}")
        return {"guestAddresses": addresses, "runCommand": output, "powerStates": power_states}

    def test_vm(self, test_id, topology, nic, nic_account, auxiliary):
        if time.monotonic() > self.test_deadline:
            raise TimeoutError("Test budget expired; proceeding to cleanup")
        vm_id = self.resource_id("A", "Microsoft.Compute/virtualMachines", "vm-" + test_id)
        result = {"test": test_id, "topology": topology, "auxiliaryToken": bool(auxiliary)}
        self.track("A", vm_id, "test VM; may be rejected")
        self.track("A", self.resource_id("A", "Microsoft.Compute/disks", "vm-" + test_id + "-os"), "VM OS disk")
        try:
            vm = self.arm.resource(vm_id, COMPUTE_API, "A", self.vm_body("vm-" + test_id, nic), auxiliary)
            _, _, nic_state = self.arm.request("GET", api_url(nic, NETWORK_API), nic_account)
            if not any(
                same_id(item.get("id"), nic)
                for item in vm["properties"]["networkProfile"]["networkInterfaces"]
            ):
                raise RuntimeError("VM does not reference the exact requested NIC")
            if not same_id(nic_state.get("properties", {}).get("virtualMachine", {}).get("id"), vm_id):
                raise RuntimeError("NIC does not report association with the test VM")
            expected_ip = nic_state["properties"]["ipConfigurations"][0]["properties"]["privateIPAddress"]
            result.update({
                "status": "control-plane-verified", "vmId": vm_id, "nicId": nic,
                "vmProvisioningState": vm["properties"]["provisioningState"],
                "nicVmId": nic_state["properties"]["virtualMachine"]["id"],
                "privateIPAddress": expected_ip,
            })
            try:
                result["runtime"] = self.runtime(vm_id, expected_ip)
                result["status"] = "runtime-verified"
            except (ArmError, RuntimeError, TimeoutError) as error:
                result["runtimeError"] = str(error)
                print(f"{test_id}: control plane verified, runtime not verified: {sanitize(str(error))}", flush=True)
        except ArmError as error:
            result.update({"status": "rejected", "httpStatus": error.status, "error": error.body})
        except (RuntimeError, TimeoutError) as error:
            result.update({"status": "inconclusive", "error": str(error)})
        finally:
            self.results.append(result)
            self.save()
            print(json.dumps(sanitize({
                key: value for key, value in result.items() if key != "runtime"
            })), flush=True)
            status, _, vm = self.arm.request(
                "GET", api_url(vm_id, COMPUTE_API), "A", allow_404=True,
            )
            if status != 404:
                state = vm.get("properties", {}).get("provisioningState", "").lower()
                if state not in {"succeeded", "failed", "canceled", "cancelled"}:
                    raise RuntimeError(f"VM still has an in-flight operation ({state}); stopping tests")
                self.arm.delete(vm_id, COMPUTE_API, "A", auxiliary="B" if nic_account == "B" else None)
        return result

    def run(self, bootstrap=None):
        with tempfile.TemporaryDirectory(prefix="xtnic-key-") as temporary:
            key = Path(temporary) / "lab-key"
            subprocess.run(
                ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                check=True, capture_output=True, text=True,
            )
            self.public_key = key.with_suffix(".pub").read_text().strip()
        original_provider = self.arm.token_provider
        try:
            if bootstrap is None:
                self.authenticate()
                self.create_groups()
            else:
                bootstrap(self)
            subnet_a = self.network("A", "10.240")
            subnet_b = self.network("B", "10.241")
            baseline_nic, _ = self.nic("A", "baseline", subnet_a)
            baseline = self.test_vm("baseline", "VM-A -> NIC-A -> subnet-A", baseline_nic, "A", None)
            if baseline["status"] not in {"runtime-verified", "control-plane-verified"}:
                raise RuntimeError("Positive baseline failed; cross-tenant trials are blocked")
            for name, auxiliary in (("foreign-noaux", None), ("foreign-aux", "B")):
                nic, _ = self.nic("B", name, subnet_b)
                self.test_vm(name, "VM-A -> NIC-B -> subnet-B", nic, "B", auxiliary)
            secondary = {
                "test": "remote-subnet", "topology": "VM-A -> NIC-A -> subnet-B",
                "auxiliaryToken": True,
            }
            try:
                nic, payload = self.nic("A", "remote-subnet", subnet_b, auxiliary="B")
                actual_subnet = payload["properties"]["ipConfigurations"][0]["properties"]["subnet"]["id"]
                if not same_id(actual_subnet, subnet_b):
                    raise RuntimeError("NIC does not reference the requested remote subnet")
                secondary.update({"status": "nic-created", "nicId": nic, "subnetId": actual_subnet})
                self.results.append(secondary)
                self.save()
                self.test_vm("remote-subnet-vm", secondary["topology"], nic, "A", "B")
            except ArmError as error:
                secondary.update({"status": "rejected", "httpStatus": error.status, "error": error.body})
                self.results.append(secondary)
                self.save()
                print(json.dumps(sanitize(secondary)), flush=True)
            sal_observation = {"test": "sal-list", "topology": "subnet-B", "readOnly": True}
            try:
                _, _, payload = self.arm.request(
                    "GET", api_url(subnet_b + "/serviceAssociationLinks", NETWORK_API), "B",
                )
                sal_observation.update({"status": "observed", "response": payload})
            except ArmError as error:
                sal_observation.update({"status": "rejected", "error": error.body, "httpStatus": error.status})
            self.results.append(sal_observation)
            self.save()
        finally:
            self.arm.token_provider = original_provider
            self.cleanup()

    def cleanup(self):
        outcome = []
        for account, resource_id in self.groups.items():
            try:
                status, _, group = self.arm.request(
                    "GET", api_url(resource_id, RESOURCE_API), account, allow_404=True,
                )
                if status == 404:
                    outcome.append({"id": resource_id, "status": "already-absent"})
                    continue
                if group.get("tags", {}).get("labRun") != self.run_id:
                    raise RuntimeError("Refusing to delete a group without this run's ownership tag")
                deadline = time.monotonic() + 600
                while True:
                    _, _, resources = self.arm.request(
                        "GET", api_url(resource_id + "/resources", "2021-04-01"), account,
                    )
                    if resources.get("nextLink"):
                        raise RuntimeError("Cleanup resource listing was paginated; manual inspection required")
                    vm_ids = [
                        item["id"] for item in resources.get("value", [])
                        if item.get("type", "").lower() == "microsoft.compute/virtualmachines"
                    ]
                    busy = []
                    for vm_id in vm_ids:
                        vm_status, _, vm = self.arm.request(
                            "GET", api_url(vm_id, COMPUTE_API), account, allow_404=True,
                        )
                        state = vm.get("properties", {}).get("provisioningState", "").lower()
                        if vm_status != 404 and state not in {"succeeded", "failed", "canceled", "cancelled"}:
                            busy.append(vm_id)
                    if not busy:
                        break
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"Cleanup blocked by in-flight VM operations: {busy}")
                    time.sleep(10)
                self.arm.delete(resource_id, RESOURCE_API, account)
                outcome.append({"id": resource_id, "status": "deleted-and-404-verified"})
                print(f"Cleanup verified: {resource_id}", flush=True)
            except (ArmError, RuntimeError, TimeoutError) as error:
                outcome.append({"id": resource_id, "status": "cleanup-failed", "error": str(error)})
                print(f"CLEANUP FAILURE: {resource_id}: {sanitize(str(error))}", flush=True)
        (self.directory / "cleanup.json").write_text(json.dumps(sanitize(outcome), indent=2) + "\n")
        self.save()
        if any(item["status"] == "cleanup-failed" for item in outcome):
            raise RuntimeError("Cleanup incomplete; inspect cleanup.json for exact remaining group IDs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true", help="Create approved lab resources; always attempt cleanup")
    mode.add_argument("--check-auth", action="store_true", help="Read-only identity and dual-token checks; no resources")
    arguments = parser.parse_args()
    if not arguments.execute and not arguments.check_auth:
        print(json.dumps({
            "mode": "dry-run; no Azure calls", "accounts": ACCOUNTS, "region": REGION,
            "size": SIZE, "image": f"Canonical:ubuntu-24_04-lts:server:{IMAGE_VERSION}",
            "executeFlagRequired": True, "cleanup": "automatic, owned lab groups only",
            "salWrites": False,
        }, indent=2))
        return
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    directory = Path(__file__).resolve().parent / "results" / run_id
    directory.mkdir(parents=True, exist_ok=False)
    print(f"Evidence directory: {directory}", flush=True)
    lab = Lab(directory, run_id)
    lab.save()
    if arguments.check_auth:
        try:
            lab.authenticate()
        finally:
            lab.cleanup()
    else:
        lab.run()


if __name__ == "__main__":
    main()
