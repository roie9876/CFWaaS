#!/usr/bin/env python3
"""Run only the explicitly approved, tagged cross-tenant AVNM functional lab."""

import argparse
import fcntl
import ipaddress
import json
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "archive/failed-scenarios/cross-tenant-nic-lab"))
from lab import ACCOUNTS, Arm, ArmError, Lab, api_url, sanitize, same_id
from app_identity import AppIdentity
from guest_tools import extract_guest_result, require_marker, request_script
from avnm_guest import bootstrap, metrics_script, targets_for, evaluate, block_script

REGION = "israelcentral"
NM_API = "2025-09-01"
NET_API = "2025-05-01"
VM_API = "2025-04-01"
RG_API = "2022-09-01"


class NetworkConvergencePending(RuntimeError):
    pass


class ThreadSafeArm(Arm):
    def __init__(self, directory):
        super().__init__(directory)
        self.lock = threading.RLock()

    def token(self, account):
        with self.lock:
            return super().token(account)

    def record(self, event):
        with self.lock:
            super().record(event)


def node_definitions(config):
    nodes = []
    for group in config["groups"]:
        prefix = ipaddress.ip_network(group["firewallPrefix"])
        nodes.append({
            "name": "fw-" + group["name"], "group": group["name"], "account": "A",
            "prefix": str(prefix), "subnetPrefix": str(prefix),
            "privateIp": group["firewallIp"], "firewall": True, "size": config["firewallSize"],
        })
        for index, value in enumerate(group["workloadPrefixes"], 1):
            network = ipaddress.ip_network(value)
            nodes.append({
                "name": group["name"] + "-" + str(index), "group": group["name"], "account": "B",
                "prefix": str(network), "subnetPrefix": str(next(network.subnets(new_prefix=24))),
                "privateIp": str(network.network_address + 4), "firewall": False,
                "size": config["workloadSize"],
            })
    return nodes


def manager_body():
    return {"location": REGION, "properties": {
        "networkManagerScopes": {"managementGroups": [], "subscriptions": [
            "/subscriptions/" + ACCOUNTS["A"]["subscription"],
        ]},
        "networkManagerScopeAccesses": ["Connectivity", "Routing"],
    }}


def connectivity_body(group_id, hub_id):
    return {"properties": {
        "connectivityTopology": "HubAndSpoke",
        "hubs": [{"resourceId": hub_id, "resourceType": "Microsoft.Network/virtualNetworks"}],
        "appliesToGroups": [{
            "networkGroupId": group_id, "groupConnectivity": "None",
            "useHubGateway": "False", "isGlobal": "False",
        }],
        "deleteExistingPeering": "False", "isGlobal": "False",
    }}


def rule_body(prefix, next_hop):
    if not ipaddress.ip_address(next_hop).is_private:
        raise ValueError("Lab appliance next hop must be private")
    return {"properties": {
        "destination": {"type": "AddressPrefix", "destinationAddress": str(ipaddress.ip_network(prefix))},
        "nextHop": {"nextHopType": "VirtualAppliance", "nextHopAddress": next_hop},
    }}


def commit_body(kind, ids):
    if kind not in {"Connectivity", "Routing"}:
        raise ValueError("Only the two approved AVNM features may be committed")
    return {"commitType": kind, "configurationIds": ids, "targetLocations": [REGION]}


def verify_effective_routes(effective, firewall_ip):
    rows = effective.get("value")
    if not isinstance(rows, list):
        raise RuntimeError("NIC effective-route response has no value array")
    for prefix in ("10.0.0.0/8", "0.0.0.0/0"):
        matched = [row for row in rows if prefix in row.get("addressPrefix", []) and row.get("state") == "Active"]
        if len(matched) != 1 or (
            matched[0].get("source") != "User" or matched[0].get("nextHopType") != "VirtualAppliance"
            or matched[0].get("nextHopIpAddress") != [firewall_ip]
        ):
            raise RuntimeError("Active NIC routes do not select the intended AVNM firewall next hop")


def compile_template(name):
    result = subprocess.run([
        "az", "bicep", "build", "--file", str(ROOT / "infra" / (name + ".bicep")), "--stdout",
    ], capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError("Bicep compilation failed: " + result.stderr)
    return json.loads(result.stdout)


def validate_config(config):
    if config["region"] != REGION or config["networkManagerApi"] != NM_API:
        raise ValueError("Region/API changes require a reviewed plan")
    if [group["name"] for group in config["groups"]] != ["group1", "group2"]:
        raise ValueError("Expected exactly the two approved groups")
    if any(len(group["workloadPrefixes"]) != 3 for group in config["groups"]):
        raise ValueError("Exactly three customer VNets per group are required")
    if config["firewallSize"] != "Standard_B2s" or config["workloadSize"] != "Standard_B1ms":
        raise ValueError("VM size changes require a new cost/quota approval")
    if config["hostEncryption"] is not False:
        raise ValueError("Host-encryption feature changes require separate approval")
    if config["testTimeoutSeconds"] != 7200 or config["retention"] != "keep":
        raise ValueError("The testing/retention policy no longer matches the approved plan")
    networks = [ipaddress.ip_network(node["prefix"]) for node in node_definitions(config)]
    for index, network in enumerate(networks):
        if network.version != 4 or not network.is_private or any(network.overlaps(other) for other in networks[index + 1:]):
            raise ValueError("Lab prefixes must be distinct private IPv4 networks")
    return config


def group_scopes(run_id):
    return {
        account: f"/subscriptions/{entry['subscription']}/resourceGroups/rg-avnmfaas-{run_id}-{account.lower()}"
        for account, entry in ACCOUNTS.items()
    }


def validate_resume_scope(state):
    recorded = state.get("groups")
    if not isinstance(recorded, dict) or set(recorded) != {"A", "B"}:
        raise ValueError("Resume requires both recorded account scopes; manual recovery review is required")
    expected = group_scopes(state["runId"])
    if any(not same_id(recorded[account], scope) for account, scope in expected.items()):
        raise ValueError("Selected account profile does not match the recorded run scopes")
    tenant_pins = state.get("accountTenants")
    if tenant_pins is not None and tenant_pins != {
        account: entry["tenant"] for account, entry in ACCOUNTS.items()
    }:
        raise ValueError("Selected account profile does not match the recorded tenant pins")
    consent = state.get("consentSnapshots", {}).get("A", {}).get("properties", {})
    if consent and (
        consent.get("tenantId") != ACCOUNTS["B"]["tenant"]
        or not same_id(consent.get("resourceId"), "/subscriptions/" + ACCOUNTS["B"]["subscription"])
    ):
        raise ValueError("Selected customer profile does not match recorded cross-tenant consent")


class Experiment:
    def __init__(self, state, directory, config):
        self.state, self.directory, self.config = state, directory, config
        self.arm = ThreadSafeArm(directory)
        self.nodes = node_definitions(config)
        self.groups = group_scopes(state["runId"])
        self.manager = self.groups["A"] + "/providers/Microsoft.Network/networkManagers/nm-" + state["runId"]
        self.a_connection = self.manager + "/scopeConnections/customer-b"
        self.b_connection = (
            f"/subscriptions/{ACCOUNTS['B']['subscription']}/providers/Microsoft.Network/networkManagerConnections/"
            + "avnmfaas-" + state["runId"]
        )
        self.routing = self.manager + "/routingConfigurations/customer-routing"
        self.tags = {"purpose": "avnm-faas-lab", "labRun": state["runId"]}
        self.deadline = time.monotonic() + config["testTimeoutSeconds"]
        self.application_auth = False
        self.save()

    def save(self):
        with tempfile.NamedTemporaryFile(mode="w", dir=self.directory, prefix=".state-", delete=False) as file:
            path = Path(file.name)
            json.dump(self.state, file, indent=2)
            file.write("\n")
        path.replace(self.directory / "state.json")

    def phase(self, name):
        self.state["phase"] = name
        self.save()
        print("PHASE: " + name, flush=True)

    def remaining(self):
        value = self.deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("Approved two-hour testing window expired; retained resources continue charging")
        return value

    def owned_group(self, account, allow_absent=False):
        status, _, group = self.arm.request(
            "GET", api_url(self.groups[account], RG_API), account, allow_404=allow_absent,
        )
        if status == 404:
            return False
        if group.get("tags", {}).get("labRun") != self.state["runId"] or group.get("tags", {}).get("purpose") != "avnm-faas-lab":
            raise RuntimeError("Refusing to use an unrelated resource group")
        return True

    def get(self, rid, account="A", version=NM_API, allow_404=False):
        return self.arm.request("GET", api_url(rid, version), account, allow_404=allow_404)

    @contextmanager
    def temporary_application(self):
        for account in ("A", "B"):
            self.owned_group(account)
        evidence = self.directory / ("application-auth-" + datetime.now(timezone.utc).strftime("%H%M%S"))
        evidence.mkdir()
        context = Lab(evidence, self.state["runId"])
        context.arm = self.arm
        context.groups = dict(self.groups)
        temporary = tempfile.TemporaryDirectory(prefix="avnm-app-certificate-")
        identity = AppIdentity(context, temporary.name)
        self.state["temporaryIdentityEvidence"] = str(evidence)
        self.save()
        try:
            try:
                identity.provision()
                identity.assign_roles()
                self.arm.token_provider = identity.token
                self.application_auth = True
                for account in ("A", "B"):
                    deadline = time.monotonic() + 300
                    while True:
                        try:
                            self.owned_group(account)
                            break
                        except ArmError as error:
                            if error.status != 403 or time.monotonic() >= deadline:
                                raise
                            time.sleep(10)
                yield
            finally:
                self.arm.token_provider = None
                self.application_auth = False
                identity.cleanup()
                self.state["temporaryIdentityCleanup"] = identity.cleanup_results
                self.save()
        finally:
            temporary.cleanup()
            self.state["temporaryCertificateFilesRemoved"] = not Path(temporary.name).exists()
            self.save()

    def control_id(self, rid):
        if not rid.lower().startswith(self.manager.lower() + "/"):
            if not same_id(rid, self.b_connection):
                raise RuntimeError("AVNM operation is outside the exact recorded manager/consent scope")

    def put_control(self, rid, body, account="A"):
        self.remaining()
        self.control_id(rid)
        auxiliary = "B" if self.application_auth and account == "A" else None
        response = self.arm.request("PUT", api_url(rid, NM_API), account, body, auxiliary=auxiliary)
        self.arm.operation(response, account, auxiliary=auxiliary, timeout=min(900, self.remaining()))
        deadline = time.monotonic() + min(600, self.remaining())
        while time.monotonic() < deadline:
            _, _, actual = self.get(rid, account)
            if not same_id(actual.get("id"), rid) or not isinstance(actual.get("properties"), dict):
                raise RuntimeError("AVNM GET did not return the intended resource model")
            state = str(actual["properties"].get("provisioningState", "")).lower()
            if state in {"failed", "canceled", "cancelled"}:
                raise ArmError(200, actual)
            connection = same_id(rid, self.a_connection) or same_id(rid, self.b_connection)
            if not state and not connection:
                raise RuntimeError("AVNM resource has no provisioningState; cannot assume success")
            if connection or state == "succeeded":
                self.state.setdefault("controlResources", {})[rid] = account
                self.save()
                return actual
            time.sleep(5)
        raise TimeoutError("AVNM child resource did not finish provisioning")

    def deploy(self, name, account, parameters):
        self.remaining()
        self.owned_group(account)
        template = compile_template(name)
        rid = self.groups[account] + "/providers/Microsoft.Resources/deployments/avnm-" + name
        return self.arm.resource(rid, RG_API, account, {"properties": {
            "mode": "Incremental", "template": template,
            "parameters": {key: {"value": value} for key, value in parameters.items()},
        }})

    def create_groups(self):
        self.phase("validating-scopes-and-creating-owned-groups")
        for account in ("A", "B"):
            self.arm.token(account)
            status, _, _ = self.get(self.groups[account], account, RG_API, True)
            if status != 404:
                self.owned_group(account)
            else:
                self.arm.resource(self.groups[account], RG_API, account, {"location": REGION, "tags": self.tags})
        self.state["groups"] = self.groups
        self.state["managerId"] = self.manager
        self.state["consentIds"] = {"A": self.a_connection, "B": self.b_connection}
        self.save()

    def networks(self):
        self.phase("deploying-network-manager-and-eight-empty-network-stacks")
        prefixes = [prefix for group in self.config["groups"] for prefix in group["workloadPrefixes"]]
        inventory = {}
        for account, name in (("A", "main"), ("B", "customer")):
            selected = [node for node in self.nodes if node["account"] == account]
            parameters = {"location": REGION, "nodes": selected, "labPrefixes": prefixes, "tags": self.tags}
            if account == "A":
                parameters["managerName"] = self.manager.rsplit("/", 1)[1]
            deployed = self.deploy(name, account, parameters)
            if account == "A":
                actual = self.get(self.manager)[2]["properties"]
                expected = manager_body()["properties"]
                if set(actual.get("networkManagerScopeAccesses", [])) != set(expected["networkManagerScopeAccesses"]):
                    raise RuntimeError("Network manager features differ from the approved contract")
                if actual.get("networkManagerScopes", {}).get("subscriptions") != expected["networkManagerScopes"]["subscriptions"]:
                    raise RuntimeError("Network manager same-tenant scope differs from the approved subscription")
            for entry in deployed["properties"]["outputs"]["networkResources"]["value"]:
                inventory[entry["name"]] = entry
        if set(inventory) != {node["name"] for node in self.nodes}:
            raise RuntimeError("Network deployment outputs do not cover all eight approved nodes")
        self.state["networks"] = inventory
        for node in self.nodes:
            entry = inventory[node["name"]]
            _, _, peers = self.get(entry["vnetId"] + "/virtualNetworkPeerings", node["account"], NET_API)
            if peers.get("value"):
                raise RuntimeError("Fresh lab VNet already has unexpected peerings")
            if not node["firewall"]:
                _, _, table = self.get(entry["routeTableId"], "B", NET_API)
                if table["properties"].get("routes"):
                    raise RuntimeError("Precreated customer route table must be empty before AVNM")
        self.state["stages"]["networks"] = True
        self.save()

    def consent(self):
        self.phase("establishing-explicit-two-owner-cross-tenant-consent")
        self.put_control(self.a_connection, {"properties": {
            "tenantId": ACCOUNTS["B"]["tenant"], "resourceId": "/subscriptions/" + ACCOUNTS["B"]["subscription"],
            "description": "Run-owned cross-tenant lab",
        }})
        self.put_control(self.b_connection, {"properties": {
            "networkManagerId": self.manager, "description": "Run-owned provider AVNM consent",
        }}, "B")
        deadline = time.monotonic() + min(600, self.remaining())
        snapshots = {}
        while time.monotonic() < deadline:
            snapshots = {
                account: self.get(rid, account)[2]
                for account, rid in (("A", self.a_connection), ("B", self.b_connection))
            }
            states = {account: value["properties"]["connectionState"] for account, value in snapshots.items()}
            if any(value in {"Conflict", "Revoked", "Rejected"} for value in states.values()):
                raise RuntimeError("Cross-tenant authorization failed: " + json.dumps(states))
            if all(value == "Connected" for value in states.values()):
                break
            time.sleep(5)
        else:
            raise TimeoutError("Two-way scope did not become Connected; no guest/IAM grants were made")
        _, _, manager = self.get(self.manager)
        self.state["consentSnapshots"] = snapshots
        self.state["observedCrossTenantScopes"] = manager["properties"]["networkManagerScopes"].get("crossTenantScopes", [])
        self.state["stages"]["consent"] = True
        self.save()

    def configure(self):
        self.phase("creating-avnm-groups-connectivity-and-routing-intent")
        connectivity = []
        self.put_control(self.routing, {"properties": {
            "description": "Two isolated customer groups", "routeTableUsageMode": "UseExisting",
        }})
        for group in self.config["groups"]:
            group_id = self.manager + "/networkGroups/" + group["name"]
            self.put_control(group_id, {"properties": {"memberType": "VirtualNetwork", "description": group["name"]}})
            for node in self.nodes:
                if node["group"] == group["name"] and not node["firewall"]:
                    self.put_control(group_id + "/staticMembers/" + node["name"], {
                        "properties": {"resourceId": self.state["networks"][node["name"]]["vnetId"]},
                    })
            cid = self.manager + "/connectivityConfigurations/" + group["name"]
            hub = self.state["networks"]["fw-" + group["name"]]["vnetId"]
            self.put_control(cid, connectivity_body(group_id, hub))
            connectivity.append(cid)
            collection = self.routing + "/ruleCollections/" + group["name"]
            self.put_control(collection, {"properties": {
                "appliesTo": [{"networkGroupId": group_id}], "disableBgpRoutePropagation": "True",
            }})
            for name, prefix in (("lab-private", "10.0.0.0/8"), ("internet", "0.0.0.0/0")):
                self.put_control(collection + "/rules/" + name, rule_body(prefix, group["firewallIp"]))
        self.state["connectivityIds"] = connectivity
        self.save()
        for kind, ids in (("Connectivity", connectivity), ("Routing", [self.routing])):
            self.commit(kind, ids)
        self.state["stages"]["configured"] = True
        self.save()

    def commit(self, kind, ids, enforce_deadline=True):
        self.phase("committing-" + kind.lower())
        response = self.arm.request(
            "POST", api_url(self.manager + "/commit", NM_API), "A", commit_body(kind, ids),
            auxiliary="B" if self.application_auth else None,
        )
        timeout = min(1800, self.remaining()) if enforce_deadline else 1800
        self.arm.operation(response, "A", auxiliary="B" if self.application_auth else None, timeout=timeout)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _, _, status = self.arm.request("POST", api_url(self.manager + "/listDeploymentStatus", NM_API), "A", {
                "regions": [REGION], "deploymentTypes": [kind],
            })
            self.state.setdefault("deploymentStatus", {})[kind] = status
            self.save()
            rows = [row for row in status.get("value", [])
                    if row.get("region", "").lower() == REGION and row.get("deploymentType") == kind]
            if any(row.get("deploymentStatus") == "Failed" for row in rows):
                raise ArmError(200, status)
            expected = {value.lower() for value in ids}
            matched = [row for row in rows if {value.lower() for value in row.get("configurationIds", [])} == expected]
            if matched and all(row.get("deploymentStatus") == "Deployed" and not row.get("errorMessage") for row in matched):
                return
            time.sleep(10)
        raise TimeoutError("AVNM deployment status did not prove the exact intended configuration set")

    def network_evidence(self):
        self.phase("verifying-avnm-created-peers-and-udrs")
        evidence = {}
        for node in self.nodes:
            entry = self.state["networks"][node["name"]]
            _, _, peers = self.get(entry["vnetId"] + "/virtualNetworkPeerings", node["account"], NET_API)
            rows = peers.get("value", [])
            if node["firewall"]:
                expected = {
                    self.state["networks"][other["name"]]["vnetId"].lower()
                    for other in self.nodes if other["group"] == node["group"] and not other["firewall"]
                }
            else:
                expected = {self.state["networks"]["fw-" + node["group"]]["vnetId"].lower()}
            actual = {row["properties"]["remoteVirtualNetwork"]["id"].lower() for row in rows}
            if actual - expected:
                raise RuntimeError("AVNM peering graph has an unexpected cross-group/bypass edge")
            if actual != expected or any(row["properties"].get("peeringState") != "Connected" for row in rows):
                raise NetworkConvergencePending("AVNM intent is deployed but peering resources are still converging")
            if not node["firewall"] and any(row["properties"].get("allowForwardedTraffic") is not True for row in rows):
                self.state.setdefault("limitations", []).append({
                    "node": node["name"], "issue": "AVNM-generated customer peering does not permit forwarded traffic",
                })
                self.save()
                raise RuntimeError("Generated peering forwarding is unsuitable; no manual repair will be performed")
            record = {"peerings": rows}
            if not node["firewall"]:
                _, _, table = self.get(entry["routeTableId"], "B", NET_API)
                routes = table["properties"]["routes"]
                for prefix in ("10.0.0.0/8", "0.0.0.0/0"):
                    expected_ip = next(group["firewallIp"] for group in self.config["groups"] if group["name"] == node["group"])
                    matched = [route["properties"] for route in routes if route["properties"].get("addressPrefix") == prefix]
                    if not matched:
                        raise NetworkConvergencePending("AVNM routes are still converging in the existing customer table")
                    if len(matched) != 1 or matched[0].get("nextHopType") != "VirtualAppliance" or matched[0].get("nextHopIpAddress") != expected_ip:
                        raise RuntimeError("AVNM did not populate the precreated customer route table as requested")
                _, _, subnet = self.get(entry["subnetId"], "B", NET_API)
                if not same_id(subnet["properties"].get("routeTable", {}).get("id"), entry["routeTableId"]):
                    raise RuntimeError("Customer subnet route-table association changed unexpectedly")
                record["routeTable"] = table
            evidence[node["name"]] = record
        self.state["networkEvidence"] = evidence
        self.state["stages"]["networkVerified"] = True
        self.save()

    def compute(self):
        self.phase("deploying-two-firewalls-and-six-private-workloads")
        if "sshPublicKey" not in self.state:
            with tempfile.TemporaryDirectory(prefix="avnm-faas-ssh-") as temporary:
                key = Path(temporary) / "key"
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True, capture_output=True)
                self.state["sshPublicKey"] = key.with_suffix(".pub").read_text().strip()
            self.save()
        for account in ("A", "B"):
            definitions = []
            for node in self.nodes:
                if node["account"] != account:
                    continue
                own = next(group["workloadPrefixes"] for group in self.config["groups"] if group["name"] == node["group"])
                other = next(group["workloadPrefixes"] for group in self.config["groups"] if group["name"] != node["group"])
                definitions.append({
                    **node, "nicId": self.state["networks"][node["name"]]["nicId"],
                    "cloudInit": bootstrap(node, own, other),
                })
            self.deploy("compute", account, {
                "location": REGION, "nodes": definitions, "sshPublicKey": self.state["sshPublicKey"],
                "image": self.config["image"], "tags": self.tags,
            })
        self.state["vmIds"] = {
            node["name"]: self.groups[node["account"]] + "/providers/Microsoft.Compute/virtualMachines/vm-" + node["name"]
            for node in self.nodes
        }
        self.state["stages"]["compute"] = True
        self.save()

    def command(self, node, script, restoration=False):
        timeout = 900 if restoration else min(900, self.remaining())
        expected_id = self.groups[node["account"]] + "/providers/Microsoft.Compute/virtualMachines/vm-" + node["name"]
        if not same_id(self.state["vmIds"][node["name"]], expected_id):
            raise RuntimeError("Refusing guest execution outside the exact run-owned VM")
        response = self.arm.request(
            "POST", api_url(self.state["vmIds"][node["name"]] + "/runCommand", VM_API),
            node["account"], {"commandId": "RunShellScript", "script": script},
        )
        return self.arm.operation(response, node["account"], timeout=timeout)

    def guests_ready(self):
        self.phase("waiting-for-guest-bootstrap")
        def ready(node):
            deadline = time.monotonic() + min(600, self.remaining())
            rid = self.state["vmIds"][node["name"]]
            while time.monotonic() < deadline:
                _, _, instance = self.get(rid + "/instanceView", node["account"], VM_API)
                statuses = instance.get("vmAgent", {}).get("statuses", [])
                if any(value.get("code", "").lower() == "provisioningstate/succeeded" for value in statuses):
                    break
                time.sleep(10)
            else:
                raise TimeoutError("Guest agent did not become ready: " + node["name"])
            result = self.command(node, [
                "set -eu", "cloud-init status --wait", "systemctl is-active faas-http.service",
                "grep AVNM_BOOTSTRAP_OK /var/log/avnm-faas-bootstrap.log",
                "printf 'AVNM_GUEST_READY\\n'",
            ])
            require_marker(result, "AVNM_GUEST_READY")
            return node["name"]
        with ThreadPoolExecutor(max_workers=8) as executor:
            self.state["readyGuests"] = list(executor.map(ready, self.nodes))
        self.save()
        for node in self.nodes:
            if node["firewall"]:
                continue
            entry = self.state["networks"][node["name"]]
            response = self.arm.request("POST", api_url(entry["nicId"] + "/effectiveRouteTable", NET_API), "B", {})
            effective = self.arm.operation(response, "B", timeout=min(600, self.remaining()))
            (self.directory / ("effective-" + node["name"] + ".json")).write_text(json.dumps(effective, indent=2) + "\n")
            firewall_ip = next(group["firewallIp"] for group in self.config["groups"] if group["name"] == node["group"])
            verify_effective_routes(effective, firewall_ip)

    def counters(self, phase):
        values = {}
        for node in self.nodes:
            if node["firewall"]:
                result = extract_guest_result(self.command(node, metrics_script()))
                if len(result) != 1 or result[0].get("kind") != "firewall-counters":
                    raise RuntimeError("Invalid firewall counter shape")
                for key in ("ownAccepted", "crossDropped"):
                    if not isinstance(result[0].get(key), int) or result[0][key] < 0:
                        raise RuntimeError("Firewall counters must be nonnegative integers")
                values[node["group"]] = result[0]
        self.state.setdefault("counterSnapshots", {})[phase] = values
        self.save()
        return values

    def measure(self, phase, blocked_groups=None):
        self.phase("measuring-" + phase)
        blocked_groups = set(blocked_groups or [])
        workloads = [node for node in self.nodes if not node["firewall"]]
        def requests(source):
            targets = targets_for(source, workloads, self.state["runId"], phase)
            measured = extract_guest_result(self.command(source, request_script(targets)))
            return evaluate(source, targets, measured, workloads, blocked_groups)
        with ThreadPoolExecutor(max_workers=6) as executor:
            batches = list(executor.map(requests, workloads))
        results = [row for batch in batches for row in batch]
        if len(results) != 30 or sum(row["sameGroup"] for row in results) != 12:
            raise RuntimeError("Expected 12 within-group and 18 cross-group directed tests")
        self.state.setdefault("measurements", {})[phase] = results
        self.save()
        if not all(row["passed"] for row in results):
            raise RuntimeError("Traffic acceptance failed in " + phase + "; inspect the saved measurements")
        print(f"PASS {phase}: {len(results)} directed tests", flush=True)
        return results

    def test(self):
        if self.state.get("activeNegativeControl"):
            self.restore_block(self.state["activeNegativeControl"])
        before = self.counters("before-baseline")
        self.measure("baseline")
        after = self.counters("after-baseline")
        for group in ("group1", "group2"):
            if after[group]["ownAccepted"] <= before[group]["ownAccepted"] or after[group]["crossDropped"] <= before[group]["crossDropped"]:
                raise RuntimeError("Correct firewall inspection and inter-group drop counters did not both increase")
        for group in ("group1", "group2"):
            node = next(node for node in self.nodes if node["firewall"] and node["group"] == group)
            try:
                self.state["activeNegativeControl"] = group
                self.save()
                require_marker(self.command(node, block_script(True)), "AVNM_NEGATIVE_CONTROL_ON")
                self.measure("blocked-" + group, {group})
            finally:
                self.restore_block(group)
            self.measure("restored-" + group)
        self.state["stages"]["trafficPassed"] = True
        self.save()

    def restore_block(self, group):
        node = next(node for node in self.nodes if node["firewall"] and node["group"] == group)
        require_marker(self.command(node, block_script(False), restoration=True), "AVNM_NEGATIVE_CONTROL_OFF")
        self.state["activeNegativeControl"] = None
        self.save()

    def run(self):
        self.create_groups()
        _, plan = load_inputs()
        approved_run = plan["meta"].get("temporaryApplicationApprovedRun")
        if approved_run == self.state["runId"] and not self.state["stages"].get("configured"):
            with self.temporary_application():
                self.run_stages()
        else:
            self.run_stages()

    def run_stages(self):
        stages = self.state["stages"]
        if not stages.get("networks"):
            self.networks()
        if not stages.get("consent"):
            self.consent()
        if not stages.get("configured"):
            self.configure()
        deadline = time.monotonic() + min(600, self.remaining())
        while True:
            try:
                self.network_evidence()
                break
            except NetworkConvergencePending as error:
                if time.monotonic() >= deadline:
                    raise TimeoutError("AVNM peering/route resources did not converge within ten minutes") from error
                print(str(error), flush=True)
                time.sleep(10)
        if not stages.get("compute"):
            self.compute()
        self.guests_ready()
        self.test()
        self.phase("passed-lab-retained-for-user-inspection")

    def cleanup(self):
        self.phase("authorized-cleanup")
        for account in ("A", "B"):
            self.owned_group(account, allow_absent=True)
        status, _, _ = self.get(self.manager, allow_404=True)
        if status != 404:
            for kind in ("Routing", "Connectivity"):
                self.commit(kind, [], enforce_deadline=False)
            resources = dict(self.state.get("controlResources", {}))
            for rid, account in sorted(resources.items(), key=lambda item: item[0].count("/"), reverse=True):
                if same_id(rid, self.a_connection) or same_id(rid, self.b_connection):
                    continue
                self.control_id(rid)
                self.arm.delete(rid, NM_API, account, timeout=1200)
            self.arm.delete(self.a_connection, NM_API, "A", timeout=1200)
        status, _, connection = self.get(self.b_connection, "B", allow_404=True)
        if status != 404:
            if not same_id(connection["properties"]["networkManagerId"], self.manager):
                raise RuntimeError("Refusing to delete a consent connection for another manager")
            self.arm.delete(self.b_connection, NM_API, "B", timeout=1200)
        for account in ("B", "A"):
            if self.owned_group(account, allow_absent=True):
                self.arm.delete(self.groups[account], RG_API, account, timeout=2400)
        self.state["cleanupVerified"] = True
        self.save()


def load_inputs():
    config_path = ROOT / "config.json"
    plan_path = ROOT / ".azure/infrastructure-plan.json"
    if not config_path.is_file() or not plan_path.is_file():
        raise RuntimeError("Local config/plan missing. Follow README setup; example plans do not authorize deployment.")
    return validate_config(json.loads(config_path.read_text())), json.loads(plan_path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true")
    mode.add_argument("--resume-run")
    mode.add_argument("--cleanup-run")
    parser.add_argument("--confirm-cleanup", action="store_true")
    args = parser.parse_args()
    config, plan = load_inputs()
    if not any((args.execute, args.resume_run, args.cleanup_run)):
        print(json.dumps({"mode": "DRY RUN; no Azure calls", "plan": plan["meta"],
                          "firewalls": 2, "privateWorkloads": 6, "retention": config["retention"]}, indent=2))
        return 0
    if plan["meta"]["status"] not in {"approved", "deployed"} or not plan["meta"]["executionApproved"]:
        raise RuntimeError("No explicit approved deployment scope")
    if plan["meta"]["status"] == "deployed" and args.execute:
        raise ValueError("This lab is already deployed; use its explicit --resume-run or approved --cleanup-run")
    if args.cleanup_run and not args.confirm_cleanup:
        raise ValueError("Retained lab cleanup requires --confirm-cleanup and fresh user authorization")
    existing = args.resume_run or args.cleanup_run
    if existing:
        import re
        if not re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{6}", existing):
            raise ValueError("Invalid run ID")
        directory = ROOT / "results" / existing
        state = json.loads((directory / "state.json").read_text())
        if state["runId"] != existing:
            raise ValueError("Run ID mismatch")
        validate_resume_scope(state)
        if "failure" in state:
            state.setdefault("previousFailures", []).append({
                "phase": state.get("phase"), "error": state.pop("failure"),
            })
    else:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        directory = ROOT / "results" / run_id
        directory.mkdir(parents=True, mode=0o700)
        state = {
            "runId": run_id, "stages": {}, "retention": "keep",
            "accountTenants": {account: entry["tenant"] for account, entry in ACCOUNTS.items()},
        }
    with (ROOT / ".execution-lock").open("w") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Another AVNM lab controller is already running") from error
        experiment = Experiment(state, directory, config)
        print("Evidence directory: " + str(directory), flush=True)
        try:
            if args.cleanup_run:
                experiment.cleanup()
            else:
                experiment.run()
        except (ArmError, RuntimeError, TimeoutError, ValueError, OSError, subprocess.SubprocessError) as error:
            state["failure"] = sanitize(str(error))
            experiment.save()
            print("LAB FAILURE: " + sanitize(str(error)), file=sys.stderr, flush=True)
            print("Lab resources are retained as approved; inspect state/evidence. No automatic cleanup.", file=sys.stderr, flush=True)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
