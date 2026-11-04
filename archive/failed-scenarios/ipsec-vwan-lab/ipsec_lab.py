#!/usr/bin/env python3
"""Explicitly approved, isolated customer-vWAN/provider-IPsec routing experiment."""

import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "cross-tenant-nic-lab"))
from lab import ACCOUNTS, Arm, ArmError, api_url, same_id, sanitize
from guest_tools import extract_guest_result, request_script, require_marker
from ipsec_guest import bootstrap, block_script, metrics_script, ping_script, prefer_tunnel_script, tunnel_script

NET = "2025-05-01"
VM = "2025-04-01"
RG = "2022-09-01"
REGION = "israelcentral"
PURPOSE = "ipsec-vwan-lab"


def fingerprint(config):
    return hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()


def validate_config(config):
    if (config["region"], config["networkApi"], config["computeApi"], config["resourceApi"]) != (REGION, NET, VM, RG):
        raise ValueError("Region or API changes require a reviewed plan")
    if (config["firewallSize"], config["workloadSize"], config["gatewayScaleUnit"], config["testWindowSeconds"]) != (
        "Standard_B2s", "Standard_B1ms", 1, 10800,
    ):
        raise ValueError("Size, gateway capacity or test-window change requires approval")
    if [node["name"] for node in config["nodes"]] != ["ipsec-fw", "ipsec-wl1", "ipsec-wl2"]:
        raise ValueError("Expected one provider simulator and two customer workloads")
    networks = [ipaddress.ip_network(config["hubPrefix"])]
    for index, node in enumerate(config["nodes"]):
        if (node["account"], node["firewall"]) != (("A", True) if index == 0 else ("B", False)):
            raise ValueError("Node ownership does not match the approved topology")
        network = ipaddress.ip_network(node["prefix"])
        subnet = ipaddress.ip_network(node["subnetPrefix"])
        address = ipaddress.ip_address(node["privateIp"])
        if network.version != 4 or not network.is_private or not subnet.subnet_of(network):
            raise ValueError("Expected a private IPv4 subnet inside each network")
        if address not in subnet or address <= subnet.network_address + 3 or address == subnet.broadcast_address:
            raise ValueError("Private endpoint is outside its usable subnet")
        if any(network.overlaps(old) for old in networks):
            raise ValueError("Lab address spaces overlap")
        networks.append(network)
    return config


def execution_gate(config, plan, acknowledge_billing):
    meta = plan["meta"]
    if meta.get("status") not in {"approved", "deployed"} or not meta.get("executionApproved"):
        raise RuntimeError("Live execution is disabled; final risk/cost approval is required")
    if not acknowledge_billing:
        raise RuntimeError("Explicit --acknowledge-billing is required")
    if meta.get("retention") not in {"cleanup", "keep"}:
        raise RuntimeError("Explicit cleanup/retention policy is required")
    if meta.get("configFingerprint") != fingerprint(config) or meta.get("accountProfiles") != dict(ACCOUNTS):
        raise RuntimeError("Configuration or account profile differs from the approved plan")


def scopes(run_id):
    return {
        account: f"/subscriptions/{entry['subscription']}/resourceGroups/rg-ipsecfaas-{run_id}-{account.lower()}"
        for account, entry in ACCOUNTS.items()
    }


def validate_resume(state, config):
    if state.get("configFingerprint") != fingerprint(config):
        raise ValueError("Saved run configuration differs")
    if state.get("accountProfiles") != dict(ACCOUNTS):
        raise ValueError("Saved run account selection differs")
    if state.get("groups") != scopes(state["runId"]):
        raise ValueError("Saved run does not match exact run-owned resource groups")


def redacted(value, key=""):
    if isinstance(value, dict):
        return {name: redacted(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [redacted(item, key) for item in value]
    if key.lower() in {"sharedkey", "psk", "presharedkey"}:
        return "[REDACTED]"
    return sanitize(value)


class EvidenceArm(Arm):
    def __init__(self, directory, private_values):
        super().__init__(directory)
        self.private_values = private_values

    def clean(self, value):
        value = redacted(value)
        variants = [variant for item in self.private_values for variant in (
            item, base64.b64encode(item.encode()).decode(),
        )]
        def walk(item):
            if isinstance(item, dict):
                return {key: walk(value) for key, value in item.items()}
            if isinstance(item, list):
                return [walk(value) for value in item]
            if isinstance(item, str):
                for private in variants:
                    item = item.replace(private, "[REDACTED]")
            return item
        return walk(value)

    def record(self, event):
        event = self.clean(event)
        if "/runCommand?" in event.get("url", "") and event.get("requestBody"):
            body = event["requestBody"]
            event["requestBody"] = {
                "commandId": body.get("commandId"), "script": "[REDACTED]",
                "parameterNames": [row["name"] for row in body.get("parameters", [])],
            }
        super().record(event)


def routing(default_id, inspect_id, inspect=False, branch=False):
    associated = default_id if branch or not inspect else inspect_id
    propagated = inspect_id if branch else default_id
    return {
        "associatedRouteTable": {"id": associated},
        "propagatedRouteTables": {
            "ids": [{"id": propagated}], "labels": ["ipsec-inspection" if branch else "Default"],
        },
    }


def vpn_body(site_id, default_id, inspect_id, key):
    return {"properties": {
        "remoteVpnSite": {"id": site_id},
        "enableBgp": False,
        "enableInternetSecurity": False,
        "routingConfiguration": routing(default_id, inspect_id, branch=True),
        "vpnLinkConnections": [{
            "name": "provider-link",
            "properties": {
                "vpnSiteLink": {"id": site_id + "/vpnSiteLinks/provider"},
                "sharedKey": key, "enableBgp": False, "connectionBandwidth": 10,
                "usePolicyBasedTrafficSelectors": False,
                "vpnConnectionProtocolType": "IKEv2", "vpnLinkConnectionMode": "Default",
                "ipsecPolicies": [{
                    "saLifeTimeSeconds": 3600, "saDataSizeKilobytes": 102400000,
                    "ipsecEncryption": "AES256", "ipsecIntegrity": "SHA256",
                    "ikeEncryption": "AES256", "ikeIntegrity": "SHA256",
                    "dhGroup": "DHGroup14", "pfsGroup": "PFS14",
                }],
            },
        }],
    }}


def gateway_peers(gateway):
    peers = {
        value
        for row in gateway.get("properties", {}).get("bgpSettings", {}).get("bgpPeeringAddresses", [])
        for value in row.get("tunnelIpAddresses", [])
        if ipaddress.ip_address(value).version == 4 and ipaddress.ip_address(value).is_global
    }
    if len(peers) != 2:
        raise RuntimeError("Cannot discover both actual active-active VPN gateway public endpoints")
    return sorted(peers)


def route_rows(value):
    if isinstance(value, list):
        return [row for item in value for row in route_rows(item)]
    if isinstance(value, dict):
        if "addressPrefixes" in value and "nextHops" in value:
            return [value]
        return [row for item in value.values() for row in route_rows(item)]
    return []


def winning_route(effective, destination):
    candidates = []
    address = ipaddress.ip_address(destination)
    for row in route_rows(effective):
        for prefix in row["addressPrefixes"]:
            network = ipaddress.ip_network(prefix)
            if address in network:
                candidates.append((network.prefixlen, row))
    if not candidates:
        raise RuntimeError("No effective hub route for a protected destination")
    best = max(length for length, _ in candidates)
    winners = [row for length, row in candidates if length == best]
    if any(row != winners[0] for row in winners):
        raise RuntimeError("Ambiguous effective hub next hops")
    return winners[0]


def has_next_hop(row, ids):
    return any(same_id(actual, expected) for actual in row.get("nextHops", []) for expected in ids)

def http_passed(source, destination, row, allowed):
    if allowed:
        return row["ok"] is True and row.get("status") == 200 and (
            row.get("body", {}).get("hostname") == "vm-" + destination["name"]
            and row["body"].get("client_ip") == source["privateIp"]
        )
    return row["ok"] is False and (
        row.get("errorType") in {"TimeoutError", "ConnectionResetError"}
        or (row.get("errorType") == "OSError" and row.get("errno") in {100, 101, 112, 113})
    )


class Experiment:
    def __init__(self, directory, state, config, plan):
        self.directory, self.state, self.config, self.plan = directory, state, config, plan
        self.groups = state["groups"]
        self.tags = {"purpose": PURPOSE, "labRun": state["runId"]}
        self.hub = self.groups["B"] + "/providers/Microsoft.Network/virtualHubs/vhub-ipsec"
        self.wan = self.groups["B"] + "/providers/Microsoft.Network/virtualWans/vwan-ipsec"
        self.gateway = self.groups["B"] + "/providers/Microsoft.Network/vpnGateways/vpng-ipsec"
        self.site = self.groups["B"] + "/providers/Microsoft.Network/vpnSites/site-ipsec-provider"
        self.vpn = self.gateway + "/vpnConnections/provider"
        self.default = self.hub + "/hubRouteTables/defaultRouteTable"
        self.inspect = self.hub + "/hubRouteTables/rt-ipsec-inspect"
        secret_path = directory / ".secrets.json"
        if not secret_path.exists():
            descriptor = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                json.dump({"psk": secrets.token_hex(32)}, stream)
        self.key = json.loads(secret_path.read_text())["psk"]
        if not re.fullmatch("[0-9a-f]{64}", self.key):
            raise ValueError("Invalid local VPN credential")
        self.arm = EvidenceArm(directory, [self.key])
        self.nodes = config["nodes"]

    def save(self):
        with tempfile.NamedTemporaryFile(mode="w", dir=self.directory, prefix=".state-", delete=False) as stream:
            json.dump(self.arm.clean(self.state), stream, indent=2)
            stream.write("\n")
            path = Path(stream.name)
        path.replace(self.directory / "state.json")

    def phase(self, name):
        self.state["phase"] = name
        self.save()
        print("PHASE:", name, flush=True)

    def remaining(self, maximum=900):
        remaining = self.state["deadlineEpoch"] - time.time()
        if remaining <= 0:
            raise TimeoutError("Approved test window expired; cleanup or explicit retention is still required")
        return min(maximum, remaining)

    def get(self, resource, account="B", api=NET, allow_404=False):
        return self.arm.request("GET", api_url(resource, api), account, allow_404=allow_404)

    def put(self, resource, body, account="B", api=NET, timeout=1800):
        result = self.arm.request("PUT", api_url(resource, api), account, body)
        self.arm.operation(result, account, timeout=self.remaining(timeout))
        value = self.get(resource, account, api)[2]
        if value.get("properties", {}).get("provisioningState") != "Succeeded":
            raise RuntimeError("Resource did not report successful provisioning")
        return value

    def owned(self, account, allow_absent=False):
        result = self.get(self.groups[account], account, RG, allow_404=allow_absent)
        if result[0] == 404:
            return False
        tags = result[2].get("tags", {})
        if any(tags.get(key) != value for key, value in self.tags.items()):
            raise RuntimeError("Refusing an operation on a resource group not owned by this exact run")
        return True

    def create_groups(self):
        for account in ("A", "B"):
            if not self.owned(account, allow_absent=True):
                response = self.arm.request("PUT", api_url(self.groups[account], RG), account, {
                    "location": REGION, "tags": self.tags,
                })
                self.arm.operation(response, account, timeout=self.remaining())
                self.owned(account)
        self.state["stages"]["groups"] = True
        self.save()

    def begin_deployment(self, name, account, parameters, deployment_name=None):
        self.owned(account)
        compiled = subprocess.run([
            "az", "bicep", "build", "--file", str(ROOT / "infra" / (name + ".bicep")), "--stdout",
        ], capture_output=True, text=True, timeout=180)
        if compiled.returncode:
            raise RuntimeError("Bicep compilation failed: " + compiled.stderr)
        rid = self.groups[account] + "/providers/Microsoft.Resources/deployments/" + (deployment_name or "ipsec-" + name)
        body = {"properties": {
            "mode": "Incremental", "template": json.loads(compiled.stdout),
            "parameters": {key: {"value": value} for key, value in parameters.items()},
        }}
        response = self.arm.request("PUT", api_url(rid, RG), account, body)
        return {"resourceId": rid, "account": account, "response": response}

    def finish_deployment(self, operation):
        self.arm.operation(tuple(operation["response"]), operation["account"], timeout=self.remaining(7200))
        deployment = self.get(operation["resourceId"], operation["account"], RG)[2]
        if deployment.get("properties", {}).get("provisioningState") != "Succeeded":
            raise RuntimeError("ARM deployment did not succeed")
        return {key: row["value"] for key, row in deployment["properties"].get("outputs", {}).items()}

    def infrastructure(self):
        stages = self.state["stages"]
        if not stages.get("foundation"):
            if "foundationOperation" not in self.state:
                self.phase("starting-customer-hub-and-vpn-gateway")
                self.state["foundationOperation"] = self.begin_deployment("main", "B", {
                    "location": REGION, "hubPrefix": self.config["hubPrefix"], "tags": self.tags,
                })
                self.save()
        if not stages.get("compute"):
            if "sshPublicKey" not in self.state:
                with tempfile.TemporaryDirectory(prefix="ipsec-lab-ssh-") as temporary:
                    key = Path(temporary) / "key"
                    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                                   check=True, capture_output=True)
                    self.state["sshPublicKey"] = key.with_suffix(".pub").read_text().strip()
            self.state.setdefault("networks", {})
            self.state.setdefault("vmIds", {})
            for account in ("A", "B"):
                self.phase("deploying-private-nodes-" + account.lower())
                nodes = [node for node in self.nodes if node["account"] == account]
                network = self.finish_deployment(self.begin_deployment("networks", account, {
                    "location": REGION, "nodes": nodes, "tags": self.tags,
                    "labPrefixes": [node["prefix"] for node in self.nodes if not node["firewall"]],
                }))
                self.state["networks"].update({row["name"]: row for row in network["resources"]})
                definitions = [{
                    **node, "nicId": self.state["networks"][node["name"]]["nicId"],
                    "size": self.config["firewallSize"] if node["firewall"] else self.config["workloadSize"],
                    "cloudInit": bootstrap(node["firewall"]),
                } for node in nodes]
                output = self.finish_deployment(self.begin_deployment("compute", account, {
                    "location": REGION, "nodes": definitions, "sshPublicKey": self.state["sshPublicKey"],
                    "image": self.config["image"], "tags": self.tags,
                }))
                self.state["vmIds"].update({row["name"]: row["id"] for row in output["vmIds"]})
                self.save()
            stages["compute"] = True
        if not stages.get("foundation"):
            self.phase("waiting-for-managed-vpn-gateway")
            self.state["foundationOutputs"] = self.finish_deployment(self.state["foundationOperation"])
            stages["foundation"] = True
        self.save()

    def command(self, node, script, parameters=None, restoration=False):
        expected = self.groups[node["account"]] + "/providers/Microsoft.Compute/virtualMachines/vm-" + node["name"]
        if not same_id(expected, self.state["vmIds"].get(node["name"])):
            raise RuntimeError("Refusing guest command outside the exact run-owned VM")
        body = {"commandId": "RunShellScript", "script": script}
        if parameters:
            body["parameters"] = parameters
        result = self.arm.request("POST", api_url(expected + "/runCommand", VM), node["account"], body)
        return self.arm.operation(result, node["account"], timeout=900 if restoration else self.remaining())

    def ready(self):
        self.phase("verifying-owned-guest-bootstrap")
        for node in self.nodes:
            command = [
                "set -eu", "cloud-init status --wait",
                "grep IPSEC_BOOTSTRAP_OK /var/log/ipsec-lab-bootstrap.log",
            ]
            if not node["firewall"]:
                command.append("systemctl is-active ipsec-lab-http.service")
            command.append("printf 'IPSEC_GUEST_READY\\n'")
            require_marker(self.command(node, command), "IPSEC_GUEST_READY")

    def connections(self, inspect):
        for node in self.nodes[1:]:
            self.put(self.hub + "/hubVirtualNetworkConnections/" + node["name"], {"properties": {
                "remoteVirtualNetwork": {"id": self.state["networks"][node["name"]]["vnetId"]},
                "enableInternetSecurity": False, "routingConfiguration": routing(self.default, self.inspect, inspect),
            }})
        self.state["inspectionSteering"] = inspect
        self.save()

    def http(self, phase, allowed, count=1):
        results = []
        for source, destination in (self.nodes[1:], self.nodes[:0:-1]):
            targets = [{
                "test": source["name"] + "-to-" + destination["name"] + "-" + str(index),
                "host": destination["privateIp"], "port": 8080, "path": "/" + phase,
            } for index in range(count)]
            measured = extract_guest_result(self.command(source, request_script(targets)))
            if len(measured) != len(targets) or [row["test"] for row in measured] != [row["test"] for row in targets]:
                raise RuntimeError("Private HTTP probe set is incomplete or mismatched")
            for row in measured:
                passed = http_passed(source, destination, row, allowed)
                results.append({**row, "phase": phase, "passed": passed})
        self.state.setdefault("tests", []).extend(results)
        self.save()
        if not all(row["passed"] for row in results):
            raise RuntimeError("Private HTTP acceptance failed in phase " + phase)
        print("PASS:", phase, len(results), "directed HTTP probes", flush=True)

    def configure_vpn(self):
        self.phase("creating-vpn-site-and-two-ikev2-tunnels")
        peers = gateway_peers(self.get(self.gateway)[2])
        pip = self.get(self.state["networks"]["ipsec-fw"]["publicIpId"], "A")[2]["properties"]["ipAddress"]
        self.state["gatewayPeers"], self.state["providerPublicIp"] = peers, pip
        self.put(self.inspect, {"properties": {"labels": ["ipsec-inspection"], "routes": []}})
        self.put(self.site, {"location": REGION, "tags": self.tags, "properties": {
            "virtualWan": {"id": self.wan},
            "addressSpace": {"addressPrefixes": [node["subnetPrefix"] for node in self.nodes[1:]]},
            "vpnSiteLinks": [{
                "name": "provider", "properties": {
                    "ipAddress": pip, "linkProperties": {"linkProviderName": "lab-provider", "linkSpeedInMbps": 10},
                },
            }],
        }})
        self.put(self.vpn, vpn_body(self.site, self.default, self.inspect, self.key))
        nsg = self.state["networks"]["ipsec-fw"]["nsgId"]
        self.put(nsg + "/securityRules/AllowManagedVpnEndpoints", {"properties": {
            "priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "Udp",
            "sourceAddressPrefixes": peers, "sourcePortRange": "*",
            "destinationAddressPrefix": "*", "destinationPortRanges": ["500", "4500"],
        }}, account="A")
        script = tunnel_script(self.nodes[0]["privateIp"], pip, peers, [node["prefix"] for node in self.nodes[1:]])
        require_marker(self.command(self.nodes[0], script, [{"name": "psk", "value": self.key}]), "IPSEC_CONFIGURED")
        deadline = time.monotonic() + self.remaining(600)
        while time.monotonic() < deadline:
            metrics = self.metrics()
            if metrics["ok"]:
                break
            time.sleep(10)
        else:
            raise TimeoutError("Both IKEv2/CHILD SAs did not become established")
        self.state["stages"]["vpn"] = True
        self.save()

    def metrics(self):
        rows = extract_guest_result(self.command(self.nodes[0], metrics_script()))
        if len(rows) != 1 or not isinstance(rows[0].get("synCount"), int):
            raise RuntimeError("Missing/invalid simulator metrics")
        return rows[0]

    def routes(self, table):
        response = self.arm.request("POST", api_url(self.hub + "/effectiveRoutes", NET), "B", {
            "virtualWanResourceType": "RouteTable", "resourceId": table,
        })
        return self.arm.operation(response, "B", timeout=self.remaining())

    def verify_routes(self):
        self.phase("verifying-separate-inspection-and-delivery-next-hops")
        deadline = time.monotonic() + self.remaining(600)
        issue = "Effective routes have not converged"
        while time.monotonic() < deadline:
            inspection, delivery = self.routes(self.inspect), self.routes(self.default)
            self.state["effectiveRoutes"] = {"inspection": inspection, "delivery": delivery}
            checks = []
            try:
                for node in self.nodes[1:]:
                    before = winning_route(inspection, node["privateIp"])
                    after = winning_route(delivery, node["privateIp"])
                    connection = self.hub + "/hubVirtualNetworkConnections/" + node["name"]
                    vpn_selected = has_next_hop(before, [self.vpn, self.gateway]) or (
                        "VPN" in before.get("nextHopType", "").upper()
                    )
                    direct_selected = has_next_hop(after, [connection, self.state["networks"][node["name"]]["vnetId"]])
                    checks.append(vpn_selected and direct_selected)
                if all(checks) and len(checks) == 2:
                    self.state["routeChecksPassed"] = True
                    self.save()
                    return
                issue = "Observed hub routes do not select VPN before inspection and the destination VNet after inspection"
            except RuntimeError as error:
                issue = str(error)
            self.save()
            time.sleep(10)
        raise RuntimeError(issue)

    def wait_baseline_routes(self):
        self.phase("waiting-for-direct-route-convergence")
        deadline = time.monotonic() + self.remaining(600)
        while time.monotonic() < deadline:
            delivery = self.routes(self.default)
            checks = []
            for node in self.nodes[1:]:
                try:
                    route = winning_route(delivery, node["privateIp"])
                except RuntimeError:
                    checks.append(False)
                    continue
                connection = self.hub + "/hubVirtualNetworkConnections/" + node["name"]
                checks.append(has_next_hop(route, [connection, self.state["networks"][node["name"]]["vnetId"]]))
            if len(checks) == 2 and all(checks):
                self.state["baselineEffectiveRoutes"] = delivery
                self.save()
                return
            time.sleep(10)
        raise RuntimeError("Direct baseline VNet routes did not converge")

    def inspect_traffic(self):
        self.phase("measuring-inspection-and-negative-control")
        before = self.metrics()
        self.http("inspected", True, count=10)
        after = self.metrics()
        self.state["counterSnapshots"] = {"before": before, "after": after}
        if after["synCount"] - before["synCount"] < 20:
            raise RuntimeError("Successful private flows did not produce the expected firewall forwarding evidence")
        for source, destination in (self.nodes[1:], self.nodes[:0:-1]):
            row = extract_guest_result(self.command(source, ping_script(destination["privateIp"])))
            self.state.setdefault("icmp", []).extend(row)
            if len(row) != 1 or not row[0]["ok"]:
                raise RuntimeError("Low-TTL ICMP did not traverse the inspected path")
        try:
            extract_guest_result(self.command(self.nodes[0], prefer_tunnel_script(1, [
                node["prefix"] for node in self.nodes[1:]
            ])))
            self.http("second-tunnel-preferred", True)
        finally:
            extract_guest_result(self.command(self.nodes[0], prefer_tunnel_script(0, [
                node["prefix"] for node in self.nodes[1:]
            ]), restoration=True))
        self.state["activeNegativeControl"] = True
        self.save()
        try:
            extract_guest_result(self.command(self.nodes[0], block_script(True)))
            self.http("firewall-blocked", False)
            if not self.metrics()["ok"]:
                raise RuntimeError("Firewall block unexpectedly broke the IPsec tunnel control plane")
        finally:
            extract_guest_result(self.command(self.nodes[0], block_script(False), restoration=True))
            self.state["activeNegativeControl"] = False
            self.save()
        self.http("restored", True)
        final = self.metrics()
        self.state["counterSnapshots"]["final"] = final
        if not final["ok"] or any(final["tunnelCounters"][str(index)]["outPackets"] <= 0 for index in (0, 1)):
            raise RuntimeError("Encrypted traffic was not observed on both selected gateway tunnels")
        self.state["stages"]["trafficPassed"] = True
        self.save()

    def run(self):
        self.create_groups()
        self.infrastructure()
        self.ready()
        stages = self.state["stages"]
        if not stages.get("baseline"):
            self.phase("proving-direct-routing-baseline")
            self.connections(False)
            self.wait_baseline_routes()
            self.http("direct-baseline", True)
            stages["baseline"] = True
            self.save()
        if not stages.get("vpn"):
            self.configure_vpn()
        self.connections(True)
        self.verify_routes()
        if not stages.get("trafficPassed"):
            self.inspect_traffic()

    def cleanup(self):
        self.phase("cleaning-only-this-run")
        for account in ("A", "B"):
            self.owned(account, allow_absent=True)
        if self.owned("B", allow_absent=True):
            for node in self.nodes[1:]:
                self.arm.delete(self.hub + "/hubVirtualNetworkConnections/" + node["name"], NET, "B", timeout=1800)
            self.arm.delete(self.vpn, NET, "B", timeout=1800)
            self.arm.delete(self.gateway, NET, "B", timeout=3600)
            self.arm.delete(self.site, NET, "B", timeout=1800)
            self.arm.delete(self.hub, NET, "B", timeout=2400)
            self.arm.delete(self.wan, NET, "B", timeout=1800)
        for account in ("B", "A"):
            if self.owned(account, allow_absent=True):
                self.arm.delete(self.groups[account], RG, account, timeout=2400)
        self.state["cleanupVerified"] = True
        (self.directory / ".secrets.json").unlink(missing_ok=True)
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--execute", action="store_true")
    modes.add_argument("--resume-run")
    modes.add_argument("--cleanup-run")
    parser.add_argument("--acknowledge-billing", action="store_true")
    parser.add_argument("--confirm-cleanup", action="store_true")
    args = parser.parse_args()
    config = validate_config(json.loads((ROOT / "config.example.json").read_text()))
    plan = json.loads((ROOT / ".azure/infrastructure-plan.json").read_text())
    if not (args.execute or args.resume_run or args.cleanup_run):
        print(json.dumps({
            "mode": "OFFLINE; no Azure calls", "simulator": "Ubuntu/strongSwan, not Check Point",
            "resources": {"providerVms": 1, "privateCustomerVms": 2, "customerVwanVpnGateway": 1},
            "executionApproved": plan["meta"].get("executionApproved", False),
        }, indent=2))
        return 0
    execution_gate(config, plan, args.acknowledge_billing)
    if args.cleanup_run and not args.confirm_cleanup:
        raise RuntimeError("Fresh authorized cleanup requires --confirm-cleanup")
    if args.execute and plan["meta"]["status"] == "deployed":
        raise RuntimeError("A run already exists; use its explicit --resume-run or --cleanup-run")
    existing = args.resume_run or args.cleanup_run
    if existing:
        if not re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{6}", existing):
            raise ValueError("Invalid run ID")
        directory = ROOT / "results" / existing
        if directory.is_symlink():
            raise ValueError("Refusing symlinked run state")
        state = json.loads((directory / "state.json").read_text())
        if state["runId"] != existing:
            raise ValueError("Saved run ID mismatch")
        validate_resume(state, config)
    else:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        directory = ROOT / "results" / run_id
        directory.mkdir(parents=True, mode=0o700)
        state = {
            "runId": run_id, "configFingerprint": fingerprint(config),
            "accountProfiles": dict(ACCOUNTS), "groups": scopes(run_id), "stages": {},
            "deadlineEpoch": time.time() + config["testWindowSeconds"], "retention": plan["meta"]["retention"],
        }
    with (ROOT / ".execution-lock").open("w") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Another IPsec lab controller is running") from error
        experiment = Experiment(directory, state, config, plan)
        experiment.save()
        plan["meta"]["status"], plan["meta"]["deployedRun"] = "deployed", state["runId"]
        (ROOT / ".azure/infrastructure-plan.json").write_text(json.dumps(plan, indent=2) + "\n")
        failed = False
        try:
            if args.cleanup_run:
                experiment.cleanup()
            else:
                experiment.run()
        except (ArmError, OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
            failed = True
            state["failure"] = experiment.arm.clean(str(error))
            experiment.save()
            print("EXPERIMENT FAILED:", state["failure"], file=sys.stderr, flush=True)
        finally:
            if not args.cleanup_run and state["retention"] == "cleanup":
                try:
                    experiment.cleanup()
                except (ArmError, OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
                    failed = True
                    state["cleanupFailure"] = experiment.arm.clean(str(error))
                    experiment.save()
                    print("CLEANUP FAILED; chargeable resources may remain:", state["cleanupFailure"], file=sys.stderr)
        print("RESULT:", "FAILED" if failed else "PASSED", flush=True)
        print("Resources:", "verified deleted" if state.get("cleanupVerified") else "retained and chargeable", flush=True)
        return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("ERROR:", error, file=sys.stderr)
        sys.exit(1)
