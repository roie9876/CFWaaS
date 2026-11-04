#!/usr/bin/env python3
"""Additive BGP/IPsec revision: mandatory inspection and automatic VNet routes."""

import argparse
import copy
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import ipsec_lab as base
import bgp_guest
from ipsec_guest import bootstrap, block_script, ping_script, tunnel_script

ROOT = Path(__file__).resolve().parent


def validate_settings(settings):
    if (settings["providerAsn"], settings["azureAsn"], settings["providerBgpIp"]) != (
        65010, 65515, "172.26.10.4",
    ) or settings["azureBgpAddressMode"] != "gateway-assigned":
        raise ValueError("BGP identity changes require a reviewed plan")
    if settings["advertiseToCustomer"] != ["0.0.0.0/0"]:
        raise ValueError("Do not advertise customer VNet prefixes back into the hub")
    if settings["acceptedCustomerAggregates"] != ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
        raise ValueError("Approved private customer address boundary changed")
    if settings["testWindowSeconds"] != 10800:
        raise ValueError("Approved testing window changed")
    node = settings["lifecycleProbe"]
    if (node["name"], node["account"], node["prefix"], node["subnetPrefix"], node["privateIp"], node["firewall"]) != (
        "ipsec-wl3", "B", "10.153.0.0/16", "10.153.0.0/24", "10.153.0.4", False,
    ):
        raise ValueError("Lifecycle probe changed outside approved scope")
    return settings


def endpoints(gateway, settings):
    result = []
    bgp = gateway.get("properties", {}).get("bgpSettings", {})
    if bgp.get("asn") != settings["azureAsn"]:
        raise RuntimeError("Actual gateway ASN differs from the authorized BGP peer")
    rows = bgp.get("bgpPeeringAddresses", [])
    for instance in ("Instance0", "Instance1"):
        matches = [row for row in rows if row.get("ipconfigurationId") == instance]
        if len(matches) != 1:
            raise RuntimeError("Actual gateway instance is missing")
        addresses = matches[0].get("defaultBgpIpAddresses", [])
        if len(addresses) != 1 or not ipaddress.IPv4Address(addresses[0]).is_private:
            raise RuntimeError("Actual gateway instance lacks a usable assigned BGP address")
        address = addresses[0]
        public = sorted({
            value for value in matches[0].get("tunnelIpAddresses", [])
            if ipaddress.ip_address(value).version == 4 and ipaddress.ip_address(value).is_global
        })
        if len(public) != 1:
            raise RuntimeError("Actual gateway instance lacks one public VPN endpoint")
        result.append({"instance": instance, "publicIp": public[0], "azureBgpIp": address})
    if len({row["publicIp"] for row in result}) != 2:
        raise RuntimeError("Gateway instances do not have distinct tunnel endpoints")
    return result


def connection_body(site, default, inspect, key, peers):
    body = base.vpn_body(site, default, inspect, key)
    properties = body["properties"]
    properties.pop("enableBgp", None)
    properties["routingConfiguration"]["propagatedRouteTables"]["labels"] = ["ipsec-bgp-inspection"]
    link = properties["vpnLinkConnections"][0]["properties"]
    link["enableBgp"] = True
    link["useLocalAzureIpAddress"] = False
    return body


def approval_gate(config, settings, plan):
    meta = plan["meta"]
    if meta.get("status") not in {"approved", "deployed"} or not meta.get("executionApproved"):
        raise RuntimeError("This BGP revision has not been authorized")
    if meta.get("accountProfiles") != dict(base.ACCOUNTS):
        raise RuntimeError("Account profiles differ from the authorized revision")
    if meta.get("configFingerprint") != base.fingerprint({"lab": config, "bgp": settings}):
        raise RuntimeError("Revision configuration differs from the authorized plan")
    if meta.get("retention") != "keep" or meta.get("automaticCoreCleanup") is not False:
        raise RuntimeError("Core resources must be retained for debugging; no automatic teardown")

def validate_references(state, config):
    base.validate_resume(state, config)
    for node in config["nodes"]:
        group = state["groups"][node["account"]]
        expected_vm = group + "/providers/Microsoft.Compute/virtualMachines/vm-" + node["name"]
        if not base.same_id(state["vmIds"].get(node["name"]), expected_vm):
            raise ValueError("Saved VM reference is outside the exact lab scope")
        for field, kind, prefix in (
            ("vnetId", "virtualNetworks", "vnet-"),
            ("nicId", "networkInterfaces", "nic-"),
            ("nsgId", "networkSecurityGroups", "nsg-"),
        ):
            expected = group + "/providers/Microsoft.Network/" + kind + "/" + prefix + node["name"]
            if not base.same_id(state["networks"][node["name"]].get(field), expected):
                raise ValueError("Saved network reference is outside the exact lab scope")


class Revision(base.Experiment):
    def __init__(self, directory, state, config, plan, settings):
        super().__init__(directory, state, config, plan)
        self.settings = settings
        self.gateway = self.groups["B"] + "/providers/Microsoft.Network/vpnGateways/vpng-ipsec-bgp"
        self.site = self.groups["B"] + "/providers/Microsoft.Network/vpnSites/site-ipsec-bgp"
        self.vpn = self.gateway + "/vpnConnections/provider-bgp"
        self.inspect = self.hub + "/hubRouteTables/rt-ipsec-bgp-inspect"

    def connection_id(self, node):
        return self.hub + "/hubVirtualNetworkConnections/bgp-" + node["name"]

    def guest(self, script, restoration=False):
        return base.extract_guest_result(self.command(self.nodes[0], script, restoration=restoration))[0]

    def bgp(self):
        return self.guest(bgp_guest.metrics_script(self.state["gatewayEndpoints"]))

    def connect(self, node):
        self.put(self.connection_id(node), {"properties": {
            "remoteVirtualNetwork": {"id": self.state["networks"][node["name"]]["vnetId"]},
            "enableInternetSecurity": True,
            "routingConfiguration": base.routing(self.default, self.inspect, inspect=True),
        }})

    def check_existing(self):
        self.phase("checking-retained-lab-ownership")
        for account in ("A", "B"):
            self.owned(account)
        for node in self.nodes:
            rid = self.state["vmIds"][node["name"]]
            value = self.get(rid, node["account"], base.VM)[2]
            if value.get("properties", {}).get("provisioningState") != "Succeeded":
                raise RuntimeError("Retained VM is not provisioned successfully")
        if self.get(self.hub)[2].get("properties", {}).get("provisioningState") != "Succeeded":
            raise RuntimeError("Retained customer hub is not ready")
        self.ready()

    def generic_lab_nsg(self, node):
        for name, priority, protocol, port in (
            ("AllowLabHttp", 100, "Tcp", "8080"), ("AllowLabIcmp", 110, "Icmp", "*"),
        ):
            self.put(self.state["networks"][node["name"]]["nsgId"] + "/securityRules/" + name, {"properties": {
                "priority": priority, "direction": "Inbound", "access": "Allow", "protocol": protocol,
                "sourceAddressPrefixes": self.settings["acceptedCustomerAggregates"],
                "sourcePortRange": "*", "destinationAddressPrefix": "*", "destinationPortRange": port,
            }})

    def endpoint_health(self, nodes=None):
        for node in nodes or self.nodes[1:]:
            rows = base.extract_guest_result(self.command(node, bgp_guest.local_health_script()))
            if len(rows) != 1 or not rows[0]["ok"] or rows[0].get("hostname") != "vm-" + node["name"]:
                raise RuntimeError("Local workload service is unhealthy; cannot call a network denial a pass")

    def preview(self, name, parameters):
        self.owned("B")
        with tempfile.TemporaryDirectory(prefix="ipsec-bgp-whatif-") as temporary:
            path = Path(temporary) / "parameters.json"
            path.write_text(json.dumps({
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
                "contentVersion": "1.0.0.0", "parameters": {key: {"value": value} for key, value in parameters.items()},
            }))
            path.chmod(0o600)
            args = [
                "az", "deployment", "group", "what-if", "--subscription", base.ACCOUNTS["B"]["subscription"],
                "--resource-group", self.groups["B"].rsplit("/", 1)[1],
                "--template-file", str(ROOT / "infra" / (name + ".bicep")), "--parameters", "@" + str(path),
                "--no-pretty-print", "--result-format", "ResourceIdOnly", "--output", "json",
            ]
            result = subprocess.run(args, capture_output=True, text=True, timeout=300)
            if result.returncode:
                raise RuntimeError("Read-only what-if failed: " + self.arm.clean(result.stderr))
            value = json.loads(result.stdout)
            unsafe = [row for row in value.get("changes", []) if row["changeType"] not in {"Create", "NoChange", "Ignore"}]
            if unsafe:
                raise RuntimeError("What-if would modify/delete referenced infrastructure; refusing deployment")
            self.state.setdefault("whatIf", {})[name] = value
            self.save()

    def establish_inspection_only_connections(self):
        self.phase("removing-native-bypass-from-the-test-design")
        self.put(self.inspect, {"properties": {"labels": ["ipsec-bgp-inspection"], "routes": []}})
        for node in self.nodes[1:]:
            self.generic_lab_nsg(node)
            self.connect(node)
        self.endpoint_health()
        self.http("no-vpn-route-fail-closed", False)
        self.state["stages"]["inspectionOnly"] = True
        self.save()

    def gateway_and_vpn(self):
        stages = self.state["stages"]
        tags = {**self.tags, "labRevision": self.state["revisionId"]}
        if not stages.get("gateway"):
            self.phase("creating-only-the-new-bgp-vpn-gateway")
            status, _, current = self.get(self.gateway, allow_404=True)
            if status != 404 and current.get("tags", {}).get("labRevision") != self.state["revisionId"]:
                raise RuntimeError("Refusing a VPN gateway owned by another revision")
            parameters = {"location": base.REGION, "hubName": "vhub-ipsec", "tags": tags}
            if status == 404:
                self.preview("bgp-gateway", parameters)
                operation = self.begin_deployment("bgp-gateway", "B", parameters, "ipsec-bgp-gateway")
                self.state["gatewayOperation"] = operation
                self.save()
            else:
                operation = self.state.get("gatewayOperation")
                if not operation:
                    raise RuntimeError("Existing gateway has no recorded operation; explicit recovery is required")
            self.finish_deployment(operation)
            stages["gateway"] = True
            self.save()
        peers = endpoints(self.get(self.gateway)[2], self.settings)
        self.phase("configuring-bgp-vpn-site-and-link")
        self.state["gatewayEndpoints"] = peers
        pip = self.get(self.state["networks"]["ipsec-fw"]["publicIpId"], "A")[2]["properties"]["ipAddress"]
        self.state["providerPublicIp"] = pip
        self.put(self.site, {"location": base.REGION, "tags": tags, "properties": {
            "virtualWan": {"id": self.wan},
            "addressSpace": {"addressPrefixes": [self.nodes[0]["prefix"]]},
            "vpnSiteLinks": [{
                "name": "provider", "properties": {
                    "ipAddress": pip,
                    "linkProperties": {"linkProviderName": "lab-provider", "linkSpeedInMbps": 10},
                    "bgpProperties": {"asn": self.settings["providerAsn"], "bgpPeeringAddress": self.settings["providerBgpIp"]},
                },
            }],
        }})
        self.put(self.vpn, connection_body(self.site, self.default, self.inspect, self.key, peers))
        self.put(self.state["networks"]["ipsec-fw"]["nsgId"] + "/securityRules/AllowManagedVpnEndpoints", {"properties": {
            "priority": 100, "direction": "Inbound", "access": "Allow", "protocol": "Udp",
            "sourceAddressPrefixes": [row["publicIp"] for row in peers], "sourcePortRange": "*",
            "destinationAddressPrefix": "*", "destinationPortRanges": ["500", "4500"],
        }}, "A")
        if not stages.get("guestConfigured"):
            self.phase("configuring-two-ipsec-bgp-peers-default-only")
            script = tunnel_script(
                self.nodes[0]["privateIp"], pip, [row["publicIp"] for row in peers],
                self.settings["acceptedCustomerAggregates"], static_routes=False, allow_within_prefix=True,
            )
            base.require_marker(self.command(self.nodes[0], script, [{"name": "psk", "value": self.key}]), "IPSEC_CONFIGURED")
            self.guest(bgp_guest.configure_script(self.settings, self.nodes[0]["privateIp"], peers))
            stages["guestConfigured"] = True
            self.save()

    def wait_peers(self):
        self.phase("waiting-for-both-ike-and-bgp-sessions")
        deadline = time.monotonic() + self.remaining(900)
        while time.monotonic() < deadline:
            crypto, bgp = self.metrics(), self.bgp()
            self.state["latestPeerMetrics"] = {"ipsec": crypto, "bgp": bgp}
            self.save()
            if crypto["ok"] and bgp["ok"] and all(node["prefix"] in bgp["learnedPrefixes"] for node in self.nodes[1:]):
                return
            time.sleep(10)
        raise RuntimeError("Two IKE/BGP peers and customer-prefix learning did not converge")

    def route_evidence(self, nodes=None):
        self.phase("proving-inspection-versus-delivery-route-contexts")
        targets = nodes or self.nodes[1:]
        deadline = time.monotonic() + self.remaining(600)
        while time.monotonic() < deadline:
            inspection, delivery = self.routes(self.inspect), self.routes(self.default)
            checks = []
            try:
                for node in targets:
                    incoming = base.winning_route(inspection, node["privateIp"])
                    returned = base.winning_route(delivery, node["privateIp"])
                    vpn = base.has_next_hop(incoming, [self.vpn, self.gateway]) or "VPN" in incoming.get("nextHopType", "").upper()
                    direct = base.has_next_hop(returned, [
                        self.connection_id(node), self.state["networks"][node["name"]]["vnetId"],
                    ])
                    checks.append(vpn and "0.0.0.0/0" in incoming["addressPrefixes"] and direct)
            except RuntimeError:
                checks = []
            self.state["lastRouteEvidence"] = {"inspection": inspection, "delivery": delivery, "checks": checks}
            self.save()
            if len(checks) == len(targets) and all(checks):
                return
            time.sleep(10)
        raise RuntimeError("Protected destinations have a bypass, missing route or wrong return context")

    def wait_default_withdrawn(self):
        deadline = time.monotonic() + self.remaining(600)
        while time.monotonic() < deadline:
            routes = self.routes(self.inspect)
            if not any("0.0.0.0/0" in row["addressPrefixes"] for row in base.route_rows(routes)):
                self.state.setdefault("withdrawalEvidence", []).append(routes)
                self.save()
                return
            time.sleep(10)
        raise RuntimeError("BGP default route did not withdraw")

    def test_inspection(self):
        self.phase("testing-mandatory-inspection-not-native-transit")
        before = self.metrics()
        self.http("inspected-bgp", True, count=10)
        after = self.metrics()
        self.state["forwardingEvidence"] = {"before": before, "after": after}
        if after["synCount"] - before["synCount"] < 20:
            raise RuntimeError("Protected HTTP lacks provider firewall forwarding evidence")
        for source, destination in (self.nodes[1:], self.nodes[:0:-1]):
            rows = base.extract_guest_result(self.command(source, ping_script(destination["privateIp"])))
            self.state.setdefault("icmp", []).extend(rows)
            if len(rows) != 1 or not rows[0]["ok"]:
                raise RuntimeError("Low-TTL inspected ICMP did not fully succeed")
        self.endpoint_health()
        try:
            self.guest(block_script(True))
            self.state["negativeControl"] = "forwarding-blocked"
            self.save()
            self.http("firewall-drop-no-bypass", False)
            if not self.metrics()["ok"] or not self.bgp()["ok"]:
                raise RuntimeError("Firewall-drop control unexpectedly broke IKE or BGP")
            self.endpoint_health()
        finally:
            self.guest(block_script(False), restoration=True)
            self.state["negativeControl"] = None
            self.save()
        self.http("firewall-restored", True)
        try:
            self.guest(bgp_guest.default_script(self.state["gatewayEndpoints"], False))
            self.state["negativeControl"] = "default-withdrawn"
            self.save()
            self.wait_default_withdrawn()
            self.http("bgp-withdraw-no-bypass", False)
            self.endpoint_health()
        finally:
            self.guest(bgp_guest.default_script(self.state["gatewayEndpoints"], True), restoration=True)
            self.state["negativeControl"] = None
            self.save()
        self.wait_peers()
        self.route_evidence()
        self.http("bgp-restored", True)
        try:
            self.guest(bgp_guest.tunnel_control_script(False))
            self.state["negativeControl"] = "ipsec-stopped"
            self.save()
            self.wait_default_withdrawn()
            self.http("tunnels-down-no-bypass", False)
            self.endpoint_health()
        finally:
            self.guest(bgp_guest.tunnel_control_script(True), restoration=True)
            self.state["negativeControl"] = None
            self.save()
        self.wait_peers()
        self.route_evidence()
        self.http("tunnels-restored", True)
        self.state["stages"]["inspectionPassed"] = True
        self.save()

    def pair(self, source, destination, phase):
        targets = [{"test": source["name"] + "-to-" + destination["name"], "host": destination["privateIp"],
                    "port": 8080, "path": "/" + phase}]
        rows = base.extract_guest_result(self.command(source, base.request_script(targets)))
        if len(rows) != 1 or rows[0].get("test") != targets[0]["test"] or not base.http_passed(source, destination, rows[0], True):
            raise RuntimeError("Dynamic VNet traffic did not traverse the expected private endpoints")
        self.state.setdefault("lifecycleHttp", []).append({**rows[0], "phase": phase, "passed": True})
        self.save()

    def lifecycle(self):
        self.phase("proving-new-vnet-add-remove-without-firewall-config-changes")
        before = self.bgp()["configurationDigests"]
        node = self.settings["lifecycleProbe"]
        stages = self.state["stages"]
        if not stages.get("probeCreated"):
            parameters = {
                "location": base.REGION, "nodes": [node],
                "labPrefixes": self.settings["acceptedCustomerAggregates"], "tags": self.tags,
            }
            self.preview("networks", parameters)
            result = self.finish_deployment(self.begin_deployment("networks", "B", parameters, "ipsec-bgp-lifecycle-network"))
            self.state["networks"].update({row["name"]: row for row in result["resources"]})
            definition = {
                **node, "nicId": self.state["networks"][node["name"]]["nicId"],
                "size": self.config["workloadSize"], "cloudInit": bootstrap(False),
            }
            parameters = {
                "location": base.REGION, "nodes": [definition], "sshPublicKey": self.state["sshPublicKey"],
                "image": self.config["image"], "tags": self.tags,
            }
            self.preview("compute", parameters)
            result = self.finish_deployment(self.begin_deployment("compute", "B", parameters, "ipsec-bgp-lifecycle-compute"))
            self.state["vmIds"].update({row["name"]: row["id"] for row in result["vmIds"]})
            stages["probeCreated"] = True
            self.save()
        self.connect(node)
        self.command(node, ["set -eu", "cloud-init status --wait", "systemctl is-active ipsec-lab-http.service"])
        deadline = time.monotonic() + self.remaining(600)
        while time.monotonic() < deadline:
            metrics = self.bgp()
            if node["prefix"] in metrics["learnedPrefixes"]:
                break
            time.sleep(10)
        else:
            raise RuntimeError("New VNet prefix was not learned automatically over BGP")
        self.route_evidence([node])
        for original in self.nodes[1:]:
            self.pair(original, node, "new-vnet")
            self.pair(node, original, "new-vnet")
        added = self.bgp()
        if added["configurationDigests"] != before:
            raise RuntimeError("Firewall configuration changed during VNet onboarding")
        self.state["lifecycleAddEvidence"] = added
        self.arm.delete(self.connection_id(node), base.NET, "B", timeout=1800)
        deadline = time.monotonic() + self.remaining(600)
        while time.monotonic() < deadline:
            removed = self.bgp()
            if node["prefix"] not in removed["learnedPrefixes"]:
                break
            time.sleep(10)
        else:
            raise RuntimeError("Deleted VNet attachment prefix did not withdraw from the firewall")
        if removed["configurationDigests"] != before:
            raise RuntimeError("Firewall configuration changed during VNet removal")
        self.state["lifecycleRemoveEvidence"] = removed
        self.save()
        self.owned("B")
        self.arm.delete(self.state["vmIds"][node["name"]], base.VM, "B", timeout=1800)
        self.arm.delete(self.state["networks"][node["name"]]["nicId"], base.NET, "B", timeout=900)
        self.arm.delete(self.state["networks"][node["name"]]["vnetId"], base.NET, "B", timeout=900)
        self.arm.delete(self.state["networks"][node["name"]]["nsgId"], base.NET, "B", timeout=900)
        disk = self.groups["B"] + "/providers/Microsoft.Compute/disks/osdisk-" + node["name"]
        self.arm.delete(disk, "2025-01-02", "B", timeout=900)
        self.http("original-vnets-after-lifecycle-removal", True)
        stages["lifecyclePassed"] = True
        self.state["probeCleanupVerified"] = True
        self.save()

    def run(self):
        self.check_existing()
        if not self.state["stages"].get("inspectionOnly"):
            self.establish_inspection_only_connections()
        self.gateway_and_vpn()
        self.wait_peers()
        self.route_evidence()
        if not self.state["stages"].get("inspectionPassed"):
            self.test_inspection()
        if not self.state["stages"].get("lifecyclePassed"):
            self.lifecycle()
        self.state["passed"] = True
        self.state["retainedCoreResources"] = True
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true")
    mode.add_argument("--resume")
    args = parser.parse_args()
    config = base.validate_config(json.loads((ROOT / "config.example.json").read_text()))
    settings = validate_settings(json.loads((ROOT / "bgp.example.json").read_text()))
    path = ROOT / ".azure/bgp-plan.json"
    plan = json.loads(path.read_text())
    if not (args.execute or args.resume):
        print(json.dumps({"mode": "OFFLINE", "executionApproved": plan["meta"].get("executionApproved", False),
                          "advertisedRoute": "0.0.0.0/0 only", "automaticCoreCleanup": False}, indent=2))
        return 0
    approval_gate(config, settings, plan)
    parent = plan["meta"]["parentRun"]
    if not re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{6}", parent):
        raise ValueError("Invalid parent lab run")
    parent_dir = ROOT / "results" / parent
    original = json.loads((parent_dir / "state.json").read_text())
    validate_references(original, config)
    if args.resume:
        if not re.fullmatch(r"bgp-\d{8}-\d{6}", args.resume):
            raise ValueError("Invalid revision identifier")
        directory = parent_dir / args.resume
        if directory.is_symlink():
            raise ValueError("Refusing symlinked revision state")
        state = json.loads((directory / "state.json").read_text())
        validate_references(state, config)
        if state.get("revisionId") != args.resume or state.get("revisionFingerprint") != base.fingerprint(settings):
            raise ValueError("Saved revision scope/configuration differs")
    else:
        if plan["meta"]["status"] == "deployed":
            raise RuntimeError("A revision already exists; use its explicit --resume identifier")
        revision = "bgp-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        directory = parent_dir / revision
        directory.mkdir(mode=0o700)
        state = {key: copy.deepcopy(original[key]) for key in (
            "runId", "groups", "accountProfiles", "configFingerprint", "networks", "vmIds", "sshPublicKey",
        )}
        state.update({
            "revisionId": revision, "revisionFingerprint": base.fingerprint(settings),
            "stages": {}, "deadlineEpoch": time.time() + settings["testWindowSeconds"], "retention": "keep",
        })
    with (ROOT / ".execution-lock").open("w") as lock:
        import fcntl
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Another lab controller is active") from error
        experiment = Revision(directory, state, config, plan, settings)
        experiment.save()
        plan["meta"]["status"], plan["meta"]["revisionId"] = "deployed", state["revisionId"]
        path.write_text(json.dumps(plan, indent=2) + "\n")
        try:
            experiment.run()
        except (base.ArmError, OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
            state["failure"] = experiment.arm.clean(str(error))
            experiment.save()
            print("BGP REVISION FAILED:", state["failure"], file=sys.stderr, flush=True)
            print("Core lab retained for debugging. No automatic deletion.", flush=True)
            return 1
        print("BGP REVISION PASSED: mandatory inspection and dynamic VNet lifecycle verified. Core lab retained.", flush=True)
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("ERROR:", error, file=sys.stderr)
        sys.exit(1)
