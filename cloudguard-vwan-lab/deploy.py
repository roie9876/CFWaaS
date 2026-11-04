#!/usr/bin/env python3
"""Offline by default. New Azure writes require both persisted and CLI approval."""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "archive/failed-scenarios/cross-tenant-nic-lab"))
from lab import ACCOUNTS, Arm, ArmError, Lab, api_url, sanitize
from app_identity import AppIdentity
from checkpoint import Client, CheckPointError, cme_path, create_policy, gateway_uids
from checkpoint import ingress_body, negative_control, provision_body

NETWORK_API = "2025-05-01"
COMPUTE_API = "2025-04-01"
RESOURCE_API = "2022-09-01"
ROLE_API = "2022-04-01"
READER = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
STAGES = ("foundation", "cloudguard", "activate", "connect", "verify", "cleanup")


def clean(value):
    text = sanitize(str(value))
    for name in ("CHECKPOINT_SIC_KEY", "CHECKPOINT_API_KEY"):
        secret = os.environ.get(name)
        if secret:
            text = text.replace(secret, "[REDACTED]")
            text = text.replace(base64.b64encode(secret.encode()).decode(), "[REDACTED]")
    return text


def azure(*arguments, timeout=5400):
    result = subprocess.run(
        ["az", *arguments, "--output", "json"], capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError("Azure CLI failed: " + clean(result.stderr))
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Azure CLI returned non-JSON output") from error


def group_id(config, account):
    entry = config["provider" if account == "A" else "customer"]
    return f"/subscriptions/{entry['subscriptionId']}/resourceGroups/{entry['resourceGroup']}"


def resource_id(config, account, resource_type, name):
    return group_id(config, account) + "/providers/" + resource_type + "/" + name


def hub_id(config):
    return resource_id(config, "A", "Microsoft.Network/virtualHubs", config["hub"]["name"])


def fingerprint(config):
    values = {key: value for key, value in config.items() if key != "deploymentEnabled"}
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def operator_cidr(value):
    network = ipaddress.ip_network(value, strict=True)
    if network.version != 4 or network.prefixlen != 32 or not network.network_address.is_global:
        raise ValueError("Operator access requires one public IPv4 /32")
    return str(network)


def validate_config(config):
    if config.get("schemaVersion") != 1 or not isinstance(config.get("deploymentEnabled"), bool):
        raise ValueError("Unsupported configuration schema or deployment flag")
    for account, key in (("A", "provider"), ("B", "customer")):
        entry = config[key]
        if (entry["tenantId"], entry["subscriptionId"]) != (
            ACCOUNTS[account]["tenant"], ACCOUNTS[account]["subscription"],
        ):
            raise ValueError("Refusing a tenant/subscription outside the two approved environments")
        if not re.fullmatch(r"rg-cgvwan-[a-z0-9-]{1,50}", entry["resourceGroup"]):
            raise ValueError("Resource groups must use the dedicated rg-cgvwan- namespace")
    if not re.fullmatch(r"mrg-cgvwan-[a-z0-9-]{1,50}", config["provider"]["managedResourceGroup"]):
        raise ValueError("Invalid dedicated managed resource group")
    if config["location"] != "israelcentral":
        raise ValueError("A region change requires a new reviewed plan")
    if not re.fullmatch(r"[0-9a-f]{40}", config["vendor"]["commit"]):
        raise ValueError("Vendor templates require an immutable commit")
    cloudguard = config["cloudguard"]
    if cloudguard["licenseType"] != "Security Enforcement (NGTP)":
        raise ValueError("A different licensing package requires a reviewed SKU/vendor contract")
    if config["management"]["version"] != "R82.10 - Pay As You Go (MGMT25)":
        raise ValueError("A management release/license change requires a new reviewed plan")
    prefixes = {"R8110": "8110.", "R8120": "8120.", "R82": "8200.", "R8210": "8210.", "R8220": "8220."}
    if not cloudguard["imageVersion"].startswith(prefixes[cloudguard["osVersion"]]):
        raise ValueError("CloudGuard image version must match its GAIA release; latest is not allowed")
    if cloudguard["scaleUnit"] not in {"2", "4", "10", "20", "30", "40", "60", "80"}:
        raise ValueError("Invalid integrated NVA scale unit")
    if config["hub"]["minRoutingCapacity"] < 2:
        raise ValueError("Managed hub minimum routing capacity must be at least two")
    hub = ipaddress.ip_network(config["hub"]["addressPrefix"], strict=True)
    if hub.version != 4 or hub.prefixlen > 23:
        raise ValueError("Hub needs an IPv4 /23 or larger")
    networks = [hub, ipaddress.ip_network(config["management"]["addressPrefix"], strict=True)]
    if len(config["spokes"]) < 2 or len({s["name"] for s in config["spokes"]}) != len(config["spokes"]):
        raise ValueError("At least two uniquely named spokes are required")
    for item in [config["management"], *config["spokes"]]:
        network = ipaddress.ip_network(item["addressPrefix"], strict=True)
        subnet = ipaddress.ip_network(item["subnetPrefix"], strict=True)
        private = ipaddress.ip_address(item["privateIp"])
        if network.version != 4 or subnet.version != 4 or private.version != 4:
            raise ValueError("This lab supports IPv4 networks and addresses")
        if not subnet.subnet_of(network) or private not in subnet:
            raise ValueError("Subnet/private IP must belong to its virtual network")
        if int(private) - int(subnet.network_address) < 4 or private == subnet.broadcast_address:
            raise ValueError("VM private IP uses an Azure-reserved subnet address")
        if item is not config["management"]:
            if not re.fullmatch(r"[a-z][a-z0-9-]{0,30}", item["name"]):
                raise ValueError("Invalid spoke name")
            networks.append(network)
    private_ranges = [ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    for index, network in enumerate(networks):
        if not any(network.subnet_of(prefix) for prefix in private_ranges):
            raise ValueError("This reviewed lab uses RFC1918 IPv4 prefixes only")
        if any(network.overlaps(other) for other in networks[index + 1:]):
            raise ValueError("Prefixes within one customer deployment cannot overlap")
    cme_path(config)
    return config


def execution_gate(config, plan, acknowledge_billing):
    if (
        not config["deploymentEnabled"] or plan["meta"]["status"] != "approved"
        or plan["meta"].get("executionApproved") is not True or not acknowledge_billing
    ):
        raise RuntimeError(
            "Deployment is disabled. Preparation approval is not execution approval. "
            "Obtain cost/risk approval, enable both persisted execution flags, and explicitly acknowledge billing."
        )


def connection_body(config, spoke):
    return {"properties": {
        "remoteVirtualNetwork": {"id": resource_id(
            config, "B", "Microsoft.Network/virtualNetworks", "vnet-cgvwan-" + spoke["name"],
        )},
        "enableInternetSecurity": True,
    }}


def discover_nva(config, response):
    candidates = response.get("value")
    if not isinstance(candidates, list):
        raise RuntimeError("Integrated NVA inventory did not return a value array")
    matched = [
        nva for nva in candidates
        if nva.get("properties", {}).get("virtualHub", {}).get("id", "").lower() == hub_id(config).lower()
        and nva.get("properties", {}).get("nvaSku", {}).get("vendor") == "checkpoint"
        and nva.get("name") == config["cloudguard"]["nvaName"]
    ]
    if len(matched) != 1:
        raise RuntimeError("Expected exactly one genuine Check Point NVA in the intended hub")
    nva = matched[0]
    managed_group = (
        "/subscriptions/" + config["provider"]["subscriptionId"]
        + "/resourceGroups/" + config["provider"]["managedResourceGroup"]
    )
    expected = managed_group + "/providers/Microsoft.Network/networkVirtualAppliances/" + nva["name"]
    if nva.get("id", "").lower() != expected.lower():
        raise RuntimeError("NVA is outside the expected publisher-managed resource group")
    if nva["properties"].get("provisioningState") != "Succeeded":
        raise RuntimeError("Integrated NVA is not successfully provisioned")
    nics = nva["properties"].get("virtualApplianceNics")
    if not isinstance(nics, list) or not nics:
        raise RuntimeError("Integrated NVA returned no actual appliance NIC inventory")
    addresses, public, instances = set(), set(), set()
    for nic in nics:
        if not nic.get("instanceName"):
            raise RuntimeError("Appliance NIC has no instanceName")
        instances.add(nic["instanceName"])
        for key in ("privateIpAddress", "publicIpAddress"):
            value = nic.get(key)
            if value:
                parsed = ipaddress.ip_address(value)
                if parsed.version != 4:
                    raise RuntimeError("This lab requires IPv4 appliance addresses")
                addresses.add(str(parsed))
                if key == "publicIpAddress":
                    if not parsed.is_global:
                        raise RuntimeError("NVA public address is not a global IPv4")
                    public.add(str(parsed) + "/32")
    if not addresses or not public or len(instances) < 2:
        raise RuntimeError("NVA HA/management address inventory is incomplete")
    return {
        "id": nva["id"], "addresses": sorted(addresses), "publicSources": sorted(public),
        "instanceCount": len(instances),
    }


def apply_template(config, account, file, parameters, subscription_scope=False, target_group=None):
    subscription = ACCOUNTS[account]["subscription"]
    with tempfile.TemporaryDirectory(prefix="cgvwan-parameters-") as temporary:
        parameter_file = Path(temporary) / "parameters.json"
        parameter_file.write_text(json.dumps({
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {key: {"value": value} for key, value in parameters.items()},
        }))
        parameter_file.chmod(0o600)
        arguments = [
            "deployment", "sub" if subscription_scope else "group", "create",
            "--subscription", subscription, "--name", "cgvwan-" + Path(file).stem,
            "--template-file", str(ROOT / "infra" / file),
            "--parameters", "@" + str(parameter_file),
        ]
        if subscription_scope:
            arguments += ["--location", config["location"]]
        else:
            arguments += ["--resource-group", target_group or config["provider" if account == "A" else "customer"]["resourceGroup"]]
        result = azure(*arguments)
    if result.get("properties", {}).get("provisioningState") != "Succeeded":
        raise RuntimeError("ARM deployment did not report Succeeded")
    return result


def preflight(config):
    blockers = []
    for account in ("A", "B"):
        details = azure("account", "show", "--subscription", ACCOUNTS[account]["subscription"])
        if details.get("id") != ACCOUNTS[account]["subscription"] or details.get("tenantId") != ACCOUNTS[account]["tenant"]:
            raise RuntimeError("Azure CLI authentication does not match the pinned tenant/subscription")
        providers = ["Microsoft.Network", "Microsoft.Compute"]
        if account == "A":
            providers += ["Microsoft.ManagedIdentity", "Microsoft.Solutions"]
        for namespace in providers:
            provider = azure(
                "provider", "show", "--subscription", ACCOUNTS[account]["subscription"],
                "--namespace", namespace,
            )
            if provider.get("registrationState") != "Registered":
                blockers.append(namespace + " must be explicitly registered in account " + account)
            if namespace == "Microsoft.Network":
                types = ("virtualHubs", "networkVirtualAppliances") if account == "A" else ("virtualNetworks",)
                for resource_type in types:
                    resources = [item for item in provider["resourceTypes"] if item["resourceType"] == resource_type]
                    locations = [] if not resources else [
                        value.replace(" ", "").lower() for value in resources[0]["locations"]
                    ]
                    if config["location"] not in locations:
                        blockers.append(resource_type + " is not advertised in the selected region for account " + account)
    sku = azure(
        "rest", "--subscription", ACCOUNTS["A"]["subscription"], "--method", "get", "--url",
        f"https://management.azure.com/subscriptions/{ACCOUNTS['A']['subscription']}"
        "/providers/Microsoft.Network/networkVirtualApplianceSkus/checkpoint?api-version=2023-05-01",
    )["properties"]
    if config["cloudguard"]["imageVersion"] not in sku["availableVersions"]:
        blockers.append("Pinned integrated Check Point gateway image is not currently advertised")
    units = [row for row in sku["availableScaleUnits"] if row["scaleUnit"] == config["cloudguard"]["scaleUnit"]]
    if len(units) != 1:
        blockers.append("Selected integrated scale unit is unavailable")
    for account, size in (("A", config["management"]["vmSize"]), ("B", config["workload"]["vmSize"])):
        sizes = azure(
            "vm", "list-skus", "--subscription", ACCOUNTS[account]["subscription"],
            "--location", config["location"], "--resource-type", "virtualMachines", "--size", size, "--all",
        )
        matching = [entry for entry in sizes if entry["name"] == size]
        if len(matching) != 1 or matching[0].get("restrictions"):
            blockers.append("VM SKU is unavailable/restricted in account " + account)
            continue
        counts = [item["value"] for item in matching[0]["capabilities"] if item["name"] == "vCPUs"]
        if len(counts) != 1:
            blockers.append("VM vCPU requirement could not be verified in account " + account)
            continue
        required = int(counts[0]) * (1 if account == "A" else len(config["spokes"]))
        usage = azure(
            "vm", "list-usage", "--subscription", ACCOUNTS[account]["subscription"],
            "--location", config["location"],
        )
        for quota_name in ("cores", matching[0]["family"]):
            quotas = [row for row in usage if row["name"]["value"].lower() == quota_name.lower()]
            if len(quotas) != 1 or int(quotas[0]["limit"]) - int(quotas[0]["currentValue"]) < required:
                blockers.append("Insufficient/unverified " + quota_name + " quota in account " + account)
    feature = azure(
        "feature", "show", "--subscription", ACCOUNTS["B"]["subscription"],
        "--namespace", "Microsoft.Compute", "--name", "EncryptionAtHost",
    )
    if config["workload"]["encryptionAtHost"] and feature["properties"]["state"] != "Registered":
        blockers.append("Customer Microsoft.Compute/EncryptionAtHost must be explicitly registered before execution")
    image = "checkpoint:check-point-cg-r8210:mgmt-25-blink-gen2:latest"
    terms = azure("vm", "image", "terms", "show", "--subscription", ACCOUNTS["A"]["subscription"], "--urn", image)
    if terms.get("accepted") is not True:
        blockers.append("Check Point management Marketplace terms must be accepted separately")
    return {"blockers": blockers, "gatewayInstances": int(units[0]["instanceCount"]) if units else None,
            "unverified": ["Managed-application purchase/eligibility and regional capacity", "CME Take >=288, license, IAM account, trusted TLS and API credentials"]}


@contextmanager
def connection_identity(config, directory, run_id):
    evidence = directory / ("identity-" + datetime.now(timezone.utc).strftime("%H%M%S") + "-" + uuid.uuid4().hex[:6])
    evidence.mkdir()
    context = Lab(evidence, run_id)
    context.groups = {account: group_id(config, account) for account in ("A", "B")}
    with tempfile.TemporaryDirectory(prefix="cgvwan-app-certificate-") as temporary:
        identity = AppIdentity(context, temporary)
        try:
            identity.provision()
            identity.assign_roles()
            context.arm.token_provider = identity.token
            for account, group in context.groups.items():
                deadline = time.monotonic() + 300
                while True:
                    try:
                        context.arm.request("GET", api_url(group, RESOURCE_API), account)
                        break
                    except ArmError as error:
                        if error.status != 403 or time.monotonic() >= deadline:
                            raise
                        time.sleep(10)
            yield context.arm
        finally:
            context.arm.token_provider = None
            identity.cleanup()


class Deployment:
    def __init__(self, config, state_file, state):
        self.config = config
        self.path = state_file
        self.state = state
        self.arm = Arm(state_file.parent)
        self.tags = {"purpose": "cloudguard-vwan-lab", "labRun": state["runId"]}

    def save(self):
        with tempfile.NamedTemporaryFile(mode="w", dir=self.path.parent, prefix=".state-", delete=False) as file:
            temporary = Path(file.name)
            file.write(json.dumps(self.state, indent=2) + "\n")
        try:
            temporary.replace(self.path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def get(self, resource, account="A", api=NETWORK_API, allow_404=False):
        return self.arm.request("GET", api_url(resource, api), account, allow_404=allow_404)

    def owned_groups(self):
        present = {}
        for account in ("A", "B"):
            status, _, group = self.get(group_id(self.config, account), account, RESOURCE_API, True)
            present[account] = status != 404
            if status != 404 and (
                group.get("tags", {}).get("labRun") != self.state["runId"]
                or group.get("tags", {}).get("purpose") != "cloudguard-vwan-lab"
                or group.get("location") != self.config["location"]
            ):
                raise RuntimeError("Existing resource group does not belong to this exact deployment")
        return present

    def require(self, stage):
        if self.state["stages"].get(stage) is not True:
            raise RuntimeError("Required stage has not completed: " + stage)
        if not all(self.owned_groups().values()):
            raise RuntimeError("Both exact run-owned resource groups are required before continuing")

    def foundation(self):
        self.owned_groups()
        config = self.config
        apply_template(config, "A", "main.bicep", {
            "location": config["location"], "resourceGroupName": config["provider"]["resourceGroup"],
            "wanName": config["hub"]["wanName"], "hubName": config["hub"]["name"],
            "hubAddressPrefix": config["hub"]["addressPrefix"],
            "minRoutingCapacity": config["hub"]["minRoutingCapacity"], "tags": self.tags,
        }, True)
        apply_template(config, "A", "management.bicep", {
            "location": config["location"], "management": config["management"],
            "operatorCidr": self.state["operatorCidr"], "sshPublicKey": self.state["sshPublicKey"],
            "vendorCommit": config["vendor"]["commit"], "tags": self.tags,
        })
        apply_template(config, "B", "customer.bicep", {
            "location": config["location"], "resourceGroupName": config["customer"]["resourceGroup"],
            "spokes": config["spokes"], "vmSize": config["workload"]["vmSize"],
            "adminUsername": config["workload"]["adminUsername"], "sshPublicKey": self.state["sshPublicKey"],
            "image": config["workload"]["image"], "encryptionAtHost": config["workload"]["encryptionAtHost"],
            "hubAddressPrefix": config["hub"]["addressPrefix"],
            "operatorCidr": self.state["operatorCidr"], "tags": self.tags,
        }, True)
        vm_id = resource_id(config, "A", "Microsoft.Compute/virtualMachines", config["management"]["vmName"])
        _, _, vm = self.get(vm_id, api=COMPUTE_API)
        self.state["managementPrincipalId"] = vm["identity"]["principalId"]
        nic_id = vm["properties"]["networkProfile"]["networkInterfaces"][0]["id"]
        if not nic_id.lower().startswith(group_id(config, "A").lower() + "/"):
            raise RuntimeError("Management NIC is outside the dedicated provider group")
        _, _, nic = self.get(nic_id)
        public_id = nic["properties"]["ipConfigurations"][0]["properties"]["publicIPAddress"]["id"]
        if not public_id.lower().startswith(group_id(config, "A").lower() + "/"):
            raise RuntimeError("Management public IP is outside the provider group")
        _, _, public = self.get(public_id)
        self.state["managementPublicIp"] = str(ipaddress.IPv4Address(public["properties"]["ipAddress"]))
        self.management_access([])
        self.state["stages"]["foundation"] = True
        self.save()

    def management_access(self, gateway_sources):
        apply_template(self.config, "A", "modules/management-access.bicep", {
            "location": self.config["location"], "nsgName": self.config["management"]["nsgName"],
            "privateIp": self.config["management"]["privateIp"], "operatorCidr": self.state["operatorCidr"],
            "gatewaySources": gateway_sources,
            "managementSelfSource": operator_cidr(self.state["managementPublicIp"] + "/32"),
            "tags": self.tags,
        })

    def cloudguard(self, sic_key):
        self.require("foundation")
        config = self.config
        _, _, hub = self.get(hub_id(config))
        properties = hub["properties"]
        peers = properties.get("virtualRouterIps")
        if properties.get("provisioningState") != "Succeeded" or not isinstance(peers, list) or len(peers) < 2:
            raise RuntimeError("Managed hub/router must finish provisioning before the CloudGuard deployment")
        deployed = apply_template(config, "A", "cloudguard.bicep", {
            "location": config["location"], "hubName": config["hub"]["name"],
            "hubAsn": properties["virtualRouterAsn"], "hubPeers": peers,
            "cloudguard": config["cloudguard"],
            "managedResourceGroupName": config["provider"]["managedResourceGroup"],
            "sshPublicKey": self.state["sshPublicKey"], "sicKey": sic_key, "tags": self.tags,
        })
        outputs = deployed["properties"]["outputs"]
        self.state["integrationRoleIds"] = {
            key: outputs[key]["value"]
            for key in ("readerRoleAssignmentId", "joinRoleAssignmentId", "joinRoleDefinitionId")
        }
        self.save()
        managed_group = (
            "/subscriptions/" + config["provider"]["subscriptionId"]
            + "/resourceGroups/" + config["provider"]["managedResourceGroup"]
        )
        _, _, inventory = self.get(managed_group + "/providers/Microsoft.Network/networkVirtualAppliances")
        self.state["nva"] = discover_nva(config, inventory)
        if self.state["nva"]["instanceCount"] != self.state["expectedGatewayInstances"]:
            raise RuntimeError("Discovered NVA instance count does not match the selected scale unit")
        public_id = resource_id(config, "A", "Microsoft.Network/publicIPAddresses", config["cloudguard"]["ingressPublicIpName"])
        _, _, public = self.get(public_id)
        self.state["ingressPublicIp"] = str(ipaddress.IPv4Address(public["properties"]["ipAddress"]))
        role_id = managed_group + "/providers/Microsoft.Authorization/roleAssignments/" + str(uuid.uuid5(
            uuid.NAMESPACE_URL, managed_group + self.state["managementPrincipalId"] + READER,
        ))
        self.arm.resource(role_id, ROLE_API, "A", {"properties": {
            "roleDefinitionId": f"/subscriptions/{config['provider']['subscriptionId']}/providers/Microsoft.Authorization/roleDefinitions/{READER}",
            "principalId": self.state["managementPrincipalId"], "principalType": "ServicePrincipal",
        }})
        self.state["managementReaderRoleId"] = role_id
        self.management_access(self.state["nva"]["publicSources"])
        self.state["stages"]["cloudguard"] = True
        self.save()

    def checkpoint_client(self):
        url = os.environ.get("CHECKPOINT_MANAGEMENT_URL")
        if not url:
            raise ValueError("Set CHECKPOINT_MANAGEMENT_URL to the management HTTPS hostname with a trusted certificate")
        return Client(
            url, os.environ.get("CHECKPOINT_API_KEY"), self.state["managementPublicIp"],
            os.environ.get("CHECKPOINT_CA_BUNDLE"),
        )

    def activate(self, sic_key):
        self.require("cloudguard")
        client = self.checkpoint_client()
        client.sensitive += [sic_key, base64.b64encode(sic_key.encode()).decode()]
        client.login()
        try:
            if "policy" not in self.state:
                self.state["policy"] = create_policy(
                    client, self.config, self.state["operatorCidr"], self.state["ingressPublicIp"],
                )
                self.save()
            elif client.mgmt("show-package", {"name": self.state["policy"]["name"]}).get("uid") != self.state["policy"]["uid"]:
                raise RuntimeError("Existing management policy does not match the recorded lab package")
            path = cme_path(self.config)
            if not self.state.get("cmeProvisioned"):
                client.cme(path.format(operation="provision"), provision_body(sic_key, self.state["policy"]["name"]))
                self.state["cmeProvisioned"] = True
                self.save()
            self.state["gatewayUids"] = gateway_uids(
                client, self.state["nva"]["addresses"], self.state["nva"]["instanceCount"],
            )
            if not self.state.get("ingressConfigured"):
                client.cme(path.format(operation="inboundRules"), ingress_body(
                    self.state["operatorCidr"], self.state["ingressPublicIp"],
                ))
                self.state["ingressConfigured"] = True
                self.save()
        finally:
            client.logout()
        apply_template(self.config, "A", "routing-intent.bicep", {
            "hubName": self.config["hub"]["name"], "nvaId": self.state["nva"]["id"],
        })
        self.state["stages"]["activate"] = True
        self.save()

    def connect(self):
        self.require("activate")
        _, _, intent = self.get(hub_id(self.config) + "/routingIntent/routing-intent-cgvwan")
        policies = intent.get("properties", {}).get("routingPolicies", [])
        if (
            len(policies) != 2 or {destination for item in policies for destination in item["destinations"]}
            != {"PrivateTraffic", "Internet"}
            or any(item["nextHop"].lower() != self.state["nva"]["id"].lower() for item in policies)
        ):
            raise RuntimeError("Live Routing Intent no longer targets the verified NVA for both traffic policies")
        with connection_identity(self.config, self.path.parent, self.state["runId"]) as arm:
            for spoke in self.config["spokes"]:
                connection = hub_id(self.config) + "/hubVirtualNetworkConnections/conn-" + spoke["name"]
                arm.resource(connection, NETWORK_API, "A", connection_body(self.config, spoke), auxiliary="B")
        self.state["stages"]["connect"] = True
        self.save()

    def measure(self, label, allowed):
        results = []
        for spoke in self.config["spokes"]:
            other = next(item for item in self.config["spokes"] if item["name"] != spoke["name"])
            tests = [
                {"name": "east-west-" + spoke["name"], "url": "http://" + other["privateIp"] + ":8080/" + uuid.uuid4().hex,
                 "hostname": "vm-cgvwan-" + other["name"], "clientIp": spoke["privateIp"], "blockDuringNegative": True},
                {"name": "internet-egress-" + spoke["name"], "url": "https://www.microsoft.com/", "hostname": None,
                 "blockDuringNegative": False},
            ]
            script = measurement_script(tests)
            output = azure(
                "vm", "run-command", "invoke", "--subscription", ACCOUNTS["B"]["subscription"],
                "--resource-group", self.config["customer"]["resourceGroup"],
                "--name", "vm-cgvwan-" + spoke["name"], "--command-id", "RunShellScript",
                "--scripts", script, timeout=600,
            )
            from run_measurements import extract_results
            results.extend(
                {**result, "phase": label}
                for result in evaluate_measurements(tests, extract_results(output), allowed)
            )
        self.state.setdefault("measurements", []).extend(results)
        self.save()
        if not all(result["passed"] for result in results):
            raise RuntimeError("Measured traffic did not meet expectations in phase " + label)
        return results

    def verify(self):
        self.require("connect")
        client = self.checkpoint_client()
        client.login()
        try:
            negative_control(client, self.state["policy"], self.state["gatewayUids"], self.measure)
        finally:
            client.logout()
        url = "http://" + self.state["ingressPublicIp"] + ":18080/" + uuid.uuid4().hex
        try:
            with urlopen(url, timeout=10) as response:
                body = json.load(response)
        except (URLError, HTTPError, TimeoutError) as error:
            raise RuntimeError("Controlled internet ingress failed: " + clean(error)) from error
        if (
            body.get("hostname") != "vm-cgvwan-" + self.config["spokes"][0]["name"]
            or body.get("client_ip") not in self.state["nva"]["addresses"]
        ):
            raise RuntimeError("Ingress response did not match the intended workload/NVA source-NAT path")
        self.state["stages"]["verify"] = True
        self.state["ingressMeasurement"] = body
        self.state["externalEgressSourceAddressAttested"] = False
        self.save()

    def cleanup(self):
        present = self.owned_groups()
        config = self.config
        if present["A"]:
            status, _, connections = self.get(
                hub_id(config) + "/hubVirtualNetworkConnections", allow_404=True,
            )
            links = [] if status == 404 else connections["value"]
            if links:
                if not present["B"]:
                    raise RuntimeError("Customer group is absent but cross-tenant links survive; manual recovery is required")
                with connection_identity(config, self.path.parent, self.state["runId"]) as arm:
                    for link in links:
                        if not link["id"].lower().startswith(hub_id(config).lower() + "/hubvirtualnetworkconnections/"):
                            raise RuntimeError("Connection inventory is outside the owned hub")
                        arm.delete(link["id"], NETWORK_API, "A", auxiliary="B", timeout=1800)
            self.arm.delete(
                hub_id(config) + "/routingIntent/routing-intent-cgvwan", NETWORK_API, "A", timeout=1800,
            )
            application = resource_id(config, "A", "Microsoft.Solutions/applications", config["cloudguard"]["applicationName"])
            self.arm.delete(application, "2021-07-01", "A", timeout=3600)
            roles = self.state.get("integrationRoleIds", {})
            for name in ("readerRoleAssignmentId", "joinRoleAssignmentId", "joinRoleDefinitionId"):
                if name in roles:
                    if not roles[name].lower().startswith(group_id(config, "A").lower() + "/"):
                        raise RuntimeError("Refusing role cleanup outside the owned provider group")
                    self.arm.delete(roles[name], ROLE_API, "A")
        for account in ("B", "A"):
            if present[account]:
                self.arm.delete(group_id(config, account), RESOURCE_API, account, timeout=3600)
        managed = (
            "/subscriptions/" + config["provider"]["subscriptionId"]
            + "/resourceGroups/" + config["provider"]["managedResourceGroup"]
        )
        status, _, _ = self.get(managed, api=RESOURCE_API, allow_404=True)
        if status != 404:
            raise RuntimeError("Publisher-managed group still exists; cleanup is not complete")
        self.state["cleanupVerified"] = True
        self.save()


def measurement_script(tests):
    from run_measurements import script
    return script(tests)


def evaluate_measurements(tests, measured, allowed):
    if len(measured) != len(tests) or {row["name"] for row in measured} != {row["name"] for row in tests}:
        raise RuntimeError("Guest must report every expected test exactly once")
    if any(not isinstance(test.get("blockDuringNegative"), bool) for test in tests):
        raise RuntimeError("Every test needs an explicit negative-control expectation")
    results = []
    for result in measured:
        test = next(item for item in tests if item["name"] == result["name"])
        if allowed or not test["blockDuringNegative"]:
            body = result.get("body")
            passed = result["ok"] is True and (
                test["hostname"] is None or (
                    isinstance(body, dict) and body.get("hostname") == test["hostname"]
                    and body.get("client_ip") == test["clientIp"]
                )
            )
        else:
            passed = result["ok"] is False and result.get("errorKind") == "timeout"
        results.append({**result, "passed": passed})
    return results


def state_for_execution(arguments, config):
    if arguments.state:
        supplied = Path(arguments.state)
        path = supplied.resolve()
        if path.name != "state.json" or ROOT / "results" not in path.parents or supplied.is_symlink():
            raise ValueError("State must be this package's results/<run>/state.json")
        state = json.loads(path.read_text())
        if not re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{6}", state.get("runId", "")) or path.parent.name != state["runId"]:
            raise ValueError("State run ID does not match its dedicated evidence directory")
        if state.get("configFingerprint") != fingerprint(config):
            raise ValueError("Configuration no longer matches this deployment state")
        if arguments.operator_cidr and operator_cidr(arguments.operator_cidr) != state["operatorCidr"]:
            raise ValueError("Operator source changed; review the access-rule migration before continuing")
        return path, state
    if arguments.stage != "foundation":
        raise ValueError("Non-foundation stages require an explicit --state path")
    if not arguments.operator_cidr or not arguments.ssh_public_key:
        raise ValueError("Foundation needs --operator-cidr and --ssh-public-key")
    public = Path(arguments.ssh_public_key).expanduser().read_text().strip()
    if not re.fullmatch(r"(ssh-ed25519|ssh-rsa) [A-Za-z0-9+/=]+(?: [^\r\n]+)?", public):
        raise ValueError("An OpenSSH public key is required; never provide a private key")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
    directory = ROOT / "results" / run_id
    directory.mkdir(parents=True, mode=0o700)
    state = {
        "runId": run_id, "configFingerprint": fingerprint(config), "stages": {},
        "operatorCidr": operator_cidr(arguments.operator_cidr), "sshPublicKey": public,
    }
    return directory / "state.json", state


def load_inputs():
    config_path = ROOT / "config.json"
    plan_path = ROOT / ".azure/infrastructure-plan.json"
    if not config_path.is_file() or not plan_path.is_file():
        raise RuntimeError("Local config/plan missing. Follow README setup; example plans do not authorize deployment.")
    return validate_config(json.loads(config_path.read_text())), json.loads(plan_path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preflight", action="store_true", help="Read-only Azure checks; never accepts agreements or registers features")
    mode.add_argument("--execute", action="store_true")
    parser.add_argument("--stage", choices=STAGES)
    parser.add_argument("--acknowledge-billing", action="store_true")
    parser.add_argument("--acknowledge-deletion", action="store_true")
    parser.add_argument("--state")
    parser.add_argument("--operator-cidr")
    parser.add_argument("--ssh-public-key")
    arguments = parser.parse_args()
    config, plan = load_inputs()
    if not arguments.execute and not arguments.preflight:
        print(json.dumps({
            "mode": "OFFLINE PLAN; no Azure or Check Point calls",
            "deploymentEnabled": config["deploymentEnabled"], "executionApproved": plan["meta"]["executionApproved"],
            "provider": config["provider"], "customer": config["customer"],
            "stages": STAGES, "workloadVnets": len(config["spokes"]),
            "securityNextHop": "Genuine hub-integrated Check Point managed application, never an external VM substitute",
        }, indent=2))
        return 0
    if arguments.preflight:
        report = preflight(config)
        print(json.dumps(report, indent=2))
        return 1 if report["blockers"] else 0
    if not arguments.stage:
        raise ValueError("--execute requires a single explicit --stage")
    if arguments.stage == "cleanup":
        if not arguments.acknowledge_deletion:
            raise ValueError("Cleanup needs --acknowledge-deletion and an explicit deployment state")
    else:
        execution_gate(config, plan, arguments.acknowledge_billing)
    sic_key = os.environ.get("CHECKPOINT_SIC_KEY", "")
    if arguments.stage in {"cloudguard", "activate"} and not re.fullmatch(r"[A-Za-z0-9]{12,30}", sic_key):
        raise ValueError("CHECKPOINT_SIC_KEY must be 12-30 ASCII alphanumeric characters")
    path, state = state_for_execution(arguments, config)
    deployment = Deployment(config, path, state)
    deployment.save()
    print("State/evidence: " + str(path), flush=True)
    if arguments.stage != "cleanup":
        report = preflight(config)
        if report["blockers"]:
            raise RuntimeError("Read-only preflight blocked execution: " + "; ".join(report["blockers"]))
        state["expectedGatewayInstances"] = report["gatewayInstances"]
        deployment.save()
    if arguments.stage in {"cloudguard", "activate"}:
        getattr(deployment, arguments.stage)(sic_key)
    else:
        getattr(deployment, arguments.stage)()
    print("Completed stage: " + arguments.stage)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, RuntimeError, ArmError, CheckPointError, TimeoutError, OSError, KeyError, subprocess.SubprocessError) as error:
        print("ERROR: " + clean(error), file=sys.stderr)
        sys.exit(1)
