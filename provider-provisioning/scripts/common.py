"""Offline-safe scope validation and explicit Azure CLI execution."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / ".azure/infrastructure-plan.json"
CUSTOMER_VPN_GATEWAY_SKUS = ("VpnGw1AZ", "VpnGw2AZ", "VpnGw3AZ", "VpnGw4AZ", "VpnGw5AZ")
WORKLOAD_VM_PROFILES = ("standard", "high-performance")
logger = logging.getLogger("faas.scripts")


def customer_sizing(config: dict) -> dict:
    bandwidth = config.get("routingApplianceBandwidthGbps", 10)
    if type(bandwidth) is not int or bandwidth != 10:
        raise ValueError("Only the verified customer Routing Appliance bandwidth of 10 Gbps is supported")
    result = {"routingApplianceBandwidthGbps": bandwidth}
    for key in ("customerIngressVpnGatewaySku", "customerDeliveryVpnGatewaySku"):
        sku = config.get(key, "VpnGw1AZ")
        if not isinstance(sku, str) or sku not in CUSTOMER_VPN_GATEWAY_SKUS:
            raise ValueError(f"{key} must be a supported BGP-capable AZ SKU")
        result[key] = sku
    profile = config.get("workloadVmProfile", "standard")
    if profile not in WORKLOAD_VM_PROFILES:
        raise ValueError("workloadVmProfile must be standard or high-performance")
    result["workloadVmProfile"] = profile
    return result


def cli(*args: str) -> dict:
    result = subprocess.run(["az", *args, "--output", "json", "--only-show-errors"],
                            check=True, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout.strip() else {}


def load_private(path: str | Path) -> dict:
    path = Path(path).resolve()
    if not path.is_relative_to(ROOT / ".local"):
        raise ValueError("Configuration/journal must live in provider-provisioning/.local")
    stat = path.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError("Private configuration must be owned by this user with mode 0600")
    return json.loads(path.read_text())


def uuid_value(value: str) -> str:
    if str(uuid.UUID(value)) != value:
        raise ValueError("Expected canonical UUID")
    return value


def group_id(subscription: str, group: str) -> str:
    uuid_value(subscription)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._()-]{0,89}", group):
        raise ValueError("Invalid resource group name")
    return f"/subscriptions/{subscription}/resourceGroups/{group}"


def validate_config(config: dict, plan: dict | None = None) -> dict:
    if "maxEnvironments" in config:
        logger.warning("Legacy maxEnvironments configuration is ignored")
    plan = plan or json.loads(PLAN.read_text())
    if plan["meta"]["status"] != "approved":
        raise ValueError("Infrastructure plan is not approved")
    for side in ("provider", "customer"):
        value, approved = config[side], plan["scope"][side]
        for field in ("tenantId", "subscriptionId"):
            uuid_value(value[field])
            if value[field] != approved[field]:
                raise ValueError(f"{side} {field} differs from approved private plan")
        for field, prefix in (
            (("controlPlaneResourceGroup" if side == "provider" else "bootstrapResourceGroup"),
             ("controlPlaneGroupPrefix" if side == "provider" else "bootstrapGroupPrefix")),
            ("dataPlaneResourceGroup", "dataPlaneGroupPrefix"),
        ):
            group_id(value["subscriptionId"], value[field])
            if not value[field].startswith(approved[prefix]):
                raise ValueError(f"{side} {field} must use approved prefix")
            if value[field] == plan["scope"]["oldLabGroup"]:
                raise ValueError("Old lab is not a deployment target")
    if config["provider"]["tenantId"] == config["customer"]["tenantId"]:
        raise ValueError("This lab requires separate tenants")
    if config["provider"]["subscriptionId"] == config["customer"]["subscriptionId"]:
        raise ValueError("This lab requires separate subscriptions")
    if config["provider"]["controlPlaneResourceGroup"] == config["provider"]["dataPlaneResourceGroup"]:
        raise ValueError("Control and dataplane groups must be separate")
    if config["customer"]["bootstrapResourceGroup"] == config["customer"]["dataPlaneResourceGroup"]:
        raise ValueError("Customer bootstrap and dataplane groups must be separate")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{2,31}", config["runId"]):
        raise ValueError("Invalid ownership runId")
    customer_sizing(config)
    return config


def verify_account(context: dict) -> None:
    account = cli("account", "show", "--subscription", context["subscriptionId"])
    if account.get("id") != context["subscriptionId"] or account.get("tenantId") != context["tenantId"]:
        raise ValueError("Azure account/subscription/tenant does not match approved context")
    if account.get("state") != "Enabled":
        raise ValueError("Subscription is not enabled")


def operator_cidr(value: str) -> str:
    network = ipaddress.ip_network(value, strict=True)
    if network.version != 4 or network.prefixlen != 32 or not network.network_address.is_global:
        raise ValueError("SCM bootstrap requires a globally routable public IPv4 /32")
    return str(network)


def public_key(value: str) -> str:
    import base64
    import struct
    parts = value.strip().split()
    if len(parts) < 2 or parts[0] not in {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"}:
        raise ValueError("Expected an OpenSSH public key, never a private key")
    blob = base64.b64decode(parts[1], validate=True)
    length = struct.unpack(">I", blob[:4])[0]
    if blob[4:4 + length].decode("ascii") != parts[0] or len(blob) <= 4 + length:
        raise ValueError("Invalid OpenSSH public-key encoding")
    return value.strip()


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def config_digest(config: dict) -> str:
    mutable = {
        "deploymentOperatorCidr", "nvaSshPublicKey", "workloadSshPublicKey",
        "maxEnvironments", "apiApplicationId", "consentRedirectUri", "cleanupOldLabRun",
        "routingApplianceBandwidthGbps", "customerIngressVpnGatewaySku", "customerDeliveryVpnGatewaySku",
        "workloadVmProfile",
    }
    return digest({key: value for key, value in config.items() if key not in mutable})


def save_private(path: Path, value: object) -> None:
    path = path.resolve()
    if not path.is_relative_to(ROOT / ".local") or path.is_symlink():
        raise ValueError("Private output must be in project .local")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())


def compile_bicep(name: str) -> bytes:
    return subprocess.run(["az", "bicep", "build", "--file", str(ROOT / "infra" / name), "--stdout"],
                          check=True, capture_output=True).stdout
