import hashlib
import ipaddress
import json
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .admin_access import normalize_admin_sources

def environment_resource_group_name(group_id: str) -> str:
    if str(UUID(group_id)) != group_id:
        raise ValueError("Invalid group ID")
    return "rg-faas-env-" + group_id


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Endpoint(StrictModel):
    publicIp: str
    bgpAddress: str
    asn: int = Field(ge=64512, le=65534)
    # Second instance of an active-active gateway; both fields or neither.
    secondaryPublicIp: str | None = None
    secondaryBgpAddress: str | None = None

    @field_validator("publicIp", "secondaryPublicIp")
    @classmethod
    def global_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        ip = ipaddress.IPv4Address(value)
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            raise ValueError("Expected a global unicast IPv4 address")
        return str(ip)

    @field_validator("bgpAddress", "secondaryBgpAddress")
    @classmethod
    def private_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        ip = ipaddress.IPv4Address(value)
        if not any(ip in ipaddress.IPv4Network(network)
                   for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
            raise ValueError("Expected an RFC1918 IPv4 address")
        return str(ip)

    @model_validator(mode="after")
    def secondary_pair(self) -> "Endpoint":
        if (self.secondaryPublicIp is None) != (self.secondaryBgpAddress is None):
            raise ValueError("Secondary public IP and BGP address must be provided together")
        return self


class RoutingAddress(StrictModel):
    routingApplianceIp: str

    @field_validator("routingApplianceIp")
    @classmethod
    def private_ip(cls, value: str) -> str:
        return Endpoint.private_ip(value)


CHECKPOINT_TOPOLOGIES = {"checkpoint-byol": "single", "checkpoint-vmss": "vmss"}
# Mirrors scripts/common.py CUSTOMER_VPN_GATEWAY_SKUS; the service must not import scripts.
PROVIDER_VPN_GATEWAY_SKUS = ("VpnGw1AZ", "VpnGw2AZ", "VpnGw3AZ", "VpnGw4AZ", "VpnGw5AZ")
DEFAULT_PROVIDER_VPN_GATEWAY_SKU = "VpnGw1AZ"


class EnvironmentRequest(StrictModel):
    region: Literal["eastus2"] = "eastus2"
    tier: Literal["lab"] = "lab"
    mode: Literal["proof", "network"] = "proof"
    customerIngress: Endpoint | None = None
    customerDelivery: Endpoint | None = None
    firewallType: Literal["ubuntu", "checkpoint-byol", "checkpoint-vmss"] = "ubuntu"
    adminAllowedSources: list[str] = Field(default_factory=list, max_length=16)
    providerVpnGatewaySku: Literal["VpnGw1AZ", "VpnGw2AZ", "VpnGw3AZ", "VpnGw4AZ", "VpnGw5AZ"] = "VpnGw1AZ"

    @field_validator("adminAllowedSources", mode="before")
    @classmethod
    def admin_sources(cls, value: object) -> list[str]:
        return normalize_admin_sources(value)

    @model_validator(mode="after")
    def endpoints_required(self) -> "EnvironmentRequest":
        if self.adminAllowedSources and self.firewallType not in CHECKPOINT_TOPOLOGIES:
            raise ValueError("Public admin sources require Check Point")
        if self.providerVpnGatewaySku != DEFAULT_PROVIDER_VPN_GATEWAY_SKU and self.mode != "network":
            raise ValueError("Provider VPN gateway sizing requires network mode")
        if bool(self.customerIngress) != bool(self.customerDelivery):
            raise ValueError("Both customer endpoints are required together")
        if self.mode == "network" and not self.customerIngress:
            raise ValueError("Network mode requires both customer endpoints")
        return self

    def stored_fields(self) -> dict:
        excluded = {"firewallType"} if self.firewallType == "ubuntu" else set()
        if not self.adminAllowedSources:
            excluded.add("adminAllowedSources")
        # Omitting the default keeps digests of requests stored before this field existed.
        if self.providerVpnGatewaySku == DEFAULT_PROVIDER_VPN_GATEWAY_SKU:
            excluded.add("providerVpnGatewaySku")
        fields = self.model_dump(exclude=excluded)
        # Unset secondary endpoint fields are omitted so digests of earlier single-instance requests do not change.
        for key in ("customerIngress", "customerDelivery"):
            if isinstance(fields.get(key), dict):
                fields[key] = {name: value for name, value in fields[key].items()
                               if not (name.startswith("secondary") and value is None)}
        return fields

    def canonical(self) -> str:
        return json.dumps(self.stored_fields(), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        return hashlib.sha256(self.canonical().encode()).hexdigest()


_PARALLEL_MARKER = "_faasParallelProviderNetworking"
_ISOLATED_MARKER = "_faasIsolatedProviderGroup"


class InvalidStoredNetworkingMode(ValueError):
    pass


def stored_environment_request(request: EnvironmentRequest, parallel: bool, isolated: bool = False) -> str:
    if (type(parallel) is not bool or type(isolated) is not bool
            or ((parallel or isolated) and request.mode != "network")):
        raise InvalidStoredNetworkingMode()
    value = request.stored_fields()
    if parallel:
        value[_PARALLEL_MARKER] = True
    if isolated:
        value[_ISOLATED_MARKER] = True
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def parse_stored_environment_request(value: str) -> tuple[EnvironmentRequest, bool, bool]:
    data = json.loads(value)
    if not isinstance(data, dict):
        raise ValueError("Invalid stored environment request")
    parallel = data.pop(_PARALLEL_MARKER, False)
    isolated = data.pop(_ISOLATED_MARKER, False)
    if type(parallel) is not bool or type(isolated) is not bool:
        raise InvalidStoredNetworkingMode()
    request = EnvironmentRequest.model_validate(data)
    if (parallel or isolated) and request.mode != "network":
        raise InvalidStoredNetworkingMode()
    return request, parallel, isolated


class ConnectionManifest(StrictModel):
    providerIngress: Endpoint
    providerDelivery: Endpoint
    firewallVip: str | None = None

    @field_validator("firewallVip")
    @classmethod
    def ipv4(cls, value: str | None) -> str | None:
        return str(ipaddress.IPv4Address(value)) if value else None
