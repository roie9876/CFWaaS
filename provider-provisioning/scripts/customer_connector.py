#!/usr/bin/env python3
"""Stdlib-only customer-UAMI connector embedded in both Azure deployment scripts.

Proof and network use the same runId-mode idempotency keys. No tokens or shared
keys are printed, returned as script outputs, or placed in process arguments.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from uuid import UUID, uuid4

TRANSIENT = {408, 429, 500, 502, 503, 504}
TERMINAL = {"Ready", "Failed", "NeedsAttention"}
CHECKPOINT_READINESS = "/v1/firewall-types/checkpoint-byol/readiness"
CHECKPOINT_TYPES = ("checkpoint-byol", "checkpoint-vmss")
PROVIDER_VPN_GATEWAY_SKUS = ("VpnGw1AZ", "VpnGw2AZ", "VpnGw3AZ", "VpnGw4AZ", "VpnGw5AZ")


class FirewallUnavailable(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class ApiCredential:
    def __init__(self, tenant: str, client: str, secret: str):
        self.tenant, self.client = canonical_uuid(tenant), canonical_uuid(client)
        if not isinstance(secret, str) or not 16 <= len(secret) <= 4096:
            raise ValueError("A customer-specific API credential is required")
        self.secret = secret
        self._token, self._expires = "", 0.0
        self._resource = ""

    def token(self, resource: str, deadline: float) -> str:
        if resource != "api://" + canonical_uuid(resource[6:]):
            raise ValueError("Unexpected provisioning API audience")
        if self._resource and self._resource != resource:
            raise ValueError("Provisioning API audience changed")
        self._resource = resource
        if self._token and time.monotonic() < self._expires:
            return self._token
        url = f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token"
        data = urllib.parse.urlencode({
            "grant_type": "client_credentials", "client_id": self.client,
            "client_secret": self.secret, "scope": resource + "/.default",
        }).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.build_opener(NoRedirect).open(req, timeout=remaining(deadline)) as response:
            raw = response.read(131073)
        if len(raw) > 131072:
            raise ValueError("Unexpected token response size")
        result = json.loads(raw)
        token, lifetime = result.get("access_token"), result.get("expires_in")
        if (result.get("token_type", "").lower() != "bearer"
                or not isinstance(token, str) or not token
                or type(lifetime) is not int or not 1 <= lifetime <= 86400):
            raise ValueError("Invalid API token response")
        self._token, self._expires = token, time.monotonic() + lifetime - min(60, lifetime / 2)
        return token


def canonical_uuid(value: str) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Expected canonical identity")
    return value


def api_origin(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.port not in (None, 443) or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment):
        raise ValueError("Expected an origin-only HTTPS API URL")
    return value.rstrip("/")


def idempotency_key(run_id: str, mode: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{2,31}", run_id) or mode not in {"proof", "network"}:
        raise ValueError("Invalid connector run or mode")
    return run_id + "-" + mode


def remaining(deadline: float, limit: float = 60) -> float:
    result = min(limit, deadline - time.monotonic())
    if result <= 0:
        raise TimeoutError("Bounded customer connector wait expired")
    return result


def pause(deadline: float, seconds: float) -> None:
    time.sleep(min(seconds, remaining(deadline, seconds)))
    remaining(deadline)


def az(arguments: list[str], deadline: float, output: str = "json"):
    completed = subprocess.run(
        ["az", *arguments, "--only-show-errors", "--output", output],
        check=True, capture_output=True, text=True, timeout=remaining(deadline, 6900))
    if output == "none":
        return None
    if output == "tsv":
        return completed.stdout.strip()
    return json.loads(completed.stdout)


def endpoint(value: dict) -> dict:
    base = {"publicIp", "bgpAddress", "asn"}
    secondary = {"secondaryPublicIp", "secondaryBgpAddress"}
    if not isinstance(value, dict) or set(value) not in (base, base | secondary):
        raise ValueError("Unexpected endpoint schema")
    for address, bgp_key in (("publicIp", "bgpAddress"), ("secondaryPublicIp", "secondaryBgpAddress")):
        if address not in value:
            continue
        ipaddress.IPv4Address(value[address])
        bgp = ipaddress.IPv4Address(value[bgp_key])
        if not any(bgp in ipaddress.IPv4Network(prefix) for prefix in (
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
            raise ValueError("Invalid private BGP endpoint")
    if type(value["asn"]) is not int or not 64512 <= value["asn"] <= 65534:
        raise ValueError("Invalid private BGP endpoint")
    # The provider additionally enforces globally routable public IPs.
    return {key: value[key] for key in ("publicIp", "bgpAddress", "asn", *sorted(secondary)) if key in value}


def admin_sources(value: object) -> list[str]:
    # Kept stdlib-only for the self-contained deployment script; matches service/admin_access.py.
    if not isinstance(value, list) or len(value) > 16:
        raise ValueError("Admin sources must be a list of at most 16 public IPv4 hosts or CIDRs")
    excluded = [ipaddress.IPv4Network(prefix) for prefix in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
        "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    )]
    result = set()
    for item in value:
        if not isinstance(item, str) or not re.fullmatch(r"[0-9.]+(?:/[0-9]{1,2})?", item.strip()):
            raise ValueError("Invalid public IPv4 admin source")
        try:
            network = ipaddress.IPv4Network(item.strip(), strict=True)
        except ValueError:
            raise ValueError("Invalid public IPv4 admin source") from None
        if (network.prefixlen == 0 or not network.is_global
                or any(network.overlaps(prefix) for prefix in excluded)):
            raise ValueError("Admin sources must contain only public unicast IPv4 addresses")
        result.add(str(network))
    return sorted(result)


def request_body(mode: str, endpoints: dict | None = None, firewall_type: str = "ubuntu",
                 admin_allowed_sources: object = None, provider_gateway_sku: str = "VpnGw1AZ") -> dict:
    if mode not in {"proof", "network"}:
        raise ValueError("Invalid mode")
    if firewall_type not in {"ubuntu", *CHECKPOINT_TYPES}:
        raise ValueError("Invalid firewall type")
    if provider_gateway_sku not in PROVIDER_VPN_GATEWAY_SKUS:
        raise ValueError("Invalid provider VPN gateway SKU")
    if provider_gateway_sku != "VpnGw1AZ" and mode != "network":
        raise ValueError("Provider VPN gateway sizing requires network mode")
    sources = admin_sources([] if admin_allowed_sources is None else admin_allowed_sources)
    if sources and firewall_type not in CHECKPOINT_TYPES:
        raise ValueError("Public admin sources require Check Point")
    body = {"mode": mode, "region": "eastus2", "tier": "lab"}
    if mode == "network":
        if not isinstance(endpoints, dict) or set(endpoints) != {"customerIngress", "customerDelivery"}:
            raise ValueError("Both customer endpoints are required")
        body.update({key: endpoint(endpoints[key]) for key in ("customerIngress", "customerDelivery")})
        if firewall_type != "ubuntu":
            body["firewallType"] = firewall_type
        if sources:
            body["adminAllowedSources"] = sources
        # Omitted at the default so older provider APIs keep accepting the request.
        if provider_gateway_sku != "VpnGw1AZ":
            body["providerVpnGatewaySku"] = provider_gateway_sku
    return body


def request(url: str, resource: str, path: str, deadline: float, body=None, key: str | None = None,
            auth: ApiCredential | None = None):
    if not path.startswith("/v1/") or "://" in path or "?" in path:
        raise ValueError("Invalid API request path")
    for attempt in range(8):
        remaining(deadline)
        try:
            token = auth.token(resource, deadline) if auth else az([
                "account", "get-access-token", "--resource", resource, "--query", "accessToken"], deadline, "tsv")
            if not token:
                raise RuntimeError("No API token")
            headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
            if key:
                headers["Idempotency-Key"] = key
            req = urllib.request.Request(url + path, headers=headers,
                                         data=None if body is None else json.dumps(body).encode())
            with urllib.request.build_opener(NoRedirect).open(req, timeout=remaining(deadline)) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            if path == CHECKPOINT_READINESS and status in {404, 409}:
                raise FirewallUnavailable("Check Point deployment is not available") from None
            if status not in TRANSIENT:
                raise RuntimeError("Provider API request was rejected; no identity fallback") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        if attempt == 7:
            break
        pause(deadline, min(2 ** attempt, 30))
    raise RuntimeError("Provider API transient retry limit reached")


def operation_identity(operation: dict, expected: str | None = None) -> str:
    operation_id = canonical_uuid(operation["operationId"])
    if operation.get("environmentId") != operation_id or (expected and expected != operation_id):
        raise ValueError("Provider operation identity changed")
    return operation_id


def poll(url: str, resource: str, operation: dict, deadline: float,
         auth: ApiCredential | None = None) -> dict:
    operation_id = operation_identity(operation)
    while operation["status"] not in TERMINAL:
        pause(deadline, 10)
        operation = request(url, resource, "/v1/operations/" + operation_id, deadline, auth=auth)
        operation_identity(operation, operation_id)
    if operation["status"] != "Ready":
        raise RuntimeError("Provider operation did not become Ready")
    return operation


def validate_connection_template(template: dict) -> None:
    expected = {"location", "runId", "providerManifest", "ingressSharedKey", "deliverySharedKey"}
    if not isinstance(template, dict) or set(template.get("parameters", {})) != expected:
        raise ValueError("Customer connection template parameter contract mismatch")
    for key in ("ingressSharedKey", "deliverySharedKey"):
        if template["parameters"][key].get("type", "").lower() != "securestring":
            raise ValueError("Connection shared keys must be secure parameters")
        if "defaultValue" in template["parameters"][key]:
            raise ValueError("Shared-key defaults are forbidden")

    def local_only(value, depth=0):
        if depth > 4 or not isinstance(value, dict) or value.get("outputs"):
            raise ValueError("Connection templates must not output connection material")
        if value.get("$schema") != "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#":
            raise ValueError("Unexpected connection template schema")
        if not isinstance(value.get("resources"), list) or not value["resources"]:
            raise ValueError("Connection template must contain local networking resources")
        for resource in value["resources"]:
            if set(resource) & {"scope", "subscriptionId", "resourceGroup", "resources"}:
                raise ValueError("Cross-scope connection deployment is forbidden")
            if resource.get("type") == "Microsoft.Resources/deployments":
                properties = resource.get("properties", {})
                if (set(properties) - {"mode", "template", "parameters", "expressionEvaluationOptions"}
                        or properties.get("mode") != "Incremental"
                        or properties.get("expressionEvaluationOptions") != {"scope": "inner"}):
                    raise ValueError("Only embedded same-group connection modules are permitted")
                local_only(properties.get("template"), depth + 1)
            elif resource.get("type") not in {"Microsoft.Network/localNetworkGateways", "Microsoft.Network/connections"}:
                raise ValueError("Unexpected customer connection resource")
    local_only(template)


def customer_scope(env: dict, deadline: float) -> tuple[str, str]:
    subscription = canonical_uuid(env["FAAS_CUSTOMER_SUBSCRIPTION_ID"])
    if env.get("FAAS_EXPECTED_CUSTOMER_SUBSCRIPTION_ID") and env["FAAS_EXPECTED_CUSTOMER_SUBSCRIPTION_ID"] != subscription:
        raise ValueError("Selected customer subscription differs from enrolled subscription")
    tenant = canonical_uuid(env["FAAS_CUSTOMER_TENANT_ID"])
    if env.get("FAAS_EXPECTED_CUSTOMER_TENANT_ID") and env["FAAS_EXPECTED_CUSTOMER_TENANT_ID"] != tenant:
        raise ValueError("Selected customer tenant differs from enrolled tenant")
    group = env["FAAS_CUSTOMER_RESOURCE_GROUP"]
    if not re.fullmatch(r"[\w().-]{1,90}", group) or group.endswith("."):
        raise ValueError("Unexpected customer resource group")
    expected = f"/subscriptions/{subscription}/resourceGroups/{group}"
    enrolled = env.get("FAAS_ENROLLED_CUSTOMER_SCOPE")
    if enrolled and enrolled.lower() != expected.lower():
        raise ValueError("Selected customer scope differs from enrolled scope")
    account = az(["account", "show", "--subscription", subscription], deadline)
    if account.get("id") != subscription or account.get("tenantId") != tenant or account.get("state") != "Enabled":
        raise ValueError("Customer account context mismatch")
    value = az(["group", "show", "--subscription", subscription, "--name", group], deadline)
    tags = value.get("tags") or {}
    if value.get("id", "").lower() != expected.lower():
        raise ValueError("Customer group ownership mismatch")
    if env.get("FAAS_ENROLL_CUSTOMER_SCOPE", "false").lower() == "true":
        if (tags.get("labRun") not in (None, env["FAAS_RUN_ID"])
                or tags.get("purpose") not in (None, "provider-provisioning")):
            raise ValueError("Customer group belongs to another deployment")
        resources = az(["resource", "list", "--subscription", subscription, "--resource-group", group], deadline)
        if not isinstance(resources, list):
            raise ValueError("Invalid customer resource inventory")
        for resource in resources:
            kind = resource.get("type", "").lower()
            if (kind.startswith("microsoft.network/") and kind != "microsoft.network/networkprofiles"
                    or kind == "microsoft.compute/virtualmachines"):
                if (resource.get("tags") or {}).get("labRun") != env["FAAS_RUN_ID"]:
                    raise ValueError("Choose a dedicated RG; existing network or VM resources are not owned by this deployment")
    elif tags.get("labRun") != env["FAAS_RUN_ID"] or tags.get("purpose") != "provider-provisioning":
        raise ValueError("Customer group ownership mismatch")
    return subscription, group


def private_json(path: Path, value: dict, exclusive: bool = True):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_EXCL if exclusive else os.O_TRUNC)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        if exclusive:
            os.fchmod(stream.fileno(), 0o600)
            if os.fstat(stream.fileno()).st_mode & 0o077:
                raise ValueError("Connector filesystem cannot enforce private parameter-file permissions")
        json.dump(value, stream)


def configure_default_site(subscription: str, group: str, deadline: float) -> None:
    site = (f"/subscriptions/{subscription}/resourceGroups/{group}/providers/"
            "Microsoft.Network/localNetworkGateways/lng-customer-ingress")
    gateway = ["network", "vnet-gateway", "show", "--subscription", subscription,
               "--resource-group", group, "--name", "gw-customer-ingress"]
    current = az(gateway, deadline)
    actual = (current.get("gatewayDefaultSite") or {}).get("id", "")
    if actual.lower() != site.lower():
        az(["network", "vnet-gateway", "update", "--subscription", subscription,
            "--resource-group", group, "--name", "gw-customer-ingress",
            "--gateway-default-site", site], deadline, "none")
        current = az(gateway, deadline)
        actual = (current.get("gatewayDefaultSite") or {}).get("id", "")
    if actual.lower() != site.lower():
        raise RuntimeError("Customer ingress gateway default site was not applied")


def deploy_connections(env: dict, operation: dict, material: dict, template: dict,
                       subscription: str, group: str, deadline: float) -> None:
    operation_id = operation_identity(operation)
    if (not isinstance(material, dict) or set(material) != {"environmentId", "ingressSharedKey", "deliverySharedKey"}
            or material["environmentId"] != operation_id):
        raise ValueError("Connection material identity mismatch")
    for key in ("ingressSharedKey", "deliverySharedKey"):
        if not isinstance(material[key], str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", material[key]):
            raise ValueError("Invalid connection material")
    manifest = operation["connectionManifest"]
    if (not isinstance(manifest, dict)
            or set(manifest) - {"providerIngress", "providerDelivery", "firewallVip"}
            or not {"providerIngress", "providerDelivery"} <= set(manifest)):
        raise ValueError("Unexpected provider connection manifest")
    for key in ("providerIngress", "providerDelivery"):
        endpoint(manifest[key])
    validate_connection_template(template)
    parameters = {"runId": env["FAAS_RUN_ID"], "providerManifest": manifest,
                  "location": env.get("FAAS_CUSTOMER_LOCATION", "eastus2"),
                  "ingressSharedKey": material["ingressSharedKey"], "deliverySharedKey": material["deliverySharedKey"]}
    directory = Path.cwd() / (".faas-connector-" + uuid4().hex)
    directory.mkdir(mode=0o700)
    template_file, parameters_file = directory / "connections.json", directory / "parameters.json"
    try:
        if directory.stat().st_mode & 0o077:
            raise ValueError("Connector working directory must be private ephemeral container storage")
        private_json(template_file, template)
        private_json(parameters_file, {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
                                      "contentVersion": "1.0.0.0",
                                      "parameters": {key: {"value": value} for key, value in parameters.items()}})
        az(["deployment", "group", "create", "--subscription", subscription,
            "--resource-group", group, "--name", "customer-connections-" + operation_id,
            "--mode", "Incremental", "--template-file", str(template_file),
            "--parameters", "@" + str(parameters_file)], deadline, "none")
        configure_default_site(subscription, group, deadline)
    finally:
        for path in (parameters_file, template_file):
            if path.exists():
                path.unlink()
        directory.rmdir()


def run(env: dict) -> dict:
    if env.get("FAAS_BACKING_APPROVED", "").lower() != "true":
        raise ValueError("Separate deployment-script backing exception must be approved")
    mode = env["FAAS_CONNECTOR_MODE"]
    key = idempotency_key(env["FAAS_RUN_ID"], mode)
    wait_seconds = int(env["FAAS_WAIT_SECONDS"])
    if not 60 <= wait_seconds <= 14100:
        raise ValueError("Connector wait must be bounded")
    deadline = time.monotonic() + wait_seconds
    url = api_origin(env["FAAS_API_URL"])
    resource = env["FAAS_API_RESOURCE"]
    if not resource.startswith("api://") or resource != "api://" + canonical_uuid(resource[6:]):
        raise ValueError("Unexpected API token resource")
    client = canonical_uuid(env["FAAS_CUSTOMER_CLIENT_ID"])
    auth_mode = env.get("FAAS_AUTH_MODE", "customer-managed-identity")
    if auth_mode not in {"customer-managed-identity", "provider-api-client"}:
        raise ValueError("Unknown API authentication mode")
    auth = (ApiCredential(env["FAAS_API_AUTHORITY_TENANT_ID"], env["FAAS_API_CLIENT_ID"],
                          env["FAAS_API_CLIENT_SECRET"]) if auth_mode == "provider-api-client" else None)
    firewall_type = env.get("FAAS_FIREWALL_TYPE", "ubuntu")
    body = request_body(mode, json.loads(env["FAAS_CUSTOMER_ENDPOINTS"]) if mode == "network" else None,
                        firewall_type, admin_sources(json.loads(env.get("FAAS_ADMIN_ALLOWED_SOURCES", "[]"))),
                        env.get("FAAS_PROVIDER_VPN_GATEWAY_SKU", "VpnGw1AZ"))
    template = json.loads(env["FAAS_CONNECTIONS_TEMPLATE"]) if mode == "network" else None
    if template is not None:
        validate_connection_template(template)
    az(["login", "--identity", "--client-id", client, "--allow-no-subscriptions"], deadline, "none")
    if firewall_type in CHECKPOINT_TYPES:
        available = request(url, resource, CHECKPOINT_READINESS.replace("checkpoint-byol", firewall_type),
                            deadline, auth=auth)
        if available != {"firewallType": firewall_type, "status": "ready"}:
            raise FirewallUnavailable("Check Point deployment is not available")
    scope = customer_scope(env, deadline) if (
        mode == "network" or env.get("FAAS_VALIDATE_CUSTOMER_SCOPE", "false").lower() == "true") else None
    operation = request(url, resource, "/v1/environments", deadline, body, key, auth=auth)
    error = operation.get("error")
    if (mode == "network" and operation.get("status") == "Failed"
            and isinstance(error, dict) and error.get("code") == "GroupOwnershipError"):
        operation_id = operation_identity(operation)
        operation = request(url, resource, "/v1/operations/" + operation_id + "/retry-group",
                            deadline, {}, auth=auth)
        operation_identity(operation, operation_id)
    operation = poll(url, resource, operation, deadline, auth=auth)
    operation_id = operation_identity(operation)
    if mode == "network":
        routing_ip = env.get("FAAS_CUSTOMER_ROUTING_APPLIANCE_IP", "")
        if routing_ip:
            address = ipaddress.IPv4Address(routing_ip)
            if not any(address in ipaddress.IPv4Network(prefix)
                       for prefix in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")):
                raise ValueError("Invalid customer Routing Appliance IP")
            registered = request(url, resource, "/v1/operations/" + operation_id + "/routing",
                                 deadline, {"routingApplianceIp": str(address)}, auth=auth)
            if registered != {"status": "registered"}:
                raise ValueError("Customer Routing Appliance registration failed")
        material = request(url, resource, "/v1/environments/" + operation_id + "/connection-material",
                           deadline, auth=auth)
        deploy_connections(env, operation, material, template, scope[0], scope[1], deadline)
    return {"operationId": operation_id, "status": "Ready"}


def main(argv=None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    try:
        result = run(os.environ)
        private_json(Path(os.environ["AZ_SCRIPTS_OUTPUT_PATH"]), result, exclusive=False)
    except FirewallUnavailable:
        raise SystemExit("Check Point BYOL deployment is not available yet. Choose the Ubuntu simulator.") from None
    except Exception:
        raise SystemExit("Customer managed-identity connector failed; inspect redacted provider status and scoped permissions. No credential fallback.") from None
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
