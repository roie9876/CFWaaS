"""Check Point management/CME operations; importing this module makes no calls."""

import base64
import ipaddress
import json
import socket
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class CheckPointError(RuntimeError):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, url, api_key, expected_ip, ca_file=None):
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"} or parsed.port not in {None, 443}
        ):
            raise ValueError("Management URL must be an HTTPS origin on port 443")
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, 443)}
        if str(ipaddress.ip_address(expected_ip)) not in addresses:
            raise ValueError("Management hostname does not resolve to the recorded management public IP")
        if not api_key:
            raise ValueError("CHECKPOINT_API_KEY is required")
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = build_opener(HTTPSHandler(context=context), NoRedirect())
        self.origin = url.rstrip("/")
        self.api_key = api_key
        self.sid = None
        self.sensitive = [api_key]

    def clean(self, value):
        result = str(value)
        for secret in self.sensitive:
            if secret:
                result = result.replace(secret, "[REDACTED]")
        return result

    def request(self, method, path, body=None):
        if path.startswith("/") or "://" in path or ".." in path.split("/"):
            raise ValueError("Management requests require a fixed-origin relative API path")
        headers = {"Content-Type": "application/json"}
        if self.sid:
            headers["X-chkp-sid"] = self.sid
        request = Request(
            self.origin + "/web_api/" + path, method=method, headers=headers,
            data=None if body is None else json.dumps(body).encode(),
        )
        try:
            response = self.opener.open(request, timeout=60)
        except HTTPError as error:
            response = error
        except (URLError, TimeoutError) as error:
            raise CheckPointError("Management transport/TLS failure: " + self.clean(error)) from error
        with response:
            status = response.code
            raw = response.read().decode()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as error:
            raise CheckPointError("Management API returned non-JSON content") from error
        if not isinstance(payload, dict):
            raise CheckPointError("Management API returned an invalid response object")
        application_status = payload.get("status-code", 200)
        if not isinstance(application_status, int):
            raise CheckPointError("Management API returned an invalid status-code")
        if not 200 <= status < 300 or payload.get("error") or application_status >= 400:
            raise CheckPointError(
                "Management API failure: " + self.clean(payload), payload.get("code"),
            )
        return payload

    def mgmt(self, command, body):
        if "/" in command:
            raise ValueError("Invalid management command")
        return self.request("POST", "v1.8/" + command, body)

    def login(self):
        payload = self.mgmt("login", {"api-key": self.api_key, "session-timeout": 3600})
        if not isinstance(payload.get("sid"), str) or not payload["sid"]:
            raise CheckPointError("Management login did not return a session ID")
        self.sid = payload["sid"]
        self.sensitive.append(self.sid)

    def logout(self):
        if self.sid:
            self.mgmt("logout", {})
            self.sid = None

    def wait_task(self, task_id, timeout=1800):
        if not isinstance(task_id, str) or not task_id:
            raise CheckPointError("Management operation did not return a task ID")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            tasks = self.mgmt("show-task", {"task-id": task_id}).get("tasks")
            if not isinstance(tasks, list) or not tasks:
                raise CheckPointError("Management task response has no tasks")
            statuses = [str(task.get("status", "")).lower() for task in tasks]
            if all(status == "succeeded" for status in statuses):
                return
            if any(status not in {"succeeded", "in progress"} for status in statuses):
                raise CheckPointError("Management task failed: " + self.clean(tasks))
            time.sleep(5)
        raise TimeoutError("Management task did not finish within its time budget")

    def publish(self):
        self.wait_task(self.mgmt("publish", {}).get("task-id"))

    def install(self, policy, gateway_uids):
        if not gateway_uids:
            raise ValueError("Policy installation requires verified gateway UIDs")
        self.wait_task(self.mgmt("install-policy", {
            "policy-package": policy, "targets": gateway_uids,
            "access": True, "threat-prevention": False,
        }).get("task-id"))

    def cme(self, path, body):
        payload = self.request("POST", "v1.8/cme-api/v1.2.1/" + path, body)
        result = payload.get("result")
        request_id = result.get("request-id") if isinstance(result, dict) else None
        if not isinstance(request_id, str) or not request_id:
            raise CheckPointError("CME did not return result.request-id")
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            result = self.request("GET", "cme-api/status/" + quote(request_id, safe="")).get("result")
            if not isinstance(result, dict):
                raise CheckPointError("CME status response has no result object")
            status = str(result.get("requestStatus", "")).replace(" ", "").lower()
            if status == "success":
                return request_id
            if status not in {"pending", "inprogress", "running", "queued"}:
                raise CheckPointError("CME operation failed: " + self.clean(result))
            time.sleep(10)
        raise TimeoutError("CME operation did not finish within its time budget")


def uid(value):
    identifier = value.get("uid")
    if not isinstance(identifier, str) or not identifier:
        raise CheckPointError("Management object has no UID")
    return identifier


def cme_path(config):
    parts = [
        config["management"]["cmeAccountName"],
        config["provider"]["managedResourceGroup"],
        config["cloudguard"]["nvaName"],
    ]
    if sum(map(len, parts)) >= 99:
        raise ValueError("CME account, managed resource group and NVA names must total fewer than 99 characters")
    account, group, nva = (quote(part, safe="") for part in parts)
    return f"azure/virtualWANs/accounts/{account}/resourceGroups/{group}/{{operation}}/{nva}"


def provision_body(sic_key, policy):
    return {
        "base64_sic_key": base64.b64encode(sic_key.encode()).decode(),
        "policy": policy, "autonomous_threat_prevention": False, "identity_awareness": False,
    }


def ingress_body(operator_cidr, public_ip):
    network = ipaddress.ip_network(operator_cidr, strict=True)
    if network.version != 4 or network.prefixlen != 32 or not network.network_address.is_global:
        raise ValueError("Ingress source must be one public operator IPv4 /32")
    if not ipaddress.ip_address(public_ip).is_global:
        raise ValueError("Ingress requires the discovered public IPv4 address")
    return {"rules": [{
        "name": "FaaS-Lab-Ingress", "original_source": str(network),
        "lb_public_ips": [public_ip], "original_ports": ["18080"], "protocol": "TCP",
    }]}


def ensure_dynamic(client, name):
    try:
        return uid(client.mgmt("show-dynamic-object", {"name": name}))
    except CheckPointError as error:
        if error.code != "generic_err_object_not_found":
            raise
    return uid(client.mgmt("add-dynamic-object", {"name": name}))


def create_policy(client, config, operator_cidr, ingress_ip):
    """Create only a new dedicated lab package, never change an existing package."""
    policy = config["management"]["policyName"]
    try:
        client.mgmt("show-package", {"name": policy})
    except CheckPointError as error:
        if error.code != "generic_err_object_not_found":
            raise
    else:
        raise CheckPointError("Refusing to overwrite existing policy " + policy)
    package = client.mgmt("add-package", {"name": policy, "access": True, "threat-prevention": False})
    package = client.mgmt("show-package", {"uid": uid(package)})
    layers = package.get("access-layers")
    if not isinstance(layers, list) or len(layers) != 1:
        raise CheckPointError("New lab package must contain exactly one access layer")
    layer = uid(layers[0])
    networks = []
    for spoke in config["spokes"]:
        network = ipaddress.ip_network(spoke["addressPrefix"])
        networks.append(uid(client.mgmt("add-network", {
            "name": f"{policy}-{spoke['name']}", "subnet": str(network.network_address),
            "subnet-mask": str(network.netmask),
        })))
    internal = uid(client.mgmt("add-group", {"name": policy + "-Internal", "members": networks}))
    http = uid(client.mgmt("add-service-tcp", {"name": policy + "-HTTP", "port": "8080"}))
    https = uid(client.mgmt("add-service-tcp", {"name": policy + "-HTTPS", "port": "443"}))
    dns_tcp = uid(client.mgmt("add-service-tcp", {"name": policy + "-DNS-TCP", "port": "53"}))
    dns_udp = uid(client.mgmt("add-service-udp", {"name": policy + "-DNS-UDP", "port": "53"}))
    echo = uid(client.mgmt("show-service-icmp", {"name": "echo-request"}))
    operator = uid(client.mgmt("add-host", {
        "name": policy + "-Operator", "ipv4-address": str(ipaddress.ip_network(operator_cidr).network_address),
    }))
    ingress = uid(client.mgmt("add-host", {"name": policy + "-Ingress", "ipv4-address": ingress_ip}))
    backend = uid(client.mgmt("add-host", {
        "name": policy + "-Backend", "ipv4-address": config["spokes"][0]["privateIp"],
    }))
    public_http = uid(client.mgmt("add-service-tcp", {"name": policy + "-Public-HTTP", "port": "18080"}))
    external = ensure_dynamic(client, "LocalGatewayExternal")
    gateway_internal = ensure_dynamic(client, "LocalGatewayInternal")
    for name, source, destination, services in [
        ("East-West", internal, internal, [http, echo]),
        ("Internet-Egress", internal, "Any", [https, dns_tcp, dns_udp]),
        ("Controlled-Ingress", operator, ingress, [public_http]),
    ]:
        client.mgmt("add-access-rule", {
            "layer": layer, "position": "top", "name": policy + "-" + name,
            "source": [source], "destination": [destination], "service": services,
            "action": "Accept", "track": {"type": "Log"},
        })
    for rule in [
        {
            "original-source": internal, "original-destination": "Any", "original-service": "Any",
            "translated-source": external, "translated-destination": "Original",
            "translated-service": "Original", "method": "hide",
        },
        {
            "original-source": internal, "original-destination": internal, "original-service": "Any",
            "translated-source": "Original", "translated-destination": "Original",
            "translated-service": "Original", "method": "static",
        },
        {
            "original-source": operator, "original-destination": ingress, "original-service": public_http,
            "translated-source": gateway_internal, "translated-destination": backend,
            "translated-service": http, "method": "hide",
        },
    ]:
        client.mgmt("add-nat-rule", {"package": policy, "position": "top", **rule})
    client.publish()
    return {
        "uid": uid(package), "layer": layer, "internal": internal,
        "http": http, "https": https, "name": policy,
    }


def gateway_uids(client, nva_addresses, expected_count):
    objects = []
    offset = 0
    while True:
        page = client.mgmt("show-gateways-and-servers", {
            "limit": 500, "offset": offset, "details-level": "full",
        })
        batch = page.get("objects")
        if not isinstance(batch, list) or not isinstance(page.get("total"), int):
            raise CheckPointError("Gateway inventory response is invalid")
        objects.extend(batch)
        offset += len(batch)
        if offset >= page["total"]:
            break
        if not batch:
            raise CheckPointError("Gateway inventory pagination did not advance")
    matches = [
        uid(item) for item in objects
        if item.get("type") == "simple-gateway" and item.get("ipv4-address") in nva_addresses
    ]
    if len(set(matches)) != expected_count:
        raise CheckPointError("Cannot uniquely match every integrated NVA instance to its management gateway object")
    return sorted(set(matches))


def negative_control(client, policy, targets, measure):
    baseline = measure("allowed", True)
    rule = client.mgmt("add-access-rule", {
        "layer": policy["layer"], "position": "top", "name": "FaaS-Lab-Temporary-Negative-Control",
        "source": [policy["internal"]], "destination": [policy["internal"]],
        "service": [policy["http"]],
        "action": "Drop", "track": {"type": "Log"},
    })
    rule_uid = uid(rule)
    try:
        client.publish()
        client.install(policy["name"], targets)
        blocked = measure("blocked", False)
    finally:
        client.mgmt("delete-access-rule", {"uid": rule_uid, "layer": policy["layer"]})
        client.publish()
        client.install(policy["name"], targets)
    restored = measure("restored", True)
    return baseline + blocked + restored
