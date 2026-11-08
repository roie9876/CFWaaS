"""Post-boot Check Point configuration through the private Management API.

Runs inside the environment's automation subnet after Terraform creates the VMs. It creates the
gateway object (SIC), the approved lab baseline policy, no-NAT east-west and hide-NAT egress,
reconciles private management logging, and configures BGP to the Route Server peers with
Management ``run-script``. Nothing here is per customer VNet: RFC1918 objects cover any customer
address added later.

Only constant step labels and Check Point error-code tokens are logged; never credentials,
API payloads or script output.
"""
import base64
import hashlib
import http.client
import ipaddress
import json
import re
import ssl
import time
from collections.abc import Callable
from dataclasses import dataclass

from .admin_access import normalize_admin_sources

MANAGEMENT_IP = "172.22.30.4"
MANAGEMENT_SUBNET = "172.22.30.0/24"
GATEWAY_FRONTEND_IP = "172.22.10.4"
GATEWAY_BACKEND_IP = "172.22.20.4"
FRONTEND_ROUTER_IP = "172.22.10.1"
ROUTE_SERVER_SUBNET = "172.20.254.0/26"
GATEWAY_ASN = 65050
POLICY_PACKAGE = "Standard"
ACCESS_LAYER = "Network"
RFC1918 = (("faas-rfc1918-10", "10.0.0.0", 8), ("faas-rfc1918-172", "172.16.0.0", 12),
           ("faas-rfc1918-192", "192.168.0.0", 16))
RFC1918_GROUP = "faas-rfc1918"
EAST_WEST_RULE, EGRESS_RULE, NO_NAT_RULE = "faas-east-west", "faas-north-south-egress", "faas-no-nat-east-west"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
ADMIN_RULE = "faas-approved-admin"
HEALTH_PROBE_RULE = "faas-lb-health-probe"
AZURE_PROBE_HOST, AZURE_PROBE_SERVICE = "faas-azure-lb-probe", "faas-lb-probe-8117"
AZURE_PROBE_IP = "168.63.129.16"
EXPORT_ROUTEMAP = "faas-out"


@dataclass(frozen=True)
class CheckpointGateway:
    name: str
    frontend_ip: str
    backend_ip: str


class CheckpointGaiaError(RuntimeError):
    """Raised with a constant, secret-free reason."""


def management_clients_script(sources: list[str]) -> str:
    """Use documented cp_conf client add, never createlist/del or direct file edits."""
    clients = []
    for source in normalize_admin_sources(sources):
        network = ipaddress.IPv4Network(source)
        clients.append(str(network.network_address) if network.prefixlen == 32
                       else f"{network.network_address}/{network.netmask}")
    commands = ["set -e", 'clients="$(cp_conf client get)"']
    for client in clients:
        pattern = "(^|[[:space:]])" + re.escape(client) + "([[:space:]]|$)"
        commands += [
            f"if ! printf '%s\\n' \"$clients\" | grep -Eq -- '{pattern}'; then",
            f"  cp_conf client add '{client}'",
            "fi",
        ]
    commands += ['clients="$(cp_conf client get)"']
    for client in clients:
        pattern = "(^|[[:space:]])" + re.escape(client) + "([[:space:]]|$)"
        commands.append(f"printf '%s\\n' \"$clients\" | grep -Eq -- '{pattern}'")
    commands.append("printf '%s\\n' faas-admin-clients-configured")
    return "\n".join(commands) + "\n"


@dataclass(frozen=True)
class BgpStatus:
    configured: int
    established: int


class TlsPin:
    """Trust-on-first-use pin for the management server certificate, persisted by the caller."""

    def __init__(self, load: Callable[[], str | None], store: Callable[[str], None]) -> None:
        self._load, self._store, self._value = load, store, None

    def check(self, certificate: bytes, allow_first_use: bool) -> None:
        fingerprint = hashlib.sha256(certificate).hexdigest()
        if self._value is None:
            self._value = self._load()
        if self._value is None:
            if not allow_first_use:
                raise CheckpointGaiaError("Management certificate is not pinned")
            self._store(fingerprint)
            self._value = fingerprint
        elif self._value != fingerprint:
            raise CheckpointGaiaError("Management certificate does not match its pin")


class ManagementApi:
    def __init__(self, pin: TlsPin, host: str = MANAGEMENT_IP, timeout: float = 120.0) -> None:
        self._pin, self._host, self._timeout, self._sid = pin, host, timeout, None

    def _post(self, command: str, body: dict, first_use: bool = False) -> tuple[int, dict]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # replaced by the explicit certificate pin below
        connection = http.client.HTTPSConnection(self._host, 443, timeout=self._timeout, context=context)
        try:
            connection.connect()
            self._pin.check(connection.sock.getpeercert(binary_form=True), first_use)
            headers = {"Content-Type": "application/json"}
            if self._sid:
                headers["X-chkp-sid"] = self._sid
            connection.request("POST", "/web_api/" + command, json.dumps(body), headers)
            response = connection.getresponse()
            payload = response.read(MAX_RESPONSE_BYTES + 1)
        finally:
            connection.close()
        if len(payload) > MAX_RESPONSE_BYTES:
            raise CheckpointGaiaError("Management response is too large")
        try:
            data = json.loads(payload or b"{}")
        except ValueError:
            data = {}
        return response.status, data if isinstance(data, dict) else {}

    def call(self, command: str, body: dict, allowed: tuple[str, ...] = ()) -> dict:
        status, data = self._post(command, body)
        if status == 200:
            return data
        code = data.get("code") if isinstance(data.get("code"), str) else ""
        if code in allowed:
            return {"code": code}
        token = code if re.fullmatch(r"[a-z_]{1,64}", code) else str(status)
        raise CheckpointGaiaError(f"Management {command} failed: {token}")

    def login(self, password: str, deadline: float, sleep: Callable[[float], None] = time.sleep) -> None:
        while True:
            try:
                status, data = self._post("login", {"user": "admin", "password": password,
                                                    "session-timeout": 3600}, first_use=True)
                sid = data.get("sid")
                if status == 200 and isinstance(sid, str) and sid:
                    self._sid = sid
                    return
            except (OSError, http.client.HTTPException, ssl.SSLError):
                pass
            if time.monotonic() >= deadline:
                raise CheckpointGaiaError("Management API did not become ready")
            sleep(30)

    def wait_task(self, task_id: str, deadline: float, sleep: Callable[[float], None] = time.sleep) -> dict:
        while True:
            data = self.call("show-task", {"task-id": task_id, "details-level": "full"})
            tasks = data.get("tasks")
            task = tasks[0] if isinstance(tasks, list) and tasks and isinstance(tasks[0], dict) else {}
            status = task.get("status")
            if status in ("succeeded", "succeeded with warnings"):
                return task
            if status not in ("in progress", None):
                raise CheckpointGaiaError("Management task failed")
            if time.monotonic() >= deadline:
                raise CheckpointGaiaError("Management task timed out")
            sleep(10)

    def publish(self, deadline: float) -> None:
        task = self.call("publish", {}).get("task-id")
        if isinstance(task, str):
            self.wait_task(task, deadline)

    def discard_and_logout(self) -> None:
        for command in ("discard", "logout"):
            try:
                self.call(command, {})
            except (CheckpointGaiaError, OSError, http.client.HTTPException, ssl.SSLError):
                pass


def bgp_script(peers: tuple[str, str], peer_asn: int, router_id: str = GATEWAY_FRONTEND_IP,
               next_hop: str | None = None) -> str:
    for peer in peers:
        if not ipaddress.ip_address(peer).is_private:
            raise CheckpointGaiaError("Invalid Route Server peer")
    if peer_asn != 65515:
        raise CheckpointGaiaError("Invalid Route Server ASN")
    for address in (router_id, next_hop):
        if address is not None and not ipaddress.ip_address(address).is_private:
            raise CheckpointGaiaError("Invalid gateway BGP address")
    commands = [
        f"set router-id {router_id}",
        f"set as {GATEWAY_ASN}",
        f"set static-route default nexthop gateway address {FRONTEND_ROUTER_IP} on",
        # The image routes RFC1918 via the backend NIC; Route Server only accepts the frontend peer IP.
        f"set static-route {ROUTE_SERVER_SUBNET} nexthop gateway address {FRONTEND_ROUTER_IP} on",
        f"set bgp external remote-as {peer_asn} on",
    ]
    for peer in peers:
        prefix = f"set bgp external remote-as {peer_asn} peer {peer}"
        commands += [f"{prefix} on", f"{prefix} multihop on", f"{prefix} ttl 5", f"{prefix} accept-routes none"]
    if next_hop is None:
        # Export only the static default route, as the Ubuntu simulator's FAAS-OUT route map does.
        commands.append(f"set route-redistribution to bgp-as {peer_asn} from static-route default on")
    else:
        # Scale set members advertise the same default with the internal load balancer as next hop,
        # so Route Server forwards to one symmetric HA-ports frontend instead of individual members.
        route_map = f"set routemap {EXPORT_ROUTEMAP} id 10"
        commands += [f"{route_map} on", f"{route_map} allow", f"{route_map} match protocol static",
                     f"{route_map} match network 0.0.0.0/0 exact", f"{route_map} action nexthop ip {next_hop}",
                     f"set bgp external remote-as {peer_asn} export-routemap {EXPORT_ROUTEMAP} preference 1 on"]
    commands.append("save config")
    lines = ["#!/bin/bash", "failed=0"]
    for index, command in enumerate(commands):
        lines.append(f'clish -c "{command}" >/dev/null 2>&1 || {{ failed=1; echo "faas-step-failed {index}"; }}')
    lines.append('[ "$failed" = 0 ] && echo faas-bgp-configured')
    return "\n".join(lines) + "\n"


BGP_STATUS_SCRIPT = '#!/bin/bash\nclish -c "show bgp peers" 2>/dev/null\n'
MANAGEMENT_ROUTE_SCRIPT = (
    '#!/bin/bash\n'
    f'clish -c "set static-route {MANAGEMENT_SUBNET} nexthop gateway address {FRONTEND_ROUTER_IP} on"'
    ' >/dev/null 2>&1 || exit 1\n'
    'clish -c "save config" >/dev/null 2>&1 || exit 1\n'
    'echo faas-management-route-configured\n'
)


def parse_bgp_peers(output: str, peers: tuple[str, str]) -> BgpStatus:
    configured = established = 0
    for line in output.splitlines():
        fields = line.split()
        if fields and fields[0] in peers:
            configured += 1
            established += int("Established" in fields)
    return BgpStatus(configured, established)


class CheckpointConfigurator:
    def __init__(self, api: ManagementApi, environment_id: str, sic_key: str, management_password: str,
                 route_server_peers: tuple[str, str] | None, route_server_asn: int | None,
                 log: Callable[[str], None], sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic,
                 admin_allowed_sources: list[str] | None = None,
                 gateways: list[CheckpointGateway] | None = None,
                 internal_load_balancer_ip: str | None = None, connectivity_mode: str = "vpn") -> None:
        self.api, self.sleep, self.clock, self.log = api, sleep, clock, log
        default = CheckpointGateway("cp-gateway-" + environment_id[:8], GATEWAY_FRONTEND_IP, GATEWAY_BACKEND_IP)
        self.gateways = list(gateways) if gateways else [default]
        # A scale set has several gateway objects behind an internal load balancer used as BGP next hop.
        self.scale_set = internal_load_balancer_ip is not None
        self.next_hop = internal_load_balancer_ip
        if (len({item.name for item in self.gateways}) != len(self.gateways)
                or (self.scale_set and len(self.gateways) < 2)
                or (not self.scale_set and self.gateways != [default])):
            raise CheckpointGaiaError("Invalid Check Point gateway set")
        self.gateway = self.gateways[0].name
        self.gateway_names = [item.name for item in self.gateways]
        self.management = "cp-management-" + environment_id[:8]
        self.sic_key, self.password = sic_key, management_password
        self.peers, self.peer_asn = route_server_peers, route_server_asn
        if (connectivity_mode not in ("vpn", "peering")
                or connectivity_mode == "peering" and (not self.scale_set or route_server_peers is not None
                                                       or route_server_asn is not None)
                or connectivity_mode == "vpn" and (route_server_peers is None or route_server_asn is None)):
            raise CheckpointGaiaError("Invalid Check Point connectivity mode")
        self.connectivity_mode = connectivity_mode
        self.admin_sources = normalize_admin_sources([] if admin_allowed_sources is None else admin_allowed_sources)

    def _deadline(self, seconds: float) -> float:
        return self.clock() + seconds

    def _install_on(self) -> str | list[str]:
        return self.gateway_names if self.scale_set else self.gateway

    def _gateway_body(self, gateway: CheckpointGateway | None = None) -> dict:
        gateway = gateway or self.gateways[0]
        # Scale set traffic enters eth1 from the internal load balancer, so upstream disables anti-spoofing.
        spoofing = not self.scale_set
        return {
            "name": gateway.name, "ip-address": gateway.frontend_ip, "version": "R82",
            "one-time-password": self.sic_key, "firewall": True,
            "interfaces": [
                {"name": "eth0", "ipv4-address": gateway.frontend_ip, "ipv4-mask-length": 24,
                 "topology": "external", "anti-spoofing": spoofing},
                {"name": "eth1", "ipv4-address": gateway.backend_ip, "ipv4-mask-length": 24,
                 "topology": "internal", "anti-spoofing": spoofing,
                 "topology-settings": {"ip-address-behind-this-interface":
                                       "network defined by the interface ip and net mask"}},
            ],
        }

    def ensure_gateway(self) -> None:
        for gateway in self.gateways:
            self._ensure_gateway(gateway)

    def _ensure_gateway(self, gateway: CheckpointGateway) -> None:
        deadline = self._deadline(3600)
        while True:
            found = self.api.call("show-simple-gateway", {"name": gateway.name},
                                  allowed=("generic_err_object_not_found",))
            if found.get("code") == "generic_err_object_not_found":
                try:
                    self.api.call("add-simple-gateway", self._gateway_body(gateway))
                    self.api.publish(self._deadline(600))
                except CheckpointGaiaError:
                    self.api.call("discard", {})
                    self.log("gateway-add-retry")
                found = self.api.call("show-simple-gateway", {"name": gateway.name},
                                      allowed=("generic_err_object_not_found",))
            if found.get("sic-state") == "communicating":
                self.log("gateway-sic-communicating")
                return
            if found.get("code") != "generic_err_object_not_found":
                if self.admin_sources:
                    raise CheckpointGaiaError("Gateway SIC is not communicating; admin access will not reset it")
                # The gateway first-time wizard may not have finished; recreate to retry SIC.
                self.api.call("delete-simple-gateway", {"name": gateway.name})
                self.api.publish(self._deadline(600))
                self.log("gateway-sic-retry")
            if self.clock() >= deadline:
                raise CheckpointGaiaError("Gateway SIC was not established")
            self.sleep(60)

    def _ensure(self, show: str, add: str, body: dict) -> bool:
        found = self.api.call(show, {"name": body["name"]} if "layer" not in body else
                              {"name": body["name"], "layer": body["layer"]},
                              allowed=("generic_err_object_not_found",))
        if found.get("code") == "generic_err_object_not_found":
            self.api.call(add, body)
            return True
        return False

    @staticmethod
    def _log_servers(gateway: dict) -> list[str]:
        settings = gateway.get("logs-settings")
        # R82 returns this at the top level, while API request/fixture shapes
        # may nest it under logs-settings.
        servers = gateway.get("send-logs-to-server")
        if servers is None and isinstance(settings, dict):
            servers = settings.get("send-logs-to-server")
        if not isinstance(servers, list):
            raise CheckpointGaiaError("Gateway log servers are unavailable")
        names = [server.get("name") if isinstance(server, dict) else server for server in servers]
        if any(not isinstance(name, str) or not name for name in names):
            raise CheckpointGaiaError("Gateway log servers are invalid")
        return names

    def ensure_management_logging(self) -> None:
        host = self.api.call("show-checkpoint-host", {"name": self.management})
        # Read every gateway's log destinations before changing anything.
        current = {name: self._log_servers(self.api.call("show-simple-gateway",
                                                         {"name": name, "details-level": "full"}))
                   for name in self.gateway_names}
        changed = False
        if host.get("ipv4-address") != MANAGEMENT_IP:
            self.api.call("set-checkpoint-host", {"name": self.management, "ipv4-address": MANAGEMENT_IP})
            changed = True
        for name, servers in current.items():
            if self.management not in servers:
                self.api.call("set-simple-gateway", {
                    "name": name, "logs-settings": {"send-logs-to-server": [*servers, self.management]}})
                changed = True
        if changed:
            self.api.publish(self._deadline(600))
        host = self.api.call("show-checkpoint-host", {"name": self.management})
        if host.get("ipv4-address") != MANAGEMENT_IP or any(
                self.management not in self._log_servers(self.api.call(
                    "show-simple-gateway", {"name": name, "details-level": "full"}))
                for name in self.gateway_names):
            raise CheckpointGaiaError("Management logging configuration did not persist")
        for name in self.gateway_names:
            output = self._run_script("faas-management-route", MANAGEMENT_ROUTE_SCRIPT, target=name)
            if "faas-management-route-configured" not in output.splitlines():
                raise CheckpointGaiaError("Management logging route configuration failed")
        # Reinstall on retries even when the objects already match: a prior run may have
        # published successfully but stopped before the database reached the log server.
        data = self.api.call("install-database", {"targets": [self.management]})
        tasks = data.get("tasks")
        if (not isinstance(tasks, list) or not tasks
                or any(not isinstance(task, dict) or not isinstance(task.get("task-id"), str)
                       or not task["task-id"] for task in tasks)):
            raise CheckpointGaiaError("Management install-database returned no tasks")
        for task in tasks:
            self.api.wait_task(task["task-id"], self._deadline(1800))
        self.log("management-logging-configured")

    def ensure_admin_access(self) -> None:
        if not self.admin_sources:
            return
        output = self._run_script("faas-admin-clients", management_clients_script(self.admin_sources),
                                  target=self.management)
        if "faas-admin-clients-configured" not in output.splitlines():
            raise CheckpointGaiaError("Management GUI client configuration did not persist")
        for source in self.admin_sources:
            network = ipaddress.IPv4Network(source)
            name = "faas-admin-" + hashlib.sha256(source.encode()).hexdigest()[:16]
            body = {"name": name, "subnet": str(network.network_address), "mask-length": network.prefixlen}
            found = self.api.call("show-network", {"name": name}, allowed=("generic_err_object_not_found",))
            if found.get("code") == "generic_err_object_not_found":
                self.api.call("add-network", body)
            elif any(found.get(key) != value for key, value in body.items()):
                raise CheckpointGaiaError("Admin source object conflicts with existing configuration")
        body = {
            "layer": ACCESS_LAYER, "position": "top", "name": ADMIN_RULE,
            "source": ["faas-admin-" + hashlib.sha256(source.encode()).hexdigest()[:16]
                       for source in self.admin_sources],
            # Built-in services: management rejects new TCP services that reuse ports 22/443.
            "destination": self.gateway_names, "service": ["ssh", "https"],
            "action": "Accept", "track": {"type": "Log"}, "install-on": self._install_on(), "enabled": True,
            "source-negate": False, "destination-negate": False, "service-negate": False,
        }
        found = self.api.call("show-access-rule", {"name": ADMIN_RULE, "layer": ACCESS_LAYER},
                              allowed=("generic_err_object_not_found",))
        if found.get("code") == "generic_err_object_not_found":
            self.api.call("add-access-rule", body)
        else:
            def names(value: object) -> set[str]:
                items = value if isinstance(value, list) else [value]
                return {item.get("name", "") if isinstance(item, dict) else item
                        for item in items if isinstance(item, (str, dict))}
            if (any(names(found.get(key)) != set(body[key]) for key in ("source", "destination", "service"))
                    or names(found.get("action")) != {"Accept"}
                    or names(found.get("install-on")) != set(self.gateway_names)
                    or found.get("enabled") is not True
                    or any(found.get(key) is not False
                           for key in ("source-negate", "destination-negate", "service-negate"))
                    or not isinstance(found.get("track"), dict)
                    or names(found["track"].get("type")) != {"Log"}):
                raise CheckpointGaiaError("Admin access rule conflicts with existing configuration")
        self.log("admin-access-configured")

    def ensure_health_probe_access(self) -> None:
        """Accept only Azure load balancer probes to the Check Point probe port; scale sets only."""
        if not self.scale_set:
            return
        self._ensure("show-host", "add-host", {"name": AZURE_PROBE_HOST, "ip-address": AZURE_PROBE_IP})
        self._ensure("show-service-tcp", "add-service-tcp",
                     {"name": AZURE_PROBE_SERVICE, "port": "8117", "ignore-warnings": True})
        self._ensure("show-access-rule", "add-access-rule", {
            "layer": ACCESS_LAYER, "position": "top", "name": HEALTH_PROBE_RULE,
            "source": [AZURE_PROBE_HOST], "destination": self.gateway_names, "service": [AZURE_PROBE_SERVICE],
            "action": "Accept", "track": {"type": "None"}, "install-on": self.gateway_names})
        self.log("health-probe-access-configured")

    def ensure_policy(self) -> None:
        self.ensure_admin_access()
        self.ensure_health_probe_access()
        install_on = self._install_on()
        for name, subnet, mask in RFC1918:
            self._ensure("show-network", "add-network", {
                "name": name, "subnet": subnet, "mask-length": mask,
                "nat-settings": {"auto-rule": True, "method": "hide", "hide-behind": "gateway",
                                 "install-on": "All" if self.scale_set else self.gateway}})
        self._ensure("show-group", "add-group", {"name": RFC1918_GROUP, "members": [item[0] for item in RFC1918]})
        self._ensure("show-access-rule", "add-access-rule", {
            "layer": ACCESS_LAYER, "position": "top", "name": EAST_WEST_RULE,
            "source": RFC1918_GROUP, "destination": RFC1918_GROUP, "action": "Accept",
            "track": {"type": "Log"}, "install-on": install_on})
        self._ensure("show-access-rule", "add-access-rule", {
            "layer": ACCESS_LAYER, "position": {"below": EAST_WEST_RULE}, "name": EGRESS_RULE,
            "source": RFC1918_GROUP, "destination": RFC1918_GROUP, "destination-negate": True,
            "action": "Accept", "track": {"type": "Log"}, "install-on": install_on})
        rulebase = self.api.call("show-access-rulebase", {"name": ACCESS_LAYER, "limit": 50})
        rules = [rule for rule in rulebase.get("rulebase", []) if isinstance(rule, dict)
                 and rule.get("type") == "access-rule"]
        if not rules or rules[-1].get("name") in (EAST_WEST_RULE, EGRESS_RULE):
            raise CheckpointGaiaError("Missing access cleanup rule")
        if not self.admin_sources:
            self.api.call("set-access-rule", {"layer": ACCESS_LAYER, "uid": rules[-1]["uid"],
                                              "action": "Drop", "track": {"type": "Log"}})
        else:
            # The rulebase API normally returns the action as a UID resolved through objects-dictionary.
            action = rules[-1].get("action")
            if isinstance(action, str):
                action = next((item for item in rulebase.get("objects-dictionary", [])
                               if isinstance(item, dict) and item.get("uid") == action), None)
            if not isinstance(action, dict) or action.get("name") != "Drop":
                raise CheckpointGaiaError("Admin access requires an existing drop cleanup rule")
        nat = self.api.call("show-nat-rulebase", {"package": POLICY_PACKAGE, "limit": 50})
        names = {rule.get("name") for rule in nat.get("rulebase", []) if isinstance(rule, dict)}
        if NO_NAT_RULE not in names:
            self.api.call("add-nat-rule", {
                "package": POLICY_PACKAGE, "position": "top", "name": NO_NAT_RULE, "method": "static",
                "original-source": RFC1918_GROUP, "original-destination": RFC1918_GROUP,
                "install-on": install_on, "enabled": True})
        self.api.publish(self._deadline(600))
        task = self.api.call("install-policy", {"policy-package": POLICY_PACKAGE, "access": True,
                                                "threat-prevention": False, "targets": self.gateway_names})
        self.api.wait_task(task.get("task-id", ""), self._deadline(1800))
        self.log("policy-installed")

    def _run_script(self, name: str, script: str, target: str | None = None) -> str:
        data = self.api.call("run-script", {"script-name": name, "script": script,
                                           "targets": [target or self.gateway]})
        tasks = data.get("tasks")
        task_id = tasks[0].get("task-id") if isinstance(tasks, list) and tasks and isinstance(tasks[0], dict) else None
        if not isinstance(task_id, str):
            raise CheckpointGaiaError("Management run-script returned no task")
        task = self.api.wait_task(task_id, self._deadline(600))
        details = task.get("task-details")
        message = details[0].get("responseMessage", "") if isinstance(details, list) and details else ""
        try:
            return base64.b64decode(message).decode("utf-8", "replace") if message else ""
        except ValueError:
            return ""

    def ensure_bgp(self) -> BgpStatus:
        for gateway in self.gateways:
            script = (bgp_script(self.peers, self.peer_asn, gateway.frontend_ip, self.next_hop) if self.scale_set
                      else bgp_script(self.peers, self.peer_asn))
            output = self._run_script("faas-bgp", script, target=gateway.name)
            if "faas-bgp-configured" not in output:
                failed = sorted({int(item) for item in re.findall(r"faas-step-failed (\d{1,2})", output)})
                raise CheckpointGaiaError("BGP configuration failed: steps " + ",".join(map(str, failed)))
        deadline = self._deadline(600)
        while True:
            statuses = [parse_bgp_peers(self._run_script("faas-bgp-status", BGP_STATUS_SCRIPT, target=name),
                                        self.peers) for name in self.gateway_names]
            status = BgpStatus(sum(item.configured for item in statuses), sum(item.established for item in statuses))
            if (all(item.established == len(self.peers) for item in statuses)
                    or self.clock() >= deadline):
                self.log(f"bgp-peers configured={status.configured} established={status.established}")
                return status
            self.sleep(30)

    def ensure_peering_routes(self) -> BgpStatus:
        script = (
            '#!/bin/bash\nset -euo pipefail\n'
            'clish -c "set static-route default nexthop gateway address 172.22.10.1 on"\n'
            'clish -c "set static-route 10.211.0.0/16 nexthop gateway address 172.22.20.1 on"\n'
            'clish -c "set static-route 10.212.0.0/16 nexthop gateway address 172.22.20.1 on"\n'
            'clish -c "save config"\necho faas-peering-routes-configured\n'
        )
        for gateway in self.gateways:
            output = self._run_script("faas-peering-routes", script, target=gateway.name)
            if "faas-peering-routes-configured" not in output.splitlines():
                raise CheckpointGaiaError("Peering static route configuration failed")
        self.log("peering-static-routes-configured")
        return BgpStatus(0, 0)

    def run(self) -> BgpStatus:
        self.api.login(self.password, self._deadline(5400), self.sleep)
        self.log("management-ready")
        try:
            self.ensure_gateway()
            self.ensure_management_logging()
            self.ensure_policy()
            return self.ensure_peering_routes() if self.connectivity_mode == "peering" else self.ensure_bgp()
        finally:
            self.api.discard_and_logout()
