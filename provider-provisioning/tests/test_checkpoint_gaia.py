import base64
import subprocess

import pytest

from service import checkpoint_gaia as gaia


PEERS = ("172.20.254.4", "172.20.254.5")
MANAGEMENT = "cp-management-00000000"


def test_tls_pin_trusts_first_use_only_when_allowed_and_then_enforces():
    stored = []
    pin = gaia.TlsPin(lambda: None, stored.append)
    with pytest.raises(gaia.CheckpointGaiaError, match="not pinned"):
        pin.check(b"cert-a", allow_first_use=False)
    pin.check(b"cert-a", allow_first_use=True)
    assert len(stored) == 1 and len(stored[0]) == 64
    pin.check(b"cert-a", allow_first_use=False)
    with pytest.raises(gaia.CheckpointGaiaError, match="does not match"):
        pin.check(b"cert-b", allow_first_use=True)
    reloaded = gaia.TlsPin(lambda: stored[0], lambda _value: pytest.fail("must not re-pin"))
    with pytest.raises(gaia.CheckpointGaiaError, match="does not match"):
        reloaded.check(b"cert-b", allow_first_use=True)


def test_bgp_script_mirrors_simulator_without_per_vnet_or_nat_commands():
    script = gaia.bgp_script(PEERS, 65515)
    assert "set as 65050" in script
    assert "set static-route 172.20.254.0/26 nexthop gateway address 172.22.10.1 on" in script
    for peer in PEERS:
        assert f"peer {peer} multihop on" in script and f"peer {peer} accept-routes none" in script
    assert "from static-route default on" in script and "save config" in script
    assert "nat" not in script.lower() and "10.0.0.0" not in script
    with pytest.raises(gaia.CheckpointGaiaError):
        gaia.bgp_script(("8.8.8.8", PEERS[1]), 65515)
    with pytest.raises(gaia.CheckpointGaiaError):
        gaia.bgp_script(PEERS, 65000)


def test_parse_bgp_peers_counts_only_expected_peers():
    output = ("Peer ID  AS  Routes  ActRts  State  InUpds  OutUpds  Uptime\n"
              "172.20.254.4  65515  0  0  Established  1  1  00:01:00\n"
              "172.20.254.5  65515  0  0  Active  0  0  00:00:00\n"
              "10.9.9.9  65515  0  0  Established  0  0  00:00:00\n")
    assert gaia.parse_bgp_peers(output, PEERS) == gaia.BgpStatus(configured=2, established=1)


@pytest.mark.parametrize("route_status,save_status", [(0, 0), (1, 0), (0, 1)])
def test_management_route_script_only_reports_success_after_route_and_save(route_status, save_status):
    mock = ('clish() {\n'
            f'  if [ "$2" = "save config" ]; then return {save_status}; fi\n'
            f'  return {route_status}\n'
            '}\n')
    result = subprocess.run(["bash"], input=mock + gaia.MANAGEMENT_ROUTE_SCRIPT,
                            text=True, capture_output=True, check=False)
    if route_status or save_status:
        assert result.returncode != 0 and not result.stdout
    else:
        assert result.returncode == 0 and result.stdout == "faas-management-route-configured\n"


class FakeApi:
    def __init__(self, sic_states):
        self.calls, self.objects, self.sic_states = [], set(), list(sic_states)
        self.rules = [{"type": "access-rule", "name": "Cleanup rule", "uid": "cleanup"}]
        self.host = {"name": MANAGEMENT, "ipv4-address": "203.0.113.4"}
        self.log_servers = [{"name": MANAGEMENT, "uid": "management-uid"}]
        self.requests = []

    def login(self, password, deadline, sleep):
        self.calls.append(("login",))

    def publish(self, deadline):
        self.calls.append(("publish",))

    def wait_task(self, task_id, deadline, sleep=None):
        self.calls.append(("wait", task_id))
        if task_id == "bgp":
            return {"task-details": [{"responseMessage": base64.b64encode(b"faas-bgp-configured\n").decode()}]}
        if task_id == "status":
            table = "".join(f"{peer} 65515 0 0 Established 1 1 0\n" for peer in PEERS)
            return {"task-details": [{"responseMessage": base64.b64encode(table.encode()).decode()}]}
        if task_id == "route":
            return {"task-details": [{"responseMessage": base64.b64encode(
                b"faas-management-route-configured\n").decode()}]}
        return {}

    def discard_and_logout(self):
        self.calls.append(("logout",))

    def call(self, command, body, allowed=()):
        self.calls.append((command, body.get("name")))
        self.requests.append((command, body))
        if command == "show-simple-gateway":
            if "gateway" not in self.objects:
                return {"code": "generic_err_object_not_found"}
            return {"sic-state": self.sic_states.pop(0) if self.sic_states else "communicating",
                    "logs-settings": {"send-logs-to-server": list(self.log_servers)}}
        if command == "show-checkpoint-host":
            return dict(self.host)
        if command == "set-checkpoint-host":
            self.host.update(body)
        elif command == "set-simple-gateway":
            self.log_servers = list(body["logs-settings"]["send-logs-to-server"])
        if command == "add-simple-gateway":
            self.objects.add("gateway")
        elif command == "delete-simple-gateway":
            self.objects.discard("gateway")
        elif command.startswith("show-") and command not in ("show-access-rulebase", "show-nat-rulebase"):
            return {} if body["name"] in self.objects else {"code": "generic_err_object_not_found"}
        elif command.startswith("add-"):
            self.objects.add(body["name"])
            if command == "add-access-rule":
                self.rules.insert(0, {"type": "access-rule", "name": body["name"], "uid": body["name"]})
        elif command == "show-access-rulebase":
            return {"rulebase": list(self.rules)}
        elif command == "show-nat-rulebase":
            return {"rulebase": []}
        elif command == "install-policy":
            return {"task-id": "install"}
        elif command == "install-database":
            return {"tasks": [{"task-id": "database"}]}
        elif command == "run-script":
            task = {"faas-bgp": "bgp", "faas-bgp-status": "status", "faas-management-route": "route"}
            return {"tasks": [{"task-id": task[body["script-name"]]}]}
        return {}


def configurator(api, logs):
    return gaia.CheckpointConfigurator(api, "00000000-0000-0000-0000-000000000004", "s" * 48, "P" * 16,
                                       PEERS, 65515, logs.append, sleep=lambda _seconds: None)


def test_configurator_creates_gateway_policy_and_bgp_in_order():
    api, logs = FakeApi(["communicating"]), []
    status = configurator(api, logs).run()
    assert status == gaia.BgpStatus(2, 2)
    commands = [call[0] for call in api.calls]
    assert commands.index("add-simple-gateway") < commands.index("install-database") < commands.index("install-policy")
    assert api.calls.index(("wait", "database")) < commands.index("install-policy")
    assert ("add-nat-rule", gaia.NO_NAT_RULE) in api.calls
    assert ("set-access-rule", None) in api.calls and commands[-1] == "logout"
    assert logs == ["management-ready", "gateway-sic-communicating", "management-logging-configured", "policy-installed",
                    "bgp-peers configured=2 established=2"]


def test_configurator_recreates_gateway_until_sic_communicates():
    api, logs = FakeApi(["uninitialized", "communicating"]), []
    configurator(api, logs).run()
    commands = [call[0] for call in api.calls]
    assert commands.count("add-simple-gateway") == 2 and commands.count("delete-simple-gateway") == 1
    assert "gateway-sic-retry" in logs


def test_configurator_is_idempotent_for_existing_objects():
    api = FakeApi([])
    api.objects |= {"gateway", *(name for name, _subnet, _mask in gaia.RFC1918), gaia.RFC1918_GROUP,
                    gaia.EAST_WEST_RULE, gaia.EGRESS_RULE}
    configurator(api, []).run()
    commands = [call[0] for call in api.calls]
    assert not any(command.startswith("add-") and command != "add-nat-rule" for command in commands)


def test_management_logging_accepts_real_r82_top_level_destinations():
    gateway = {
        "send-logs-to-server": ["cp-management-example"],
        "logs-settings": {"forward-logs-to-log-server": False},
    }
    assert gaia.CheckpointConfigurator._log_servers(gateway) == ["cp-management-example"]
    gateway["send-logs-to-server"] = [{"name": "cp-management-example"}]
    assert gaia.CheckpointConfigurator._log_servers(gateway) == ["cp-management-example"]


def test_management_logging_repairs_only_exact_host_and_saves_private_route():
    api, logs = FakeApi([]), []
    api.objects.add("gateway")
    runner = configurator(api, logs)
    runner.ensure_management_logging()
    assert ("set-checkpoint-host", {"name": MANAGEMENT, "ipv4-address": gaia.MANAGEMENT_IP}) in api.requests
    mutations = [(command, body) for command, body in api.requests if command.startswith(("set-", "add-", "delete-"))]
    assert mutations == [("set-checkpoint-host", {"name": MANAGEMENT, "ipv4-address": gaia.MANAGEMENT_IP})]
    assert ("install-database", {"targets": [MANAGEMENT]}) in api.requests
    script = next(body for command, body in api.requests if command == "run-script")
    assert script["targets"] == [runner.gateway]
    assert script["script-name"] == "faas-management-route"
    assert ('clish -c "set static-route 172.22.30.0/24 nexthop gateway address 172.22.10.1 on"'
            ' >/dev/null 2>&1 || exit 1') in script["script"]
    assert 'clish -c "save config" >/dev/null 2>&1 || exit 1' in script["script"]
    assert "nat" not in script["script"].lower()
    commands = [call[0] for call in api.calls]
    assert commands.index("set-checkpoint-host") < commands.index("publish") < commands.index("install-database")
    assert api.calls.index(("wait", "route")) < commands.index("install-database")
    assert ("wait", "database") in api.calls
    assert logs == ["management-logging-configured"]


def test_management_logging_preserves_other_destinations_and_is_idempotent():
    api, logs = FakeApi([]), []
    api.objects.add("gateway")
    api.host["ipv4-address"] = gaia.MANAGEMENT_IP
    api.log_servers = [{"name": "user-log-server", "uid": "user-server"}, "another-log-server"]
    rules = list(api.rules)
    runner = configurator(api, logs)
    runner.ensure_management_logging()
    runner.ensure_management_logging()
    updates = [(command, body) for command, body in api.requests if command.startswith(("set-", "add-", "delete-"))]
    assert updates == [("set-simple-gateway", {
        "name": runner.gateway, "logs-settings": {
            "send-logs-to-server": ["user-log-server", "another-log-server", MANAGEMENT]}})]
    assert [call[0] for call in api.calls].count("publish") == 1
    assert [call[0] for call in api.calls].count("install-database") == 2
    assert api.rules == rules
    assert logs == ["management-logging-configured"] * 2


def test_management_logging_unchanged_objects_still_install_database_on_retry():
    api = FakeApi([])
    api.objects.add("gateway")
    api.host["ipv4-address"] = gaia.MANAGEMENT_IP
    configurator(api, []).ensure_management_logging()
    commands = [call[0] for call in api.calls]
    assert not any(command.startswith(("set-", "add-", "delete-")) for command in commands)
    assert "publish" not in commands
    assert ("wait", "database") in api.calls


def test_management_logging_waits_for_every_database_task():
    class MultipleTasksApi(FakeApi):
        def call(self, command, body, allowed=()):
            result = super().call(command, body, allowed)
            if command == "install-database":
                return {"tasks": [{"task-id": "database-1"}, {"task-id": "database-2"}]}
            return result

    api = MultipleTasksApi([])
    api.objects.add("gateway")
    configurator(api, []).ensure_management_logging()
    waits = [call for call in api.calls if call[0] == "wait"]
    assert waits == [("wait", "route"), ("wait", "database-1"), ("wait", "database-2")]


@pytest.mark.parametrize("response", [
    {}, {"task-id": "not-the-install-database-contract"}, {"tasks": []}, {"tasks": {}},
    {"tasks": [None]}, {"tasks": [{"task-id": ""}]}, {"tasks": [{"task-id": 1}]},
    {"tasks": [{"task-id": "database"}, {}]},
])
def test_management_logging_rejects_missing_database_tasks(response):
    class MissingTasksApi(FakeApi):
        def call(self, command, body, allowed=()):
            result = super().call(command, body, allowed)
            return response if command == "install-database" else result

    api, logs = MissingTasksApi([]), []
    api.objects.add("gateway")
    with pytest.raises(gaia.CheckpointGaiaError, match="install-database returned no tasks"):
        configurator(api, logs).ensure_management_logging()
    assert logs == []
    assert ("wait", "database") not in api.calls


@pytest.mark.parametrize("servers", [None, {}, [None], [{}], [""], [1]])
def test_management_logging_rejects_unverifiable_log_destinations(servers):
    api, logs = FakeApi([]), []
    api.objects.add("gateway")
    api.log_servers = servers
    # Return the malformed API value without normalizing it in the test double.
    original = api.call

    def malformed(command, body, allowed=()):
        if command == "show-simple-gateway":
            return {"logs-settings": {"send-logs-to-server": servers}}
        return original(command, body, allowed)

    api.call = malformed
    with pytest.raises(gaia.CheckpointGaiaError, match="Gateway log servers"):
        configurator(api, logs).ensure_management_logging()
    assert not any(command.startswith("set-") for command, _body in api.requests)
    assert logs == []


@pytest.mark.parametrize("broken", ["host", "gateway"])
def test_management_logging_requires_object_readback(broken):
    class UnchangedApi(FakeApi):
        def call(self, command, body, allowed=()):
            if command == ("set-checkpoint-host" if broken == "host" else "set-simple-gateway"):
                return {}
            return super().call(command, body, allowed)

    api, logs = UnchangedApi([]), []
    api.objects.add("gateway")
    api.log_servers = []
    with pytest.raises(gaia.CheckpointGaiaError, match="did not persist"):
        configurator(api, logs).ensure_management_logging()
    assert not any(command == "install-database" for command, _body in api.requests)
    assert logs == []


@pytest.mark.parametrize("output", [b"", b"faas-management-route-configured-but-failed\n"])
def test_management_logging_requires_route_success_marker(output):
    class FailedRouteApi(FakeApi):
        def wait_task(self, task_id, deadline, sleep=None):
            if task_id == "route":
                return {"task-details": [{"responseMessage": base64.b64encode(output).decode()}]}
            return super().wait_task(task_id, deadline, sleep)

    api, logs = FailedRouteApi([]), []
    api.objects.add("gateway")
    with pytest.raises(gaia.CheckpointGaiaError, match="route configuration failed"):
        configurator(api, logs).ensure_management_logging()
    assert not any(command == "install-database" for command, _body in api.requests)
    assert logs == []


def test_management_logging_database_failure_stops_policy_install_and_logs_out():
    class FailedDatabaseApi(FakeApi):
        def wait_task(self, task_id, deadline, sleep=None):
            if task_id == "database":
                raise gaia.CheckpointGaiaError("Management task failed")
            return super().wait_task(task_id, deadline, sleep)

    api, logs = FailedDatabaseApi([]), []
    api.objects.add("gateway")
    with pytest.raises(gaia.CheckpointGaiaError, match="Management task failed"):
        configurator(api, logs).run()
    commands = [call[0] for call in api.calls]
    assert "install-policy" not in commands
    assert not any(command.startswith(("delete-", "add-")) for command in commands)
    assert commands[-1] == "logout"
    assert "management-logging-configured" not in logs
