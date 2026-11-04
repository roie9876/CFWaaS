import base64
import io
import json
import tempfile
import unittest
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import ipsec_lab as lab
from ipsec_guest import block_script, bootstrap, metrics_script, ping_script, prefer_tunnel_script, tunnel_script


ACCOUNTS = {
    "A": {"tenant": str(uuid.UUID(int=1)), "subscription": str(uuid.UUID(int=2))},
    "B": {"tenant": str(uuid.UUID(int=3)), "subscription": str(uuid.UUID(int=4))},
}


def config():
    return json.loads((Path(__file__).resolve().parent / "config.example.json").read_text())


def approved_plan(settings):
    return {"meta": {
        "status": "approved", "executionApproved": True, "retention": "keep",
        "configFingerprint": lab.fingerprint(settings), "accountProfiles": ACCOUNTS,
    }}


class IpsecTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(lab, "ACCOUNTS", ACCOUNTS))

    def experiment(self, directory, settings=None):
        settings = settings or config()
        run = "20000101-000000-000000"
        state = {
            "runId": run, "groups": lab.scopes(run), "stages": {},
            "configFingerprint": lab.fingerprint(settings), "accountProfiles": ACCOUNTS,
            "deadlineEpoch": 9999999999, "retention": "keep",
        }
        return lab.Experiment(Path(directory), state, settings, approved_plan(settings))

    def test_fixed_isolated_topology_and_usable_private_addresses(self):
        settings = lab.validate_config(config())
        self.assertEqual([node["account"] for node in settings["nodes"]], ["A", "B", "B"])
        self.assertEqual(sum(node["firewall"] for node in settings["nodes"]), 1)
        for modify in (
            lambda value: value.update(region="another-region"),
            lambda value: value.update(gatewayScaleUnit=10),
            lambda value: value["nodes"][1].update(privateIp="10.151.0.1"),
            lambda value: value["nodes"][2].update(prefix="10.151.0.0/16"),
            lambda value: value["nodes"][0].update(account="B"),
        ):
            changed = config()
            modify(changed)
            with self.subTest(change=modify), self.assertRaises(ValueError):
                lab.validate_config(changed)

    def test_execution_requires_approval_billing_retention_and_exact_profile(self):
        settings = config()
        plan = approved_plan(settings)
        lab.execution_gate(settings, plan, True)
        for name, value in (
            ("executionApproved", False), ("retention", "unspecified"),
            ("accountProfiles", {}), ("configFingerprint", "different"),
        ):
            changed = approved_plan(settings)
            changed["meta"][name] = value
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                lab.execution_gate(settings, changed, True)
        with self.assertRaises(RuntimeError):
            lab.execution_gate(settings, plan, False)

    def test_default_mode_is_offline_without_private_configuration_or_azure_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".azure").mkdir()
            (root / "config.example.json").write_text(json.dumps(config()))
            (root / ".azure/infrastructure-plan.json").write_text(json.dumps({"meta": {"executionApproved": False}}))
            with patch.object(lab, "ROOT", root), patch("sys.argv", ["ipsec_lab.py"]), patch.object(
                lab.Arm, "request",
            ) as request, redirect_stdout(io.StringIO()) as output:
                self.assertEqual(lab.main(), 0)
            request.assert_not_called()
            self.assertIn("OFFLINE", output.getvalue())
            self.assertFalse((root / "results").exists())

    def test_resume_cannot_retarget_account_or_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            experiment = self.experiment(directory)
            lab.validate_resume(experiment.state, experiment.config)
            for key, value in (("groups", {}), ("accountProfiles", {}), ("configFingerprint", "changed")):
                with self.subTest(key=key), self.assertRaises(ValueError):
                    lab.validate_resume({**experiment.state, key: value}, experiment.config)

    def test_branch_uses_default_for_return_and_only_inspect_for_propagation(self):
        properties = lab.vpn_body("/site", "/default", "/inspect", "fixture")["properties"]
        self.assertNotIn("sharedKey", properties)
        self.assertEqual(properties["routingConfiguration"], {
            "associatedRouteTable": {"id": "/default"},
            "propagatedRouteTables": {"ids": [{"id": "/inspect"}], "labels": ["ipsec-inspection"]},
        })
        link = properties["vpnLinkConnections"][0]["properties"]
        self.assertEqual(link["sharedKey"], "fixture")
        self.assertEqual(link["vpnConnectionProtocolType"], "IKEv2")
        self.assertFalse(link["usePolicyBasedTrafficSelectors"])
        self.assertFalse(link["enableBgp"])
        policy = link["ipsecPolicies"][0]
        self.assertEqual((policy["ikeEncryption"], policy["ikeIntegrity"], policy["dhGroup"]), ("AES256", "SHA256", "DHGroup14"))
        self.assertEqual(policy["pfsGroup"], "PFS14")

    def test_workloads_propagate_only_to_default_and_switch_their_association(self):
        for inspect in (False, True):
            value = lab.routing("/default", "/inspect", inspect)
            self.assertEqual(value["associatedRouteTable"]["id"], "/inspect" if inspect else "/default")
            self.assertEqual(value["propagatedRouteTables"]["ids"], [{"id": "/default"}])
            self.assertEqual(value["propagatedRouteTables"]["labels"], ["Default"])

    def test_both_actual_public_gateway_peers_are_required(self):
        def response(values):
            return {"properties": {"bgpSettings": {"bgpPeeringAddresses": [{"tunnelIpAddresses": values}]}}}
        self.assertEqual(lab.gateway_peers(response(["8.8.8.8", "9.9.9.9"])), ["8.8.8.8", "9.9.9.9"])
        for values in ([], ["8.8.8.8"], ["10.0.0.1", "169.254.1.1"], ["8.8.8.8", "8.8.8.8"]):
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                lab.gateway_peers(response(values))

    def test_effective_route_selection_does_not_accept_a_less_specific_proxy(self):
        broad = {"addressPrefixes": ["10.0.0.0/8"], "nextHops": ["/vpn"]}
        specific = {"addressPrefixes": ["10.151.0.0/24"], "nextHops": ["/direct"]}
        effective = {"value": [broad, specific]}
        self.assertEqual(lab.winning_route(effective, "10.151.0.4"), specific)
        self.assertFalse(lab.has_next_hop(specific, ["/vpn"]))
        self.assertTrue(lab.has_next_hop(specific, ["/DIRECT/"]))
        with self.assertRaises(RuntimeError):
            lab.winning_route({"value": []}, "10.151.0.4")
        with self.assertRaises(RuntimeError):
            lab.winning_route({"value": [specific, {**specific, "nextHops": ["/wrong"]}]}, "10.151.0.4")

    def test_evidence_redacts_vpn_keys_and_guest_parameters_and_scripts(self):
        with tempfile.TemporaryDirectory() as directory:
            experiment = self.experiment(directory)
            arm = experiment.arm
            arm.record({
                "url": "https://management.azure.com/owned/runCommand?api-version=fixture",
                "requestBody": {
                    "commandId": "RunShellScript", "script": ["configure " + experiment.key],
                    "parameters": [{"name": "psk", "value": experiment.key}],
                },
                "responseBody": {"sharedKey": experiment.key, "other": base64.b64encode(experiment.key.encode()).decode()},
            })
            text = (Path(directory) / "events.jsonl").read_text()
            self.assertNotIn(experiment.key, text)
            self.assertNotIn(base64.b64encode(experiment.key.encode()).decode(), text)
            self.assertNotIn("configure ", text)
            self.assertIn("[REDACTED]", text)
            self.assertEqual((Path(directory) / ".secrets.json").stat().st_mode & 0o777, 0o600)

    def test_guest_execution_rejects_a_foreign_vm_before_network_access(self):
        with tempfile.TemporaryDirectory() as directory:
            experiment = self.experiment(directory)
            experiment.state["vmIds"] = {"ipsec-fw": "/foreign/vm"}
            with patch.object(experiment.arm, "request") as request, self.assertRaises(RuntimeError):
                experiment.command(experiment.nodes[0], ["true"])
            request.assert_not_called()

    def test_group_ownership_is_required_for_cleanup_or_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            experiment = self.experiment(directory)
            with patch.object(experiment.arm, "request", return_value=(200, {}, {"tags": {"purpose": "unrelated"}})):
                with self.assertRaises(RuntimeError):
                    experiment.owned("B")

    def test_http_never_passes_incomplete_wrong_host_or_nat_source(self):
        with tempfile.TemporaryDirectory() as directory:
            experiment = self.experiment(directory)
            for rows in ([], [{"ok": True, "test": "wrong"}]):
                with patch.object(experiment, "command", return_value={"value": [{
                    "message": "FAAS_RESULT_BEGIN\n" + json.dumps(rows) + "\nFAAS_RESULT_END",
                }]}), self.assertRaises(RuntimeError):
                    experiment.http("fixture", True)

    def test_no_implicit_identity_host_feature_or_workload_route_tables(self):
        root = Path(__file__).resolve().parent / "infra"
        vm = (root / "modules/vm.bicep").read_text()
        network = (root / "modules/network.bicep").read_text()
        self.assertNotIn("encryptionAtHost", vm)
        self.assertNotIn("identity:", vm)
        self.assertIn("TrustedLaunch", vm)
        self.assertNotIn("Microsoft.Network/routeTables", network)
        self.assertNotIn("virtualNetworkPeerings", network)
        self.assertIn("defaultOutboundAccess: false", network)

    def test_guest_scripts_compile_and_do_not_embed_a_vpn_key(self):
        scripts = [
            metrics_script(), block_script(True), block_script(False),
            ping_script("10.151.0.4"), prefer_tunnel_script(1, ["10.151.0.0/16"]),
        ]
        for script in scripts:
            compile(script[1], "<guest-script>", "exec")
        protected = tunnel_script("172.26.10.4", "8.8.8.8", ["1.1.1.1", "9.9.9.9"], ["10.151.0.0/16", "10.152.0.0/16"])
        compile(protected[2], "<tunnel-script>", "exec")
        self.assertIn('key = sys.argv[1]', protected[2])
        self.assertIn("if_id_in", protected[2])
        self.assertIn("if_id_out", protected[2])
        self.assertIn("install_routes_xfrmi = no", protected[2])
        self.assertIn("aes256-sha256-modp2048", protected[2])
        self.assertNotIn("MASQUERADE", protected[2])
        self.assertNotIn("SNAT", protected[2])
        self.assertIn('"--dport", "8080"', protected[2])

    def test_metrics_require_both_established_children_and_actual_packet_counters(self):
        text = "\n".join(
            "azure-" + str(index) + ": #1, ESTABLISHED, IKEv2\n"
            " net: #1, reqid 1, INSTALLED, TUNNEL\n"
            " in  abc12345, 120 bytes, 3 packets\n"
            " out def12345, 240 bytes, 4 packets"
            for index in (0, 1)
        )
        table = "Chain IV_COUNT\n pkts bytes target\n 20 1200 RETURN\n"
        annotated = text.replace("abc12345,", "abc12345 (-|0x0000002a),").replace("def12345,", "def12345 (-|0x0000002a),")
        deleting = annotated.replace("azure-0: #1, ESTABLISHED", "azure-0: #1, DELETING")
        for sas, ready in ((text, True), (annotated, True), (deleting, False), (text.replace("azure-1", "unrelated"), False)):
            with patch("subprocess.check_output", side_effect=[sas, table]), redirect_stdout(io.StringIO()) as output:
                exec(compile(metrics_script()[1], "<metrics-fixture>", "exec"), {})
            payload = lab.extract_guest_result({"value": [{"message": output.getvalue()}]})[0]
            self.assertEqual(payload["ok"], ready)
            self.assertEqual(payload["synCount"], 20)
            if ready:
                self.assertEqual(payload["tunnelCounters"]["1"]["outPackets"], 4)

    def test_workload_bootstrap_does_not_need_package_downloads(self):
        self.assertNotIn("apt-get", bootstrap(False))
        self.assertIn("ThreadingHTTPServer", bootstrap(False))
        self.assertIn("strongswan-swanctl", bootstrap(True))
        self.assertNotIn("PRIVATE KEY", bootstrap(True))


if __name__ == "__main__":
    unittest.main()
