import io
import json
import tempfile
import unittest
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

import deploy
from checkpoint import Client, CheckPointError, cme_path, create_policy, gateway_uids
from checkpoint import ingress_body, negative_control, provision_body
from run_measurements import extract_results, script

TEST_ACCOUNTS = {
    "A": {"tenant": str(uuid.UUID(int=1)), "subscription": str(uuid.UUID(int=2))},
    "B": {"tenant": str(uuid.UUID(int=3)), "subscription": str(uuid.UUID(int=4))},
}


def config():
    settings = json.loads((Path(__file__).resolve().parent / "config.example.json").read_text())
    for account, role in (("A", "provider"), ("B", "customer")):
        settings[role]["tenantId"] = TEST_ACCOUNTS[account]["tenant"]
        settings[role]["subscriptionId"] = TEST_ACCOUNTS[account]["subscription"]
    return settings


def nva_response(settings):
    group = (
        "/subscriptions/" + settings["provider"]["subscriptionId"]
        + "/resourceGroups/" + settings["provider"]["managedResourceGroup"]
    )
    return {"value": [{
        "id": group + "/providers/Microsoft.Network/networkVirtualAppliances/" + settings["cloudguard"]["nvaName"],
        "name": settings["cloudguard"]["nvaName"],
        "properties": {
            "virtualHub": {"id": deploy.hub_id(settings)}, "nvaSku": {"vendor": "checkpoint"},
            "provisioningState": "Succeeded",
            "virtualApplianceNics": [
                {"instanceName": "actual-instance-a", "privateIpAddress": "10.250.0.5", "publicIpAddress": "8.8.8.8"},
                {"instanceName": "actual-instance-b", "privateIpAddress": "10.250.0.6", "publicIpAddress": "9.9.9.9"},
            ],
        },
    }]}


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(deploy, "ACCOUNTS", TEST_ACCOUNTS))
        self.enterContext(patch.object(deploy, "load_inputs", return_value=(
            config(), {"meta": {"status": "draft", "executionApproved": False}},
        )))

    def test_default_is_offline_and_persisted_execution_is_disabled(self):
        with patch("sys.argv", ["deploy.py"]), patch.object(deploy, "azure") as azure, patch.object(
            deploy.Arm, "request",
        ) as arm, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(deploy.main(), 0)
        azure.assert_not_called()
        arm.assert_not_called()
        result = json.loads(output.getvalue())
        self.assertIn("OFFLINE", result["mode"])
        self.assertFalse(result["deploymentEnabled"])
        self.assertFalse(result["executionApproved"])

    def test_requires_both_persisted_approval_and_explicit_billing_ack(self):
        settings = config()
        plan = {"meta": {"status": "approved", "executionApproved": False}}
        with self.assertRaises(RuntimeError):
            deploy.execution_gate(settings, plan, True)
        settings["deploymentEnabled"] = True
        with self.assertRaises(RuntimeError):
            deploy.execution_gate(settings, plan, True)
        plan["meta"]["executionApproved"] = True
        with self.assertRaises(RuntimeError):
            deploy.execution_gate(settings, plan, False)
        deploy.execution_gate(settings, plan, True)

    def test_execute_cannot_reach_azure_with_the_shipped_configuration(self):
        with patch("sys.argv", [
            "deploy.py", "--execute", "--stage", "foundation", "--acknowledge-billing",
        ]), patch.object(deploy, "azure") as azure, patch.object(deploy.Arm, "request") as arm:
            with self.assertRaisesRegex(RuntimeError, "Deployment is disabled"):
                deploy.main()
        azure.assert_not_called()
        arm.assert_not_called()

    def test_approved_account_pins_are_not_swappable(self):
        settings = config()
        deploy.validate_config(settings)
        settings["provider"]["subscriptionId"] = settings["customer"]["subscriptionId"]
        with self.assertRaises(ValueError):
            deploy.validate_config(settings)

    def test_rejects_overlaps_reserved_addresses_and_ipv6(self):
        changes = [
            ("overlap", lambda c: c["spokes"][1].update(c["spokes"][0], name="spoke2")),
            ("reserved", lambda c: c["spokes"][0].update(privateIp="10.10.0.1")),
            ("ipv6", lambda c: c["spokes"][0].update(
                addressPrefix="fd00::/48", subnetPrefix="fd00::/64", privateIp="fd00::4",
            )),
        ]
        for name, modify in changes:
            with self.subTest(name=name):
                settings = config()
                modify(settings)
                with self.assertRaises(ValueError):
                    deploy.validate_config(settings)

    def test_image_version_cannot_be_latest_or_a_different_gaia_release(self):
        for version in ("latest", "8120.900634.1641"):
            settings = config()
            settings["cloudguard"]["imageVersion"] = version
            with self.assertRaises(ValueError):
                deploy.validate_config(settings)

    def test_operator_and_ingress_never_allow_the_whole_internet(self):
        for cidr in ("0.0.0.0/0", "10.10.0.4/32", "1.1.1.0/24", "::/0"):
            with self.assertRaises(ValueError):
                deploy.operator_cidr(cidr)
        self.assertEqual(deploy.operator_cidr("1.1.1.1/32"), "1.1.1.1/32")
        body = ingress_body("1.1.1.1/32", "8.8.8.8")
        self.assertEqual(body["rules"][0]["original_source"], "1.1.1.1/32")
        self.assertEqual(body["rules"][0]["original_ports"], ["18080"])
        self.assertEqual(body["rules"][0]["lb_public_ips"], ["8.8.8.8"])

    def test_connections_belong_to_a_but_reference_b_vnets(self):
        settings = config()
        body = deploy.connection_body(settings, settings["spokes"][0])
        self.assertIn(settings["customer"]["subscriptionId"], body["properties"]["remoteVirtualNetwork"]["id"])
        self.assertIn(settings["provider"]["subscriptionId"], deploy.hub_id(settings))
        self.assertTrue(body["properties"]["enableInternetSecurity"])
        self.assertNotIn("vnetRoutes", json.dumps(body))

    def test_connections_cannot_be_added_before_security_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            state = {"runId": "test", "stages": {}}
            deployment = deploy.Deployment(config(), Path(directory) / "state.json", state)
            with patch.object(deployment.arm, "request") as arm, self.assertRaises(RuntimeError):
                deployment.connect()
            arm.assert_not_called()

    def test_later_stages_recheck_ownership_instead_of_trusting_stale_state(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = deploy.Deployment(config(), Path(directory) / "state.json", {
                "runId": "test", "stages": {"foundation": True},
            })
            with patch.object(deployment, "owned_groups", return_value={"A": True, "B": False}):
                with self.assertRaisesRegex(RuntimeError, "Both exact run-owned"):
                    deployment.require("foundation")

    def test_nva_is_discovered_from_actual_hub_vendor_and_instance_addresses(self):
        settings = config()
        found = deploy.discover_nva(settings, nva_response(settings))
        self.assertEqual(found["instanceCount"], 2)
        self.assertEqual(found["publicSources"], ["8.8.8.8/32", "9.9.9.9/32"])
        self.assertIn("10.250.0.5", found["addresses"])
        for field, value in (("nvaSku", {"vendor": "ordinary-ubuntu"}), ("virtualHub", {"id": "/another-hub"})):
            response = nva_response(settings)
            response["value"][0]["properties"][field] = value
            with self.assertRaises(RuntimeError):
                deploy.discover_nva(settings, response)

    def test_nva_inventory_without_public_management_addresses_is_not_silently_accepted(self):
        settings = config()
        response = nva_response(settings)
        for nic in response["value"][0]["properties"]["virtualApplianceNics"]:
            nic["publicIpAddress"] = ""
        with self.assertRaises(RuntimeError):
            deploy.discover_nva(settings, response)

    def test_fingerprint_changes_for_topology_but_not_execution_flag(self):
        settings = config()
        original = deploy.fingerprint(settings)
        settings["deploymentEnabled"] = True
        self.assertEqual(deploy.fingerprint(settings), original)
        settings["hub"]["name"] += "-different"
        self.assertNotEqual(deploy.fingerprint(settings), original)

    def test_positive_measurement_requires_hostname_and_preserved_private_source(self):
        tests = [{"name": "ew", "hostname": "vm-spoke2", "clientIp": "10.10.0.4", "blockDuringNegative": True}]
        result = [{"name": "ew", "ok": True, "body": {"hostname": "vm-spoke2", "client_ip": "10.10.0.4"}}]
        self.assertTrue(deploy.evaluate_measurements(tests, result, True)[0]["passed"])
        result[0]["body"]["client_ip"] = "10.250.0.5"
        self.assertFalse(deploy.evaluate_measurements(tests, result, True)[0]["passed"])

    def test_measured_result_count_and_names_must_match_the_full_requirement(self):
        tests = [{"name": "ew", "hostname": None, "blockDuringNegative": True},
                 {"name": "egress", "hostname": None, "blockDuringNegative": False}]
        for rows in (
            [{"name": "ew", "ok": True}],
            [{"name": "ew", "ok": True}, {"name": "ew", "ok": True}],
        ):
            with self.assertRaises(RuntimeError):
                deploy.evaluate_measurements(tests, rows, True)

    def test_http_errors_do_not_masquerade_as_a_firewall_negative_control(self):
        tests = [{"name": "ew", "hostname": None, "blockDuringNegative": True}]
        for kind in ("http", "transport"):
            result = [{"name": "ew", "ok": False, "errorKind": kind}]
            self.assertFalse(deploy.evaluate_measurements(tests, result, False)[0]["passed"])
        self.assertTrue(deploy.evaluate_measurements(
            tests, [{"name": "ew", "ok": False, "errorKind": "timeout"}], False,
        )[0]["passed"])

    def test_guest_output_must_be_framed_and_boolean(self):
        good = {"value": [{"message": 'FAAS_RESULT_BEGIN\n[{"name":"ew","ok":true}]\nFAAS_RESULT_END'}]}
        self.assertEqual(extract_results(good), [{"name": "ew", "ok": True}])
        for output in ({}, {"value": [{"message": "Enable succeeded"}]}, {
            "value": [{"message": 'FAAS_RESULT_BEGIN\n[{"name":"ew","ok":1}]\nFAAS_RESULT_END'}],
        }):
            with self.assertRaises(RuntimeError):
                extract_results(output)

    def test_guest_code_is_valid_python_and_test_strings_are_quoted(self):
        text = script([{"name": "quoted", "url": "https://www.microsoft.com/\"x", "hostname": None}])
        python = text.split("\n", 1)[1].rsplit("\nFAAS_PY", 1)[0]
        compile(python, "<measurement>", "exec")
        self.assertNotIn("apt-get", text)

    def test_cme_contract_matches_the_pinned_vendor_example(self):
        settings = config()
        path = cme_path(settings).format(operation="provision")
        self.assertIn("azure/virtualWANs/accounts/faas-provider/resourceGroups/", path)
        body = provision_body("abcdefghijkl", "FaaS-Lab")
        self.assertEqual(body["base64_sic_key"], "YWJjZGVmZ2hpamts")
        self.assertIs(body["autonomous_threat_prevention"], False)
        self.assertEqual(body["policy"], "FaaS-Lab")

    def test_cme_success_requires_its_real_request_and_terminal_status_shapes(self):
        client = object.__new__(Client)
        client.sensitive = []
        client.request = Mock(side_effect=[
            {"result": {"request-id": "request-1"}}, {"result": {"requestStatus": "Success"}},
        ])
        self.assertEqual(client.cme("test", {}), "request-1")
        client.request = Mock(return_value={"status": "success"})
        with self.assertRaises(CheckPointError):
            client.cme("test", {})
        client.request = Mock(side_effect=[
            {"result": {"request-id": "request-1"}}, {"result": {"requestStatus": "Failed"}},
        ])
        with self.assertRaises(CheckPointError):
            client.cme("test", {})

    def test_management_origin_must_be_https_and_resolve_to_the_actual_management_vm(self):
        with patch("checkpoint.socket.getaddrinfo", return_value=[(0, 0, 0, "", ("8.8.8.8", 443))]):
            for url in ("http://management.example", "https://user:password@management.example", "https://management.example/path"):
                with self.assertRaises(ValueError):
                    Client(url, "test-key", "8.8.8.8")
            with self.assertRaises(ValueError):
                Client("https://management.example", "test-key", "9.9.9.9")

    def test_gateway_objects_are_matched_by_actual_addresses_not_assumed_names(self):
        client = Mock()
        client.mgmt.return_value = {"total": 3, "objects": [
            {"type": "simple-gateway", "uid": "one", "name": "unpredicted-a", "ipv4-address": "10.250.0.5"},
            {"type": "simple-gateway", "uid": "two", "name": "unpredicted-b", "ipv4-address": "10.250.0.6"},
            {"type": "checkpoint-host", "uid": "manager", "ipv4-address": "172.29.0.4"},
        ]}
        self.assertEqual(gateway_uids(client, {"10.250.0.5", "10.250.0.6"}, 2), ["one", "two"])
        with self.assertRaises(CheckPointError):
            gateway_uids(client, {"10.250.0.5"}, 2)

    def test_negative_control_restores_only_its_own_rule_even_if_measurement_fails(self):
        client = Mock()
        client.mgmt.return_value = {"uid": "temporary-block"}
        policy = {"layer": "layer", "internal": "internal", "http": "http", "https": "https", "name": "FaaS-Lab"}
        def measure(phase, allowed):
            if not allowed:
                raise RuntimeError("measurement failed")
            return [{"phase": phase}]
        with self.assertRaisesRegex(RuntimeError, "measurement failed"):
            negative_control(client, policy, ["one", "two"], measure)
        client.mgmt.assert_any_call("delete-access-rule", {"uid": "temporary-block", "layer": "layer"})
        self.assertEqual(client.install.call_count, 2)
        block = client.mgmt.call_args_list[0].args[1]
        self.assertEqual(block["service"], ["http"])
        self.assertEqual(block["destination"], ["internal"])

    def test_guest_agent_https_remains_allowed_during_the_ew_negative_control(self):
        tests = [{"name": "egress", "hostname": None, "blockDuringNegative": False}]
        result = [{"name": "egress", "ok": True}]
        self.assertTrue(deploy.evaluate_measurements(tests, result, False)[0]["passed"])

    def test_existing_security_policy_is_never_overwritten(self):
        client = Mock()
        client.mgmt.return_value = {"uid": "not-owned"}
        with self.assertRaises(CheckPointError):
            create_policy(client, config(), "1.1.1.1/32", "8.8.8.8")
        self.assertEqual(client.mgmt.call_count, 1)

    def test_new_policy_preserves_private_sources_and_has_controlled_ingress_nat(self):
        client = Mock()
        calls = []
        def mgmt(command, body):
            calls.append((command, body))
            if command == "show-package":
                if "name" in body:
                    raise CheckPointError("Not found", "generic_err_object_not_found")
                return {"uid": "package", "access-layers": [{"uid": "layer"}]}
            if command == "add-package":
                return {"uid": "package"}
            if command == "show-dynamic-object":
                return {"uid": body["name"]}
            return {"uid": command + "-" + str(len(calls))}
        client.mgmt.side_effect = mgmt
        policy = create_policy(client, config(), "1.1.1.1/32", "8.8.8.8")
        self.assertEqual(policy["uid"], "package")
        nat = [body for command, body in calls if command == "add-nat-rule"]
        self.assertEqual(len(nat), 3)
        self.assertEqual(nat[0]["translated-source"], "LocalGatewayExternal")
        self.assertEqual(nat[1]["translated-source"], "Original")
        self.assertEqual(nat[1]["translated-destination"], "Original")
        self.assertEqual(nat[1]["method"], "static")
        self.assertEqual(nat[2]["translated-source"], "LocalGatewayInternal")
        access = [body for command, body in calls if command == "add-access-rule"]
        self.assertEqual(len(access), 3)
        self.assertTrue(all(rule["track"] == {"type": "Log"} for rule in access))

    def test_secrets_and_their_sic_encoding_are_redacted(self):
        with patch.dict("os.environ", {"CHECKPOINT_SIC_KEY": "abcdefghijkl", "CHECKPOINT_API_KEY": "private-api-key"}):
            result = deploy.clean("abcdefghijkl YWJjZGVmZ2hpamts private-api-key")
        self.assertNotIn("abcdefghijkl", result)
        self.assertNotIn("YWJjZGVmZ2hpamts", result)
        self.assertNotIn("private-api-key", result)


if __name__ == "__main__":
    unittest.main()
