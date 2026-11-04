import io
import json
import tempfile
import unittest
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import avnm_lab
from avnm_guest import block_script, bootstrap, evaluate, firewall_rules, targets_for

TEST_ACCOUNTS = {
    "A": {"tenant": str(uuid.UUID(int=1)), "subscription": str(uuid.UUID(int=2))},
    "B": {"tenant": str(uuid.UUID(int=3)), "subscription": str(uuid.UUID(int=4))},
}


def config():
    return json.loads((Path(__file__).resolve().parent / "config.example.json").read_text())


class AvnmLabTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.object(avnm_lab, "ACCOUNTS", TEST_ACCOUNTS))
        self.enterContext(patch.object(avnm_lab, "load_inputs", return_value=(
            config(), {"meta": {"status": "deployed", "executionApproved": True}},
        )))

    def test_default_is_a_real_offline_dry_run(self):
        with patch("sys.argv", ["avnm_lab.py"]), patch.object(avnm_lab.Arm, "request") as request:
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(avnm_lab.main(), 0)
        request.assert_not_called()
        self.assertIn("DRY RUN", output.getvalue())

    def test_deployed_plan_cannot_accidentally_start_another_billable_run(self):
        with patch("sys.argv", ["avnm_lab.py", "--execute"]), patch.object(
            avnm_lab.Arm, "request",
        ) as request:
            with self.assertRaisesRegex(ValueError, "already deployed"):
                avnm_lab.main()
        request.assert_not_called()

    def test_exactly_two_provider_firewalls_and_six_private_endpoints(self):
        settings = avnm_lab.validate_config(config())
        nodes = avnm_lab.node_definitions(settings)
        self.assertEqual(sum(node["account"] == "A" and node["firewall"] for node in nodes), 2)
        self.assertEqual(sum(node["account"] == "B" and not node["firewall"] for node in nodes), 6)
        self.assertEqual(sum(2 if node["firewall"] else 1 for node in nodes), 10)
        self.assertEqual(len({node["privateIp"] for node in nodes}), 8)

    def test_invalid_group_count_or_cost_shape_is_rejected(self):
        settings = config()
        settings["groups"][0]["workloadPrefixes"].pop()
        with self.assertRaises(ValueError):
            avnm_lab.validate_config(settings)
        settings = config()
        settings["workloadSize"] = "Standard_D64s_v5"
        with self.assertRaises(ValueError):
            avnm_lab.validate_config(settings)
        settings = config()
        settings["hostEncryption"] = True
        with self.assertRaises(ValueError):
            avnm_lab.validate_config(settings)

    def test_no_implicit_cross_tenant_scope_or_security_admin(self):
        body = avnm_lab.manager_body()["properties"]
        self.assertEqual(body["networkManagerScopeAccesses"], ["Connectivity", "Routing"])
        self.assertEqual(body["networkManagerScopes"]["subscriptions"], [
            "/subscriptions/" + avnm_lab.ACCOUNTS["A"]["subscription"],
        ])
        self.assertNotIn("crossTenantScopes", body["networkManagerScopes"])

    def test_connectivity_disables_mesh_gateways_and_destructive_peer_cleanup(self):
        properties = avnm_lab.connectivity_body("/manager/group", "/a/hub")["properties"]
        self.assertEqual(properties["connectivityTopology"], "HubAndSpoke")
        self.assertEqual(properties["hubs"], [{"resourceId": "/a/hub", "resourceType": "Microsoft.Network/virtualNetworks"}])
        group = properties["appliesToGroups"][0]
        self.assertEqual(group["groupConnectivity"], "None")
        self.assertEqual(group["useHubGateway"], "False")
        self.assertEqual(properties["deleteExistingPeering"], "False")

    def test_rule_contract_has_one_less_specific_prefix_and_private_next_hop(self):
        body = avnm_lab.rule_body("10.0.0.0/8", "172.22.1.4")["properties"]
        self.assertEqual(body["destination"], {"type": "AddressPrefix", "destinationAddress": "10.0.0.0/8"})
        self.assertEqual(body["nextHop"], {"nextHopType": "VirtualAppliance", "nextHopAddress": "172.22.1.4"})
        with self.assertRaises(ValueError):
            avnm_lab.rule_body("0.0.0.0/0", "8.8.8.8")

    def test_commits_use_configuration_ids_and_never_enable_security_admin(self):
        self.assertEqual(avnm_lab.commit_body("Connectivity", ["/c1", "/c2"]), {
            "commitType": "Connectivity", "configurationIds": ["/c1", "/c2"], "targetLocations": ["israelcentral"],
        })
        with self.assertRaises(ValueError):
            avnm_lab.commit_body("SecurityAdmin", [])

    def test_nic_effective_routes_must_be_active_user_routes_to_the_correct_firewall(self):
        output = {"value": [{
            "addressPrefix": [prefix], "source": "User", "state": "Active",
            "nextHopType": "VirtualAppliance", "nextHopIpAddress": ["172.22.1.4"],
        } for prefix in ("10.0.0.0/8", "0.0.0.0/0")]}
        avnm_lab.verify_effective_routes(output, "172.22.1.4")
        output["value"][0]["nextHopIpAddress"] = ["172.22.2.4"]
        with self.assertRaises(RuntimeError):
            avnm_lab.verify_effective_routes(output, "172.22.1.4")

    def test_all_directed_pairs_cover_twelve_internal_and_eighteen_cross_group(self):
        nodes = [node for node in avnm_lab.node_definitions(config()) if not node["firewall"]]
        pairs = [(source, destination) for source in nodes for destination in nodes if source != destination]
        self.assertEqual(len(pairs), 30)
        self.assertEqual(sum(source["group"] == dest["group"] for source, dest in pairs), 12)
        for source in nodes:
            self.assertEqual(len(targets_for(source, nodes, "run", "baseline")), 5)

    def test_http_success_requires_correct_host_and_original_customer_source(self):
        nodes = [node for node in avnm_lab.node_definitions(config()) if not node["firewall"]]
        source = nodes[0]
        targets = targets_for(source, nodes, "run", "baseline")
        measured = []
        for destination in nodes[1:]:
            if destination["group"] == source["group"]:
                measured.append({
                    "test": source["name"] + "-to-" + destination["name"], "ok": True,
                    "body": {"hostname": "vm-" + destination["name"], "client_ip": source["privateIp"]},
                })
            else:
                measured.append({
                    "test": source["name"] + "-to-" + destination["name"],
                    "ok": False, "errorType": "TimeoutError",
                })
        self.assertTrue(all(row["passed"] for row in evaluate(source, targets, measured, nodes, set())))
        measured[0]["body"]["client_ip"] = "172.22.1.4"
        self.assertFalse(evaluate(source, targets, measured, nodes, set())[0]["passed"])

    def test_partial_guest_output_cannot_pass_the_group_test(self):
        nodes = [node for node in avnm_lab.node_definitions(config()) if not node["firewall"]]
        targets = targets_for(nodes[0], nodes, "run", "phase")
        with self.assertRaises(RuntimeError):
            evaluate(nodes[0], targets, [], nodes, set())

    def test_http_error_is_not_an_isolation_or_negative_control_success(self):
        nodes = [node for node in avnm_lab.node_definitions(config()) if not node["firewall"]]
        source = nodes[0]
        targets = targets_for(source, nodes, "run", "phase")
        measured = [{"test": target["test"], "ok": False, "errorType": "HTTPError", "status": 503} for target in targets]
        self.assertFalse(any(row["passed"] for row in evaluate(source, targets, measured, nodes, {"group1"})))

    def test_firewall_policy_denies_other_group_before_internet_allow_and_preserves_private_nat(self):
        settings = config()
        own, other = (group["workloadPrefixes"] for group in settings["groups"])
        text = "\n".join(firewall_rules(own, other))
        self.assertIn("-d 10.201.0.0/16 -j AF_ISOLATE", text)
        self.assertLess(text.index("-d 10.201.0.0/16 -j AF_ISOLATE"), text.index("--dports 80,443"))
        self.assertLess(text.index("-d 10.0.0.0/8 -j RETURN"), text.index("-j MASQUERADE"))
        self.assertIn("-d 10.102.0.0/16 -p tcp --dport 8080 -j AF_OWN", text)

    def test_negative_control_is_bounded_idempotent_and_does_not_block_guest_https(self):
        for enabled in (True, False):
            lines = block_script(enabled)
            python = "\n".join(lines[1:-1])
            compile(python, "<block-script>", "exec")
            self.assertIn('"8080"', python)
            self.assertNotIn('"443"', python)
            self.assertIn("avnm-faas-negative-control", python)
            self.assertIn("check.returncode not in (0, 1)", python)

    def test_health_bootstrap_has_no_workload_package_download_dependency(self):
        node = next(node for node in avnm_lab.node_definitions(config()) if not node["firewall"])
        text = bootstrap(node, config()["groups"][0]["workloadPrefixes"], config()["groups"][1]["workloadPrefixes"])
        self.assertIn("AVNM_BOOTSTRAP_OK", text)
        self.assertNotIn("apt-get", text)
        self.assertIn("ThreadingHTTPServer", text)

    def test_only_exact_control_scope_and_b_consent_are_writable(self):
        with tempfile.TemporaryDirectory() as directory:
            exp = avnm_lab.Experiment({"runId": "unit", "stages": {}}, Path(directory), config())
            exp.control_id(exp.manager + "/networkGroups/group1")
            exp.control_id(exp.b_connection)
            for value in ("/subscriptions/unrelated/resource", exp.manager.replace("unit", "another") + "/networkGroups/group1"):
                with self.assertRaises(RuntimeError):
                    exp.control_id(value)

    def test_child_without_required_provisioning_state_does_not_fake_success(self):
        with tempfile.TemporaryDirectory() as directory:
            exp = avnm_lab.Experiment({"runId": "unit", "stages": {}}, Path(directory), config())
            target = exp.manager + "/networkGroups/group1"
            with patch.object(exp.arm, "request"), patch.object(exp.arm, "operation"), patch.object(
                exp, "get", return_value=(200, {}, {"id": target, "properties": {"memberType": "VirtualNetwork"}}),
            ):
                with self.assertRaisesRegex(RuntimeError, "no provisioningState"):
                    exp.put_control(target, {"properties": {"memberType": "VirtualNetwork"}})

    def test_application_auth_supplies_b_auxiliary_only_for_a_operations(self):
        with tempfile.TemporaryDirectory() as directory:
            exp = avnm_lab.Experiment({"runId": "unit", "stages": {}}, Path(directory), config())
            exp.application_auth = True
            target = exp.manager + "/networkGroups/group1"
            with patch.object(exp.arm, "request", return_value=(200, {}, {})) as request, patch.object(
                exp.arm, "operation",
            ), patch.object(exp, "get", return_value=(200, {}, {
                "id": target, "properties": {"provisioningState": "Succeeded"},
            })):
                exp.put_control(target, {"properties": {"memberType": "VirtualNetwork"}})
            self.assertEqual(request.call_args.kwargs["auxiliary"], "B")

    def test_group_ownership_prevents_touching_unrelated_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            exp = avnm_lab.Experiment({"runId": "unit", "stages": {}}, Path(directory), config())
            with patch.object(exp.arm, "request", return_value=(200, {}, {"tags": {"labRun": "other"}})):
                with self.assertRaises(RuntimeError):
                    exp.owned_group("B")

    def test_missing_new_peers_are_a_bounded_convergence_condition_not_a_fake_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            exp = avnm_lab.Experiment({"runId": "unit", "stages": {}, "networks": {
                "fw-group1": {"vnetId": "/owned/firewall-vnet"},
                **{f"group1-{index}": {"vnetId": f"/owned/spoke-{index}"} for index in (1, 2, 3)},
            }}, Path(directory), config())
            with patch.object(exp, "get", return_value=(200, {}, {"value": []})):
                with self.assertRaises(avnm_lab.NetworkConvergencePending):
                    exp.network_evidence()

    def test_completed_control_plane_does_not_create_another_temporary_application(self):
        with tempfile.TemporaryDirectory() as directory:
            exp = avnm_lab.Experiment({
                "runId": "20000101-000000-000000", "stages": {"configured": True},
            }, Path(directory), config())
            with patch.object(exp, "create_groups"), patch.object(exp, "run_stages") as stages, patch.object(
                exp, "temporary_application",
            ) as identity:
                exp.run()
            stages.assert_called_once()
            identity.assert_not_called()

    def test_restoration_can_run_after_testing_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            exp = avnm_lab.Experiment({"runId": "unit", "stages": {}}, Path(directory), config())
            exp.deadline = 0
            node = next(node for node in exp.nodes if node["firewall"])
            exp.state["vmIds"] = {node["name"]: exp.groups["A"] + "/providers/Microsoft.Compute/virtualMachines/vm-" + node["name"]}
            with patch.object(exp.arm, "request", return_value=(200, {}, {})), patch.object(
                exp.arm, "operation", return_value={"value": []},
            ) as operation:
                exp.command(node, ["true"], restoration=True)
            self.assertEqual(operation.call_args.kwargs["timeout"], 900)

    def test_resume_rejects_wrong_account_or_missing_scope_before_saving(self):
        run_id = "20000101-000000-000000"
        state = {"runId": run_id, "groups": avnm_lab.group_scopes(run_id)}
        avnm_lab.validate_resume_scope(state)
        for groups in ({}, {**state["groups"], "B": "/subscriptions/unrelated/resourceGroups/wrong"}):
            with self.subTest(groups=groups):
                changed = {**state, "groups": groups}
                with self.assertRaises(ValueError):
                    avnm_lab.validate_resume_scope(changed)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "results" / run_id / "state.json"
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps({**state, "groups": {}}))
            before = target.read_bytes()
            with patch.object(avnm_lab, "ROOT", root), patch(
                "sys.argv", ["avnm_lab.py", "--resume-run", run_id],
            ), patch.object(avnm_lab, "Experiment") as experiment:
                with self.assertRaises(ValueError):
                    avnm_lab.main()
            experiment.assert_not_called()
            self.assertEqual(target.read_bytes(), before)

    def test_resume_rejects_changed_tenants_and_customer_consent(self):
        run_id = "20000101-000000-000000"
        state = {"runId": run_id, "groups": avnm_lab.group_scopes(run_id)}
        for extra in (
            {"accountTenants": {"A": "different", "B": TEST_ACCOUNTS["B"]["tenant"]}},
            {"consentSnapshots": {"A": {"properties": {"tenantId": "different", "resourceId": "/wrong"}}}},
        ):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                avnm_lab.validate_resume_scope({**state, **extra})


if __name__ == "__main__":
    unittest.main()
