"""Offline infrastructure/bootstrap contract tests. Bicep compilation does not deploy."""
from __future__ import annotations
import argparse
import base64
import copy
import io
from datetime import datetime, timezone, timedelta
import importlib
import ipaddress
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import urllib.error
import zipfile
from unittest.mock import patch
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import common
import bootstrap
import bootstrap_identity
import cleanup_old_lab
import customer_run
import customer_connector
import package_apps
import prepare_customer_portal


def uid(n):
    return str(UUID(int=n))


def fixture():
    config = {
        "runId": "test-owned-run",
        "provider": {"tenantId": uid(1), "subscriptionId": uid(2),
                     "controlPlaneResourceGroup": "rg-faas-control-unit",
                     "dataPlaneResourceGroup": "rg-faas-provider-unit"},
        "customer": {"tenantId": uid(3), "subscriptionId": uid(4),
                     "bootstrapResourceGroup": "rg-faas-customer-auth-unit",
                     "dataPlaneResourceGroup": "rg-faas-customer-unit"},
        "cleanupOldLabRun": "old-owned-run",
    }
    plan = {"meta": {"status": "approved"}, "scope": {
        "provider": {"tenantId": uid(1), "subscriptionId": uid(2),
                     "controlPlaneGroupPrefix": "rg-faas-control-", "dataPlaneGroupPrefix": "rg-faas-provider-"},
        "customer": {"tenantId": uid(3), "subscriptionId": uid(4),
                     "bootstrapGroupPrefix": "rg-faas-customer-auth-", "dataPlaneGroupPrefix": "rg-faas-customer-"},
        "oldLabGroup": "rg-ravpn-old-unit",
    }}
    return config, plan


class ScopeTests(unittest.TestCase):
    def test_candidate_package_uses_its_own_validation_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT / '.local') as directory:
            target = Path(directory) / 'apps.zip'
            with patch.object(package_apps, 'compile_bicep', return_value=b'{}'), \
                    patch.object(package_apps, 'validate_runtime_template') as validate:
                package_apps.package(target)
            self.assertEqual(validate.call_args.args[0], target.parent / 'provider-template.json')
            self.assertTrue(target.is_file())

    def test_nva_startup_scopes_nat_and_filters_bgp(self):
        source = (ROOT / 'infra/cloud-init/nva.yaml').read_text()
        sources = source.split('for source in ', 1)[1].split('; do', 1)[0].split()
        excluded = source.split('for excluded in ', 1)[1].split('; do', 1)[0].split()
        self.assertEqual(sources, ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])
        excluded_networks = [ipaddress.ip_network(prefix) for prefix in excluded]
        for address in ('10.213.0.4', '172.31.0.4', '192.168.1.4'):
            self.assertTrue(any(ipaddress.ip_address(address) in ipaddress.ip_network(prefix)
                                for prefix in sources))
            self.assertTrue(any(ipaddress.ip_address(address) in network for network in excluded_networks))
        self.assertFalse(any(ipaddress.ip_address('1.1.1.1') in network for network in excluded_networks))
        self.assertNotIn('10.211.0.4/32', source)
        self.assertNotIn('10.212.0.4/32', source)
        self.assertIn('iptables -t nat -C POSTROUTING', source)
        self.assertIn('iptables -t nat -A FAAS_NS_EGRESS -o eth0 -j MASQUERADE', source)
        self.assertIn('route-map FAAS-IN deny 10', source)
        self.assertIn('ip prefix-list FAAS-DEFAULT seq 10 permit 0.0.0.0/0', source)
        self.assertEqual(source.count(' route-map FAAS-OUT out'), 2)
        self.assertNotIn('__DELIVERY_PEER_', source)
        self.assertIn('Requires=faas-forwarding.service', source)
        unit = source.split('path: /etc/systemd/system/faas-forwarding.service', 1)[1].split('  - path:', 1)[0]
        self.assertIn('After=network-pre.target systemd-sysctl.service', unit)
        self.assertNotIn('network-online.target', unit)
        live = (ROOT / 'scripts/persist-live-nva.sh').read_text()
        service = live.split("<<'FAAS_SERVICE'", 1)[1].split('FAAS_SERVICE', 1)[0]
        self.assertIn('After=network-pre.target systemd-sysctl.service', service)
        self.assertNotIn('faas-forwarding.service', service)
        self.assertIn('Before=frr.service', service)

    def test_route_server_subnets_have_supported_minimum_size(self):
        source = (ROOT / 'infra/provider-dataplane.bicep').read_text()
        self.assertIn("'172.20.254.0/26'", source)
        self.assertNotIn("'172.21.254.0/26'", source)

    def test_customer_default_routes_preserve_east_west_steering(self):
        source = (ROOT / 'infra/customer-foundation.bicep').read_text()
        self.assertIn("name: 'other-workload-via-ra'", source)
        self.assertIn("name: 'workload-${i}-via-ci'", source)
        self.assertIn("name: 'internet-via-ra'", source)
        self.assertIn("name: 'internet-via-ci'", source)
        self.assertEqual(source.count("addressPrefix: '0.0.0.0/0'"), 2)

    def test_customer_deployment_accepts_untagged_resource_group(self):
        source = (ROOT / 'infra/customer-deployment.bicep').read_text()
        self.assertIn('resourceGroup().?tags ?? {}', source)

    def test_customer_sizing_defaults_and_validation(self):
        defaults = common.customer_sizing({})
        self.assertEqual(defaults, {
            "routingApplianceBandwidthGbps": 10,
            "customerIngressVpnGatewaySku": "VpnGw1AZ",
            "customerDeliveryVpnGatewaySku": "VpnGw1AZ",
            "providerVpnGatewaySku": "VpnGw1AZ",
            "workloadVmProfile": "standard",
        })
        self.assertEqual(common.customer_sizing({"workloadVmProfile": "high-performance"})["workloadVmProfile"],
                         "high-performance")
        for field in ("customerIngressVpnGatewaySku", "customerDeliveryVpnGatewaySku", "providerVpnGatewaySku"):
            for sku in common.CUSTOMER_VPN_GATEWAY_SKUS:
                with self.subTest(field=field, sku=sku):
                    self.assertEqual(common.customer_sizing({field: sku})[field], sku)
        for field, value in (
            ("routingApplianceBandwidthGbps", 1),
            ("routingApplianceBandwidthGbps", "10"),
            ("routingApplianceBandwidthGbps", 10.0),
            ("routingApplianceBandwidthGbps", True),
            ("customerIngressVpnGatewaySku", "Basic"),
            ("customerDeliveryVpnGatewaySku", "VpnGw1"),
            ("customerDeliveryVpnGatewaySku", []),
            ("providerVpnGatewaySku", "VpnGw1"),
            ("workloadVmProfile", "Standard_D8s_v6"),
            ("workloadVmProfile", None),
        ):
            config, plan = fixture()
            config[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                common.validate_config(config, plan)

    def test_customer_sizing_updates_preserve_ownership_binding(self):
        config, _ = fixture()
        changed = {**config, "customerIngressVpnGatewaySku": "VpnGw2AZ",
                   "customerDeliveryVpnGatewaySku": "VpnGw5AZ", "providerVpnGatewaySku": "VpnGw4AZ",
                   "routingApplianceBandwidthGbps": 10, "workloadVmProfile": "high-performance"}
        self.assertEqual(common.config_digest(config), common.config_digest(changed))

    def test_customer_foundation_forwards_only_customer_sizing(self):
        config, _ = fixture()
        config.update(workloadSshPublicKey="fixture-public-key", customerIngressVpnGatewaySku="VpnGw2AZ",
                      customerDeliveryVpnGatewaySku="VpnGw5AZ", workloadVmProfile="high-performance",
                      providerVpnGatewaySku="VpnGw3AZ")
        journal = {"proof": {"status": "Ready"}}
        with patch.object(bootstrap, "verify_account"), patch.object(bootstrap, "encryption_preflight"), \
                patch.object(bootstrap, "save_private"), patch.object(bootstrap, "deploy", return_value={
                    "properties": {"outputs": {}}}) as deploy:
            bootstrap.run_phase(config, "customer-foundation", journal, ROOT / ".local/unused.json", None)
        self.assertEqual(deploy.call_args.args[:3], (
            config["customer"], config["customer"]["dataPlaneResourceGroup"], "customer-foundation.bicep"))
        parameters = deploy.call_args.args[3]
        self.assertEqual(parameters["routingApplianceBandwidthGbps"], 10)
        self.assertEqual(parameters["customerIngressVpnGatewaySku"], "VpnGw2AZ")
        self.assertEqual(parameters["customerDeliveryVpnGatewaySku"], "VpnGw5AZ")
        self.assertEqual(parameters["workloadVmProfile"], "high-performance")
        # customer-foundation.bicep has no provider gateway parameter; customer-network carries it.
        self.assertNotIn("providerVpnGatewaySku", parameters)

    def test_customer_network_phase_forwards_provider_gateway_sku(self):
        config, _ = fixture()
        config["providerVpnGatewaySku"] = "VpnGw5AZ"
        journal = {"proof": {"status": "Ready"}, "customerFoundation": {"customerEndpoints": {}},
                   "customerIdentity": {"identityId": "id", "clientId": uid(9)},
                   "customerConnectorScope": common.group_id(
                       config["customer"]["subscriptionId"], config["customer"]["dataPlaneResourceGroup"]),
                   "controlPlane": {"apiUrl": "https://api.example.invalid"}}
        identity = {"apiResource": "api://" + uid(8), "configDigest": common.config_digest(config)}
        with patch.object(bootstrap, "verify_account"), patch.object(bootstrap, "save_private"), \
                patch.object(bootstrap, "load_private",
                             side_effect=lambda path: identity if "identity" in str(path) else {}), \
                patch.object(bootstrap, "validate_connection_template"), \
                patch.object(bootstrap, "connector_result", return_value={}), \
                patch.object(bootstrap, "deploy", return_value={
                    "properties": {"outputs": {"networkResult": {"value": {}}}}}) as deploy:
            bootstrap.run_phase(config, "customer-network", journal, ROOT / ".local/unused.json", None)
        self.assertEqual(deploy.call_args.args[2], "customer-network.bicep")
        self.assertEqual(deploy.call_args.args[3]["providerVpnGatewaySku"], "VpnGw5AZ")

    def test_scope_fingerprint_allows_only_explicit_mutable_runtime_inputs(self):
        config, _ = fixture()
        baseline = common.config_digest(config)
        for field, value in (
            ("deploymentOperatorCidr", "192.0.2.1/32"), ("nvaSshPublicKey", "unit-public-key"),
            ("workloadSshPublicKey", "unit-other-public-key"), ("maxEnvironments", 3),
            ("apiApplicationId", uid(5)), ("consentRedirectUri", "https://unit.invalid/callback"),
            ("cleanupOldLabRun", "old-owned-run-changed"),
        ):
            with self.subTest(mutable=field):
                self.assertEqual(common.config_digest({**config, field: value}), baseline)
        for field in ("tenantId", "subscriptionId", "dataPlaneResourceGroup"):
            altered = copy.deepcopy(config)
            altered["provider"][field] = uid(20) if field.endswith("Id") else "rg-faas-provider-changed"
            self.assertNotEqual(common.config_digest(altered), baseline)
        self.assertNotEqual(common.config_digest({**config, "runId": "different-run"}), baseline)

    def test_exact_approved_context(self):
        config, plan = fixture()
        self.assertIs(common.validate_config(config, plan), config)

    def test_reject_wrong_tenant_subscription_and_scope(self):
        config, plan = fixture()
        for side in ("provider", "customer"):
            for field in ("tenantId", "subscriptionId", "dataPlaneResourceGroup"):
                wrong = copy.deepcopy(config)
                wrong[side][field] = uid(10) if field.endswith("Id") else "unapproved-group"
                with self.subTest(side=side, field=field), self.assertRaises(ValueError):
                    common.validate_config(wrong, plan)

    def test_reject_same_tenant_and_same_group(self):
        config, plan = fixture()
        plan["scope"]["customer"]["tenantId"] = config["customer"]["tenantId"] = config["provider"]["tenantId"]
        with self.assertRaises(ValueError):
            common.validate_config(config, plan)

    def test_reject_resource_id_in_group_name(self):
        with self.assertRaises(ValueError):
            common.group_id(uid(1), "group/providers/Microsoft.Authorization")

    def test_reject_wide_private_and_documentation_scm_cidrs(self):
        for address in ("0.0.0.0/0", "10.0.0.1/32", "192.0.2.1/32", "::/0", "192.0.2.0/24"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                common.operator_cidr(address)

    def test_public_key_validation(self):
        blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
        key = "ssh-ed25519 " + base64.b64encode(blob).decode() + " unit-public"
        self.assertEqual(common.public_key(key), key)
        for invalid in ("-----BEGIN " + "OPENSSH PRIVATE KEY-----", "ssh-rsa bad", "password"):
            with self.assertRaises((ValueError, struct.error)):
                common.public_key(invalid)

    def test_customer_origin_no_token_redirects(self):
        self.assertEqual(customer_run.api_origin("https://unit.azurewebsites.net/"), "https://unit.azurewebsites.net")
        for value in ("http://unit", "https://user:pass" + "@" + "unit", "https://unit/path", "https://unit?token=value"):
            with self.assertRaises(ValueError):
                customer_run.api_origin(value)
        self.assertIsNone(customer_run.NoRedirect().redirect_request())

    def test_no_cloud_calls_on_import(self):
        with patch("subprocess.run", side_effect=AssertionError("cloud call on import")):
            for module in (common, customer_connector, bootstrap, bootstrap_identity, customer_run, cleanup_old_lab, package_apps, prepare_customer_portal):
                importlib.reload(module)

    def test_dry_run_all_phases_no_cloud_calls(self):
        config, _ = fixture()
        with patch.object(bootstrap, "load_private", return_value=config), \
                patch.object(bootstrap, "validate_config", return_value=config), \
                patch.object(bootstrap, "cli", side_effect=AssertionError("dry-run cloud call")):
            for phase in bootstrap.PHASES:
                if phase != "validate-local":
                    self.assertEqual(bootstrap.main([phase, "--config", "unused"]), 0)
        with patch.object(bootstrap_identity, "load_private", return_value=config), \
                patch.object(bootstrap_identity, "validate_config", return_value=config), \
                patch.object(bootstrap_identity, "verify_account", side_effect=AssertionError("dry-run cloud call")):
            for phase in ("provider", "customer"):
                self.assertEqual(bootstrap_identity.main([phase, "--config", "unused"]), 0)

    def test_help_commands_are_offline(self):
        for name in ("bootstrap.py", "bootstrap_identity.py", "package_apps.py", "customer_run.py", "customer_connector.py", "cleanup_old_lab.py", "prepare_customer_portal.py"):
            process = subprocess.run([sys.executable, str(ROOT / "scripts" / name), "--help"],
                                     capture_output=True, text=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertIn("usage:", process.stdout)

    def test_scm_exception_and_backing_exception_are_explicit(self):
        args = argparse.Namespace(approve_scm_bootstrap_exception=False, approve_script_backing_exception=False)
        for phase in ("control-plane", "customer-proof", "customer-network"):
            with self.assertRaises(ValueError):
                bootstrap.validate_runtime({}, phase, args)

    def test_legacy_capacity_does_not_block_customer_foundation(self):
        with patch.object(bootstrap, "public_key"):
            bootstrap.validate_runtime({"maxEnvironments": 1, "workloadSshPublicKey": "key"},
                                       "customer-foundation", None)

    def test_customer_portal_ignores_legacy_global_capacity(self):
        config, _ = fixture()
        config["maxEnvironments"] = 0
        provider = {"configDigest": common.config_digest(config),
                    "apiAuthMode": prepare_customer_portal.MODE,
                    "controlPlane": {"apiUrl": "https://unit.azurewebsites.net"}}
        with patch.object(prepare_customer_portal, "validate_identity"), \
                patch.object(prepare_customer_portal, "compile_bicep", side_effect=RuntimeError("compile reached")):
            with self.assertRaisesRegex(RuntimeError, "compile reached"):
                prepare_customer_portal.prepare(config, provider, {}, ROOT / ".local")
            config["maxEnvironments"] = 1
            with self.assertRaisesRegex(RuntimeError, "compile reached"):
                prepare_customer_portal.prepare(config, provider, {}, ROOT / ".local")

    def test_graph_appid_exact_lookup_no_displayname(self):
        graph = unittest.mock.Mock()
        graph.request.return_value = {"value": []}
        self.assertIsNone(bootstrap_identity.find_exact(graph, "servicePrincipals", uid(1)))
        self.assertIn("appId", graph.request.call_args.args[1])
        self.assertNotIn("displayName", graph.request.call_args.args[1])
        graph.request.return_value = {"value": [{}, {}]}
        with self.assertRaises(ValueError):
            bootstrap_identity.find_exact(graph, "servicePrincipals", uid(1))

    def test_graph_tokens_are_tenant_scoped_and_not_argv(self):
        token_result = subprocess.CompletedProcess([], 0, stdout="do-not-print-token\n")
        with patch.object(bootstrap_identity.subprocess, "run", return_value=token_result) as run:
            graph = bootstrap_identity.Graph(uid(1))
            arguments = run.call_args.args[0]
            self.assertIn("--tenant", arguments)
            self.assertIn("--scope", arguments)
            self.assertIn("https://graph.microsoft.com/.default", arguments)
            self.assertIn(uid(1), arguments)
            self.assertNotIn("do-not-print-token", arguments)
        with self.assertRaises(ValueError):
            graph.request("GET", "https://untrusted.invalid")

    def test_expensive_foundation_gated_on_customer_mi_proof(self):
        config, _ = fixture()
        with patch.object(bootstrap, "verify_account"), \
                patch.object(bootstrap, "deploy", side_effect=AssertionError("expensive deploy")):
            with self.assertRaisesRegex(ValueError, "proof"):
                bootstrap.run_phase(config, "customer-foundation", {}, ROOT / ".local/unused.json", None)

    def test_foreign_identity_journal_rejected_before_all_identity_bound_deployments(self):
        config, _ = fixture()
        foreign = copy.deepcopy(config)
        foreign["customer"]["tenantId"] = uid(20)
        identities = {"configDigest": common.config_digest(foreign)}
        with patch.object(bootstrap, "verify_account"), patch.object(bootstrap, "load_private", return_value=identities), \
                patch.object(bootstrap, "deploy", side_effect=AssertionError("foreign identity must not deploy")) as deploy:
            for phase in ("control-plane", "customer-proof", "customer-connector-role", "customer-network"):
                with self.subTest(phase=phase), self.assertRaisesRegex(ValueError, "Identity journal"):
                    bootstrap.run_phase(config, phase, {}, ROOT / ".local/unused.json", None)
            deploy.assert_not_called()

    def test_encryption_preflight_both_scopes_read_only_and_fail_before_networking(self):
        config, _ = fixture()
        for unregistered_side in ("provider", "customer"):
            def feature(*arguments):
                self.assertEqual(arguments[:2], ("feature", "show"))
                self.assertNotIn("register", arguments)
                subscription = arguments[arguments.index("--subscription") + 1]
                state = "NotRegistered" if subscription == config[unregistered_side]["subscriptionId"] else "Registered"
                return {"properties": {"state": state}}
            with self.subTest(side=unregistered_side), patch.object(bootstrap, "verify_account"), \
                    patch.object(bootstrap, "cli", side_effect=feature), \
                    patch.object(bootstrap, "deploy", side_effect=AssertionError("no gateway before feature registration")):
                with self.assertRaisesRegex(ValueError, "EncryptionAtHost"):
                    bootstrap.run_phase(config, "customer-foundation", {"proof": {"status": "Ready"}},
                                        ROOT / ".local/unused.json", None)
        with patch.object(bootstrap, "verify_account"), patch.object(bootstrap, "cli", return_value={
                "properties": {"state": "Registered"}}) as cli:
            bootstrap.encryption_preflight(config)
            self.assertEqual(cli.call_count, 2)


def connection_template():
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {key: {"type": "secureString" if key.endswith("SharedKey") else (
            "object" if key == "providerManifest" else "string")} for key in (
                "location", "runId", "providerManifest", "ingressSharedKey", "deliverySharedKey")},
        "resources": [{"type": "Microsoft.Network/connections", "name": "unit-connection", "properties": {}}],
    }


def connector_env(mode="network"):
    return {
        "FAAS_BACKING_APPROVED": "true", "FAAS_CONNECTOR_MODE": mode, "FAAS_WAIT_SECONDS": "600",
        "FAAS_RUN_ID": "unit-run", "FAAS_API_URL": "https://unit.azurewebsites.net",
        "FAAS_API_RESOURCE": "api://" + uid(5), "FAAS_CUSTOMER_CLIENT_ID": uid(6),
        "FAAS_CUSTOMER_TENANT_ID": uid(3), "FAAS_CUSTOMER_SUBSCRIPTION_ID": uid(4),
        "FAAS_CUSTOMER_RESOURCE_GROUP": "rg-faas-customer-unit",
        "FAAS_CUSTOMER_ENDPOINTS": json.dumps({
            "customerIngress": {"publicIp": "192.0.2.10", "bgpAddress": "172.18.255.30", "asn": 65020},
            "customerDelivery": {"publicIp": "192.0.2.11", "bgpAddress": "172.19.255.30", "asn": 65021}}),
        "FAAS_CONNECTIONS_TEMPLATE": json.dumps(connection_template()),
    }


def ready_operation():
    return {"operationId": uid(10), "environmentId": uid(10), "status": "Ready", "connectionManifest": {
        "providerIngress": {"publicIp": "192.0.2.20", "bgpAddress": "172.20.255.30", "asn": 65030},
        "providerDelivery": {"publicIp": "192.0.2.21", "bgpAddress": "172.21.255.30", "asn": 65031}}}


class ConnectorTests(unittest.TestCase):
    def test_customer_default_site_is_scoped_idempotent_and_verified(self):
        subscription, group = uid(4), 'rg-faas-customer-unit'
        site = f'/subscriptions/{subscription}/resourceGroups/{group}/providers/Microsoft.Network/localNetworkGateways/lng-customer-ingress'
        configured = {'gatewayDefaultSite': {'id': site}}
        with patch.object(customer_connector, 'az', side_effect=[{}, None, configured]) as az:
            customer_connector.configure_default_site(subscription, group, time.monotonic() + 60)
            self.assertEqual(az.call_count, 3)
            self.assertIn(site, az.call_args_list[1].args[0])
        with patch.object(customer_connector, 'az', return_value=configured) as az:
            customer_connector.configure_default_site(subscription, group, time.monotonic() + 60)
            az.assert_called_once()
        with patch.object(customer_connector, 'az', side_effect=[{}, None, {}]):
            with self.assertRaisesRegex(RuntimeError, 'default site'):
                customer_connector.configure_default_site(subscription, group, time.monotonic() + 60)

    def test_portal_scope_pin_rejects_wrong_group_before_any_arm_lookup(self):
        env = connector_env("proof")
        env["FAAS_ENROLLED_CUSTOMER_SCOPE"] = (
            common.group_id(uid(4), "rg-faas-customer-different"))
        with patch.object(customer_connector, "az") as az:
            with self.assertRaisesRegex(ValueError, "enrolled scope"):
                customer_connector.customer_scope(env, time.monotonic() + 60)
            az.assert_not_called()

    def test_portal_proof_checks_enrolled_scope_before_requesting_provider_resources(self):
        env = connector_env("proof")
        env["FAAS_VALIDATE_CUSTOMER_SCOPE"] = "true"
        with patch.object(customer_connector, "az"), \
                patch.object(customer_connector, "customer_scope", side_effect=ValueError("wrong scope")), \
                patch.object(customer_connector, "request") as request:
            with self.assertRaises(ValueError):
                customer_connector.run(env)
            request.assert_not_called()

    def test_portal_proof_validates_scope_but_does_not_deploy_connections(self):
        env = connector_env("proof")
        env["FAAS_VALIDATE_CUSTOMER_SCOPE"] = "true"
        with patch.object(customer_connector, "az"), \
                patch.object(customer_connector, "customer_scope", return_value=(uid(4), "rg-faas-customer-unit")) as scope, \
                patch.object(customer_connector, "request", return_value=ready_operation()), \
                patch.object(customer_connector, "deploy_connections") as deploy:
            self.assertEqual(customer_connector.run(env)["status"], "Ready")
            scope.assert_called_once()
            deploy.assert_not_called()

    def test_proof_canonical_key_matches_existing_cli_and_network_key_is_distinct(self):
        self.assertEqual(customer_connector.idempotency_key("unit-run", "proof"), "unit-run-proof")
        self.assertEqual(customer_connector.idempotency_key("unit-run", "network"), "unit-run-network")
        source = (ROOT / "scripts/customer_run.py").read_text()
        self.assertIn('config["runId"] + "-" + args.mode', source)

    def test_proof_has_no_customer_arm_prerequisites(self):
        env = connector_env("proof")
        with patch.object(customer_connector, "az") as az, \
                patch.object(customer_connector, "request", return_value=ready_operation()) as request, \
                patch.object(customer_connector, "customer_scope", side_effect=AssertionError("proof ARM call")), \
                patch.object(customer_connector, "deploy_connections", side_effect=AssertionError("proof connections")):
            self.assertEqual(customer_connector.run(env), {"operationId": uid(10), "status": "Ready"})
            az.assert_called_once()
            self.assertIn("--identity", az.call_args.args[0])
            self.assertIn("--allow-no-subscriptions", az.call_args.args[0])
            self.assertEqual(request.call_args.args[4], {"mode": "proof", "region": "eastus2", "tier": "lab"})
            self.assertEqual(request.call_args.args[5], "unit-run-proof")

    def test_checkpoint_preflight_blocks_before_customer_scope_or_provider_reservation(self):
        for mode in ("proof", "network"):
            env = connector_env(mode)
            env["FAAS_FIREWALL_TYPE"] = "checkpoint-byol"
            with self.subTest(mode=mode), patch.object(customer_connector, "az"), \
                    patch.object(customer_connector, "customer_scope") as scope, \
                    patch.object(customer_connector, "request", return_value={"status": "ready"}) as request:
                with self.assertRaises(customer_connector.FirewallUnavailable):
                    customer_connector.run(env)
                scope.assert_not_called()
                request.assert_called_once()
                self.assertEqual(request.call_args.args[2], customer_connector.CHECKPOINT_READINESS)

    def test_old_or_unavailable_api_rejects_checkpoint_preflight(self):
        for code in (404, 409):
            opener = unittest.mock.Mock()
            opener.open.side_effect = urllib.error.HTTPError("https://unit", code, "redacted", {}, None)
            with self.subTest(code=code), patch.object(customer_connector, "az", return_value="memory-only-token"), \
                    patch.object(customer_connector.urllib.request, "build_opener", return_value=opener):
                with self.assertRaises(customer_connector.FirewallUnavailable):
                    customer_connector.request("https://unit.azurewebsites.net", "api://" + uid(5),
                                               customer_connector.CHECKPOINT_READINESS, time.monotonic() + 60)
                self.assertEqual(opener.open.call_count, 1)

    def test_checkpoint_failure_has_an_explicit_customer_message(self):
        with patch.object(customer_connector, "run",
                          side_effect=customer_connector.FirewallUnavailable("not ready")):
            with self.assertRaisesRegex(SystemExit, "Check Point BYOL deployment is not available yet"):
                customer_connector.main([])

    def test_checkpoint_request_is_explicit_and_never_uses_ubuntu_implicitly(self):
        endpoints = json.loads(connector_env()["FAAS_CUSTOMER_ENDPOINTS"])
        body = customer_connector.request_body("network", endpoints, "checkpoint-byol")
        self.assertEqual(body["firewallType"], "checkpoint-byol")
        self.assertNotIn("firewallType", customer_connector.request_body("network", endpoints, "ubuntu"))
        with self.assertRaises(ValueError):
            customer_connector.request_body("proof", firewall_type="unknown")

    def test_provider_gateway_sku_is_sent_only_when_non_default(self):
        endpoints = json.loads(connector_env()["FAAS_CUSTOMER_ENDPOINTS"])
        default = customer_connector.request_body("network", endpoints)
        self.assertEqual(default, customer_connector.request_body("network", endpoints, "ubuntu", [], "VpnGw1AZ"))
        self.assertNotIn("providerVpnGatewaySku", default)
        sized = customer_connector.request_body("network", endpoints, "ubuntu", [], "VpnGw5AZ")
        self.assertEqual(sized, {**default, "providerVpnGatewaySku": "VpnGw5AZ"})
        for args in (("network", endpoints, "ubuntu", [], "VpnGw1"), ("proof", None, "ubuntu", [], "VpnGw2AZ")):
            with self.assertRaises(ValueError):
                customer_connector.request_body(*args)

    def test_checkpoint_scale_set_uses_its_own_readiness_and_request_type(self):
        endpoints = json.loads(connector_env()["FAAS_CUSTOMER_ENDPOINTS"])
        body = customer_connector.request_body("network", endpoints, "checkpoint-vmss", ["8.8.8.8"])
        self.assertEqual((body["firewallType"], body["adminAllowedSources"]), ("checkpoint-vmss", ["8.8.8.8/32"]))
        env = connector_env("network")
        env["FAAS_FIREWALL_TYPE"] = "checkpoint-vmss"
        with patch.object(customer_connector, "az"), patch.object(customer_connector, "customer_scope") as scope, \
                patch.object(customer_connector, "request",
                             return_value={"firewallType": "checkpoint-byol", "status": "ready"}) as request:
            with self.assertRaises(customer_connector.FirewallUnavailable):
                customer_connector.run(env)
        scope.assert_not_called()
        self.assertEqual(request.call_args.args[2], "/v1/firewall-types/checkpoint-vmss/readiness")

    def test_network_uses_only_endpoints_and_never_outputs_material(self):
        env = connector_env()
        material = {"environmentId": uid(10), "ingressSharedKey": "unit-ingress-material",
                    "deliverySharedKey": "unit-delivery-material"}
        with patch.object(customer_connector, "az"), \
                patch.object(customer_connector, "customer_scope", return_value=(uid(4), env["FAAS_CUSTOMER_RESOURCE_GROUP"])), \
                patch.object(customer_connector, "request", side_effect=[ready_operation(), material]) as request, \
                patch.object(customer_connector, "deploy_connections") as deploy:
            result = customer_connector.run(env)
            self.assertEqual(set(result), {"operationId", "status"})
            body = request.call_args_list[0].args[4]
            self.assertEqual(set(body), {"mode", "region", "tier", "customerIngress", "customerDelivery"})
            self.assertEqual(request.call_args_list[0].args[5], "unit-run-network")
            self.assertEqual(deploy.call_args.args[2], material)
            self.assertEqual(deploy.call_args.args[4:6], (uid(4), env["FAAS_CUSTOMER_RESOURCE_GROUP"]))

    def test_network_rerun_retries_only_the_same_failed_group_operation(self):
        env = connector_env()
        failed = {**ready_operation(), "status": "Failed",
                  "error": {"code": "GroupOwnershipError"}}
        material = {"environmentId": uid(10), "ingressSharedKey": "unit-ingress-material",
                    "deliverySharedKey": "unit-delivery-material"}
        with patch.object(customer_connector, "az"), \
                patch.object(customer_connector, "customer_scope", return_value=(uid(4), env["FAAS_CUSTOMER_RESOURCE_GROUP"])), \
                patch.object(customer_connector, "request", side_effect=[failed, ready_operation(), material]) as request, \
                patch.object(customer_connector, "deploy_connections"):
            self.assertEqual(customer_connector.run(env)["status"], "Ready")
            self.assertEqual(request.call_args_list[1].args[2], f"/v1/operations/{uid(10)}/retry-group")
            self.assertEqual(request.call_args_list[1].args[4], {})

    def test_network_rerun_does_not_retry_other_failures(self):
        env = connector_env()
        failed = {**ready_operation(), "status": "Failed", "error": {"code": "DeploymentFailed"}}
        with patch.object(customer_connector, "az"), \
                patch.object(customer_connector, "customer_scope", return_value=(uid(4), env["FAAS_CUSTOMER_RESOURCE_GROUP"])), \
                patch.object(customer_connector, "request", return_value=failed) as request:
            with self.assertRaises(RuntimeError):
                customer_connector.run(env)
            self.assertEqual(request.call_count, 1)

    def test_reject_endpoint_scope_injection_and_material_identity_change(self):
        endpoints = json.loads(connector_env()["FAAS_CUSTOMER_ENDPOINTS"])
        endpoints["resourceGroup"] = "untrusted"
        with self.assertRaises(ValueError):
            customer_connector.request_body("network", endpoints)
        with self.assertRaises(ValueError):
            customer_connector.deploy_connections(connector_env(), ready_operation(),
                {"environmentId": uid(11), "ingressSharedKey": "unit-key-one", "deliverySharedKey": "unit-key-two"},
                connection_template(), uid(4), "rg-faas-customer-unit", time.monotonic() + 60)

    def test_http_transients_retry_and_401_403_redirects_do_not(self):
        for code in (*sorted(customer_connector.TRANSIENT), 401, 403, 302):
            opener = unittest.mock.Mock()
            success = unittest.mock.MagicMock()
            success.__enter__.return_value = io.BytesIO(b'{"status":"Ready"}')
            opener.open.side_effect = [urllib.error.HTTPError("https://unit", code, "redacted", {}, None), success]
            with self.subTest(code=code), patch.object(customer_connector, "az", return_value="memory-only-token") as az, \
                    patch.object(customer_connector.urllib.request, "build_opener", return_value=opener), \
                    patch.object(customer_connector, "pause"):
                call = lambda: customer_connector.request("https://unit.azurewebsites.net", "api://" + uid(5),
                    "/v1/environments", time.monotonic() + 60, {"mode": "proof"}, "unit-run-proof")
                if code in customer_connector.TRANSIENT:
                    self.assertEqual(call(), {"status": "Ready"})
                    self.assertEqual(az.call_count, 2)
                else:
                    with self.assertRaises(RuntimeError):
                        call()
                    self.assertEqual(az.call_count, 1)
                self.assertTrue(all(arguments.args[0][:2] == ["account", "get-access-token"] for arguments in az.call_args_list))
        self.assertIsNone(customer_connector.NoRedirect().redirect_request())

    def test_transient_retry_count_and_deadline_are_bounded(self):
        opener = unittest.mock.Mock()
        opener.open.side_effect = urllib.error.HTTPError("https://unit", 503, "redacted", {}, None)
        with patch.object(customer_connector, "az", return_value="memory-only-token"), \
                patch.object(customer_connector.urllib.request, "build_opener", return_value=opener), \
                patch.object(customer_connector, "pause"):
            with self.assertRaises(RuntimeError):
                customer_connector.request("https://unit", "api://" + uid(5), "/v1/environments", time.monotonic() + 60)
            self.assertEqual(opener.open.call_count, 8)
        with self.assertRaises(TimeoutError):
            customer_connector.remaining(time.monotonic() - 1)

    def test_scope_checks_explicit_subscription_and_owned_tags(self):
        env = connector_env()
        account = {"id": uid(4), "tenantId": uid(3), "state": "Enabled"}
        group = {"id": common.group_id(uid(4), env["FAAS_CUSTOMER_RESOURCE_GROUP"]),
                 "tags": {"purpose": "provider-provisioning", "labRun": env["FAAS_RUN_ID"]}}
        with patch.object(customer_connector, "az", side_effect=[account, group]) as az:
            customer_connector.customer_scope(env, time.monotonic() + 60)
            for call in az.call_args_list:
                self.assertIn("--subscription", call.args[0])
                self.assertIn(uid(4), call.args[0])
        for bad in ({**account, "tenantId": uid(7)}, {**group, "tags": {"labRun": "foreign-run"}}):
            responses = [bad] if "tenantId" in bad else [account, bad]
            with patch.object(customer_connector, "az", side_effect=responses), self.assertRaises(ValueError):
                customer_connector.customer_scope(env, time.monotonic() + 60)

    def test_parameters_private_ephemeral_and_not_in_process_arguments(self):
        material = {"environmentId": uid(10), "ingressSharedKey": "unit-ingress-material",
                    "deliverySharedKey": "unit-delivery-material"}
        captured = []
        def deploy(arguments, deadline, output):
            self.assertEqual(output, "none")
            self.assertEqual(arguments[arguments.index("--name") + 1], "customer-connections-" + uid(10))
            file = Path(arguments[arguments.index("--parameters") + 1][1:])
            captured.append(file)
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(file.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(json.loads(file.read_text())["parameters"]["ingressSharedKey"]["value"], material["ingressSharedKey"])
            self.assertNotIn(material["ingressSharedKey"], " ".join(arguments))
            self.assertNotIn(material["deliverySharedKey"], " ".join(arguments))
        with patch.object(customer_connector.Path, "cwd", return_value=ROOT / ".local"), \
            patch.object(customer_connector, "configure_default_site") as default_site, \
                patch.object(customer_connector, "az", side_effect=deploy):
            customer_connector.deploy_connections(connector_env(), ready_operation(), material,
                connection_template(), uid(4), "rg-faas-customer-unit", time.monotonic() + 60)
        default_site.assert_called_once()
        self.assertTrue(captured)
        self.assertFalse(captured[0].exists())
        self.assertFalse(captured[0].parent.exists())

    def test_template_rejects_plaintext_keys_outputs_and_cross_scope(self):
        base = connection_template()
        customer_connector.validate_connection_template(base)
        for invalid in (
            {**base, "outputs": {"secret": {"type": "string", "value": "not-allowed"}}},
            {**base, "resources": [{"type": "Microsoft.Network/connections", "scope": "foreign"}]},
            {**base, "parameters": {**base["parameters"], "ingressSharedKey": {"type": "string"}}},
        ):
            with self.assertRaises(ValueError):
                customer_connector.validate_connection_template(invalid)

    def test_stderr_is_redacted_at_entrypoint(self):
        with patch.object(customer_connector, "run", side_effect=RuntimeError("unit-sensitive-material")):
            with self.assertRaises(SystemExit) as result:
                customer_connector.main([])
        self.assertNotIn("unit-sensitive-material", str(result.exception))

    def test_bootstrap_network_gates_and_nonsecret_result(self):
        config, _ = fixture()
        identities = {"configDigest": common.config_digest(config), "apiResource": "api://" + uid(5)}
        env = connector_env()
        journal = {"proof": {"status": "Ready"}, "customerFoundation": {
            "customerEndpoints": json.loads(env["FAAS_CUSTOMER_ENDPOINTS"])},
            "customerConnectorScope": common.group_id(uid(4), config["customer"]["dataPlaneResourceGroup"]),
            "customerIdentity": {"identityId": "unit-identity", "clientId": uid(6)},
            "controlPlane": {"apiUrl": env["FAAS_API_URL"]}}
        def load(path):
            return identities if str(path).endswith("identity-journal.json") else connection_template()
        result = {"properties": {"outputs": {"networkResult": {"value": {"operationId": uid(10), "status": "Ready"}}}}}
        with patch.object(bootstrap, "load_private", side_effect=load), patch.object(bootstrap, "verify_account"), \
                patch.object(bootstrap, "encryption_preflight"), patch.object(bootstrap, "save_private"), \
                patch.object(bootstrap, "deploy", return_value=result) as deploy:
            bootstrap.run_phase(config, "customer-network", journal, ROOT / ".local/unused.json", None)
            self.assertEqual(journal["networkResult"], {"operationId": uid(10), "status": "Ready"})
            self.assertEqual(deploy.call_args.args[2], "customer-network.bicep")
            self.assertEqual(deploy.call_args.args[3]["customerEndpoints"], journal["customerFoundation"]["customerEndpoints"])
            for key in ("proof", "customerFoundation", "customerConnectorScope"):
                bad = {k: v for k, v in journal.items() if k != key}
                with self.subTest(key=key), self.assertRaises(ValueError):
                    bootstrap.run_phase(config, "customer-network", bad, ROOT / ".local/unused.json", None)
            self.assertEqual(deploy.call_count, 1)

    def test_embedded_python_and_cloud_init_snippets_have_valid_syntax(self):
        source = (ROOT / "scripts/customer_connector.py").read_text()
        compile(source, "customer_connector.py", "exec")
        wrapper = 'set -euo pipefail\ncd "$HOME"\npython3 - <<\'FAAS_CONNECTOR_PY\'\n' + source + "\nFAAS_CONNECTOR_PY\n"
        shell = subprocess.run(["bash", "-n"], input=wrapper, capture_output=True, text=True)
        self.assertEqual(shell.returncode, 0, shell.stderr)
        for name in ("nva.yaml", "workload.yaml"):
            lines = (ROOT / "infra/cloud-init" / name).read_text().splitlines()
            current_path, content = None, []
            for line in lines + ["  - path: /end"]:
                if line.startswith("  - path:"):
                    if current_path and content:
                        code = textwrap.dedent("\n".join(content))
                        if current_path.endswith(".py"):
                            compile(code, current_path, "exec")
                        elif current_path.endswith("faas-forwarding"):
                            shell = subprocess.run(["bash", "-n"], input=code, capture_output=True, text=True)
                            self.assertEqual(shell.returncode, 0, shell.stderr)
                    current_path, content = line.split(":", 1)[1].strip(), []
                elif line.startswith("      "):
                    content.append(line)


class CleanupTests(unittest.TestCase):
    def test_exact_digest_fresh_evidence_and_ownership(self):
        config, plan = fixture()
        inventory = {"resourceGroupId": common.group_id(uid(2), plan["scope"]["oldLabGroup"]),
                     "tags": {"labRun": "old-owned-run", "purpose": "routing-appliance-vpn-lab"}, "resources": []}
        saved = {"capturedAt": datetime.now(timezone.utc).isoformat(), "inventory": inventory}
        evidence = {"verifiedAt": datetime.now(timezone.utc).isoformat(), "runId": config["runId"],
                    "replacementProviderGroupId": common.group_id(uid(2), config["provider"]["dataPlaneResourceGroup"]),
                    "ipsecBgp": True, "sourcePreservation": True, "denialRecovery": True, "cutover": True}
        args = [config, plan, saved, inventory, evidence, plan["scope"]["oldLabGroup"], common.digest(inventory)]
        self.assertEqual(cleanup_old_lab.validate_deletion(*args), plan["scope"]["oldLabGroup"])
        for index, replacement in (
            (5, "rg-ew21-never"), (6, "unapproved-digest"),
            (4, {**evidence, "sourcePreservation": False}),
            (2, {**saved, "capturedAt": (datetime.now(timezone.utc) - timedelta(hours=73)).isoformat()}),
            (3, {**inventory, "tags": {"purpose": "wrong", "labRun": "old-owned-run"}}),
        ):
            bad = list(args)
            bad[index] = replacement
            with self.assertRaises(ValueError):
                cleanup_old_lab.validate_deletion(*bad)


def nested_templates(template):
    yield template
    for resource in template.get("resources", []):
        if resource["type"].lower() == "microsoft.resources/deployments":
            yield from nested_templates(resource["properties"]["template"])


class BicepTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled = {}
        cls.warnings = {}
        for path in sorted((ROOT / "infra").rglob("*.bicep")):
            result = subprocess.run(["az", "bicep", "build", "--file", str(path), "--stdout"],
                                    capture_output=True, text=True)
            if result.returncode:
                raise AssertionError(f"{path.name} compilation failed:\n{result.stderr}")
            cls.compiled[str(path.relative_to(ROOT / "infra"))] = json.loads(result.stdout)
            cls.warnings[str(path.relative_to(ROOT / "infra"))] = result.stderr

    def resources(self, name, kind):
        return [r for t in nested_templates(self.compiled[name]) for r in t.get("resources", [])
                if r["type"].lower() == kind.lower()]

    def test_all_bicep_files_compile(self):
        self.assertEqual(len(self.compiled), 37)
        self.assertIn("peering-customer.bicep", self.compiled)

    def test_checkpoint_foundation_is_isolated_and_does_not_deploy_a_firewall_vm(self):
        name = "provider-checkpoint-foundation.bicep"
        template = self.compiled[name]
        self.assertEqual(set(template["parameters"]), {
            "location", "environmentId", "customerIngressPublicIp", "customerIngressBgpAddress",
            "customerIngressAsn", "customerDeliveryPublicIp", "customerDeliveryBgpAddress",
            "customerDeliveryAsn", "ingressSharedKey", "deliverySharedKey", "adminAllowedSources",
            "firewallTopology", "providerVpnGatewaySku"})
        self.assertEqual(template["parameters"]["firewallTopology"]["defaultValue"], "single")
        self.assertEqual(set(template["outputs"]), {"connectionManifest", "checkpointFoundation"})
        for key in ("ingressSharedKey", "deliverySharedKey"):
            self.assertEqual(template["parameters"][key]["type"].lower(), "securestring")
            self.assertNotIn("defaultValue", template["parameters"][key])
        for nested in nested_templates(template):
            self.assertNotIn("sharedkey", json.dumps(nested.get("outputs", {})).lower())
            for resource in nested.get("resources", []):
                self.assertNotIn("scope", resource)
                self.assertNotIn("templateLink", resource.get("properties", {}))
                if "nat" in resource["type"].lower():
                    self.assertEqual(resource["type"], "Microsoft.Network/natGateways")
                    self.assertIn("nat-cp-automation-", resource["name"])
        self.assertFalse(self.resources(name, "Microsoft.Compute/virtualMachines"))
        self.assertFalse(self.resources(name, "Microsoft.Authorization/roleAssignments"))
        self.assertEqual(len(self.resources(name, "Microsoft.Network/virtualHubs")), 1)
        peers = self.resources(name, "Microsoft.Network/virtualHubs/bgpConnections")
        self.assertEqual(len(peers), 2)
        self.assertEqual({peer["name"] for peer in peers}, {"[format('{0}/{1}', parameters('name'), 'nva-primary')]",
                                                            "[format('{0}/{1}', parameters('routeServerName'), "
                                                            "'nva-secondary')]"})
        self.assertTrue(all(peer["properties"]["peerAsn"] == 65050 for peer in peers))
        self.assertEqual({peer["properties"]["peerIp"] for peer in peers}, {"[parameters('peerIp')]"})
        secondary = next(resource for resource in template["resources"]
                         if resource["type"] == "Microsoft.Resources/deployments"
                         and "checkpoint-route-server-peer2-" in resource["name"])
        self.assertEqual(secondary["condition"], "[equals(parameters('firewallTopology'), 'vmss')]")
        self.assertEqual(template["variables"]["secondaryFirewallPrivateIp"],
                         "[if(equals(parameters('firewallTopology'), 'vmss'), '172.22.10.5', '')]")
        route_server = next(resource for resource in template["resources"]
                            if resource["type"] == "Microsoft.Resources/deployments"
                            and "checkpoint-route-server-" in resource["name"])
        self.assertEqual(route_server["properties"]["parameters"]["peerIp"]["value"],
                         "[variables('firewallPrivateIp')]")
        self.assertEqual(template["variables"]["firewallPrivateIp"], "172.22.10.4")
        delivery = next(resource for resource in template["resources"]
                        if resource["type"] == "Microsoft.Resources/deployments"
                        and "checkpoint-delivery-connection-" in resource["name"])
        self.assertTrue(delivery["properties"]["parameters"]["enableBgp"]["value"])
        self.assertTrue(delivery["properties"]["parameters"]["useExistingLocalGateway"]["value"])
        self.assertEqual(delivery["properties"]["parameters"]["remotePrefixes"]["value"],
                         ["[format('{0}/32', parameters('customerDeliveryBgpAddress'))]"])
        outputs = template["outputs"]["checkpointFoundation"]["value"]
        self.assertEqual(outputs["firewallFrontendPrivateIp"], "[variables('firewallPrivateIp')]")
        self.assertEqual(outputs["firewallBackendPrivateIp"], "172.22.20.4")
        self.assertEqual(outputs["routeServerAsn"], 65515)
        self.assertIn("peerAddresses", outputs["routeServerPeerAddresses"])
        for peering in self.resources(name, "Microsoft.Network/virtualNetworks/virtualNetworkPeerings"):
            self.assertNotIn("subscription", peering["properties"]["remoteVirtualNetwork"]["id"].lower())
        from service.templates import Templates
        with self.assertRaises(ValueError):
            Templates.validate(template, True)
        self.assertIs(Templates.validate_checkpoint_foundation(template), template)

    def test_checkpoint_foundation_validator_rejects_nat_vm_scope_and_secret_outputs(self):
        from service.templates import Templates

        source = self.compiled["provider-checkpoint-foundation.bicep"]
        bad_nat = copy.deepcopy(source)
        connection = next(resource for nested in nested_templates(bad_nat)
                          for resource in nested.get("resources", [])
                          if resource["type"] == "Microsoft.Network/connections")
        connection["properties"]["ingressNatRules"] = []
        bad_vm = copy.deepcopy(source)
        bad_vm["resources"].append({"type": "Microsoft.Compute/virtualMachines",
                                    "apiVersion": "2024-01-01", "name": "unexpected", "properties": {}})
        bad_scope = copy.deepcopy(source)
        bad_scope["resources"][0]["scope"] = "/subscriptions/other"
        bad_output = copy.deepcopy(source)
        bad_output["outputs"]["connectionManifest"]["value"]["providerIngress"] = "[parameters('ingressSharedKey')]"
        security = next(resource for resource in source["resources"]
                        if resource["type"] == "Microsoft.Network/virtualNetworks"
                        and resource["name"] == "[variables('securityVnetName')]")
        security_index = source["resources"].index(security)
        bad_attachment = copy.deepcopy(source)
        subnets = bad_attachment["resources"][security_index]["properties"]["subnets"]
        runner = next(subnet for subnet in subnets if subnet["name"] == "automation")
        next(subnet for subnet in subnets if subnet["name"] == "firewall-frontend")["properties"]["natGateway"] = (
            runner["properties"]["natGateway"])
        bad_delegation = copy.deepcopy(source)
        runner = next(subnet for subnet in bad_delegation["resources"][security_index]["properties"]["subnets"]
                      if subnet["name"] == "automation")
        runner["properties"]["delegations"] = []
        bad_nsg = copy.deepcopy(source)
        next(resource for resource in bad_nsg["resources"]
             if resource["type"] == "Microsoft.Network/networkSecurityGroups"
             and "nsg-cp-automation-" in resource["name"])["properties"]["securityRules"][0]["properties"]["access"] = "Allow"
        bad_route = copy.deepcopy(source)
        next(resource for resource in bad_route["resources"]
             if resource["type"] == "Microsoft.Network/routeTables"
             and "rt-cp-security-" in resource["name"])["properties"]["routes"] = [{
                 "name": "firewall-internet", "properties": {
                     "addressPrefix": "0.0.0.0/0", "nextHopType": "VirtualAppliance"}}]
        malformed_route = copy.deepcopy(source)
        next(resource for resource in malformed_route["resources"]
             if resource["type"] == "Microsoft.Network/routeTables"
             and "rt-cp-security-" in resource["name"])["properties"]["disableBgpRoutePropagation"] = 0
        bad_nat_ip = copy.deepcopy(source)
        next(resource for resource in bad_nat_ip["resources"]
             if resource["type"] == "Microsoft.Network/natGateways")["properties"]["publicIpAddresses"][0]["id"] = "/foreign"
        duplicate_nat = copy.deepcopy(source)
        duplicate_nat["resources"].append(copy.deepcopy(next(resource for resource in duplicate_nat["resources"]
                                                             if resource["type"] == "Microsoft.Network/natGateways")))
        bad_suffix = copy.deepcopy(source)
        bad_suffix["variables"]["suffix"] = "other-environment"
        for index, invalid in enumerate((bad_nat, bad_vm, bad_scope, bad_output, bad_attachment,
                                         bad_delegation, bad_nsg, bad_route, malformed_route,
                                         bad_nat_ip, duplicate_nat, bad_suffix)):
            with self.subTest(case=index), self.assertRaises(ValueError):
                Templates.validate_checkpoint_foundation(invalid)

    def test_checkpoint_nat_is_only_on_container_runner_subnet(self):
        name = "provider-checkpoint-foundation.bicep"
        template = self.compiled[name]
        self.assertEqual(len(self.resources(name, "Microsoft.Network/natGateways")), 1)
        security = next(resource for resource in template["resources"]
                        if resource["type"] == "Microsoft.Network/virtualNetworks"
                        and resource["name"] == "[variables('securityVnetName')]")
        subnets = security["properties"]["subnets"]
        runner = next(subnet for subnet in subnets if subnet["name"] == "automation")
        self.assertEqual([subnet["name"] for subnet in subnets if "natGateway" in subnet["properties"]],
                         ["automation"])
        self.assertEqual(runner["properties"]["delegations"][0]["properties"]["serviceName"],
                         "Microsoft.ContainerInstance/containerGroups")
        self.assertIn("nat-cp-automation-", runner["properties"]["natGateway"]["id"])
        self.assertIn("rt-cp-security-", runner["properties"]["routeTable"]["id"])
        self.assertFalse(runner["properties"]["defaultOutboundAccess"])
        nsg = next(resource for resource in template["resources"]
                   if resource["type"] == "Microsoft.Network/networkSecurityGroups"
                   and "nsg-cp-automation-" in resource["name"])
        self.assertEqual(nsg["properties"]["securityRules"], [{
            "name": "deny-inbound",
            "properties": {"priority": 100, "direction": "Inbound", "access": "Deny", "protocol": "*",
                           "sourceAddressPrefix": "*", "sourcePortRange": "*",
                           "destinationAddressPrefix": "*", "destinationPortRange": "*"},
        }])

    def test_checkpoint_private_data_is_private_and_environment_scoped(self):
        from service.templates import CHECKPOINT_PRIVATE_DATA_RESOURCES, Templates

        name = "provider-checkpoint-private-data.bicep"
        template = self.compiled[name]
        self.assertIs(Templates.validate_checkpoint_private_data(template), template)
        self.assertEqual({item["type"] for item in template["resources"]}, CHECKPOINT_PRIVATE_DATA_RESOURCES)
        self.assertFalse(self.resources(name, "Microsoft.Authorization/roleAssignments"))
        self.assertFalse(self.resources(name, "Microsoft.KeyVault/vaults/secrets"))
        self.assertFalse(self.resources(name, "Microsoft.Resources/resourceGroups"))
        storage = self.resources(name, "Microsoft.Storage/storageAccounts")[0]["properties"]
        self.assertFalse(storage["allowSharedKeyAccess"])
        self.assertFalse(storage["allowBlobPublicAccess"])
        self.assertEqual(storage["publicNetworkAccess"], "Disabled")
        vault = self.resources(name, "Microsoft.KeyVault/vaults")[0]["properties"]
        self.assertEqual(vault["publicNetworkAccess"], "Disabled")
        self.assertTrue(vault["enableRbacAuthorization"])
        self.assertTrue(vault["enablePurgeProtection"])
        links = template["variables"]["privateLinks"]
        self.assertEqual([link["name"] for link in links], ["vault", "blob"])
        endpoint = self.resources(name, "Microsoft.Network/privateEndpoints")[0]
        self.assertEqual(endpoint["copy"]["count"], "[length(variables('privateLinks'))]")
        self.assertIn("private-endpoints", endpoint["properties"]["subnet"]["id"])
        foundation = self.compiled["provider-checkpoint-foundation.bicep"]
        security = next(resource for resource in foundation["resources"]
                        if resource["type"] == "Microsoft.Network/virtualNetworks"
                        and resource["name"] == "[variables('securityVnetName')]")
        subnet = next(item for item in security["properties"]["subnets"] if item["name"] == "private-endpoints")
        self.assertEqual(subnet["properties"]["addressPrefix"], "172.22.42.0/24")
        self.assertEqual(subnet["properties"]["privateEndpointNetworkPolicies"], "Disabled")
        self.assertFalse(subnet["properties"]["defaultOutboundAccess"])

    def test_checkpoint_private_data_validator_rejects_unsafe_templates(self):
        from service.templates import Templates

        source = self.compiled["provider-checkpoint-private-data.bicep"]
        cases = []
        for resource_type, key, value in (
            ("Microsoft.KeyVault/vaults", "publicNetworkAccess", "Enabled"),
            ("Microsoft.KeyVault/vaults", "enableRbacAuthorization", False),
            ("Microsoft.Storage/storageAccounts", "publicNetworkAccess", "Enabled"),
            ("Microsoft.Storage/storageAccounts", "allowSharedKeyAccess", True),
            ("Microsoft.Storage/storageAccounts", "allowSharedKeyAccess", 0),
            ("Microsoft.Storage/storageAccounts", "allowBlobPublicAccess", True),
            ("Microsoft.Storage/storageAccounts", "allowCrossTenantReplication", True),
            ("Microsoft.Storage/storageAccounts/blobServices/containers", "publicAccess", "Blob"),
        ):
            item = copy.deepcopy(source)
            resource = next(r for r in item["resources"] if r["type"] == resource_type)
            resource["properties"][key] = value
            cases.append(item)
        wrong_scope = copy.deepcopy(source)
        wrong_scope["resources"][0]["scope"] = "/subscriptions/other"
        cases.append(wrong_scope)
        wrong_endpoint = copy.deepcopy(source)
        next(r for r in wrong_endpoint["resources"] if r["type"] == "Microsoft.Network/privateEndpoints"
             )["properties"]["subnet"]["id"] = "/other/subnet"
        cases.append(wrong_endpoint)
        missing_endpoints = copy.deepcopy(source)
        next(r for r in missing_endpoints["resources"] if r["type"] == "Microsoft.Network/privateEndpoints"
             )["copy"]["count"] = 0
        cases.append(missing_endpoints)
        wrong_zone = copy.deepcopy(source)
        next(r for r in wrong_zone["resources"] if r["type"] == "Microsoft.Network/privateEndpoints/privateDnsZoneGroups"
             )["properties"]["privateDnsZoneConfigs"][0]["properties"]["privateDnsZoneId"] = "/other/zone"
        cases.append(wrong_zone)
        secret_output = copy.deepcopy(source)
        secret_output["outputs"]["stateBlobEndpoint"]["value"] = "[listKeys('unsafe', '2023-05-01')]"
        cases.append(secret_output)
        arbitrary_output = copy.deepcopy(source)
        arbitrary_output["outputs"]["credentialVaultUri"]["value"] = "[reference('other').value]"
        cases.append(arbitrary_output)
        unexpected = copy.deepcopy(source)
        unexpected["resources"].append({"type": "Microsoft.Authorization/roleAssignments"})
        cases.append(unexpected)
        for index, invalid in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(ValueError):
                Templates.validate_checkpoint_private_data(invalid)

    def test_checkpoint_foundation_keeps_network_prefixes_generic_and_management_private(self):
        name = "provider-checkpoint-foundation.bicep"
        source = (ROOT / "infra" / name).read_text()
        self.assertNotIn("10.211.0.0/16", source)
        self.assertNotIn("10.212.0.0/16", source)
        self.assertNotIn("natRules", source)
        self.assertIn("remotePrefixes: ['${customerDeliveryBgpAddress}/32']", source)
        self.assertIn("defaultSiteId: i == 1 ? deliveryLocalGateway.id : ''", source)
        networks = [ipaddress.ip_network(value) for value in (
            "172.20.0.0/16", "172.21.0.0/16", "172.22.0.0/16")]
        self.assertTrue(all(not first.overlaps(second)
                            for index, first in enumerate(networks) for second in networks[index + 1:]))
        subnets = [ipaddress.ip_network(value) for value in (
            "172.22.10.0/24", "172.22.20.0/24", "172.22.30.0/24",
            "172.22.40.0/23", "172.22.42.0/24")]
        self.assertTrue(all(subnet.subnet_of(networks[2]) for subnet in subnets))
        self.assertTrue(all(not first.overlaps(second)
                            for index, first in enumerate(subnets) for second in subnets[index + 1:]))
        provider = self.compiled[name]
        routes = [resource for resource in provider["resources"]
                  if resource["type"] == "Microsoft.Network/routeTables"]
        ingress = next(resource for resource in routes if "rt-cp-pi-" in resource["name"])
        security = next(resource for resource in routes if "rt-cp-security-" in resource["name"])
        self.assertEqual(ingress["properties"]["routes"], [])
        self.assertEqual(security["properties"]["routes"], (
            "[concat(createArray(createObject('name', 'firewall-internet', 'properties', "
            "createObject('addressPrefix', '0.0.0.0/0', 'nextHopType', 'Internet'))), variables('adminReturnRoutes'))]"))
        management = next(resource for resource in provider["resources"]
                          if resource["type"] == "Microsoft.Network/networkSecurityGroups"
                          and "nsg-cp-management-" in resource["name"])
        self.assertEqual(management["properties"], (
            "[if(empty(parameters('adminAllowedSources')), createObject('securityRules', "
            "variables('legacyManagementRules')), createObject())]"))
        rules = provider["variables"]["legacyManagementRules"]
        self.assertEqual([rule["properties"]["access"] for rule in rules], ["Allow", "Deny"])
        self.assertEqual(rules[0]["properties"]["sourceAddressPrefixes"],
                         ["172.22.10.4/32", "172.22.10.5/32", "172.22.20.4/32", "172.22.30.0/24",
                          "172.22.40.0/23"])
        self.assertEqual(rules[1]["properties"]["sourceAddressPrefix"], "*")
        self.assertLess(rules[0]["properties"]["priority"], rules[1]["properties"]["priority"])


    def test_compiled_customer_release_passes_firewall_publishing_guard(self):
        from service.enrollment import CustomerBinding
        from service.profiles import ProfilePublisher

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "customer.json").write_text(json.dumps(self.compiled["customer-deployment.bicep"]))
            (path / "customer-connections.json").write_text(json.dumps(self.compiled["customer-connections.bicep"]))
            (path / "customer-form.json").write_text((ROOT / "portal/customer-form.json").read_text())
            with patch("service.profiles.BlobServiceClient"):
                publisher = ProfilePublisher(unittest.mock.Mock(), "https://unit.blob.core.windows.net",
                                             "https://unit.azurewebsites.net", "api://" + uid(6), uid(1), path)
            customer = CustomerBinding(uid(10), "unit", uid(1), uid(2), uid(3), uid(4), 1, "Ready")
            template, form = publisher.documents(customer)
            self.assertEqual(template["parameters"]["firewallType"]["defaultValue"], "ubuntu")
            self.assertEqual(form["view"]["outputs"]["parameters"]["firewallType"],
                             "[steps('basics').firewallType]")

    def test_isolated_group_role_is_opt_in_and_constrained(self):
        main = self.compiled['main.bicep']
        self.assertFalse(main['parameters']['prepareIsolatedEnvironments']['defaultValue'])
        self.assertFalse(main['parameters']['approveEnvironmentDelegation']['defaultValue'])
        definitions = self.resources('modules/environment-group-roles.bicep',
                                     'Microsoft.Authorization/roleDefinitions')
        assignments = self.resources('modules/environment-group-roles.bicep',
                                     'Microsoft.Authorization/roleAssignments')
        actions = definitions[0]['properties']['permissions'][0]['actions']
        self.assertIn('Microsoft.Resources/subscriptions/resourceGroups/write', actions)
        self.assertIn('Microsoft.Authorization/roleAssignments/write', actions)
        self.assertNotIn('Microsoft.Authorization/roleAssignments/delete', actions)
        self.assertEqual(assignments[0]['properties']['condition'], "[variables('condition')]")
        condition = self.compiled['modules/environment-group-roles.bicep']['variables']['condition']
        self.assertIn('Microsoft.Authorization/roleAssignments:PrincipalId', condition)
        self.assertIn('Microsoft.Authorization/roleAssignments:RoleDefinitionId', condition)

    def test_deployment_zip_contains_both_templates_and_no_private_files(self):
        target = ROOT / ".local/test-infra-package.zip"
        generated = (target, target.with_suffix(".metadata.json"), target.parent / "customer-connections.json")
        old_customer_template = generated[2].read_bytes() if generated[2].exists() else None
        provider_template = target.parent / "provider-template.json"
        old_provider_template = provider_template.read_bytes() if provider_template.exists() else None
        try:
            with patch.object(package_apps, "compile_bicep", side_effect=lambda name: json.dumps(self.compiled[name]).encode()), \
                    patch.object(package_apps, "validate_runtime_template") as validate:
                metadata = package_apps.package(target)
                validate.assert_called_once()
            with zipfile.ZipFile(target) as archive:
                names = set(archive.namelist())
                self.assertIn("service/templates/proof.json", names)
                self.assertIn("service/templates/provider.json", names)
                self.assertIn("startup-api.sh", names)
                self.assertIn("startup-worker.sh", names)
                self.assertIn("startup-management.sh", names)
                self.assertIn("service/static/management.html", names)
                self.assertIn("service/templates/customer.json", names)
                self.assertIn("service/templates/customer-form.json", names)
                self.assertTrue(metadata["includesManagement"])
                self.assertNotIn("includesCheckpointPreview", metadata)
                self.assertNotIn("service/templates/checkpoint-foundation.json", names)
                self.assertNotIn("service/templates/checkpoint-private-data.json", names)
                self.assertNotIn(".local", "/".join(names))
                self.assertNotIn(".venv", "/".join(names))
                self.assertEqual(json.loads(archive.read("service/templates/provider.json")), self.compiled["provider-dataplane.bicep"])
                self.assertEqual(len(metadata["providerTemplateSha256"]), 64)
        finally:
            for path in generated[:2]:
                if path.exists():
                    path.unlink()
            if old_customer_template is None:
                if generated[2].exists():
                    generated[2].unlink()
            else:
                generated[2].write_bytes(old_customer_template)
            if old_provider_template is None:
                if provider_template.exists():
                    provider_template.unlink()
            else:
                provider_template.write_bytes(old_provider_template)

    def test_control_plane_hardening(self):
        main = self.compiled["main.bicep"]
        plan = self.resources("main.bicep", "Microsoft.Web/serverfarms")[0]
        self.assertEqual(plan["sku"]["name"], "B2")
        self.assertTrue(plan["properties"]["reserved"])
        apps = self.resources("main.bicep", "Microsoft.Web/sites")[0]
        self.assertIn("equals(variables('appModes')[copyIndex()], 'worker')", apps["identity"])
        self.assertIn("createObject('type', 'SystemAssigned')", apps["identity"])
        self.assertIn("SystemAssigned, UserAssigned", apps["identity"])
        self.assertTrue(apps["properties"]["httpsOnly"])
        settings = apps["properties"]["siteConfig"]
        self.assertEqual(settings["linuxFxVersion"], "PYTHON|3.12")
        self.assertTrue(settings["alwaysOn"])
        self.assertEqual(settings["ftpsState"], "Disabled")
        self.assertEqual(settings["minTlsVersion"], "1.2")
        self.assertTrue(settings["http20Enabled"])
        self.assertEqual(settings["scmIpSecurityRestrictionsDefaultAction"], "Deny")
        self.assertFalse(settings["scmIpSecurityRestrictionsUseMain"])
        self.assertIn("createObject('name', 'WEBSITE_DNS_SERVER', 'value', '168.63.129.16')",
                      settings["appSettings"])
        self.assertIn("'Deny'", settings["ipSecurityRestrictionsDefaultAction"])
        self.assertFalse(main["parameters"]["approveScmBootstrapException"]["defaultValue"])
        for policy in self.resources("main.bicep", "Microsoft.Web/sites/basicPublishingCredentialsPolicies"):
            self.assertFalse(policy["properties"]["allow"])

    def test_private_state_no_keys(self):
        storage = self.resources("main.bicep", "Microsoft.Storage/storageAccounts")[0]
        vault = self.resources("main.bicep", "Microsoft.KeyVault/vaults")[0]
        self.assertFalse(storage["properties"]["allowSharedKeyAccess"])
        self.assertEqual(storage["properties"]["publicNetworkAccess"], "Disabled")
        self.assertEqual(vault["properties"]["publicNetworkAccess"], "Disabled")
        for field in ("enableRbacAuthorization", "enableSoftDelete", "enablePurgeProtection"):
            self.assertTrue(vault["properties"][field])
        self.assertEqual(len(self.resources("main.bicep", "Microsoft.Network/privateEndpoints")), 1)
        self.assertIn("'Operations'", self.resources("main.bicep", "Microsoft.Storage/storageAccounts/tableServices/tables")[0]["name"])
        self.assertNotIn("listKeys", json.dumps(self.compiled["main.bicep"]))

    def test_management_platform_auth_and_private_credential_boundaries(self):
        template = self.compiled["provider-management.bicep"]
        app = self.resources("provider-management.bicep", "Microsoft.Web/sites")[0]
        settings = app["properties"]["siteConfig"]
        self.assertEqual(settings["scmIpSecurityRestrictionsDefaultAction"], "Deny")
        self.assertEqual(settings["scmIpSecurityRestrictions"], [])
        self.assertEqual(len(settings["cors"]["allowedOrigins"]), 1)
        self.assertIn("appName", settings["cors"]["allowedOrigins"][0])
        self.assertTrue(app["properties"]["vnetRouteAllEnabled"])
        auth = next(resource for resource in template["resources"]
                    if resource["type"] == "Microsoft.Web/sites/config")["properties"]
        self.assertTrue(auth["platform"]["enabled"])
        self.assertTrue(auth["globalValidation"]["requireAuthentication"])
        self.assertTrue(auth["login"]["tokenStore"]["enabled"])
        self.assertEqual(len(auth["login"]["allowedExternalRedirectUrls"]), 1)
        self.assertIn("appName", auth["login"]["allowedExternalRedirectUrls"][0])
        allowed = auth["identityProviders"]["azureActiveDirectory"]["validation"]
        self.assertIn("administratorObjectIds",
                      allowed["defaultAuthorizationPolicy"]["allowedPrincipals"]["identities"])
        vault = self.resources("provider-management.bicep", "Microsoft.KeyVault/vaults")[0]
        self.assertEqual(vault["properties"]["publicNetworkAccess"], "Disabled")
        self.assertTrue(vault["properties"]["enablePurgeProtection"])
        self.assertEqual(template["parameters"]["managementApplicationSecret"]["type"], "securestring")
        self.assertNotIn("defaultValue", template["parameters"]["managementApplicationSecret"])
        self.assertNotIn("secret", " ".join(template["outputs"]).lower())

    def test_native_provider_installation_pins_and_declared_storage_exception(self):
        install = self.compiled["provider-installation.bicep"]
        self.assertIn("subscriptionDeploymentTemplate", install["$schema"])
        self.assertEqual(install["parameters"]["codePackageUri"]["type"], "securestring")
        self.assertEqual(install["parameters"]["managementApplicationSecret"]["type"], "securestring")
        self.assertNotIn("defaultValue", install["parameters"]["managementApplicationSecret"])
        backing = self.resources("provider-installation-code.bicep", "Microsoft.Storage/storageAccounts")[0]
        self.assertIn("Ignore", str(backing["tags"]))
        self.assertFalse(backing["properties"]["allowBlobPublicAccess"])
        self.assertIn("approveDeploymentScriptBackingException",
                      backing["properties"]["allowSharedKeyAccess"])
        publisher = self.resources("provider-installation-code.bicep",
                                   "Microsoft.Resources/deploymentScripts")[0]
        self.assertIn("publicationAttempt", publisher["properties"]["forceUpdateTag"])
        variables = publisher["properties"]["environmentVariables"]
        package = next(item for item in variables if item["name"] == "FAAS_PACKAGE_URI")
        self.assertIn("secureValue", package)
        self.assertNotIn("value", package)

    def test_guided_installer_uses_private_endpoint_not_arm_secret_reference(self):
        wrapper = self.compiled["provider-guided-installation.bicep"]
        self.assertNotIn("managementApplicationSecret", wrapper["parameters"])
        deployment = next(resource for resource in wrapper["resources"]
                          if resource["type"] == "Microsoft.Resources/deployments")
        parameters = deployment["properties"]["parameters"]
        self.assertEqual(parameters["managementApplicationSecret"]["value"], "")
        self.assertNotIn("controlResourceGroupName", wrapper["parameters"])
        self.assertEqual(parameters["controlResourceGroupName"]["value"], "[resourceGroup().name]")
        self.assertIn("managementSecretName", parameters["managementSecretName"]["value"])
        self.assertIn("managementSecretVersion", parameters["managementSecretVersion"]["value"])
        self.assertNotIn("secret", " ".join(wrapper["outputs"]).lower())
        vault = self.resources("provider-setup-vault.bicep", "Microsoft.KeyVault/vaults")[0]
        self.assertFalse(vault["properties"].get("enabledForTemplateDeployment", False))
        self.assertTrue(vault["properties"]["enableRbacAuthorization"])
        self.assertTrue(vault["properties"]["enablePurgeProtection"])
        self.assertEqual(vault["properties"]["publicNetworkAccess"], "Disabled")
        self.assertEqual(vault["properties"]["networkAcls"]["defaultAction"], "Deny")
        self.assertEqual(vault["properties"]["networkAcls"]["bypass"], "None")
        access = self.compiled["provider-setup-management-access.bicep"]
        role = next(item for item in access["resources"]
                    if item["type"] == "Microsoft.Authorization/roleAssignments")
        self.assertIn("secretName", role["scope"])
        management = self.compiled["provider-management.bicep"]
        self.assertIn("managementSecretVersion", json.dumps(management))
        endpoint = next(item for item in management["resources"]
                        if item["type"] == "Microsoft.Network/privateEndpoints"
                        and "setup-vault" in item["name"])
        self.assertIn("usesSetupVault", endpoint["condition"])

    def test_setup_host_has_private_state_and_scoped_release_access(self):
        setup = self.compiled["provider-setup-host.bicep"]
        storage = self.resources("provider-setup-host.bicep", "Microsoft.Storage/storageAccounts")[0]
        self.assertEqual(storage["properties"]["publicNetworkAccess"], "Disabled")
        self.assertFalse(storage["properties"]["allowSharedKeyAccess"])
        self.assertFalse(storage["properties"]["allowBlobPublicAccess"])
        vault = self.resources("provider-setup-host.bicep", "Microsoft.KeyVault/vaults")[0]
        self.assertEqual(vault["properties"]["publicNetworkAccess"], "Disabled")
        self.assertEqual(vault["properties"]["networkAcls"]["bypass"], "None")
        self.assertFalse(vault["properties"].get("enabledForTemplateDeployment", False))
        self.assertTrue(vault["properties"]["enablePurgeProtection"])
        app = self.resources("provider-setup-host.bicep", "Microsoft.Web/sites")[0]
        self.assertTrue(app["properties"]["httpsOnly"])
        self.assertEqual(app["identity"], {"type": "SystemAssigned"})
        self.assertEqual(app["properties"]["siteConfig"]["scmIpSecurityRestrictions"], [])
        self.assertEqual(app["properties"]["siteConfig"]["scmIpSecurityRestrictionsDefaultAction"], "Deny")
        access = self.compiled["provider-setup-release-access.bicep"]
        roles = [item for item in access["resources"]
                 if item["type"] == "Microsoft.Authorization/roleAssignments"]
        self.assertEqual(len(roles), 2)
        self.assertTrue(any("delegator" in str(item["name"]).lower()
                            or "db58b8e5" in str(item["properties"]["roleDefinitionId"]) for item in roles))
        self.assertNotIn("managementApplicationSecret", setup["parameters"])

    def test_bootstrap_entry_has_only_essential_admin_fields(self):
        form = json.loads((ROOT / "portal/provider-bootstrap-form.json").read_text())
        self.assertEqual(form["view"]["outputs"]["kind"], "ResourceGroup")
        self.assertEqual(set(form["view"]["outputs"]["parameters"]),
                         {"approveDeploymentScriptBackingException"})
        fields = [item for step in form["view"]["properties"]["steps"] for item in step["elements"]]
        self.assertFalse(any(item["type"] == "Microsoft.Common.PasswordBox" for item in fields))
        entry = self.compiled["provider-bootstrap-entry.bicep"]
        host = next(item for item in entry["resources"]
                    if item["type"] == "Microsoft.Resources/deployments"
                    and "provider-setup-host" in str(item["name"]))
        parameters = host["properties"]["parameters"]
        self.assertIn("deployer().objectId", parameters["administratorObjectId"]["value"])
        self.assertIn("deployer().tenantId", parameters["administratorTenantId"]["value"])

    def test_scoped_roles_no_directory_or_customer_provider_rbac(self):
        role = self.compiled["modules/worker-role.bicep"]
        self.assertNotIn("scope", role["resources"][0])
        deploy = next(r for r in self.compiled["main.bicep"]["resources"] if r["type"] == "Microsoft.Resources/deployments")
        self.assertIn("resourceGroup", deploy)
        self.assertIn("subscriptionId", deploy)
        compiled = json.dumps(self.compiled)
        self.assertNotRegex(compiled, r"\bOwner\b")
        self.assertNotIn("8e3af657-a8ff-443c-a75c-2fe8c4bcb635", compiled.lower())
        self.assertFalse(self.resources("provider-dataplane.bicep", "Microsoft.Authorization/roleAssignments"))
        self.assertFalse(self.resources("customer-foundation.bicep", "Microsoft.Authorization/roleAssignments"))
        table_roles = [r for r in self.resources("main.bicep", "Microsoft.Authorization/roleAssignments")
                       if r.get("scope") and "table" in r["scope"].lower()]
        self.assertTrue(table_roles)

    def test_network_parameter_contract_and_secrets(self):
        template = self.compiled["provider-dataplane.bicep"]
        expected = {"location", "environmentId", "customerIngressPublicIp", "customerIngressBgpAddress",
                    "customerIngressAsn", "customerDeliveryPublicIp", "customerDeliveryBgpAddress",
                    "customerDeliveryAsn", "ingressSharedKey", "deliverySharedKey", "sshPublicKey",
                    "parallelProviderNetworking", "providerVpnGatewaySku"}
        self.assertEqual(set(template["parameters"]), expected)
        self.assertFalse(template["parameters"]["parallelProviderNetworking"]["defaultValue"])
        self.assertEqual(template["parameters"]["ingressSharedKey"]["type"].lower(), "securestring")
        self.assertEqual(template["parameters"]["deliverySharedKey"]["type"].lower(), "securestring")
        self.assertEqual(set(template["outputs"]), {"connectionManifest"})
        for name in ("provider-dataplane.bicep", "customer-connections.bicep"):
            for template in nested_templates(self.compiled[name]):
                self.assertNotIn("sharedKey", json.dumps(template.get("outputs", {})))
                for resource in template.get("resources", []):
                    self.assertNotIn("templateLink", resource.get("properties", {}))

    def test_source_preserving_delivery_and_no_cross_side_peerings(self):
        source = (ROOT / "infra/provider-dataplane.bicep").read_text()
        self.assertIn("name: 'nva-internet'", source)
        self.assertIn("disableBgpRoutePropagation: false", source)
        self.assertIn("remotePrefixes: ['${customerDeliveryBgpAddress}/32']", source)
        self.assertNotIn("10.211.0.0/16", source)
        self.assertNotIn("10.212.0.0/16", source)
        self.assertIn("useExistingLocalGateway: true", source)
        self.assertIn("defaultSiteId: i == 1 ? deliveryLocalGateway.id : ''", source)
        for name in ("provider-dataplane.bicep", "customer-foundation.bicep"):
            for peering in self.resources(name, "Microsoft.Network/virtualNetworks/virtualNetworkPeerings"):
                self.assertNotIn("subscription", peering["properties"]["remoteVirtualNetwork"]["id"].lower())
        self.assertIn("== 1", source)
        provider = self.compiled["provider-dataplane.bicep"]
        route_tables = [resource for resource in provider["resources"]
                        if resource["type"] == "Microsoft.Network/routeTables"]
        ingress = next(resource for resource in route_tables if "rt-pi-" in resource["name"])
        security = next(resource for resource in route_tables if "rt-security-" in resource["name"])
        self.assertEqual(ingress["properties"]["routes"], [])
        self.assertEqual(security["properties"]["routes"], [{
            "name": "nva-internet",
            "properties": {"addressPrefix": "0.0.0.0/0", "nextHopType": "Internet"},
        }])
        site = next(resource for resource in provider["resources"]
                    if resource["type"] == "Microsoft.Network/localNetworkGateways")
        self.assertEqual(site["properties"]["localNetworkAddressSpace"]["addressPrefixes"],
                         ["[format('{0}/32', parameters('customerDeliveryBgpAddress'))]"])
        self.assertEqual(site["properties"]["bgpSettings"]["asn"], "[parameters('customerDeliveryAsn')]")

    def test_gateway_bgp_and_nva_ha_shape(self):
        gateway = self.compiled["modules/gateway.bicep"]["resources"][-1]["properties"]
        self.assertIn("'enableBgp', true()", gateway)
        self.assertIn("'activeActive', parameters('activeActive')", gateway)
        self.assertIn("'gatewayDefaultSite'", gateway)
        self.assertEqual(self.compiled["modules/gateway.bicep"]["parameters"]["defaultSiteId"]["defaultValue"], "")
        self.assertFalse(self.compiled["modules/gateway.bicep"]["parameters"]["activeActive"]["defaultValue"])
        self.assertEqual(self.compiled["modules/gateway.bicep"]["parameters"]["sku"]["defaultValue"], "VpnGw1AZ")
        self.assertIn("'sku', createObject('name', parameters('sku'), 'tier', parameters('sku'))", gateway)
        self.assertIn("if(equals(parameters('sku'), 'VpnGw1AZ'), 'Generation1', 'Generation2')", gateway)
        lb = self.resources("provider-dataplane.bicep", "Microsoft.Network/loadBalancers")[0]["properties"]
        self.assertEqual(lb["probes"][0]["properties"]["port"], 9999)
        rule = lb["loadBalancingRules"][0]["properties"]
        self.assertEqual(rule["protocol"], "All")
        self.assertTrue(rule["enableFloatingIP"])
        self.assertTrue(rule["disableOutboundSnat"])
        self.assertEqual(lb["frontendIPConfigurations"][0]["properties"]["privateIPAddress"], "[variables('vip')]")

    def test_portal_sizing_dropdowns_match_arm_types_allowed_values_and_defaults(self):
        form = json.loads((ROOT / "portal/customer-form.json").read_text())
        self.assertEqual(form["view"]["kind"], "Form")
        self.assertIn("uiFormDefinition.schema.json", form["$schema"])
        fields = {element["name"]: element for step in form["view"]["properties"]["steps"]
                  for element in step["elements"]}
        parameters = self.compiled["customer-deployment.bicep"]["parameters"]
        outputs = form["view"]["outputs"]["parameters"]
        self.assertEqual(set(parameters) - set(outputs), {
            "apiAuthorityTenantId", "expectedCustomerTenantId", "expectedCustomerSubscriptionId", "enrolledCustomerResourceGroupId",
            "apiUrl", "apiResource", "customerConnectionsTemplateBase64", "deploymentMode",
            "providerProtectedResourceGroupIds"})
        self.assertTrue(set(outputs) <= set(parameters))
        ssh = fields["sshCredentials"]
        self.assertEqual(ssh["type"], "Microsoft.Compute.CredentialsCombo")
        self.assertIn("An admin list restricts public test VM SSH", ssh["toolTip"]["sshPublicKey"])
        self.assertIn("empty list retains legacy", ssh["toolTip"]["sshPublicKey"])
        self.assertIn("unrestricted lab NSG traffic", fields["approveDeploymentScriptBackingException"]["label"])
        self.assertEqual(ssh["osPlatform"], "Linux")
        self.assertTrue(ssh["options"]["hidePassword"])
        self.assertEqual(ssh["constraints"]["required"], "[not(steps('basics').manualSshKey)]")
        self.assertEqual(outputs["sshPublicKey"],
                         "[if(steps('basics').manualSshKey, steps('basics').sshPublicKey, steps('basics').sshCredentials.sshPublicKey)]")
        self.assertEqual(fields["sshPublicKey"]["visible"], "[steps('basics').manualSshKey]")
        for name, default in common.customer_sizing({}).items():
            field = fields[name]
            self.assertEqual(field["type"], "Microsoft.Common.DropDown")
            self.assertFalse(field["multiselect"])
            self.assertTrue(field["constraints"]["required"])
            choices = field["constraints"]["allowedValues"]
            self.assertEqual([choice["value"] for choice in choices], parameters[name]["allowedValues"])
            selected = [choice["value"] for choice in choices if choice["label"] == field["defaultValue"]]
            self.assertEqual(selected, [default])
            self.assertEqual(parameters[name]["defaultValue"], default)
            self.assertEqual(outputs[name], f"[steps('sizing').{name}]")
        self.assertIs(type(fields["routingApplianceBandwidthGbps"]["constraints"]["allowedValues"][0]["value"]), int)
        for name in ("customerIngressVpnGatewaySku", "customerDeliveryVpnGatewaySku", "providerVpnGatewaySku"):
            self.assertEqual(parameters[name]["allowedValues"], list(common.CUSTOMER_VPN_GATEWAY_SKUS))
        # The provider gateway SKU is the only provider-facing wizard choice.
        self.assertEqual([name for name in fields if "provider" in name.lower()], ["providerVpnGatewaySku"])
        provider_field = fields["providerVpnGatewaySku"]
        self.assertEqual(provider_field["label"], "Provider VPN gateway SKU (both provider gateways)")
        self.assertEqual(provider_field["constraints"]["allowedValues"],
                         fields["customerIngressVpnGatewaySku"]["constraints"]["allowedValues"])
        sizing = next(step for step in form["view"]["properties"]["steps"] if step["name"] == "sizing")
        self.assertIn(provider_field, sizing["elements"])
        self.assertEqual(fields["approveDeploymentScriptBackingException"]["type"], "Microsoft.Common.CheckBox")
        self.assertNotIn("defaultValue", fields["approveDeploymentScriptBackingException"])
        self.assertTrue(fields["approveDeploymentScriptBackingException"]["constraints"]["required"])
        self.assertEqual(parameters["approveDeploymentScriptBackingException"]["allowedValues"], [True])
        regions = json.loads((ROOT / "portal/customer-regions.json").read_text())
        self.assertEqual(parameters["location"]["allowedValues"], regions)
        self.assertEqual([choice["value"] for choice in fields["customerLocation"]["constraints"]["allowedValues"]], regions)
        self.assertEqual(outputs["location"], "[steps('basics').customerLocation]")
        firewall = fields["firewallType"]
        self.assertEqual(parameters["firewallType"]["defaultValue"], "ubuntu")
        self.assertEqual(parameters["firewallType"]["allowedValues"], ["ubuntu", "checkpoint-byol", "checkpoint-vmss"])
        self.assertEqual([choice["value"] for choice in firewall["constraints"]["allowedValues"]],
                         parameters["firewallType"]["allowedValues"])
        self.assertEqual(firewall["defaultValue"], firewall["constraints"]["allowedValues"][2]["label"])
        self.assertIn("lab preview", firewall["constraints"]["allowedValues"][1]["label"])
        self.assertIn("BYOL", firewall["constraints"]["allowedValues"][2]["label"])
        self.assertEqual(outputs["firewallType"], "[steps('basics').firewallType]")
        self.assertIn("not available", fields["checkpointUnavailable"]["options"]["text"])
        for name in ("customer-foundation.bicep", "customer-connections.bicep", "customer-network.bicep"):
            self.assertEqual(self.compiled[name]["parameters"]["location"]["allowedValues"], regions)
        self.assertEqual(fields["apiClientSecret"]["type"], "Microsoft.Common.PasswordBox")
        self.assertNotIn("defaultValue", fields["apiClientSecret"])
        self.assertEqual(parameters["apiClientSecret"]["type"].lower(), "securestring")
        self.assertNotIn("defaultValue", parameters["apiClientSecret"])

    def test_full_customer_portal_dependency_chain_and_native_identity(self):
        template = self.compiled["customer-deployment.bicep"]
        modules = {resource["name"]: resource for resource in template["resources"]
                   if resource["type"] == "Microsoft.Resources/deployments"}
        self.assertEqual(set(modules), {
            "customer-authorization-proof", "customer-foundation", "customer-provider-connection"})
        self.assertIn("customer-authorization-proof", json.dumps(modules["customer-foundation"]["dependsOn"]))
        self.assertIn("customer-foundation", json.dumps(modules["customer-provider-connection"]["dependsOn"]))
        proof = modules["customer-authorization-proof"]["properties"]["parameters"]
        self.assertIs(proof["validateCustomerScope"]["value"], True)
        self.assertEqual(proof["customerSubscriptionId"]["value"], "[subscription().subscriptionId]")
        self.assertEqual(proof["customerResourceGroup"]["value"], "[resourceGroup().name]")
        self.assertEqual(proof["enrolledCustomerResourceGroupId"]["value"],
                         "[parameters('enrolledCustomerResourceGroupId')]")
        network = modules["customer-provider-connection"]["properties"]["parameters"]
        self.assertEqual(proof["firewallType"]["value"], "[parameters('firewallType')]")
        self.assertEqual(network["firewallType"]["value"], "[parameters('firewallType')]")
        for name in ("customer-proof.bicep", "customer-network.bicep"):
            script = self.resources(name, "Microsoft.Resources/deploymentScripts")[0]
            env = {item["name"]: item for item in script["properties"]["environmentVariables"]}
            self.assertEqual(env["FAAS_FIREWALL_TYPE"]["value"], "[parameters('firewallType')]")
            self.assertIn(customer_connector.CHECKPOINT_READINESS, json.dumps(self.compiled[name]["variables"]))
        self.assertEqual(network["customerConnectionsTemplate"]["value"],
                         "[base64ToJson(parameters('customerConnectionsTemplateBase64'))]")
        self.assertEqual(set(template["outputs"]), {"operationId", "status"})
        self.assertEqual(template["parameters"]["deploymentMode"]["allowedValues"], ["proof", "network"])
        for name in ("customer-foundation", "customer-provider-connection"):
            self.assertIn("deploymentMode", modules[name]["condition"])
        self.assertTrue(any(resource["type"] == "Microsoft.ManagedIdentity/userAssignedIdentities"
                            for resource in template["resources"]))
        roles = [resource for resource in template["resources"]
                 if resource["type"] == "Microsoft.Authorization/roleAssignments"]
        self.assertEqual(len(roles), 2)
        for role in roles:
            self.assertNotIn("scope", role)
        self.assertTrue(any("4d97b98b-1d4f-4787-a291-c67834d212e7" in role["properties"]["roleDefinitionId"] for role in roles))
        self.assertTrue(any("acdd72a7-3385-48ef-bd42-f606fba81ae7" in role["properties"]["roleDefinitionId"] for role in roles))
        self.assertIn("roleAssignments", json.dumps(modules["customer-authorization-proof"]["dependsOn"]))
        self.assertEqual(proof["apiAuthMode"]["value"], "provider-api-client")
        self.assertIs(proof["enrollCustomerScope"]["value"], True)
        self.assertIn("customer-authorization-proof",
                      json.dumps(next(resource for resource in template["resources"]
                                      if resource["type"] == "Microsoft.Resources/tags")["dependsOn"]))
        self.assertEqual(network["executionLocation"]["value"], "eastus2")
        self.assertEqual(network["location"]["value"], "[parameters('location')]")
        for nested in nested_templates(template):
            for resource in nested.get("resources", []):
                self.assertFalse(resource["type"].startswith("Microsoft.Graph/"))
                if resource["type"] == "Microsoft.Resources/deploymentScripts":
                    script = resource["properties"]["scriptContent"]
                    for local_tool in ("bootstrap.py", "load_private", "bootstrap-journal", "identity-journal"):
                        self.assertNotIn(local_tool, script)

    def test_customer_connection_region_is_not_provider_region(self):
        source = self.compiled["customer-network.bicep"]
        variables = {item["name"]: item for item in source["resources"][0]["properties"]["environmentVariables"]}
        self.assertEqual(variables["FAAS_CUSTOMER_LOCATION"]["value"], "[parameters('location')]")

    def test_customer_sizing_reaches_resources_and_provider_gateway_sku_reaches_both_provider_gateways(self):
        foundation = self.compiled["customer-foundation.bicep"]
        appliance = self.resources("customer-foundation.bicep", "Microsoft.Network/virtualNetworkAppliances")[0]
        self.assertEqual(appliance["properties"]["bandwidthInGbps"],
                         "[parameters('routingApplianceBandwidthGbps')]")
        for suffix, parameter in (("ingress", "customerIngressVpnGatewaySku"),
                                  ("delivery", "customerDeliveryVpnGatewaySku")):
            module = next(resource for resource in foundation["resources"]
                          if resource["name"] == "customer-" + suffix + "-gateway")
            self.assertEqual(module["properties"]["parameters"]["sku"]["value"], f"[parameters('{parameter}')]")
        sku_values = list(common.CUSTOMER_VPN_GATEWAY_SKUS)
        for name in ("provider-dataplane.bicep", "provider-checkpoint-foundation.bicep"):
            with self.subTest(template=name):
                provider = self.compiled[name]
                self.assertEqual(set(common.customer_sizing({})) & set(provider["parameters"]),
                                 {"providerVpnGatewaySku"})
                self.assertEqual(provider["parameters"]["providerVpnGatewaySku"]["allowedValues"], sku_values)
                self.assertEqual(provider["parameters"]["providerVpnGatewaySku"]["defaultValue"], "VpnGw1AZ")
                gateways = next(resource for resource in provider["resources"]
                                if resource.get("copy", {}).get("name") == "gateways")
                # One copy loop deploys both provider gateways (ingress i=0, delivery i=1).
                self.assertEqual(gateways["copy"]["count"], "[length(range(0, 2))]")
                self.assertEqual(gateways["properties"]["parameters"]["sku"],
                                 {"value": "[parameters('providerVpnGatewaySku')]"})
                self.assertEqual(gateways["properties"]["template"]["parameters"]["sku"]["defaultValue"], "VpnGw1AZ")
        network = self.compiled["customer-network.bicep"]
        self.assertNotIn("providerVpnGatewaySku", foundation["parameters"])
        variables = {item["name"]: item for item in network["resources"][0]["properties"]["environmentVariables"]}
        self.assertEqual(variables["FAAS_PROVIDER_VPN_GATEWAY_SKU"]["value"], "[parameters('providerVpnGatewaySku')]")
        deployment = self.compiled["customer-deployment.bicep"]
        module = next(r for r in deployment["resources"] if r.get("name") == "customer-provider-connection")
        self.assertEqual(module["properties"]["parameters"]["providerVpnGatewaySku"],
                         {"value": "[parameters('providerVpnGatewaySku')]"})
        proof = next(r for r in deployment["resources"] if r.get("name") == "customer-authorization-proof")
        self.assertNotIn("providerVpnGatewaySku", proof["properties"]["parameters"])

    def test_four_vms_no_guest_vpn_or_cloudinit_secrets(self):
        for name, module_name in (("provider-dataplane.bicep", "nvas"), ("customer-foundation.bicep", "workloadVms")):
            modules = [r for r in self.compiled[name]["resources"] if r["type"] == "Microsoft.Resources/deployments"
                       and r.get("copy", {}).get("name") == module_name]
            self.assertEqual(len(modules), 1)
            self.assertEqual(len(self.resources(name, "Microsoft.Compute/virtualMachines")), 1)
        vm = self.compiled["modules/vm.bicep"]["resources"][-1]["properties"]
        self.assertEqual(vm["securityProfile"]["securityType"], "TrustedLaunch")
        self.assertTrue(vm["securityProfile"]["encryptionAtHost"])
        self.assertTrue(vm["osProfile"]["linuxConfiguration"]["disablePasswordAuthentication"])
        self.assertNotIn("plan", vm)
        cloudinit = (ROOT / "infra/cloud-init/nva.yaml").read_text()
        self.assertIn("MASQUERADE", cloudinit)
        self.assertNotIn("SNAT --", cloudinit)
        self.assertNotIn("PRIVATE KEY", cloudinit)
        self.assertIn("User=labuser", cloudinit)

    def test_high_performance_workload_vms_use_d8s_v6_jumbo_frames_and_iperf3(self):
        module = self.compiled["modules/vm.bicep"]
        self.assertEqual(module["parameters"]["size"]["defaultValue"], "Standard_B1ms")
        self.assertFalse(module["parameters"]["acceleratedNetworking"]["defaultValue"])
        self.assertEqual(module["parameters"]["diskControllerType"]["allowedValues"], ["", "NVMe"])
        nic = next(r for r in module["resources"] if r["type"] == "Microsoft.Network/networkInterfaces")
        self.assertEqual(nic["properties"]["enableAcceleratedNetworking"], "[parameters('acceleratedNetworking')]")
        foundation = self.compiled["customer-foundation.bicep"]
        self.assertEqual(foundation["parameters"]["workloadVmProfile"]["allowedValues"],
                         list(common.WORKLOAD_VM_PROFILES))
        vms = next(r for r in foundation["resources"] if r.get("copy", {}).get("name") == "workloadVms")
        params = json.dumps(vms["properties"]["parameters"])
        for expected in ("Standard_D8s_v6", "Standard_B1ms", "NVMe", "acceleratedNetworking"):
            self.assertIn(expected, params)
        cloudinit = (ROOT / "infra/cloud-init/workload-performance.yaml").read_text()
        self.assertTrue(cloudinit.startswith("#cloud-config\n"))
        self.assertIn("  - path: /etc/netplan/90-faas-jumbo.yaml\n    permissions: '0600'\n", cloudinit)
        self.assertIn("        ethernets:\n          eth0:\n            mtu: 9000\n", cloudinit)
        self.assertIn("apt-get install -y iperf3", cloudinit)
        self.assertIn("ExecStart=/usr/bin/iperf3 --server --port 5201", cloudinit)
        self.assertIn("runcmd:\n  - netplan apply\n", cloudinit)
        receiver = (ROOT / "infra/cloud-init/workload.yaml").read_text().split("runcmd:")[0]
        self.assertTrue(cloudinit.startswith(receiver))
        self.assertNotIn("PRIVATE KEY", cloudinit)

    def test_enrollment_scope_is_checked_before_identity_and_protected_provider_groups(self):
        template = self.compiled["customer-deployment.bicep"]
        self.assertEqual(template["parameters"]["scopeMode"]["allowedValues"], ["customer", "provider-lab"])
        self.assertEqual(template["parameters"]["scopeMode"]["defaultValue"], "customer")
        check = next(r for r in template["resources"] if r["name"] == "customer-enrollment-scope-check")
        self.assertEqual(check["properties"]["template"]["parameters"]
                         ["deploymentMatchesApprovedEnrollment"]["allowedValues"], [True])
        condition = check["properties"]["parameters"]["deploymentMatchesApprovedEnrollment"]["value"]
        for name in ("scopeMatches", "tagsMatch", "groupMatches"):
            self.assertIn(name, condition)
        caller = next(r for r in template["resources"] if r["type"] == "Microsoft.ManagedIdentity/userAssignedIdentities")
        self.assertIn("customer-enrollment-scope-check", json.dumps(caller["dependsOn"]))
        self.assertIn("protectedProviderGroups", template["variables"]["groupMatches"])

    def test_publisher_restricts_scope_to_registered_lab_mode(self):
        from service.deployment_scope import ProviderScope
        from service.enrollment import CustomerBinding
        from service.profiles import ProfilePublisher
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "customer.json").write_text(json.dumps(self.compiled["customer-deployment.bicep"]))
            (path / "customer-connections.json").write_text(json.dumps(self.compiled["customer-connections.bicep"]))
            (path / "customer-form.json").write_text((ROOT / "portal/customer-form.json").read_text())
            protected = f"/subscriptions/{uid(2)}/resourceGroups/provider-control"
            scope = ProviderScope(uid(1), uid(2), (protected,))
            with patch("service.profiles.BlobServiceClient"):
                publisher = ProfilePublisher(unittest.mock.Mock(), "https://unit.blob.core.windows.net",
                                             "https://unit.azurewebsites.net", "api://" + uid(6), uid(1), path,
                                             provider_scope=scope)
            customer = CustomerBinding(uid(10), "Provider lab", uid(1), uid(2), uid(3), uid(4), 1, "Ready",
                                       scope_mode="provider-lab", provider_lab_acknowledged=True)
            template, form = publisher.documents(customer)
            self.assertEqual(template["parameters"]["scopeMode"]["allowedValues"], ["provider-lab"])
            self.assertEqual(template["parameters"]["providerProtectedResourceGroupIds"]["defaultValue"], [protected])
            fields = {item["name"]: item for step in form["view"]["properties"]["steps"] for item in step["elements"]}
            self.assertEqual([item["value"] for item in fields["scopeMode"]["constraints"]["allowedValues"]],
                             ["provider-lab"])
            self.assertIn(uid(2), fields["deploymentScopeNotice"]["options"]["text"])
            self.assertIn("does not test cross-tenant", fields["deploymentScopeNotice"]["options"]["text"])

    def test_proof_before_network_and_separate_backing_exception(self):
        proof = self.compiled["customer-proof.bicep"]
        self.assertEqual(proof["parameters"]["approveDeploymentScriptBackingException"]["allowedValues"], [True])
        script = proof["resources"][0]
        self.assertEqual(script["identity"]["type"], "UserAssigned")
        self.assertEqual(script["properties"]["timeout"], "PT2H")
        self.assertEqual(script["properties"]["cleanupPreference"], "Always")
        self.assertIn("idempotency_key", json.dumps(proof["variables"]))
        self.assertEqual(next(item["value"] for item in script["properties"]["environmentVariables"]
                              if item["name"] == "FAAS_CONNECTOR_MODE"), "proof")
        self.assertNotIn("Microsoft.Network/virtualNetworkGateways", json.dumps(proof))
        self.assertEqual(len(proof["resources"]), 2)

    def test_customer_script_storage_exception_is_explicit_and_limited(self):
        for name, phase, location in (
            ("customer-proof.bicep", "proof", "location"),
            ("customer-network.bicep", "network", "executionLocation"),
        ):
            template = self.compiled[name]
            self.assertEqual(template["parameters"]["approveDeploymentScriptBackingException"]["allowedValues"], [True])
            storage = next(r for r in template["resources"] if r["type"] == "Microsoft.Storage/storageAccounts")
            script = next(r for r in template["resources"] if r["type"] == "Microsoft.Resources/deploymentScripts")
            self.assertIn(f"'{phase}'", template["variables"]["backingAccountName"])
            self.assertEqual(storage["location"],
                             f"[parameters('{location}')]")
            self.assertEqual(storage["tags"]["SecurityControl"], "Ignore")
            self.assertEqual(storage["properties"]["allowSharedKeyAccess"],
                             "[parameters('approveDeploymentScriptBackingException')]")
            self.assertFalse(storage["properties"]["allowBlobPublicAccess"])
            self.assertTrue(storage["properties"]["supportsHttpsTrafficOnly"])
            self.assertEqual(storage["properties"]["minimumTlsVersion"], "TLS1_2")
            self.assertNotIn("SecurityControl", script["tags"])
            settings = script["properties"]["storageAccountSettings"]
            self.assertEqual(settings["storageAccountName"], storage["name"])
            self.assertIn("listKeys(", settings["storageAccountKey"])
            self.assertIn("Microsoft.Storage/storageAccounts", json.dumps(script["dependsOn"]))
            self.assertNotIn("storageAccountKey", json.dumps(template["outputs"]))
            self.assertNotIn("listKeys", json.dumps(template["outputs"]))
        operations = self.resources("main.bicep", "Microsoft.Storage/storageAccounts")[0]
        self.assertFalse(operations["properties"]["allowSharedKeyAccess"])
        artifacts = self.compiled["provider-artifacts.bicep"]["resources"][0]
        self.assertFalse(artifacts["properties"]["allowSharedKeyAccess"])

    def test_network_connector_same_implementation_and_nonsecret_output(self):
        proof = self.compiled["customer-proof.bicep"]["resources"][0]
        network = self.compiled["customer-network.bicep"]
        script = network["resources"][0]
        self.assertEqual(script["properties"]["scriptContent"], proof["properties"]["scriptContent"])
        self.assertEqual(network["parameters"]["approveDeploymentScriptBackingException"]["allowedValues"], [True])
        self.assertEqual(script["identity"]["type"], "UserAssigned")
        self.assertEqual(script["properties"]["cleanupPreference"], "Always")
        self.assertEqual(set(network["outputs"]), {"networkResult"})
        self.assertEqual(set(network["outputs"]["networkResult"]["value"]), {"operationId", "status"})
        self.assertNotIn("ingressSharedKey", json.dumps(network["outputs"]))
        variables = script["properties"]["environmentVariables"]
        self.assertEqual(next(item["value"] for item in variables if item["name"] == "FAAS_CONNECTOR_MODE"), "network")
        self.assertIn("FAAS_CONNECTIONS_TEMPLATE", {item["name"] for item in variables})
        customer_connector.validate_connection_template(self.compiled["customer-connections.bicep"])

    def test_dynamic_delivery_and_single_ingress_route_server(self):
        connection = self.compiled["modules/connection.bicep"]
        self.assertFalse(connection["parameters"]["enableBgp"]["defaultValue"])
        self.assertFalse(connection["parameters"]["useExistingLocalGateway"]["defaultValue"])
        policies = connection["parameters"]["ipsecPolicies"]["defaultValue"]
        self.assertEqual([(p["ipsecEncryption"], p["ipsecIntegrity"], p["pfsGroup"]) for p in policies],
                         [("None", "SHA256", "None")])
        resource = next(r for r in connection["resources"] if r["type"] == "Microsoft.Network/connections")
        self.assertEqual(resource["properties"]["ipsecPolicies"], "[parameters('ipsecPolicies')]")
        for name in ("provider-dataplane.bicep", "provider-checkpoint-foundation.bicep", "customer-connections.bicep"):
            for module in (r for r in self.compiled[name]["resources"] if r["type"] == "Microsoft.Resources/deployments"
                           and "sharedKey" in r["properties"].get("parameters", {})):
                self.assertNotIn("ipsecPolicies", module["properties"]["parameters"])
        for name in ("provider-dataplane.bicep", "customer-connections.bicep"):
            modules = [r for r in self.compiled[name]["resources"] if r["type"] == "Microsoft.Resources/deployments"
                       and "sharedKey" in r["properties"].get("parameters", {})]
            self.assertEqual(len(modules), 2)
            enabled = [module["properties"]["parameters"].get("enableBgp", {}).get("value", False)
                       for module in modules]
            self.assertEqual(sorted(enabled), [False, True])
            delivery = next(module for module in modules
                            if module["properties"]["parameters"].get("enableBgp", {}).get("value") is True)
            self.assertIn("/32", json.dumps(delivery["properties"]["parameters"]["remotePrefixes"]))
            if name == "provider-dataplane.bicep":
                self.assertIs(delivery["properties"]["parameters"]["useExistingLocalGateway"]["value"], True)
        route_server = self.compiled["modules/route-server.bicep"]
        self.assertTrue(route_server["parameters"]["createPeer"]["defaultValue"])
        hub = next(item for item in route_server["resources"] if item["type"] == "Microsoft.Network/virtualHubs")
        self.assertTrue(hub["properties"]["allowBranchToBranchTraffic"])
        peers = [item for item in route_server["resources"] if item["type"] == "Microsoft.Network/virtualHubs/bgpConnections"]
        self.assertEqual(peers[0]["properties"]["peerAsn"], 65050)
        provider = self.compiled["provider-dataplane.bicep"]
        self.assertEqual(len(self.resources("provider-dataplane.bicep", "Microsoft.Network/virtualHubs")), 2)
        modules = [item for item in provider["resources"] if item["type"] == "Microsoft.Resources/deployments"]
        sequential = next(item for item in modules
                          if "provider-route-server-ingress-" in item["name"]
                          and "parallel" not in item["name"])
        parallel = next(item for item in modules
                        if "provider-route-server-ingress-parallel-" in item["name"])
        parallel_peer = next(item for item in modules
                             if "provider-route-server-peer-parallel-" in item["name"])
        self.assertEqual(sequential["condition"], "[not(parameters('parallelProviderNetworking'))]")
        self.assertEqual(parallel["condition"], "[parameters('parallelProviderNetworking')]")
        self.assertEqual(parallel_peer["condition"], parallel["condition"])
        self.assertEqual(sequential["properties"]["parameters"]["name"],
                         parallel["properties"]["parameters"]["name"])
        self.assertIs(parallel["properties"]["parameters"]["createPeer"]["value"], False)
        self.assertNotIn("peerings", json.dumps(parallel["dependsOn"]))
        self.assertNotIn("provider-gateway-", json.dumps(parallel["dependsOn"]))
        self.assertIn("peerings", json.dumps(sequential["dependsOn"]))
        self.assertIn("peerings", json.dumps(parallel_peer["dependsOn"]))
        self.assertIn("provider-route-server-ingress-parallel", json.dumps(parallel_peer["dependsOn"]))
        peerings = next(item for item in modules if item.get("copy", {}).get("name") == "peerings")
        self.assertIn("gateways", json.dumps(peerings["dependsOn"]))
        self.assertIn("provider-route-server-ingress-parallel", json.dumps(peerings["dependsOn"]))
        gateways = next(item for item in provider["resources"] if item.get("copy", {}).get("name") == "gateways")
        parameters = gateways["properties"]["parameters"]
        self.assertIn("65515", parameters["asn"])
        self.assertIn("65031", parameters["asn"])
        self.assertIn("lng-pd-", parameters["defaultSiteId"])
        nvas = next(item for item in provider["resources"] if item.get("copy", {}).get("name") == "nvas")
        self.assertNotIn("deliveryRouteServerName", nvas["properties"]["parameters"])
        wrapper = nvas["properties"]["template"]
        vm = next(item for item in wrapper["resources"] if item["type"] == "Microsoft.Resources/deployments")
        cloud_init = vm["properties"]["parameters"]["cloudInit"]["value"]
        self.assertEqual(cloud_init.count("Microsoft.Network/virtualHubs"), 2)
        self.assertIn("provider-route-server-ingress", json.dumps(nvas["dependsOn"]))
        self.assertIn("provider-route-server-peer-parallel", json.dumps(nvas["dependsOn"]))
        from service.templates import Templates
        Templates.validate(provider, True)

    def test_lab_nsgs_allow_all_inbound_and_outbound(self):
        for name in ("provider-dataplane.bicep", "customer-foundation.bicep"):
            nsgs = self.resources(name, "Microsoft.Network/networkSecurityGroups")
            self.assertEqual(len(nsgs), 1)
            if name == "customer-foundation.bicep":
                self.assertEqual(nsgs[0]["properties"], (
                    "[if(empty(variables('adminSources')), createObject('securityRules', "
                    "variables('legacyWorkloadRules')), createObject())]"))
                rules = self.compiled[name]["variables"]["legacyWorkloadRules"]
            else:
                rules = nsgs[0]["properties"]["securityRules"]
            allow_all = [rule for rule in rules if rule["name"].startswith("allow-all-")]
            self.assertEqual({rule["properties"]["direction"] for rule in allow_all}, {"Inbound", "Outbound"})
            self.assertEqual(len(allow_all), 2)
            for rule in allow_all:
                properties = rule["properties"]
                self.assertEqual(properties["access"], "Allow")
                for field in ("protocol", "sourceAddressPrefix", "sourcePortRange",
                              "destinationAddressPrefix", "destinationPortRange"):
                    self.assertEqual(properties[field], "*")
        rules = {rule["name"]: rule["properties"] for rule in
                 self.resources("provider-dataplane.bicep", "Microsoft.Network/networkSecurityGroups")[0]
                 ["properties"]["securityRules"]}
        self.assertEqual(rules["allow-rfc1918-internet-tcp"]["destinationPortRanges"],
                         ["22", "53", "80", "443"])
        self.assertEqual(rules["allow-rfc1918-internet-udp"]["destinationPortRanges"],
                         ["53", "123", "443"])
        self.assertEqual(rules["allow-rfc1918-internet-icmp"]["protocol"], "Icmp")
        self.assertEqual(rules["allow-rfc1918-east-west"]["protocol"], "*")
        for rule_name in ("allow-rfc1918-internet-tcp", "allow-rfc1918-internet-udp",
                          "allow-rfc1918-internet-icmp", "allow-rfc1918-east-west"):
            self.assertEqual(rules[rule_name]["sourceAddressPrefixes"], "[variables('privatePrefixes')]")


if __name__ == "__main__":
    unittest.main()
