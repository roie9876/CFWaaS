import copy
import io
import json
import unittest
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import ipsec_lab as lab
import bgp_guest
import bgp_revision as revision
from ipsec_guest import tunnel_script

ROOT = Path(__file__).resolve().parent
ACCOUNTS = {
    "A": {"tenant": str(uuid.UUID(int=1)), "subscription": str(uuid.UUID(int=2))},
    "B": {"tenant": str(uuid.UUID(int=3)), "subscription": str(uuid.UUID(int=4))},
}


def settings():
    return json.loads((ROOT / "bgp.example.json").read_text())


def gateway():
    return {"properties": {"bgpSettings": {"asn": 65515, "bgpPeeringAddresses": [
        {"ipconfigurationId": "Instance0", "defaultBgpIpAddresses": ["10.253.0.4"], "tunnelIpAddresses": ["9.9.9.9", "10.253.0.12"]},
        {"ipconfigurationId": "Instance1", "defaultBgpIpAddresses": ["10.253.0.5"], "tunnelIpAddresses": ["8.8.8.8", "10.253.0.13"]},
    ]}}}


class BgpRevisionTests(unittest.TestCase):
    def test_only_default_is_advertised_and_new_vnet_is_not_a_firewall_prefix(self):
        value = revision.validate_settings(settings())
        self.assertEqual(value["advertiseToCustomer"], ["0.0.0.0/0"])
        self.assertNotIn(value["lifecycleProbe"]["prefix"], value["acceptedCustomerAggregates"])
        changed = settings()
        changed["advertiseToCustomer"] = ["10.151.0.0/16", "10.152.0.0/16"]
        with self.assertRaises(ValueError):
            revision.validate_settings(changed)

    def test_instance_to_public_ip_mapping_is_not_broken_by_ip_sorting(self):
        peers = revision.endpoints(gateway(), settings())
        self.assertEqual(peers[0], {"instance": "Instance0", "publicIp": "9.9.9.9", "azureBgpIp": "10.253.0.4"})
        self.assertEqual(peers[1]["publicIp"], "8.8.8.8")
        bad = gateway()
        bad["properties"]["bgpSettings"]["bgpPeeringAddresses"][1]["defaultBgpIpAddresses"] = []
        with self.assertRaises(RuntimeError):
            revision.endpoints(bad, settings())

    def test_vpn_bgp_has_correct_return_association_and_isolated_propagation(self):
        peers = revision.endpoints(gateway(), settings())
        properties = revision.connection_body("/site", "/default", "/inspect", "fixture", peers)["properties"]
        self.assertNotIn("enableBgp", properties)
        self.assertEqual(properties["routingConfiguration"]["associatedRouteTable"], {"id": "/default"})
        self.assertEqual(properties["routingConfiguration"]["propagatedRouteTables"], {
            "ids": [{"id": "/inspect"}], "labels": ["ipsec-bgp-inspection"],
        })
        link = properties["vpnLinkConnections"][0]["properties"]
        self.assertTrue(link["enableBgp"])
        self.assertFalse(link["useLocalAzureIpAddress"])
        self.assertNotIn("vpnGatewayCustomBgpAddresses", link)

    def test_revision_cannot_silently_reenable_core_teardown(self):
        config = json.loads((ROOT / "config.example.json").read_text())
        value = settings()
        plan = {"meta": {
            "status": "approved", "executionApproved": True, "accountProfiles": ACCOUNTS,
            "retention": "keep", "automaticCoreCleanup": False,
            "configFingerprint": lab.fingerprint({"lab": config, "bgp": value}),
        }}
        with patch.object(lab, "ACCOUNTS", ACCOUNTS):
            revision.approval_gate(config, value, plan)
            for key, change in (("automaticCoreCleanup", True), ("retention", "cleanup"), ("executionApproved", False)):
                bad = copy.deepcopy(plan)
                bad["meta"][key] = change
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    revision.approval_gate(config, value, bad)

    def test_scripts_compile_and_static_customer_routes_are_disabled(self):
        value = settings()
        peers = revision.endpoints(gateway(), value)
        scripts = [
            bgp_guest.configure_script(value, "172.26.10.4", peers),
            bgp_guest.metrics_script(peers),
            bgp_guest.default_script(peers, True),
            bgp_guest.default_script(peers, False),
            bgp_guest.tunnel_control_script(True),
            bgp_guest.tunnel_control_script(False),
            bgp_guest.local_health_script(),
        ]
        for script in scripts:
            source = script[-2]
            compile(source, "<bgp-guest-script>", "exec")
        tunnel = tunnel_script(
            "172.26.10.4", "1.1.1.1", [peer["publicIp"] for peer in peers],
            value["acceptedCustomerAggregates"], static_routes=False, allow_within_prefix=True,
        )
        compile(tunnel[2], "<bgp-tunnel-script>", "exec")
        self.assertIn("'staticRoutes': False", tunnel[2])
        self.assertIn("'allowWithinPrefix': True", tunnel[2])
        self.assertNotIn("10.153.0.0/16", tunnel[2])
        self.assertNotIn("10.153.0.0/16", "\n".join(scripts[0]))
        self.assertIn("default-originate", "\n".join(scripts[0]))
        self.assertIn("prefix-list CUSTOMER-ROUTES", "\n".join(scripts[0]))
        self.assertIn("blackhole", "\n".join(scripts[0]))

    def test_negative_probe_requires_a_network_denial_not_an_http_or_service_error(self):
        source = {"privateIp": "10.151.0.4"}
        destination = {"name": "ipsec-wl2"}
        self.assertTrue(lab.http_passed(source, destination, {"ok": False, "errorType": "OSError", "errno": 113}, False))
        self.assertFalse(lab.http_passed(source, destination, {"ok": False, "errorType": "ConnectionRefusedError", "errno": 111}, False))
        self.assertFalse(lab.http_passed(source, destination, {"ok": False, "errorType": "HTTPError", "status": 503}, False))
        self.assertFalse(lab.http_passed(source, destination, {"ok": False, "errorType": "OSError", "errno": 13}, False))

    def test_frr_originated_default_is_recognized_without_faking_an_advertisement(self):
        peers = revision.endpoints(gateway(), settings())
        summary = {"ipv4Unicast": {"peers": {
            row["azureBgpIp"]: {"state": "Established", "remoteAs": 65515, "pfxRcd": 2}
            for row in peers
        }}}
        table = {"routes": {"10.151.0.0/16": [], "10.152.0.0/16": []}}
        for originated in (True, False):
            advertised = {"advertisedRoutes": {}}
            if originated:
                advertised["bgpOriginatingDefaultNetwork"] = "0.0.0.0/0"
            outputs = [json.dumps(value) for value in (summary, table, advertised, advertised)]
            outputs += ["-A IV_FORWARD -j IV_NEGATIVE\n"]
            with patch("subprocess.check_output", side_effect=outputs), patch(
                "pathlib.Path.read_bytes", return_value=b"stable owned configuration",
            ), redirect_stdout(io.StringIO()) as output:
                exec(compile(bgp_guest.metrics_script(peers)[1], "<frr-metrics>", "exec"), {})
            metrics = lab.extract_guest_result({"value": [{"message": output.getvalue()}]})[0]
            self.assertEqual(metrics["ok"], originated)
            for row in metrics["neighbors"].values():
                self.assertEqual(row["advertised"], ["0.0.0.0/0"] if originated else [])

    def test_gateway_template_references_existing_hub_and_no_vm_or_wan_redeploy(self):
        text = (ROOT / "infra/bgp-gateway.bicep").read_text()
        self.assertIn("existing =", text)
        self.assertIn("vpng-ipsec-bgp", text)
        self.assertNotIn("Microsoft.Compute", text)
        self.assertNotIn("Microsoft.Network/virtualWans", text)
        self.assertNotIn("bgpPeeringAddresses", text)
        self.assertNotIn("customBgpIpAddresses", text)


if __name__ == "__main__":
    unittest.main()
