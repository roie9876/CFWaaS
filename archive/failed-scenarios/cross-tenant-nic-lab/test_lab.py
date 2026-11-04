import unittest
from unittest.mock import patch
import tempfile
import uuid
from pathlib import Path

from lab import Arm, ArmError, Lab, approved_url, same_id, sanitize
from app_identity import AppIdentity, validate_application_claims

ACCOUNTS = {
    "A": {"tenant": str(uuid.UUID(int=1)), "subscription": str(uuid.UUID(int=2))},
    "B": {"tenant": str(uuid.UUID(int=3)), "subscription": str(uuid.UUID(int=4))},
}


class LabSafetyTests(unittest.TestCase):
    def setUp(self):
        for target in ("lab.ACCOUNTS", "app_identity.ACCOUNTS"):
            replacement = patch(target, ACCOUNTS)
            replacement.start()
            self.addCleanup(replacement.stop)

    def test_only_arm_https_urls_are_accepted(self):
        for url in (
            "https://example.com/poll",
            "http://management.azure.com/poll",
            "https://management.azure.com.evil.example/poll",
            "https://user" + "@" + "management.azure.com/poll",
            "https://management.azure.com:444/poll",
            "https://management.azure.com/poll#fragment",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                approved_url(url)
        self.assertEqual(approved_url("/poll"), "https://management.azure.com/poll")

    def test_secrets_are_redacted_recursively(self):
        data = {
            "Authorization": "Bearer sensitive",
            "secretText": "do-not-log-secret",
            "client_assertion": "do-not-log-assertion",
            "nested": [
                "Bearer secret", "https://storage.blob.core.windows.net/log?sv=1&sig=secret",
                "eyJheader.eyJpayload.signature",
                "https://management.azure.com/poll?api-version=2025-04-01&s=signedsecret&c=certificate",
            ],
        }
        result = str(sanitize(data))
        for secret in (
            "sensitive", "Bearer secret", "sig=secret", "eyJheader",
            "signedsecret", "c=certificate", "do-not-log-secret", "do-not-log-assertion",
        ):
            self.assertNotIn(secret, result)
        self.assertIn("api-version=2025-04-01", result)

    def test_resource_ids_are_compared_case_insensitively(self):
        self.assertTrue(same_id("/SUBSCRIPTIONS/A/", "/subscriptions/a"))
        self.assertFalse(same_id(None, "/subscriptions/a"))
        self.assertFalse(same_id("/subscriptions/b", "/subscriptions/a"))

    def test_vm_payload_preserves_ownership_and_ssh_only_auth(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Lab(Path(directory), "unit-test")
            lab.public_key = "ssh-ed25519 public-test-key"
            foreign_nic = f"/subscriptions/{ACCOUNTS['B']['subscription']}/resourceGroups/test/providers/Microsoft.Network/networkInterfaces/test"
            body = lab.vm_body("test", foreign_nic)
            properties = body["properties"]
            self.assertEqual(properties["networkProfile"]["networkInterfaces"][0]["id"], foreign_nic)
            self.assertTrue(properties["osProfile"]["linuxConfiguration"]["disablePasswordAuthentication"])
            self.assertNotIn("adminPassword", properties["osProfile"])
            self.assertEqual(properties["storageProfile"]["osDisk"]["deleteOption"], "Delete")

    def test_operation_polls_and_returns_final_location_output(self):
        with tempfile.TemporaryDirectory() as directory:
            arm = Arm(Path(directory))
            response = (202, {"azure-asyncoperation": "/operation", "location": "/result"}, {})
            with patch("lab.time.sleep"), patch.object(arm, "request") as request:
                request.side_effect = [
                    (200, {}, {"status": "Succeeded"}),
                    (200, {}, {"value": [{"message": "guest output"}]}),
                ]
                self.assertEqual(arm.operation(response, "A"), {"value": [{"message": "guest output"}]})
                self.assertEqual(request.call_count, 2)

    def test_completed_result_does_not_repoll_headers_echoed_by_network_rp(self):
        for status, body in (
            (200, {"value": [{"addressPrefixes": ["10.10.0.0/16"]}]}),
            (204, {}),
        ):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                arm = Arm(Path(directory))
                headers = {"azure-asyncoperation": "/operation", "location": "/result"}
                with patch("lab.time.sleep"), patch.object(arm, "request") as request:
                    request.side_effect = [
                        (200, {}, {"status": "Succeeded"}),
                        (status, headers, body),
                    ]
                    self.assertEqual(arm.operation((202, headers, {}), "B"), body)
                    self.assertEqual(request.call_count, 2)

    def test_location_poll_can_return_accepted_with_null_body(self):
        with tempfile.TemporaryDirectory() as directory:
            arm = Arm(Path(directory))
            with patch("lab.time.sleep"), patch.object(arm, "request") as request:
                request.side_effect = [
                    (202, {"location": "/result", "retry-after": "10"}, None),
                    (200, {}, {"value": [{"network": "10.151.0.0/16"}]}),
                ]
                self.assertEqual(arm.operation((202, {"location": "/result"}, None), "A"),
                                 {"value": [{"network": "10.151.0.0/16"}]})
                self.assertEqual(request.call_count, 2)

    def test_null_completed_poll_is_not_a_success_shaped_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            arm = Arm(Path(directory))
            with patch("lab.time.sleep"), patch.object(arm, "request", return_value=(200, {}, None)):
                with self.assertRaisesRegex(RuntimeError, "invalid HTTP 200 result shape"):
                    arm.operation((202, {"location": "/result"}, None), "A")

    def test_operation_does_not_follow_unapproved_poll_host(self):
        with tempfile.TemporaryDirectory() as directory:
            arm = Arm(Path(directory))
            with self.assertRaises(ValueError):
                arm.operation((202, {"azure-asyncoperation": "https://example.com/poll"}, {}), "A")

    def test_accepted_without_polling_contract_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            arm = Arm(Path(directory))
            with self.assertRaises(RuntimeError):
                arm.operation((202, {}, {}), "A")

    def test_rejected_foreign_vm_is_inspected_without_auxiliary_auth(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Lab(Path(directory), "unit-test")
            lab.groups["A"] = "/subscriptions/a/resourceGroups/lab"
            with (
                patch.object(lab.arm, "resource", side_effect=ArmError(403, {"error": {"code": "LinkedAuthorizationFailed"}})),
                patch.object(lab.arm, "request", return_value=(404, {}, {})) as request,
                patch("builtins.print"),
            ):
                result = lab.test_vm("foreign", "VM-A -> NIC-B", "/nic-b", "B", None)
            self.assertEqual(result["status"], "rejected")
            self.assertEqual(result["httpStatus"], 403)
            self.assertNotIn("auxiliary", request.call_args.kwargs)

    def test_identity_preflight_records_rejection_without_creating_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Lab(Path(directory), "unit-test")
            with patch.object(lab.arm, "request") as request, patch("builtins.print"):
                request.side_effect = [
                    (200, {}, {"tenantId": config["tenant"], "state": "Enabled"})
                    for config in ACCOUNTS.values()
                ] + [ArmError(401, {"error": {"code": "AuxiliaryTokensInvalidUserIdentity"}})]
                with self.assertRaises(ArmError):
                    lab.authenticate()
            self.assertEqual(lab.groups, {})
            self.assertEqual(lab.manifest, [])
            self.assertEqual(lab.results[0]["status"], "rejected")
            self.assertEqual(request.call_args.args[0], "GET")

    def test_injected_tokens_do_not_require_cli_user_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            provider = lambda account: "application-token-" + account
            arm = Arm(Path(directory), token_provider=provider)
            with patch("lab.subprocess.run") as cli:
                self.assertEqual(arm.token("B"), "application-token-B")
                cli.assert_not_called()

    def test_application_claims_must_match_tenant_app_and_principal(self):
        valid = {
            "tid": ACCOUNTS["A"]["tenant"], "appid": "shared-app",
            "oid": "principal-a", "aud": "https://management.azure.com/",
        }
        validate_application_claims(valid, "A", "shared-app", "principal-a")
        for key, value in (("tid", "wrong"), ("appid", "other-app"), ("oid", "wrong"), ("aud", "https://graph.microsoft.com")):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_application_claims(dict(valid, **{key: value}), "A", "shared-app", "principal-a")

    def test_application_role_assignments_are_only_at_lab_group_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = Lab(Path(directory), "unit-test")
            lab.groups = {
                key: "/subscriptions/" + value["subscription"] + "/resourceGroups/owned-lab"
                for key, value in ACCOUNTS.items()
            }
            identity = AppIdentity(lab, directory)
            identity.principals = {"A": {"objectId": "sp-a"}, "B": {"objectId": "sp-b"}}
            with patch.object(lab.arm, "request") as request, patch("builtins.print"):
                identity.assign_roles()
            self.assertEqual(request.call_count, 2)
            for account, call in zip(("A", "B"), request.call_args_list):
                self.assertTrue(call.args[1].startswith(
                    "https://management.azure.com" + lab.groups[account]
                    + "/providers/Microsoft.Authorization/roleAssignments/"
                ))
                self.assertEqual(call.args[3]["properties"]["principalType"], "ServicePrincipal")

    def test_service_principal_creation_retries_only_backing_app_replication(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = AppIdentity(Lab(Path(directory), "unit-test"), directory)
            pending = ArmError(400, {"error": {"details": [{"code": "NoBackingApplicationObject"}]}})
            with (
                patch.object(identity, "graph", side_effect=[
                    pending, (201, {"id": "principal-b", "appId": "shared-app"}),
                ]) as graph,
                patch("app_identity.time.sleep"),
                patch("builtins.print"),
            ):
                self.assertEqual(identity.create_principal("B", "shared-app")["id"], "principal-b")
                self.assertEqual(graph.call_count, 2)
            with patch.object(identity, "graph", side_effect=ArmError(403, {})) as graph:
                with self.assertRaises(ArmError):
                    identity.create_principal("B", "shared-app")
                self.assertEqual(graph.call_count, 1)


if __name__ == "__main__":
    unittest.main()
