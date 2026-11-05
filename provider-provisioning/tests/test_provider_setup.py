"""Provider-only orchestration tests: all cloud calls are mocked."""
from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import common
import provider_setup as setup
import prepare_customer_portal as portal


def uid(number):
    return str(UUID(int=number))


def config():
    return {
        "runId": "public-fixture", "namePrefix": "public-fixture",
        "provider": {"tenantId": uid(1), "subscriptionId": uid(2),
                     "controlPlaneResourceGroup": "rg-provider-control",
                     "dataPlaneResourceGroup": "rg-provider-data"},
        "customer": {"tenantId": uid(3), "subscriptionId": uid(4),
                     "bootstrapResourceGroup": "rg-customer-bootstrap",
                     "dataPlaneResourceGroup": "rg-customer-data"},
        "deploymentOperatorCidr": "192.0.2.1/32",
    }


def identity(cfg):
    return {"configDigest": common.config_digest(cfg), "apiApplicationId": uid(5),
            "apiAudience": uid(5), "apiResource": "api://" + uid(5), "appRoleId": uid(6)}


def full_identity(cfg):
    return {**identity(cfg), "providerApiServicePrincipalId": uid(7),
            "customerApiClientId": uid(8), "customerApiClientApplicationObjectId": uid(9),
            "customerApiPrincipalId": uid(10)}


def role():
    return {"id": uid(6), "value": setup.ROLE,
            "allowedMemberTypes": ["Application"], "isEnabled": True}


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.cfg = config()
        self.state = {}
        self.path = setup.ROOT / ".local/provider-identity.json"
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # Fail loudly rather than invoking any cloud process accidentally.
        self.stack.enter_context(patch("subprocess.run", side_effect=AssertionError("Unexpected process")))
        self.stack.enter_context(patch.object(setup, "save_private", side_effect=self.save))
        self.stack.enter_context(patch.object(setup, "load_private", side_effect=self.load))
        self.stack.enter_context(patch.object(Path, "exists", lambda path: str(path) in self.state))
        self.graph = Mock()
        self.graph.tenant = uid(1)
        self.graph.request.side_effect = self.graph_request
        self.graph_constructor = self.stack.enter_context(
            patch.object(setup.identity_bootstrap, "Graph", return_value=self.graph))
        self.objects = {
            ("applications", uid(5)): {"id": uid(11), "appId": uid(5), "appRoles": [role()]},
            ("servicePrincipals", uid(5)): {"id": uid(7), "appId": uid(5), "appRoles": [role()]},
        }
        self.stack.enter_context(patch.object(setup.identity_bootstrap, "find_exact",
                                            side_effect=lambda graph, collection, app_id:
                                            deepcopy(self.objects.get((collection, app_id)))))
        self.grants = []

    def save(self, path, value):
        self.state[str(path)] = deepcopy(value)

    def load(self, path):
        return deepcopy(self.state[str(path)])

    def graph_request(self, method, path, body=None):
        if method == "POST" and path == "/applications":
            result = {**body, "id": uid(9), "appId": uid(8)}
            self.objects[("applications", uid(8))] = result
            return deepcopy(result)
        if method == "POST" and path == "/servicePrincipals":
            app_id = body["appId"]
            result = {"appId": app_id, "id": uid(7) if app_id == uid(5) else uid(10)}
            if app_id == uid(5):
                result["appRoles"] = [role()]
            self.objects[("servicePrincipals", app_id)] = result
            return deepcopy(result)
        if path.endswith("/appRoleAssignments"):
            if method == "GET":
                return {"value": deepcopy(self.grants)}
            self.grants.append(deepcopy(body))
            return {"id": uid(12), **body}
        if path.endswith("/addPassword"):
            return {"keyId": uid(13), "secretText": "PUBLIC-MOCK-ONLY-NOT-A-CREDENTIAL",
                    "endDateTime": body["passwordCredential"]["endDateTime"]}
        if path.endswith("/removePassword"):
            return {}
        raise AssertionError((method, path))

    def setup_client(self):
        value = identity(self.cfg)
        setup.api_client(self.cfg, value, self.path)
        return value

    def test_api_client_only_custom_role_in_provider_graph(self):
        value = self.setup_client()
        self.graph_constructor.assert_called_once_with(uid(1))
        create = next(call.args[2] for call in self.graph.request.call_args_list
                      if call.args[:2] == ("POST", "/applications"))
        self.assertEqual(create["signInAudience"], "AzureADMyOrg")
        self.assertEqual(create["requiredResourceAccess"], [{
            "resourceAppId": uid(5), "resourceAccess": [{"id": uid(6), "type": "Role"}]}])
        self.assertEqual(self.grants, [{"principalId": uid(10), "resourceId": uid(7), "appRoleId": uid(6)}])
        self.assertEqual(value["customerApiClientId"], uid(8))
        self.assertNotIn("secret", json.dumps(self.state[str(self.path)]).lower())
        self.assertNotIn("adminConsentUrl", value)

    def test_missing_home_api_principal_is_created(self):
        del self.objects[("servicePrincipals", uid(5))]
        self.setup_client()
        self.assertIn(("servicePrincipals", uid(5)), self.objects)
        self.graph.request.assert_any_call("POST", "/servicePrincipals", {"appId": uid(5)})

    def test_existing_valid_credential_is_reused_without_password_rotation(self):
        value = self.setup_client()
        self.graph.request.reset_mock()
        setup.api_client(self.cfg, value, self.path)
        self.assertFalse(any(call.args[0] == "POST" for call in self.graph.request.call_args_list))

    def test_expired_credential_requires_explicit_rotation(self):
        value = self.setup_client()
        credential_path = setup.ROOT / ".local/customer-api-credential.json"
        credential = self.state[str(credential_path)]
        credential["expiresAt"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        value["credentialDigest"] = common.digest(credential)
        self.graph.request.reset_mock()
        with self.assertRaisesRegex(ValueError, "expired"):
            setup.api_client(self.cfg, value, self.path)
        self.assertFalse(any(call.args[1].endswith("/addPassword")
                             for call in self.graph.request.call_args_list))
        setup.api_client(self.cfg, value, self.path, rotate=True)
        self.graph.request.assert_any_call(
            "POST", "/applications/" + uid(9) + "/removePassword", {"keyId": uid(13)})

    def test_missing_or_unmatched_credential_never_implicitly_rotates(self):
        value = self.setup_client()
        credential_path = setup.ROOT / ".local/customer-api-credential.json"
        self.state[str(credential_path)]["clientId"] = uid(14)
        with self.assertRaisesRegex(ValueError, "does not match"):
            setup.api_client(self.cfg, value, self.path)
        del self.state[str(credential_path)]
        with self.assertRaisesRegex(ValueError, "missing"):
            setup.api_client(self.cfg, value, self.path)

    def test_credential_expiry_is_24h_and_never_printed(self):
        stdout = io.StringIO()
        before = datetime.now(timezone.utc)
        with redirect_stdout(stdout):
            self.setup_client()
        credential = self.state[str(setup.ROOT / ".local/customer-api-credential.json")]
        self.assertEqual(set(credential), {"clientId", "secret", "expiresAt"})
        expiry = datetime.fromisoformat(credential["expiresAt"].replace("Z", "+00:00"))
        self.assertAlmostEqual((expiry - before).total_seconds(), 24 * 3600, delta=2)
        self.assertEqual(stdout.getvalue(), "")

    def test_uncertain_application_create_blocks_retry_and_rotation(self):
        original = self.graph.request.side_effect

        def fail(method, path, body=None):
            if (method, path) == ("POST", "/applications"):
                raise RuntimeError("untrusted Graph response containing MOCK-SECRET")
            return original(method, path, body)

        self.graph.request.side_effect = fail
        value = identity(self.cfg)
        with self.assertRaises(RuntimeError):
            setup.api_client(self.cfg, value, self.path)
        self.assertEqual(self.state[str(self.path)]["pendingClientOperation"]["path"], "/applications")
        self.graph.request.reset_mock()
        with self.assertRaisesRegex(ValueError, "Uncertain"):
            setup.api_client(self.cfg, value, self.path, rotate=True)
        self.graph.request.assert_not_called()
        self.assertNotIn("MOCK-SECRET", json.dumps(self.state))

    def test_uncertain_password_crash_blocks_second_add(self):
        original = self.graph.request.side_effect

        def fail(method, path, body=None):
            if path.endswith("/addPassword"):
                raise RuntimeError("uncertain")
            return original(method, path, body)

        self.graph.request.side_effect = fail
        value = identity(self.cfg)
        with self.assertRaises(RuntimeError):
            setup.api_client(self.cfg, value, self.path)
        self.assertTrue(value["pendingClientOperation"]["path"].endswith("/addPassword"))
        self.graph.request.reset_mock()
        with self.assertRaisesRegex(ValueError, "Uncertain"):
            setup.api_client(self.cfg, value, self.path)
        self.graph.request.assert_not_called()

    def test_role_must_be_enabled_application_only_exact_value(self):
        for field, invalid in (("value", "User.Read.All"),
                               ("allowedMemberTypes", ["User", "Application"]),
                               ("isEnabled", False)):
            with self.subTest(field=field):
                self.objects[("applications", uid(5))]["appRoles"] = [{**role(), field: invalid}]
                with self.assertRaises(ValueError):
                    setup.api_client(self.cfg, identity(self.cfg), self.path)
        self.graph.request.assert_not_called()

    def test_existing_extra_grants_or_client_permissions_refused(self):
        value = self.setup_client()
        self.grants.append({"principalId": uid(10), "resourceId": uid(15), "appRoleId": uid(16)})
        with self.assertRaisesRegex(ValueError, "unexpected"):
            setup.api_client(self.cfg, value, self.path)
        self.grants.pop()
        self.objects[("applications", uid(8))]["requiredResourceAccess"].append({
            "resourceAppId": uid(17), "resourceAccess": [{"id": uid(18), "type": "Role"}]})
        with self.assertRaisesRegex(ValueError, "only"):
            setup.api_client(self.cfg, value, self.path)

    def test_missing_bound_application_or_principal_never_replaced(self):
        value = self.setup_client()
        del self.objects[("applications", uid(8))]
        self.graph.request.reset_mock()
        with self.assertRaisesRegex(ValueError, "no replacement"):
            setup.api_client(self.cfg, value, self.path)
        self.graph.request.assert_not_called()

    def test_groups_only_two_provider_groups_and_tags(self):
        cli = Mock(side_effect=lambda *args: False if args[:2] == ("group", "exists") else {
            "id": common.group_id(uid(2), args[args.index("--name") + 1])})
        with patch.object(setup, "cli", cli):
            setup.groups(self.cfg, {}, self.path)
        self.assertEqual(cli.call_count, 4)
        for call in cli.call_args_list:
            args = call.args
            self.assertEqual(args[args.index("--subscription") + 1], uid(2))
            self.assertNotIn(uid(4), args)
            if args[1] == "create":
                self.assertIn("purpose=provider-provisioning", args)
                self.assertIn("labRun=public-fixture", args)

    def test_groups_refuse_foreign_ownership(self):
        with patch.object(setup, "cli", return_value=True), patch.object(
                setup.bootstrap, "assert_owned_group", side_effect=ValueError("ownership")) as owned:
            with self.assertRaisesRegex(ValueError, "ownership"):
                setup.groups(self.cfg, {}, self.path)
        owned.assert_called_once_with(self.cfg["provider"], "rg-provider-control", self.cfg["runId"])

    def test_feature_preflight_only_provider_subscription(self):
        with patch.object(setup, "verify_account") as account, patch.object(setup, "cli",
                return_value={"properties": {"state": "Registered"}}) as cli:
            setup.provider_feature_preflight(self.cfg)
        account.assert_called_once_with(self.cfg["provider"])
        cli.assert_called_once_with("feature", "show", "--subscription", uid(2),
                                    "--namespace", "Microsoft.Compute", "--name", "EncryptionAtHost")

    def test_unregistered_feature_is_not_registered_by_helper(self):
        with patch.object(setup, "verify_account"), patch.object(setup, "cli",
                return_value={"properties": {"state": "NotRegistered"}}) as cli:
            with self.assertRaisesRegex(ValueError, "already"):
                setup.provider_feature_preflight(self.cfg)
        self.assertEqual(cli.call_count, 1)

    def test_api_strips_customer_admin_consent(self):
        value = identity(self.cfg)
        value["adminConsentUrl"] = "https://example.invalid/legacy"
        self.cfg["consentRedirectUri"] = "https://example.invalid/redirect"
        with patch.object(setup.identity_bootstrap, "provider") as provider:
            setup.api(self.cfg, value, self.path)
        self.assertNotIn("consentRedirectUri", provider.call_args.args[0])
        self.assertNotIn("adminConsentUrl", value)

    def test_dry_run_and_help_have_no_effects(self):
        with patch.object(setup, "validate_config", return_value=self.cfg), patch.object(
                setup, "load_private", return_value=self.cfg), patch.object(
                setup, "verify_account") as account, redirect_stdout(io.StringIO()):
            for phase in setup.PHASES:
                self.assertEqual(setup.main([phase, "--config", "unused"]), 0)
            with self.assertRaises(SystemExit) as exited:
                setup.main(["--help"])
            self.assertEqual(exited.exception.code, 0)
        account.assert_not_called()
        self.graph_constructor.assert_not_called()
        self.assertEqual(self.state, {})

    def test_entrypoint_redacts_untrusted_error_content(self):
        stdout = io.StringIO()
        with patch.object(setup, "main", side_effect=RuntimeError(
                "MOCK-SECRET Graph body")), redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as stopped:
                setup.entrypoint()
        self.assertNotIn("MOCK-SECRET", str(stopped.exception))
        self.assertNotIn("Graph body", str(stopped.exception))
        self.assertEqual(stdout.getvalue(), "")

    def test_control_plane_uses_provider_context_and_customer_metadata_only(self):
        metadata = {"providerTemplateSha256": "a" * 64, "packageSha256": "b" * 64}
        journal = {"configDigest": common.config_digest(self.cfg)}
        with patch.object(setup, "operator_cidr"), patch.object(
                setup, "package_metadata", return_value=metadata), patch.object(
                setup.bootstrap, "assert_owned_group") as owned, patch.object(
                setup.bootstrap, "deploy", return_value={"properties": {"outputs": {
                    "apiUrl": {"value": "https://example.invalid"}}}}) as deploy:
            setup.control_plane(self.cfg, journal, self.path, full_identity(self.cfg), True)
        owned.assert_called_once_with(self.cfg["provider"], "rg-provider-data", "public-fixture")
        context, group, template, params, run = deploy.call_args.args
        self.assertEqual(context, self.cfg["provider"])
        self.assertEqual(params["trustedTenantId"], uid(3))
        self.assertEqual(params["trustedPrincipalId"], uid(10))
        self.assertEqual(params["trustedClientId"], uid(8))
        self.assertEqual(params["apiAuthMode"], setup.MODE)
        self.assertNotIn("secret", json.dumps(params).lower())
        self.assertNotIn("codePackageSha256", journal)

    def test_control_plane_requires_explicit_scm_exception(self):
        with self.assertRaisesRegex(ValueError, "approve-scm"):
            setup.control_plane(self.cfg, {}, self.path, full_identity(self.cfg), False)

    def test_code_publish_provider_apps_only_no_credentials(self):
        journal = {"apiAuthMode": setup.MODE, "providerTemplateSha256": "a" * 64,
                   "controlPlane": {"apiAppName": "public-api", "workerAppName": "public-worker"}}
        metadata = {"providerTemplateSha256": "a" * 64, "packageSha256": "b" * 64}

        def cloud(*args):
            return {"azure-cli": "2.80.0"} if args == ("version",) else {"properties": {"allow": False}}

        with patch.object(setup, "package_metadata", return_value=metadata), patch.object(
                setup.bootstrap, "assert_owned_group"), patch.object(setup, "cli", side_effect=cloud) as cli:
            setup.code_deploy(self.cfg, journal, self.path)
        self.assertEqual(journal["codePackageSha256"], "b" * 64)
        for call in cli.call_args_list:
            args = call.args
            if args != ("version",):
                self.assertEqual(args[args.index("--subscription") + 1], uid(2))
                self.assertNotIn(uid(4), args)
                self.assertNotIn("--password", args)
        self.assertEqual(sum(call.args[:2] == ("webapp", "deploy") for call in cli.call_args_list), 2)

    def test_code_publish_refuses_basic_scm_or_hash_mismatch(self):
        journal = {"apiAuthMode": setup.MODE, "providerTemplateSha256": "a" * 64,
                   "controlPlane": {"apiAppName": "public-api", "workerAppName": "public-worker"}}
        metadata = {"providerTemplateSha256": "a" * 64, "packageSha256": "b" * 64}
        with patch.object(setup, "package_metadata", return_value=metadata), patch.object(
                setup.bootstrap, "assert_owned_group"), patch.object(setup, "cli",
                side_effect=lambda *args: {"azure-cli": "2.80.0"} if args == ("version",)
                else {"properties": {"allow": True}}):
            with self.assertRaisesRegex(ValueError, "disabled"):
                setup.code_deploy(self.cfg, journal, self.path)
            journal["providerTemplateSha256"] = "c" * 64
            with self.assertRaisesRegex(ValueError, "current provider"):
                setup.code_deploy(self.cfg, journal, self.path)

    def test_publish_wait_requires_recent_active_success(self):
        started = datetime.now(timezone.utc)
        old = {"start_time": (started - timedelta(minutes=5)).isoformat(), "status": 4, "active": True}
        pending = {"start_time": started.isoformat(), "status": 4, "active": False}
        active = {**pending, "active": True}
        with patch.object(setup, "cli", side_effect=[
                {"value": [{"properties": old}, {"properties": pending}]},
                {"value": [{"properties": active}]}]) as cli, \
                patch.object(setup.time, "monotonic", side_effect=[0, 0, 0]), \
                patch.object(setup.time, "sleep") as sleep:
            setup.wait_for_publish(self.cfg["provider"], "public-api", started, timeout=1)
        self.assertEqual(cli.call_count, 2)
        sleep.assert_called_once_with(5)
        self.assertIn("/sites/public-api/deployments?", cli.call_args.args[-1])

    def test_publish_wait_rejects_failed_remote_build(self):
        started = datetime.now(timezone.utc)
        failed = {"startTime": started.isoformat(), "status": 3, "active": False}
        with patch.object(setup, "cli", return_value={"value": [{"properties": failed}]}), \
                patch.object(setup.time, "monotonic", side_effect=[0, 0]), \
                self.assertRaisesRegex(ValueError, "remote build failed"):
            setup.wait_for_publish(self.cfg["provider"], "public-api", started, timeout=1)

    def test_publish_wait_times_out_without_active_success(self):
        started = datetime.now(timezone.utc)
        inactive = {"start_time": started.isoformat(), "status": 4, "active": False}
        with patch.object(setup, "cli", return_value={"value": [{"properties": inactive}]}), \
                patch.object(setup.time, "monotonic", side_effect=[0, 0, 2]), \
                patch.object(setup.time, "sleep"), \
                self.assertRaisesRegex(TimeoutError, "successful active"):
            setup.wait_for_publish(self.cfg["provider"], "public-api", started, timeout=1)

    def test_arm_pull_publishing_keeps_sas_out_of_command_arguments(self):
        journal = {"apiAuthMode": setup.MODE, "providerTemplateSha256": "a" * 64,
                   "controlPlane": {"apiAppName": "public-api", "workerAppName": "public-worker"}}
        metadata = {"providerTemplateSha256": "a" * 64, "packageSha256": "b" * 64}
        uri = "https://unitstore.blob.core.windows.net/artifacts/apps.zip?sp=r&sr=b&sig=unit-read-only"
        self.state["package-uri.json"] = {
            "uri": uri, "sha256": "b" * 64,
            "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()}
        self.state[str(setup.ROOT / ".local/artifact-host.json")] = {
            "host": {"accountName": "unitstore"}, "configDigest": common.config_digest(self.cfg)}
        def cloud(*args):
            return {"azure-cli": "2.80.0"} if args == ("version",) else {"properties": {"allow": False}}
        with patch.object(setup, "package_metadata", return_value=metadata), \
                patch.object(setup.bootstrap, "assert_owned_group"), patch.object(setup, "wait_for_publish") as wait, \
                patch.object(setup, "cli", side_effect=cloud) as cli:
            setup.code_deploy(self.cfg, journal, self.path, "package-uri.json")
        for call in cli.call_args_list:
            self.assertNotIn(uri, call.args)
            self.assertNotEqual(call.args[:2], ("webapp", "deploy"))
        body = self.state[str(setup.ROOT / ".local/provider-code-public-api.json")]
        self.assertEqual(body["properties"]["packageUri"], uri)
        self.assertEqual(wait.call_count, 2)
        self.assertEqual(journal["codePackageSha256"], "b" * 64)


class PortalTests(unittest.TestCase):
    def test_launch_url_preserves_read_only_artifact_uris(self):
        template = "https://artifacts.example/azuredeploy.json?sp=r&sr=b&sig=unit-read-only"
        form = "https://artifacts.example/ui.json"
        url = portal.portal_link(template, form)
        prefix = "https://portal.azure.com/#create/Microsoft.Template/uri/"
        self.assertTrue(url.startswith(prefix))
        first, second = url[len(prefix):].split("/uiFormDefinitionUri/")
        from urllib.parse import unquote
        self.assertEqual(unquote(first), template)
        self.assertEqual(unquote(second), form)
        for invalid in (
            "http://artifacts.example/file.json", "https://artifacts.example/file.json#fragment",
            "https://artifacts.example/file.json?client_secret=forbidden",
            "https://artifacts.example/file.json?sig=unit&sp=rw&sr=b",
            "https://artifacts.example/file.json?sig=unit&sp=r&sr=c",
        ):
            with self.subTest(uri=invalid), self.assertRaises(ValueError):
                portal.portal_link(invalid, form)

    def setUp(self):
        self.cfg = config()
        self.identity = full_identity(self.cfg)
        self.journal = {"configDigest": common.config_digest(self.cfg), "apiAuthMode": setup.MODE,
                        "controlPlane": {"apiUrl": "https://api.example.invalid"}}
        self.defaults = ("runId", "apiAuthorityTenantId", "apiClientId", "enrolledCustomerResourceGroupId",
                         "expectedCustomerTenantId", "expectedCustomerSubscriptionId", "apiUrl", "apiResource",
                         "customerConnectionsTemplateBase64", "deploymentMode", "routingApplianceBandwidthGbps",
                         "customerIngressVpnGatewaySku", "customerDeliveryVpnGatewaySku", "workloadVmProfile",
                         "providerVpnGatewaySku")
        self.template = {"parameters": {key: {"type": "string"} for key in self.defaults},
                         "outputs": {"operationId": {}, "status": {}}}
        self.template["parameters"].update(apiClientSecret={"type": "secureString"},
                                            sshPublicKey={"type": "string"},
                                            adminAllowedSources={"type": "array", "defaultValue": [], "maxLength": 16})
        fields = [{"name": "runId"}, {"name": "apiClientId"},
                  {"name": "adminAllowedSources", "type": "Microsoft.Common.TextBox", "defaultValue": ""},
                  {"name": "approveDeploymentScriptBackingException",
                   "label": "unrestricted lab NSG traffic",
                   "constraints": {"required": True, "validationMessage": "Approve lab deployment"}},
                  {"name": "manualSshKey", "type": "Microsoft.Common.CheckBox"},
                  {"name": "sshCredentials", "type": "Microsoft.Compute.CredentialsCombo",
                   "constraints": {"required": True}},
                  {"name": "sshPublicKey", "type": "Microsoft.Common.TextBox",
                   "visible": False, "constraints": {"required": False}},
                  {"name": "apiClientSecret", "type": "Microsoft.Common.PasswordBox",
                   "constraints": {"required": True}}]
        self.form = {"view": {"properties": {"steps": [{"elements": fields}]},
                              "outputs": {"parameters": {key: "UI" for key in
                                          ("runId", "apiClientId", "apiClientSecret", "sshPublicKey",
                                           "adminAllowedSources")}}}}
        self.writes = {}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(portal, "compile_bicep", side_effect=lambda name:
            json.dumps(self.template if name == "customer-deployment.bicep" else {"resources": []}).encode()))
        self.stack.enter_context(patch.object(portal, "validate_connection_template"))
        self.stack.enter_context(patch.object(Path, "read_text", side_effect=lambda:
                                              json.dumps(self.form)))
        self.stack.enter_context(patch.object(portal, "save_private",
            side_effect=lambda path, value: self.writes.update({path.name: deepcopy(value)})))
        self.stack.enter_context(patch("subprocess.run", side_effect=AssertionError("Unexpected process")))

    def prepare(self):
        return portal.prepare(self.cfg, self.journal, self.identity, portal.ROOT / ".local/customer-portal")

    def test_profile_builds_without_old_customer_journals_or_credentials(self):
        with patch.object(portal, "load_private", side_effect=AssertionError("No journal reads")):
            metadata = self.prepare()
        parameters = self.writes["azuredeploy.json"]["parameters"]
        self.assertEqual(parameters["apiAuthorityTenantId"]["defaultValue"], uid(1))
        self.assertEqual(parameters["apiClientId"]["defaultValue"], uid(8))
        self.assertEqual(parameters["expectedCustomerTenantId"]["defaultValue"], uid(3))
        self.assertEqual(parameters["enrolledCustomerResourceGroupId"]["defaultValue"],
                         "")
        self.assertEqual(parameters["expectedCustomerSubscriptionId"]["defaultValue"], uid(4))
        self.assertEqual(parameters["apiClientSecret"], {"type": "secureString"})
        self.assertNotIn("customerIdentityId", parameters)
        self.assertNotIn("customerLocalToolsRequired", metadata)
        self.assertNotIn("providerAzureRbacRequiredByCustomer", metadata)
        fields = self.writes["uiFormDefinition.json"]["view"]["properties"]["steps"][0]["elements"]
        self.assertFalse(next(field for field in fields if field["name"] == "runId")["visible"])
        self.assertNotIn("defaultValue", next(field for field in fields if field["name"] == "apiClientSecret"))
        self.assertNotIn("PUBLIC-MOCK-ONLY-NOT-A-CREDENTIAL", json.dumps(self.writes))

    def test_operator_defaults_come_only_from_approved_configuration(self):
        self.cfg["adminAllowedSources"] = ["8.8.8.8", "1.1.1.1"]
        fingerprint = common.config_digest(self.cfg)
        self.journal["configDigest"] = self.identity["configDigest"] = fingerprint
        self.prepare()
        self.assertEqual(self.writes["azuredeploy.json"]["parameters"]["adminAllowedSources"]["defaultValue"],
                         ["1.1.1.1/32", "8.8.8.8/32"])
        fields = self.writes["uiFormDefinition.json"]["view"]["properties"]["steps"][0]["elements"]
        self.assertEqual(next(field for field in fields if field["name"] == "adminAllowedSources")["defaultValue"],
                         "1.1.1.1/32, 8.8.8.8/32")

    def test_proof_profile_never_creates_customer_vpn_resources(self):
        metadata = portal.prepare(self.cfg, self.journal, self.identity,
                                  portal.ROOT / ".local/customer-portal", proof_only=True)
        self.assertEqual(metadata["deploymentMode"], "proof")
        self.assertEqual(self.writes["azuredeploy.json"]["parameters"]["deploymentMode"]["defaultValue"], "proof")
        self.assertEqual(self.writes["azuredeploy.json"]["parameters"]["deploymentMode"]["allowedValues"], ["proof"])
        self.assertIn("no VPN gateways", self.writes["uiFormDefinition.json"]["view"]["properties"]["title"])
        fields = self.writes["uiFormDefinition.json"]["view"]["properties"]["steps"][0]["elements"]
        self.assertFalse(next(field for field in fields if field["name"] == "sshCredentials")["visible"])
        approval = next(field for field in fields if field["name"] == "approveDeploymentScriptBackingException")
        self.assertIn("authorization proof", approval["label"])
        self.assertNotIn("NSG", approval["label"])
        self.assertEqual(self.writes["uiFormDefinition.json"]["view"]["outputs"]["parameters"]["sshPublicKey"], "")

    def test_explicit_workload_public_key_remains_editable(self):
        self.cfg["workloadSshPublicKey"] = "fixture"
        fingerprint = common.config_digest(self.cfg)
        self.journal["configDigest"] = fingerprint
        self.identity["configDigest"] = fingerprint
        with patch.object(portal, "public_key", return_value="ssh-ed25519 fixture-public-key"):
            self.prepare()
        form = self.writes["uiFormDefinition.json"]
        fields = {field["name"]: field for field in form["view"]["properties"]["steps"][0]["elements"]}
        self.assertFalse(fields["sshCredentials"]["visible"])
        self.assertTrue(fields["sshPublicKey"]["visible"])
        self.assertTrue(fields["sshPublicKey"]["constraints"]["required"])
        self.assertEqual(fields["sshPublicKey"]["defaultValue"], "ssh-ed25519 fixture-public-key")
        self.assertEqual(form["view"]["outputs"]["parameters"]["sshPublicKey"],
                         "[steps('basics').sshPublicKey]")

    def test_root_secret_must_be_required_secure_no_default(self):
        self.template["parameters"]["apiClientSecret"]["defaultValue"] = ""
        with self.assertRaisesRegex(ValueError, "secureString"):
            self.prepare()
        self.assertEqual(self.writes, {})

    def test_secret_form_must_never_have_default_or_be_hidden(self):
        secret = self.form["view"]["properties"]["steps"][0]["elements"][-1]
        secret["defaultValue"] = "PUBLIC-MOCK-ONLY"
        with self.assertRaisesRegex(ValueError, "PasswordBox"):
            self.prepare()
        self.assertEqual(self.writes, {})

    def test_dynamic_unmapped_parameter_validation(self):
        self.template["parameters"]["newRequiredParam"] = {"type": "string"}
        with self.assertRaisesRegex(ValueError, "binding"):
            self.prepare()
        self.template["parameters"]["newRequiredParam"]["defaultValue"] = "approved"
        self.prepare()

    def test_legacy_or_wrong_config_refused(self):
        self.journal["apiAuthMode"] = "customer-managed-identity"
        with self.assertRaisesRegex(ValueError, "provider-api-client"):
            self.prepare()
        self.journal["apiAuthMode"] = setup.MODE
        self.identity["configDigest"] = "wrong"
        with self.assertRaisesRegex(ValueError, "different"):
            self.prepare()

    def test_main_loads_only_provider_state_and_checks_provider_feature(self):
        self.cfg["nvaSshPublicKey"] = "public-fixture"
        metadata = {"providerTemplateSha256": "a" * 64, "packageSha256": "b" * 64}
        self.journal.update(providerTemplateSha256="a" * 64, codePackageSha256="b" * 64)
        loads = []

        def load(path):
            loads.append(Path(path).name)
            return {"config.json": self.cfg, "provider-journal.json": self.journal,
                    "provider-identity.json": self.identity}[Path(path).name]

        with patch.object(portal, "load_private", side_effect=load), patch.object(
                portal, "validate_config", side_effect=lambda value: value), patch.object(
                portal, "package_metadata", return_value=metadata), patch.object(
                portal, "public_key"), patch.object(portal, "provider_feature_preflight") as preflight, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(portal.main(["--config", "config.json", "--execute"]), 0)
        self.assertEqual(loads, ["config.json", "provider-journal.json", "provider-identity.json"])
        preflight.assert_called_once_with(self.cfg)

    def test_proof_preparation_skips_vm_prerequisites(self):
        metadata = {"providerTemplateSha256": "a" * 64, "packageSha256": "b" * 64}
        self.journal.update(providerTemplateSha256="a" * 64, codePackageSha256="b" * 64)
        def load(path):
            return {"config.json": self.cfg, "provider-journal.json": self.journal,
                    "provider-identity.json": self.identity}[Path(path).name]
        with patch.object(portal, "load_private", side_effect=load), \
                patch.object(portal, "validate_config", side_effect=lambda value: value), \
                patch.object(portal, "package_metadata", return_value=metadata), \
                patch.object(portal, "public_key") as key_check, \
                patch.object(portal, "provider_feature_preflight") as preflight:
            self.assertEqual(portal.main(["--config", "config.json", "--execute", "--proof-only"]), 0)
        key_check.assert_not_called()
        preflight.assert_not_called()
        self.assertEqual(self.writes["profile.json"]["deploymentMode"], "proof")


if __name__ == "__main__":
    unittest.main()
