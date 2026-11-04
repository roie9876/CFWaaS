"""Provider artifact contract tests; every Azure operation is mocked."""
from contextlib import ExitStack, redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest.mock import patch
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import common
import provider_artifacts as artifacts


def uid(n):
    return str(UUID(int=n))


class ArtifactTests(unittest.TestCase):
    def test_preview_accepts_azure_normalized_builtin_role_without_principal_type(self):
        changes = [{
            "changeType": "Create", "resourceId": self.host["accountId"],
            "after": {"properties": {}},
        }, {
            "changeType": "Create",
            "resourceId": self.host["accountId"] + "/providers/Microsoft.Authorization/roleAssignments/" + uid(9),
            "after": {"properties": {
                "principalId": uid(6),
                "roleDefinitionId": "https://management.azure.com/providers/Microsoft.Authorization/roleDefinitions/" + artifacts.ROLE}},
        }]
        self.assertEqual(artifacts.preview(self.cfg, changes, uid(6), "User"), self.host["accountId"])
        changes[1]["after"]["properties"]["roleDefinitionId"] = (
            "https://untrusted.example/providers/Microsoft.Authorization/roleDefinitions/" + artifacts.ROLE)
        with self.assertRaises(ValueError):
            artifacts.preview(self.cfg, changes, uid(6), "User")

    def setUp(self):
        self.cfg = {"runId": "fixture-run", "provider": {
            "tenantId": uid(1), "subscriptionId": uid(2), "controlPlaneResourceGroup": "rg-provider-control"},
            "customer": {"tenantId": uid(3), "subscriptionId": uid(4)}}
        self.directory = artifacts.ROOT / ".local" / ("artifact-unit-" + str(os.getpid()))
        self.directory.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.directory)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.process = self.stack.enter_context(patch("subprocess.run", side_effect=AssertionError("Unmocked cloud")))
        self.cli = self.stack.enter_context(patch.object(artifacts, "cli"))
        self.data = self.stack.enter_context(patch.object(artifacts, "storage"))
        self.name = "stfaasart" + "a" * 13
        self.host = {"accountName": self.name, "blobEndpoint": f"https://{self.name}.blob.core.windows.net/",
                     "containerName": artifacts.CONTAINER, "accountId": common.group_id(uid(2), "rg-provider-control")
                     + "/providers/Microsoft.Storage/storageAccounts/" + self.name}
        self.sha = hashlib.sha256(b"public-fixture").hexdigest()
        self.uri = self.host["blobEndpoint"] + "deployment-artifacts/apps.zip?sp=r&sr=b&spr=https&skoid=" + uid(6) + "&sig=public-fixture"
        self.source = self.file("apps.zip", b"public-fixture")
        self.output = self.directory / "uri.json"
        self.cli.return_value = {"id": self.host["accountId"],
                                 "tags": {"purpose": "provider-provisioning", "labRun": self.cfg["runId"],
                                          "SecurityControl": "Ignore"},
                                 "properties": {"allowSharedKeyAccess": False, "allowBlobPublicAccess": False,
                                                "publicNetworkAccess": "Enabled"}}
        self.data.side_effect = lambda *a: ({"properties": {"publicAccess": None}} if a[:2] == ("container", "show")
            else {"exists": True} if a[:2] == ("blob", "exists") else {"metadata": {"sha256": self.sha}}
            if a[:2] == ("blob", "show") else self.uri if a[:2] == ("blob", "generate-sas") else {})

    def file(self, name, value):
        path = self.directory / name
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    def upload(self):
        artifacts.upload(self.cfg, {"host": self.host}, self.source, self.sha, "apps.zip", self.output)

    def test_existing_hash_reused_private_sas_never_logged_provider_only(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.upload()
        self.assertNotIn(self.uri, stdout.getvalue())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        result = json.loads(self.output.read_text())
        self.assertEqual(result["uri"], self.uri)
        self.assertAlmostEqual((datetime.fromisoformat(result["expiresAt"].replace("Z", "+00:00"))
                               - datetime.now(timezone.utc)).total_seconds(), 14400, delta=2)
        for call in [*self.cli.call_args_list, *self.data.call_args_list]:
            self.assertEqual(call.args[call.args.index("--subscription") + 1], uid(2))
            self.assertNotIn("--account-key", call.args)
        self.assertFalse(any(c.args[:2] == ("blob", "upload") for c in self.data.call_args_list))

    def test_governance_disabled_networking_is_not_overridden(self):
        self.cli.return_value["properties"]["publicNetworkAccess"] = "Disabled"
        with self.assertRaisesRegex(ValueError, "governance"):
            self.upload()
        self.data.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_missing_blob_upload_has_aad_no_overwrite_hash_pin(self):
        original = self.data.side_effect
        self.data.side_effect = lambda *a: {"exists": False} if a[:2] == ("blob", "exists") else original(*a)
        self.upload()
        call = next(c.args for c in self.data.call_args_list if c.args[:2] == ("blob", "upload"))
        for key, value in (("--auth-mode", "login"), ("--overwrite", "false"), ("--metadata", "sha256=" + self.sha)):
            self.assertEqual(call[call.index(key) + 1], value)

    def test_hash_mismatch_never_sas_or_overwrite(self):
        original = self.data.side_effect
        self.data.side_effect = lambda *a: {"metadata": {"sha256": "different"}} if a[:2] == ("blob", "show") else original(*a)
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.upload()
        self.assertFalse(self.output.exists())
        self.assertFalse(any(c.args[:2] in {("blob", "generate-sas"), ("blob", "upload")} for c in self.data.call_args_list))

    def test_private_paths_names_and_no_credentials(self):
        link = self.directory / "linked"
        link.symlink_to(self.directory, target_is_directory=True)
        for path in (self.directory.parent.parent / "outside", link / "apps.zip"):
            with self.assertRaises(ValueError):
                artifacts.private_path(path)
        self.source.chmod(0o644)
        with self.assertRaises(ValueError):
            artifacts.private_path(self.source, source=True)
        for name in ("../x", "/x", "a\\b", "a" * 501, ""):
            with self.assertRaises(ValueError):
                artifacts.blob_name(name)
        with patch.object(artifacts, "load_private") as load:
            with self.assertRaises(ValueError):
                artifacts.source_file(self.file("customer-api-credential.json", b"{}"), self.cfg)
            load.assert_not_called()

    def test_candidate_package_requires_matching_private_metadata_and_hash(self):
        metadata = {"packagePath": str(self.source), "packageSha256": self.sha,
                    "includesManagement": True}
        self.file("apps.metadata.json", json.dumps(metadata).encode())
        self.assertEqual(artifacts.source_file(self.source, self.cfg), (self.source, self.sha))
        for field, value in (("packagePath", str(self.output)),
                             ("packageSha256", "0" * 64), ("includesManagement", False)):
            self.file("apps.metadata.json", json.dumps({**metadata, field: value}).encode())
            with self.subTest(field=field), self.assertRaises(ValueError):
                artifacts.source_file(self.source, self.cfg)

    def test_api_client_role_assignment_refused(self):
        with patch.object(artifacts, "private_path"), patch.object(artifacts, "load_private", return_value={
                "configDigest": common.config_digest(self.cfg), "customerApiPrincipalId": uid(5)}):
            with self.assertRaisesRegex(ValueError, "never receive Azure RBAC"):
                artifacts.host(self.cfg, {}, self.output, uid(5), "ServicePrincipal")
        self.cli.assert_not_called()

    def test_host_incremental_provider_only_with_private_bound_outputs(self):
        state = {"configDigest": common.config_digest(self.cfg)}
        self.cli.side_effect = [
            {"changes": [{"resourceId": self.host["accountId"], "changeType": "Create"}]},
            {"properties": {"outputs": {k: {"value": v} for k, v in self.host.items()}}},
            self.cli.return_value]
        with patch.object(artifacts, "private_path"), patch.object(artifacts, "load_private", return_value={
                "configDigest": common.config_digest(self.cfg), "customerApiPrincipalId": uid(5)}):
            artifacts.host(self.cfg, state, self.output, uid(6), "User")
        self.assertEqual(json.loads(self.output.read_text())["host"], self.host)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        for call in self.cli.call_args_list:
            self.assertEqual(call.args[call.args.index("--subscription") + 1], uid(2))
            if call.args[0] == "deployment":
                self.assertEqual(call.args[call.args.index("--mode") + 1], "Incremental")
                self.assertEqual(call.args[call.args.index("--resource-group") + 1], "rg-provider-control")

    def test_whatif_role_scope_ownership_and_no_deletes(self):
        changes = [{"resourceId": self.host["accountId"], "changeType": "Create"}]
        self.assertEqual(artifacts.preview(self.cfg, changes, uid(6), "User"), self.host["accountId"])
        for resource, change in ((self.host["accountId"], "Delete"),
                                 (common.group_id(uid(4), "rg-customer"), "Create"),
                                 (self.host["accountId"] + "/providers/Microsoft.Authorization/roleAssignments/" + uid(7), "Create")):
            with self.assertRaises(ValueError):
                artifacts.preview(self.cfg, [*changes, {"resourceId": resource, "changeType": change}], uid(6), "User")

    def test_dry_run_never_cloud_and_unsafe_outputs_refused(self):
        cfg = self.file("config.json", b"{}")
        with patch.object(artifacts, "load_private", return_value=self.cfg), \
                patch.object(artifacts, "validate_config", return_value=self.cfg), patch.object(artifacts, "publisher"), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(artifacts.main(["host", "--config", str(cfg), "--publisher-principal-id", uid(6),
                                            "--publisher-principal-type", "User"]), 0)
        self.cli.assert_not_called()
        self.data.assert_not_called()
        self.upload()
        with self.assertRaises(FileExistsError):
            self.upload()

    def test_rbac_retry_only_classified_403_and_timeout(self):
        function = self.real_storage
        denied = subprocess.CompletedProcess([], 1, "", "403 AuthorizationPermissionMismatch")
        self.process.side_effect = [denied, subprocess.CompletedProcess([], 0, '{"exists":true}', "")]
        with patch.object(artifacts.time, "sleep") as sleep:
            self.assertEqual(function("blob", "exists"), {"exists": True})
            sleep.assert_called_once_with(5)
        self.assertLessEqual(self.process.call_args.kwargs["timeout"], 180)
        self.process.side_effect = [subprocess.CompletedProcess([], 1, "", "403 AuthenticationFailed")]
        with self.assertRaises(ValueError):
            function("blob", "exists")
        self.process.side_effect = [denied]
        with patch.object(artifacts.time, "monotonic", side_effect=[0, 0, 180]), \
                patch.object(artifacts.time, "sleep") as sleep, self.assertRaises(ValueError):
            function("blob", "exists")
        sleep.assert_not_called()

    def test_bicep_native_security_and_account_only_role(self):
        source = (artifacts.ROOT / "infra/provider-artifacts.bicep").read_text()
        for invariant in ("allowSharedKeyAccess: false", "allowBlobPublicAccess: false",
                          "defaultToOAuthAuthentication: true", "publicAccess: 'None'",
                          "minimumTlsVersion: 'TLS1_2'", "supportsHttpsTrafficOnly: true",
                          "scope: artifacts", artifacts.ROLE, "sku: { name: 'Standard_LRS' }",
                          "'stfaasart${uniqueString(resourceGroup().id)}'"):
            self.assertIn(invariant, source)
        self.assertIn("SecurityControl: 'Ignore'", source)
        self.assertNotIn("listKeys", source)
        self.assertEqual(source.count("\noutput "), 4)

    def test_generated_sources_hash_pinned_and_uri_symlink_refused(self):
        document = {"public": "fixture"}
        self.file("azuredeploy.json", json.dumps(document).encode())
        profile = {"configDigest": common.config_digest(self.cfg), "templateSha256": common.digest(document)}
        self.file("profile.json", json.dumps(profile).encode())
        source, sha = artifacts.source_file(self.directory / "azuredeploy.json", self.cfg)
        self.assertEqual(sha, hashlib.sha256(source.read_bytes()).hexdigest())
        source.write_text("{}")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            artifacts.source_file(source, self.cfg)
        self.output.symlink_to(self.source)
        with self.assertRaises(ValueError):
            self.upload()
        self.assertEqual(self.source.read_bytes(), b"public-fixture")

    real_storage = staticmethod(artifacts.storage)


if __name__ == "__main__":
    unittest.main()
