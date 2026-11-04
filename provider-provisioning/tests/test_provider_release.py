import hashlib
import importlib.util
import io
import json
import sys
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("publish_provider", ROOT / "infra/cloud-init/publish-provider.py")
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)


def test_provider_form_exposes_required_parameters_without_secrets_or_sas():
    form = json.loads((ROOT / "portal/provider-form.json").read_text())
    assert form["view"]["outputs"]["kind"] == "Subscription"
    outputs = form["view"]["outputs"]["parameters"]
    assert {"apiApplicationId", "apiRoleId", "managementApplicationId",
            "managementApplicationSecret", "managementCredentialExpiresOn",
            "administratorObjectIds", "nvaSshPublicKey",
            "approveDeploymentScriptBackingException"} <= set(outputs)
    assert "codePackageUri" not in outputs
    fields = {item["name"]: item for step in form["view"]["properties"]["steps"]
              for item in step["elements"]}
    secret = fields["managementSecret"]
    assert secret["type"] == "Microsoft.Common.PasswordBox"
    assert secret["constraints"]["required"] is True
    assert "defaultValue" not in secret
    assert fields["subscription"]["type"] == "Microsoft.Common.SubscriptionSelector"


def test_private_release_package_uses_uami_and_verifies_real_app_builds(monkeypatch, tmp_path):
    payload = b"unit-release-zip"
    monkeypatch.setenv("FAAS_PACKAGE_URI", "https://unitstore.blob.core.windows.net/releases/immutable/apps.zip")
    monkeypatch.setenv("FAAS_RELEASE_STORAGE_ACCOUNT", "unitstore")
    monkeypatch.setenv("FAAS_PACKAGE_SHA256", hashlib.sha256(payload).hexdigest())
    monkeypatch.setenv("FAAS_PROVIDER_SUBSCRIPTION", "unit-subscription")
    monkeypatch.setenv("FAAS_PROVIDER_CONTROL_GROUP", "rg-unit")
    monkeypatch.setenv("FAAS_PROVIDER_APPS", json.dumps(["api-unit", "worker-unit", "admin-unit"]))
    output = tmp_path / "output.json"
    monkeypatch.setenv("AZ_SCRIPTS_OUTPUT_PATH", str(output))
    signed = ("https://unitstore.blob.core.windows.net/releases/immutable/apps.zip"
              "?sp=r&sr=b&spr=https&skoid=unit&sig=unit-read-only")
    writes, calls = [], []

    def cli(*args):
        calls.append(args)
        if args[:3] == ("storage", "blob", "generate-sas"):
            assert "--as-user" in args
            assert args[args.index("--auth-mode") + 1] == "login"
            return signed
        if args[:2] == ("account", "show"):
            return {"id": "unit-subscription"}
        if args[:3] == ("rest", "--method", "put"):
            path = Path(args[args.index("--body") + 1][1:])
            writes.append(json.loads(path.read_text()))
            assert path.stat().st_mode & 0o777 == 0o600
            assert signed not in args
            return {}
        if args[:3] == ("rest", "--method", "get"):
            return {"value": [{"properties": {"start_time": datetime.now(timezone.utc).isoformat(),
                                                "status": 4, "active": True}}]}
        raise AssertionError("Unexpected CLI call")

    with patch.object(publisher, "cli", side_effect=cli), \
            patch.object(publisher.urllib.request, "urlopen", return_value=io.BytesIO(payload)):
        publisher.main()
    assert len(writes) == 3
    assert all(value["properties"]["packageUri"] == signed for value in writes)
    assert json.loads(output.read_text()) == {"status": "Published"}
    assert len([item for item in calls if item[:3] == ("rest", "--method", "get")]) == 3


def test_unsigned_release_refuses_another_storage_account(monkeypatch):
    monkeypatch.setenv("FAAS_PACKAGE_URI", "https://otherstore.blob.core.windows.net/releases/immutable/apps.zip")
    monkeypatch.setenv("FAAS_RELEASE_STORAGE_ACCOUNT", "unitstore")
    with patch.object(publisher, "cli") as cli, pytest.raises(ValueError):
        publisher.main()
    cli.assert_not_called()


def test_publisher_request_error_exposes_only_safe_error_classification():
    stderr = ("ERROR: ServiceUnavailable HTTP 503 "
              "https://example.test/?sig=secret authorization=token")
    with patch.object(publisher.subprocess, "run") as run:
        run.return_value.returncode = 1
        run.return_value.stderr = stderr
        with pytest.raises(publisher.ProviderPublishRequestError) as error:
            publisher.cli("rest", "--method", "get")
    assert str(error.value) == "Azure request failed (code: ServiceUnavailable, HTTP: 503)."
    assert "secret" not in str(error.value)
    assert "token" not in str(error.value)


def test_publisher_reports_package_http_status_without_leaking_uri(monkeypatch):
    uri = ("https://unitstore.blob.core.windows.net/releases/immutable/apps.zip"
           "?sp=r&sr=b&spr=https&skoid=unit&sig=secret-signature")
    monkeypatch.setenv("FAAS_PACKAGE_URI", uri)
    monkeypatch.setenv("FAAS_PACKAGE_SHA256", "a" * 64)
    with patch.object(publisher.urllib.request, "urlopen",
                      side_effect=urllib.error.HTTPError(uri, 403, "private body", None, None)):
        with pytest.raises(publisher.ProviderPublishRequestError) as error:
            publisher.main()
    assert str(error.value) == "Provider package download failed (HTTP 403)."
    assert "secret-signature" not in str(error.value)
    assert "private body" not in str(error.value)


def guided_release_fixture():
    import uuid
    names = ("providerTenantId", "providerSubscriptionId", "administratorObjectId",
             "apiApplicationId", "apiRoleId", "managementApplicationId")
    identity = {name: str(uuid.UUID(int=index + 1)) for index, name in enumerate(names)}
    identity.update(
        consentVerified=True, managementSecretStored=True, sshPrivateKeyStored=True,
        managementCredentialExpiresOn="2099-01-01T00:00:00Z",
        managementAppName="faas-admin-management", setupVaultName="kvfaasguide",
        setupVaultResourceGroupName="rg-setup",
        managementSecretName="faas-mgmt-" + "a" * 32,
        managementSecretVersion="b" * 32,
        nvaSshPublicKey=Ed25519PublicKey.from_public_bytes(bytes(range(32))).public_bytes(
            Encoding.OpenSSH, PublicFormat.OpenSSH).decode(),
    )
    release = {"subscriptionId": identity["providerSubscriptionId"], "accountName": "unitstore",
               "resourceGroupName": "rg-release",
               "packageUri": "https://unitstore.blob.core.windows.net/deployment-artifacts/releases/a/apps.zip",
               "sha256": "a" * 64}
    package = {"includesManagement": True, "packageSha256": "a" * 64, "providerTemplateSha256": "b" * 64}
    return identity, release, package


def test_guided_release_has_no_secret_parameter_and_requires_verified_prerequisites(tmp_path):
    import prepare_guided_provider as guided
    identity, release, package = guided_release_fixture()
    names = (
        "releaseStorageResourceGroupName", "releaseStorageAccountName", "setupVaultName",
        "setupVaultResourceGroupName",
        "managementSecretName", "managementSecretVersion",
        "apiApplicationId", "apiRoleId", "managementApplicationId", "managementAppName",
        "managementCredentialExpiresOn", "administratorObjectIds", "nvaSshPublicKey",
        "codePackageUri", "codePackageSha256", "providerTemplateSha256",
    )
    template = {"parameters": {name: {"type": "string"} for name in names}}
    with patch.object(guided, "compile_bicep", return_value=json.dumps(template).encode()), \
            patch.object(guided, "save_private") as save, \
            patch.object(Path, "resolve", return_value=ROOT / ".local/guided-unit"):
        guided.prepare(tmp_path, release, identity, package)
        document = save.call_args_list[0].args[1]
        assert "managementApplicationSecret" not in document["parameters"]
        assert document["parameters"]["administratorObjectIds"]["defaultValue"] == [identity["administratorObjectId"]]
        for field in ("consentVerified", "managementSecretStored", "sshPrivateKeyStored"):
            wrong = dict(identity, **{field: False})
            with pytest.raises(ValueError):
                guided.prepare(tmp_path, release, wrong, package)
        with pytest.raises(ValueError):
            guided.prepare(tmp_path, release, dict(identity, pendingOperation="uncertain"), package)
        with pytest.raises(ValueError):
            guided.prepare(tmp_path, release, dict(identity, managementSecretVersion="invalid"), package)
        with pytest.raises(ValueError):
            guided.prepare(tmp_path, dict(release, packageUri=release["packageUri"] + "?sig=not-allowed"),
                           identity, package)


def test_guided_form_does_not_ask_for_internal_ids_or_secrets():
    form = json.loads((ROOT / "portal/provider-guided-form.json").read_text())
    assert form["view"]["outputs"]["kind"] == "ResourceGroup"
    outputs = form["view"]["outputs"]["parameters"]
    assert set(outputs) == {"dataResourceGroupName",
                            "approveDeploymentScriptBackingException"}
    for step in form["view"]["properties"]["steps"]:
        for element in step["elements"]:
            assert element["type"] != "Microsoft.Common.PasswordBox"


def test_setup_release_pins_public_client_and_contains_no_secret_parameter(tmp_path):
    import prepare_setup_release as setup
    identity, release, package = guided_release_fixture()
    client = {"providerTenantId": identity["providerTenantId"],
              "clientId": identity["managementApplicationId"],
              "applicationObjectId": identity["apiApplicationId"],
              "principalId": identity["apiRoleId"]}
    parameters = {name: {"type": "string"} for name in (
        "bootstrapApplicationId", "releaseStorageAccountName",
        "releaseStorageResourceGroupName", "codePackageSha256", "providerTemplateSha256")}
    with patch.object(setup, "compile_bicep", return_value=json.dumps({"parameters": parameters}).encode()), \
            patch.object(setup, "save_private") as save, \
            patch.object(Path, "resolve", return_value=ROOT / ".local/setup-unit"):
        setup.prepare(tmp_path, release, client, package)
        document = save.call_args_list[0].args[1]
        assert document["parameters"]["bootstrapApplicationId"]["defaultValue"] == client["clientId"]
        assert document["parameters"]["codePackageSha256"]["defaultValue"] == package["packageSha256"]
        assert "managementApplicationSecret" not in document["parameters"]
        with pytest.raises(ValueError):
            setup.prepare(tmp_path, release, dict(client, pendingOperation="CreateApplication"), package)
