"""Publish a short-lived provider installation form without including credentials."""
import copy
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import BlobSasPermissions, BlobServiceClient, ContentSettings, generate_blob_sas

from .config import endpoint
from .provider_bootstrap import BootstrapContext, BootstrapError


class BootstrapReleasePublisher:
    def __init__(self, credential, account_url: str, release_group: str, vault_name: str, vault_group: str,
                 package_uri: str, package_sha256: str, template_sha256: str,
                 template_directory: Path | None = None) -> None:
        account_url = endpoint(account_url, ".blob.core.windows.net")
        self.account = urlsplit(account_url).hostname.split(".")[0]
        if (not re.fullmatch(r"[a-z0-9]{3,24}", self.account)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.()-]{0,89}", release_group)
                or release_group.endswith(".")
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.()-]{0,89}", vault_group)
                or vault_group.endswith(".")
                or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,22}[a-z0-9]", vault_name)
                or "--" in vault_name):
            raise ValueError("Invalid provider release configuration")
        parsed = urlsplit(package_uri)
        if (parsed.scheme != "https" or parsed.hostname != self.account + ".blob.core.windows.net"
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.port not in (None, 443)
                or not parsed.path.startswith("/deployment-artifacts/releases/")):
            raise ValueError("Expected an unsigned private provider release package")
        if not all(re.fullmatch(r"[a-f0-9]{64}", value) for value in (package_sha256, template_sha256)):
            raise ValueError("Invalid provider release hash")
        self.release_group, self.vault_name, self.vault_group = release_group, vault_name, vault_group
        self.package_uri, self.package_sha256, self.template_sha256 = package_uri, package_sha256, template_sha256
        self.directory = template_directory or Path(__file__).parent / "templates"
        self.blobs = BlobServiceClient(account_url, credential=credential, logging_enable=False,
                                       retry_total=2, connection_timeout=5, read_timeout=20)

    def documents(self, context: BootstrapContext, parameters: dict) -> tuple[dict, dict]:
        template = copy.deepcopy(json.loads((self.directory / "provider-guided.json").read_text()))
        form = copy.deepcopy(json.loads((self.directory / "provider-guided-form.json").read_text()))
        if (parameters.get("providerTenantId") != context.tenant_id
                or parameters.get("providerSubscriptionId") != context.subscription_id
                or parameters.get("administratorObjectId") != context.administrator_id
                or parameters.get("managementAppName") != context.management_origin.removeprefix(
                    "https://").split(".")[0]
                or not re.fullmatch(r"faas-mgmt-[a-f0-9]{32}", str(parameters.get("managementSecretName", "")))
                or not re.fullmatch(r"[a-f0-9]{32}", str(parameters.get("managementSecretVersion", "")))):
            raise BootstrapError(403, "BootstrapInstallationBindingMismatch")
        defaults = {
            "releaseStorageResourceGroupName": self.release_group,
            "releaseStorageAccountName": self.account,
            "setupVaultName": self.vault_name,
            "setupVaultResourceGroupName": self.vault_group,
            "managementSecretName": parameters["managementSecretName"],
            "managementSecretVersion": parameters["managementSecretVersion"],
            "apiApplicationId": parameters["apiApplicationId"],
            "apiRoleId": parameters["apiRoleId"],
            "managementApplicationId": parameters["managementApplicationId"],
            "managementAppName": parameters["managementAppName"],
            "managementCredentialExpiresOn": parameters["managementCredentialExpiresOn"],
            "administratorObjectIds": [context.administrator_id],
            "nvaSshPublicKey": parameters["nvaSshPublicKey"],
            "codePackageUri": self.package_uri,
            "codePackageSha256": self.package_sha256,
            "providerTemplateSha256": self.template_sha256,
        }
        inputs = template["parameters"]
        if "managementApplicationSecret" in inputs or inputs["codePackageUri"]["type"].lower() != "securestring":
            raise ValueError("Provider installer must reference the private vault")
        for key, value in defaults.items():
            inputs[key]["defaultValue"] = value
        if form["view"]["outputs"]["kind"] != "ResourceGroup":
            raise ValueError("Provider installer must use the setup resource group")
        return template, form

    def publish(self, context: BootstrapContext, parameters: dict) -> dict:
        container = self.blobs.get_container_client("deployment-artifacts")
        if container.get_container_properties().public_access:
            raise ValueError("Release artifact container must be private")
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(hours=4)
        delegation = self.blobs.get_user_delegation_key(now - timedelta(minutes=5), expiry)
        uris = []
        for name, document in zip(("azuredeploy.json", "uiFormDefinition.json"),
                                  self.documents(context, parameters), strict=True):
            data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            digest = hashlib.sha256(data).hexdigest()
            blob = container.get_blob_client(f"guided/{context.installation_id}/{digest}/{name}")
            try:
                blob.upload_blob(data, overwrite=False, metadata={"sha256": digest},
                                 content_settings=ContentSettings(content_type="application/json"))
            except ResourceExistsError:
                if blob.get_blob_properties().metadata.get("sha256") != digest:
                    raise ValueError("Existing provider artifact hash mismatch") from None
            signature = generate_blob_sas(
                self.account, container.container_name, blob.blob_name,
                user_delegation_key=delegation, permission=BlobSasPermissions(read=True),
                start=now - timedelta(minutes=5), expiry=expiry, protocol="https",
            )
            uris.append(blob.url + "?" + signature)
        return {
            "portalUrl": "https://portal.azure.com/#create/Microsoft.Template/uri/"
                         + quote(uris[0], safe="") + "/uiFormDefinitionUri/"
                         + quote(uris[1], safe=""),
            "expiresAt": expiry.isoformat(),
        }

    def close(self) -> None:
        self.blobs.close()
