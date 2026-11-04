#!/usr/bin/env python3
"""Prepare a provider-tenant-specific Portal installer from a verified setup journal.

The setup journal contains public identifiers only. Entra permission grants and
the private Key Vault secret must already have been verified by the operator.
No directory or Azure calls happen in this preparation step.
"""
import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from common import ROOT, compile_bicep, load_private, public_key, save_private, uuid_value
from provider_setup import package_metadata


def prepare(output: Path, release: dict, identity: dict, package: dict) -> None:
    if not output.resolve().is_relative_to(ROOT / ".local"):
        raise ValueError("Guided release artifacts must remain under project .local")
    if (identity.get("pendingOperation") or identity.get("consentVerified") is not True
            or identity.get("managementSecretStored") is not True
            or identity.get("sshPrivateKeyStored") is not True):
        raise ValueError("Identity consent and private secret custody must be verified")
    for key in ("providerTenantId", "providerSubscriptionId", "administratorObjectId",
                "apiApplicationId", "apiRoleId", "managementApplicationId"):
        uuid_value(identity[key])
    if identity["providerSubscriptionId"] != release["subscriptionId"]:
        raise ValueError("Identity and release subscription differ")
    expiry = datetime.fromisoformat(identity["managementCredentialExpiresOn"].replace("Z", "+00:00"))
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc) + timedelta(days=1):
        raise ValueError("Management credential expires too soon for installation")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,58}[a-z0-9]", identity["managementAppName"]):
        raise ValueError("Invalid management web app name")
    if (not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,22}[a-z0-9]", identity["setupVaultName"])
            or "--" in identity["setupVaultName"]):
        raise ValueError("Invalid private setup vault name")
    source = urlsplit(release["packageUri"])
    if (source.scheme != "https" or source.hostname != release["accountName"] + ".blob.core.windows.net"
            or source.query or source.fragment or source.username or source.password
            or source.port not in (None, 443)
            or not source.path.startswith("/deployment-artifacts/releases/")):
        raise ValueError("Guided installer requires an exact private provider release blob")
    if package.get("includesManagement") is not True or release["sha256"] != package["packageSha256"]:
        raise ValueError("The provider management release package pin does not match")
    template = json.loads(compile_bicep("provider-guided-installation.bicep"))
    defaults = {
        "releaseStorageResourceGroupName": release["resourceGroupName"],
        "releaseStorageAccountName": release["accountName"],
        "setupVaultName": identity["setupVaultName"],
        "setupVaultResourceGroupName": identity["setupVaultResourceGroupName"],
        "managementSecretName": identity["managementSecretName"],
        "managementSecretVersion": identity["managementSecretVersion"],
        "apiApplicationId": identity["apiApplicationId"],
        "apiRoleId": identity["apiRoleId"],
        "managementApplicationId": identity["managementApplicationId"],
        "managementAppName": identity["managementAppName"],
        "managementCredentialExpiresOn": identity["managementCredentialExpiresOn"],
        "administratorObjectIds": [identity["administratorObjectId"]],
        "nvaSshPublicKey": public_key(identity["nvaSshPublicKey"]),
        "codePackageUri": release["packageUri"],
        "codePackageSha256": package["packageSha256"],
        "providerTemplateSha256": package["providerTemplateSha256"],
    }
    if "managementApplicationSecret" in template["parameters"]:
        raise ValueError("Guided installation must not expose the management credential")
    if not re.fullmatch(r"faas-mgmt-[0-9a-f]{32}", identity["managementSecretName"]):
        raise ValueError("Invalid unique management secret name")
    if not re.fullmatch(r"[0-9a-f]{32}", identity["managementSecretVersion"]):
        raise ValueError("Invalid management secret version")
    for name, value in defaults.items():
        template["parameters"][name]["defaultValue"] = value
    save_private(output / "azuredeploy.json", template)
    save_private(output / "release.json", {
        "templateSha256": hashlib.sha256(json.dumps(template, sort_keys=True).encode()).hexdigest(),
        "packageSha256": package["packageSha256"],
        "scope": "provider-tenant-specific guided lab release",
    })


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-journal", required=True)
    parser.add_argument("--identity-journal", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / ".local/provider-guided")
    args = parser.parse_args()
    prepare(args.output, load_private(args.release_journal),
            load_private(args.identity_journal), package_metadata())
    print("Guided installer prepared privately; no Azure resource deployed.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Guided release preparation stopped; credential values suppressed.") from None
