#!/usr/bin/env python3
"""Publisher engineering prepares the provider setup Portal template."""
import argparse
import hashlib
import json
import re
from pathlib import Path

from common import ROOT, compile_bicep, load_private, save_private, uuid_value
from provider_setup import package_metadata


def prepare(output: Path, release: dict, client: dict, package: dict) -> None:
    if not output.resolve().is_relative_to(ROOT / ".local"):
        raise ValueError("Release artifacts must stay under project .local")
    if client.get("pendingOperation"):
        raise ValueError("Uncertain setup client identity requires review")
    for key in ("providerTenantId", "clientId", "applicationObjectId", "principalId"):
        uuid_value(client[key])
    uuid_value(release["subscriptionId"])
    account, group = release["accountName"], release["resourceGroupName"]
    if (not re.fullmatch(r"[a-z0-9]{3,24}", account)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.()-]{0,89}", group)
            or group.endswith(".")
            or package.get("includesManagement") is not True):
        raise ValueError("Invalid provider release configuration")
    for key in ("packageSha256", "providerTemplateSha256"):
        if not re.fullmatch(r"[a-f0-9]{64}", package[key]):
            raise ValueError("Invalid release package pin")
    template = json.loads(compile_bicep("provider-bootstrap-entry.bicep"))
    parameters = template["parameters"]
    defaults = {
        "bootstrapApplicationId": client["clientId"],
        "releaseStorageAccountName": account,
        "releaseStorageResourceGroupName": group,
        "codePackageSha256": package["packageSha256"],
        "providerTemplateSha256": package["providerTemplateSha256"],
    }
    if any("secret" in key.lower() or "password" in key.lower() for key in parameters):
        raise ValueError("Provider setup entrypoint must not ask for a secret")
    for name, value in defaults.items():
        parameters[name]["defaultValue"] = value
    save_private(output / "azuredeploy.json", template)
    save_private(output / "release.json", {
        "templateSha256": hashlib.sha256(json.dumps(template, sort_keys=True).encode()).hexdigest(),
        "packageSha256": package["packageSha256"],
        "providerTenantId": client["providerTenantId"],
        "providerSubscriptionId": release["subscriptionId"],
    })


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-journal", required=True)
    parser.add_argument("--client-journal", required=True)
    parser.add_argument("--output", type=Path, default=ROOT / ".local/provider-setup-release")
    args = parser.parse_args()
    prepare(args.output, load_private(args.release_journal),
            load_private(args.client_journal), package_metadata())
    print("Provider setup template prepared privately; no Azure resources deployed.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Provider setup release preparation stopped; values suppressed.") from None
