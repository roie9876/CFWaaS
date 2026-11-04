#!/usr/bin/env python3
"""Engineering release preparation; provider administrators use the resulting Portal template."""
import argparse
import hashlib
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

from common import ROOT, compile_bicep, load_private, save_private
from prepare_customer_portal import portal_link
from provider_setup import package_metadata


def prepare(output: Path, package_uri: str, package: dict,
            release_account: str = "", release_group: str = "") -> None:
    if package.get("includesManagement") is not True:
        raise ValueError("Rebuild the release with management assets before preparing installation")
    parsed = urlsplit(package_uri)
    query = parse_qs(parsed.query)
    if (parsed.scheme != "https" or not parsed.hostname
            or not parsed.hostname.endswith(".blob.core.windows.net")
            or parsed.username or parsed.password or parsed.fragment
            or parsed.port not in (None, 443) or not parsed.path):
        raise ValueError("An Azure Blob package URI is required")
    if query:
        if (release_account or release_group or query.get("sp") != ["r"]
                or query.get("sr") != ["b"] or query.get("spr") != ["https"]
                or not query.get("skoid") or not query.get("sig")):
            raise ValueError("A read-only single-blob user-delegation SAS is required")
        expiry = datetime.fromisoformat(query.get("se", [""])[0].replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc) + timedelta(hours=2):
            raise ValueError("Publish a fresh package URI with at least two hours remaining")
    else:
        import re
        if (not re.fullmatch(r"[a-z0-9]{3,24}", release_account)
                or parsed.hostname != release_account + ".blob.core.windows.net"
                or not re.fullmatch(r"[A-Za-z0-9_.()-]{1,90}", release_group)
                or release_group.endswith(".")):
            raise ValueError("An exact provider release account and RG are required")
    template = json.loads(compile_bicep("provider-installation.bicep"))
    parameters = template["parameters"]
    for name in ("managementApplicationSecret", "codePackageUri"):
        if parameters[name]["type"].lower() != "securestring":
            raise ValueError("Installation credentials require secure parameters")
    if "defaultValue" in parameters["managementApplicationSecret"]:
        raise ValueError("Never preset the management app credential")
    defaults = {
        "codePackageUri": package_uri,
        "codePackageSha256": package["packageSha256"],
        "providerTemplateSha256": package["providerTemplateSha256"],
        "controlResourceGroupName": "rg-faas-admin-control",
        "dataResourceGroupName": "rg-faas-admin-data",
        "runId": "faas-admin-installation",
        "releaseStorageAccountName": release_account,
        "releaseStorageResourceGroupName": release_group,
    }
    for name, value in defaults.items():
        parameters[name]["defaultValue"] = value
    save_private(output / "azuredeploy.json", template)
    save_private(output / "release.json", {
        "templateSha256": hashlib.sha256(json.dumps(template, sort_keys=True).encode()).hexdigest(),
        "packageSha256": package["packageSha256"],
        "scope": "provider subscription only; customer resources are not installed",
        "requires": "Explicit provider Entra app setup/Graph consent and ARM deployment permissions",
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-uri-file", required=True,
                        help="Private .local URI metadata from engineering package publication")
    parser.add_argument("--output", type=Path, default=ROOT / ".local/provider-installation")
    parser.add_argument("--artifact-uris",
                        help="Optional private JSON with templateUri; no management credential")
    parser.add_argument("--release-account", default="")
    parser.add_argument("--release-group", default="")
    args = parser.parse_args()
    if not args.output.resolve().is_relative_to(ROOT / ".local"):
        raise ValueError("Release artifacts must stay under .local")
    package = package_metadata()
    source = load_private(args.package_uri_file)
    if source.get("sha256") != package["packageSha256"]:
        raise ValueError("Published package pin mismatch")
    prepare(args.output, source["uri"], package, args.release_account, args.release_group)
    if args.artifact_uris:
        from urllib.parse import quote
        uri = load_private(args.artifact_uris)["templateUri"]
        portal_link(uri, uri)
        save_private(args.output / "launch.json", {
            "portalUrl": "https://portal.azure.com/#create/Microsoft.Template/uri/" + quote(uri, safe=""),
        })
    print("Provider installation ARM prepared privately; no Azure resources deployed.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Provider installation preparation stopped; credential values suppressed.") from None
