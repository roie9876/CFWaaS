#!/usr/bin/env python3
"""Prepare a self-contained ARM/Form pair for read-only provider HTTPS distribution.

--execute permits provider-only prerequisite reads and local artifact generation,
not deployment or publication. Enrollment is approved local metadata, not proof of
customer Azure ownership. The customer supplies the API secret in the secure UI;
this tool never opens the credential file or embeds it in artifacts or URLs.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import urllib.parse

from common import (ROOT, compile_bicep, config_digest, customer_sizing, digest,
                    group_id, load_private, public_key, save_private, validate_config)
from customer_connector import admin_sources, api_origin, validate_connection_template
from provider_setup import MODE, package_metadata, provider_feature_preflight, validate_identity


def portal_link(template_uri: str, form_uri: str) -> str:
    for uri in (template_uri, form_uri):
        parsed = urllib.parse.urlsplit(uri)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.port not in (None, 443) or not parsed.path or parsed.fragment):
            raise ValueError("Artifact distribution requires HTTPS file URLs without embedded credentials")
        query = urllib.parse.parse_qs(parsed.query)
        if any(key.lower() in {"client_secret", "apiclientsecret", "access_token", "authorization"}
               for key in query):
            raise ValueError("API credentials must never be embedded in artifact URLs")
        if "sig" in query and (query.get("sp") != ["r"] or query.get("sr") != ["b"]):
            raise ValueError("Artifact SAS must be read-only and scoped to one blob")
    return ("https://portal.azure.com/#create/Microsoft.Template/uri/"
            + urllib.parse.quote(template_uri, safe="") + "/uiFormDefinitionUri/"
            + urllib.parse.quote(form_uri, safe=""))


def prepare(config: dict, provider: dict, identity: dict, output: Path, proof_only: bool = False) -> dict:
    fingerprint = config_digest(config)
    if provider.get("configDigest") != fingerprint:
        raise ValueError("Portal preparation requires journals for the exact approved configuration")
    validate_identity(config, identity)
    if provider.get("apiAuthMode") != MODE:
        raise ValueError("Portal preparation requires provider-api-client authentication")
    customer = config["customer"]
    # Source-controlled approved enrollment only: no customer resource or Graph reads.
    url = api_origin(provider["controlPlane"]["apiUrl"])
    connections = json.loads(compile_bicep("customer-connections.bicep"))
    validate_connection_template(connections)
    template = json.loads(compile_bicep("customer-deployment.bicep"))
    if "deploymentMode" not in template["parameters"]:
        raise ValueError("Portal template must support a separate harmless proof stage")
    template["parameters"]["deploymentMode"]["defaultValue"] = "proof" if proof_only else "network"
    if proof_only:
        template["parameters"]["deploymentMode"]["allowedValues"] = ["proof"]
    defaults = {
        "runId": config["runId"],
        "apiAuthorityTenantId": config["provider"]["tenantId"],
        "apiClientId": identity["customerApiClientId"],
        "enrolledCustomerResourceGroupId": "",
        "expectedCustomerSubscriptionId": customer["subscriptionId"],
        "expectedCustomerTenantId": customer["tenantId"],
        "apiUrl": url, "apiResource": identity["apiResource"],
        "customerConnectionsTemplateBase64": base64.b64encode(
            json.dumps(connections, separators=(",", ":")).encode()).decode(),
        **customer_sizing({}),
        "adminAllowedSources": admin_sources(config.get("adminAllowedSources", [])),
    }
    if "customerIdentityId" in template["parameters"]:
        raise ValueError("Legacy pre-onboarded customer identity is not supported")
    secret = template["parameters"].get("apiClientSecret", {})
    if secret.get("type", "").lower() != "securestring" or "defaultValue" in secret:
        raise ValueError("API secret must be a required secureString without a default")
    for name, value in defaults.items():
        template["parameters"][name]["defaultValue"] = value
    if set(template.get("outputs", {})) != {"operationId", "status"}:
        raise ValueError("Portal template must expose only safe operation status")

    form = json.loads((ROOT / "portal/customer-form.json").read_text())
    fields = {element["name"]: element for step in form["view"]["properties"]["steps"]
              for element in step["elements"]}
    fields["adminAllowedSources"]["defaultValue"] = ", ".join(defaults["adminAllowedSources"])
    if proof_only:
        form["view"]["properties"]["title"] = "EW-18 customer API authorization proof (no VPN gateways)"
    fields["runId"].update(defaultValue=config["runId"], visible=False)
    fields["apiClientId"].update(defaultValue=identity["customerApiClientId"])
    secret_field = fields["apiClientSecret"]
    if (secret_field.get("type") != "Microsoft.Common.PasswordBox"
            or secret_field.get("constraints", {}).get("required") is not True
            or "defaultValue" in secret_field or secret_field.get("visible") is False):
        raise ValueError("API secret must be a visible required PasswordBox with no default")
    if proof_only:
        template["parameters"]["sshPublicKey"]["defaultValue"] = ""
        fields["approveDeploymentScriptBackingException"]["label"] = (
            "I approve temporary Azure-hosted authorization proof execution and storage")
        fields["approveDeploymentScriptBackingException"]["constraints"]["validationMessage"] = (
            "Approve temporary Azure execution and backing storage to continue.")
        fields["manualSshKey"]["visible"] = False
        fields["sshCredentials"].update(visible=False, constraints={"required": False})
        fields["sshPublicKey"].update(visible=False, constraints={"required": False})
        form["view"]["outputs"]["parameters"]["sshPublicKey"] = ""
    elif config.get("workloadSshPublicKey"):
        key = public_key(config["workloadSshPublicKey"])
        fields["manualSshKey"]["visible"] = False
        fields["sshCredentials"].update(visible=False, constraints={"required": False})
        fields["sshPublicKey"].update(defaultValue=key, visible=True)
        fields["sshPublicKey"]["constraints"]["required"] = True
        form["view"]["outputs"]["parameters"]["sshPublicKey"] = "[steps('basics').sshPublicKey]"
        template["parameters"]["sshPublicKey"]["defaultValue"] = key
    exposed = set(form["view"]["outputs"]["parameters"])
    parameters = template["parameters"]
    if (exposed - set(parameters) or "apiClientSecret" not in exposed
            or any("defaultValue" not in parameters[name] for name in set(parameters) - exposed)):
        raise ValueError("Portal parameter binding is incomplete")
    metadata = {
        "configDigest": fingerprint, "customerSubscriptionId": customer["subscriptionId"],
        "resourceGroupSelection": "Customer chooses a new or dedicated existing RG in the enrolled subscription",
        "apiAuthMode": MODE, "apiAuthorityTenantId": config["provider"]["tenantId"],
        "apiClientId": identity["customerApiClientId"],
        "deploymentMode": "proof" if proof_only else "network",
        "enrollmentSource": "Approved local configuration; not proof of customer Azure ownership",
        "requiredCustomerPermissions": [
            "Owner, or Contributor plus Role Based Access Control Administrator, on the enrolled customer RG",
            "Create a user-assigned managed identity and its local resource-group role assignments",
        ],
        "distribution": "Self-contained ARM/Form files intended for provider HTTPS read-only hosting; not published",
        "prerequisites": "Customer confirms feature registration, required RG permissions and private VM update egress.",
        "templateSha256": digest(template), "formSha256": digest(form),
    }
    save_private(output / "azuredeploy.json", template)
    save_private(output / "uiFormDefinition.json", form)
    save_private(output / "profile.json", metadata)
    return metadata


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Authorized provider/admin .local configuration")
    parser.add_argument("--output", type=Path, default=ROOT / ".local/customer-portal")
    parser.add_argument("--execute", action="store_true", help="Allow provider prerequisite reads and local preparation")
    parser.add_argument("--proof-only", action="store_true", help="Prepare only the API proof; no VM/gateway prerequisites or deployment")
    parser.add_argument("--artifact-uris", help="Optional 0600 .local JSON containing published templateUri/formUri; launch URL saved privately")
    args = parser.parse_args(argv)
    config = validate_config(load_private(args.config))
    if not args.execute:
        print("DRY RUN: approved enrollment metadata checked; no cloud requests or artifacts.")
        return 0
    if not args.proof_only:
        public_key(config.get("nvaSshPublicKey", ""))
    provider = load_private(ROOT / ".local/provider-journal.json")
    identity = load_private(ROOT / ".local/provider-identity.json")
    package = package_metadata()
    if (provider.get("codePackageSha256") != package["packageSha256"]
            or provider.get("providerTemplateSha256") != package["providerTemplateSha256"]):
        raise ValueError("Configure and publish the current provider package before preparing customer deployment")
    if not args.proof_only:
        provider_feature_preflight(config)
    prepare(config, provider, identity, args.output, proof_only=args.proof_only)
    if args.artifact_uris:
        uris = load_private(args.artifact_uris)
        if set(uris) != {"templateUri", "formUri"}:
            raise ValueError("Artifact URI file must contain only templateUri and formUri")
        save_private(args.output / "launch.json", {"portalUrl": portal_link(uris["templateUri"], uris["formUri"])})
    print("Customer Portal ARM/Form prepared under .local; no deployment or publishing performed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit("Portal preparation stopped; check provider state and package pins. "
                         "No response bodies or credentials are logged.") from None
