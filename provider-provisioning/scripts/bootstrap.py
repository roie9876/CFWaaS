#!/usr/bin/env python3
"""Approved-scope bootstrap/deploy phases; default is offline validation, never cloud writes.

Sequence: groups, customer-identity, bootstrap_identity.py provider/customer,
package_apps.py, control-plane, code-deploy, customer-proof, customer-foundation,
customer-connector-role, customer-network. Both connector phases run as the customer
UAMI inside Bicep-triggered deploymentScripts; no pre-existing customer VM is needed.

Privileges required separately: provider operator needs resource deployment plus
roleAssignments/write on the control-plane resources and the one provider RG;
customer operator needs resource deployment, UAMI assignment, deploymentScripts
ACI/storage creation, and roleAssignments/write on the one customer network RG.
Graph registration/app-role consent requires an already-authorized directory
administrator in each corresponding tenant, not merely an Azure subscription Owner.
Code publishing needs Microsoft.Web/sites/publish/action and SCM /32 reachability.
No runtime identity receives role-assignment authority or cross-tenant Azure RBAC.
No live scope, IPsec/BGP, source-preservation or cutover result is claimed.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess

from common import (ROOT, cli, compile_bicep, config_digest, customer_sizing, group_id, load_private,
                    operator_cidr, public_key, save_private, validate_config, verify_account)
from customer_connector import canonical_uuid, validate_connection_template

PHASES = ("groups", "customer-identity", "control-plane", "code-deploy",
          "customer-proof", "customer-foundation", "customer-connector-role", "customer-network", "validate-local")
PURPOSE = "provider-provisioning"


def assert_owned_group(context: dict, group: str, run_id: str) -> dict:
    resource = cli("group", "show", "--subscription", context["subscriptionId"], "--name", group)
    if resource.get("id", "").lower() != group_id(context["subscriptionId"], group).lower():
        raise ValueError("Unexpected resource group ID")
    tags = resource.get("tags") or {}
    if tags.get("labRun") != run_id or tags.get("purpose") != PURPOSE:
        raise ValueError("Resource group ownership tags do not match this exact run")
    return resource


def groups(config: dict, journal: dict, path: Path):
    for side, fields, location in (
        ("provider", ("controlPlaneResourceGroup", "dataPlaneResourceGroup"), "centralus"),
        ("customer", ("bootstrapResourceGroup", "dataPlaneResourceGroup"), "eastus2"),
    ):
        context = config[side]
        verify_account(context)
        for field in fields:
            group = context[field]
            exists = cli("group", "exists", "--subscription", context["subscriptionId"], "--name", group)
            if exists:
                assert_owned_group(context, group, config["runId"])
                continue
            resource = cli("group", "create", "--subscription", context["subscriptionId"], "--name", group,
                           "--location", "eastus2" if field == "dataPlaneResourceGroup" else location,
                           "--tags", f"purpose={PURPOSE}", f"labRun={config['runId']}")
            journal.setdefault("createdResourceGroups", []).append(resource["id"])
            save_private(path, journal)


def deploy(context: dict, group: str, template: str, parameters: dict, run_id: str) -> dict:
    assert_owned_group(context, group, run_id)
    name = "faas-" + template.removesuffix(".bicep")
    file = ROOT / ".local" / f"{name}.parameters.json"
    save_private(file, {"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
                        "contentVersion": "1.0.0.0", "parameters": {k: {"value": v} for k, v in parameters.items()}})
    return cli("deployment", "group", "create", "--subscription", context["subscriptionId"],
               "--resource-group", group, "--name", name,
               "--template-file", str(ROOT / "infra" / template), "--parameters", "@" + str(file))


def outputs(result: dict) -> dict:
    return {name: item["value"] for name, item in result["properties"]["outputs"].items()}


def connector_result(result: dict) -> dict:
    if set(result) != {"operationId", "status"} or result["status"] != "Ready":
        raise ValueError("Unexpected connector result; refusing ordinary secret-bearing outputs")
    return {"operationId": canonical_uuid(result["operationId"]), "status": "Ready"}


def encryption_preflight(config: dict) -> None:
    unregistered = []
    for side in ("provider", "customer"):
        context = config[side]
        verify_account(context)
        feature = cli("feature", "show", "--subscription", context["subscriptionId"],
                      "--namespace", "Microsoft.Compute", "--name", "EncryptionAtHost")
        if feature.get("properties", {}).get("state") != "Registered":
            unregistered.append(side)
    if unregistered:
        raise ValueError(", ".join(unregistered) + " EncryptionAtHost feature must already be Registered before networking. No registration or policy change was attempted.")


def validate_runtime(config: dict, phase: str, args) -> None:
    if phase == "control-plane":
        if not args.approve_scm_bootstrap_exception:
            raise ValueError("Control plane requires --approve-scm-bootstrap-exception; see worker SCM exposure exception")
        operator_cidr(config["deploymentOperatorCidr"])
        if config.get("nvaSshPublicKey"):
            public_key(config["nvaSshPublicKey"])
    elif phase == "customer-foundation":
        public_key(config.get("nvaSshPublicKey", ""))
        public_key(config["workloadSshPublicKey"])
    elif phase in ("customer-proof", "customer-network") and not args.approve_script_backing_exception:
        raise ValueError("Customer connector requires --approve-script-backing-exception for transient shared-key ACI storage")


def run_phase(config: dict, phase: str, journal: dict, path: Path, args) -> None:
    provider, customer = config["provider"], config["customer"]
    if phase == "groups":
        groups(config, journal, path)
        return
    side = "provider" if phase in ("control-plane", "code-deploy") else "customer"
    context = config[side]
    verify_account(context)
    identity_journal = load_private(ROOT / ".local/identity-journal.json") if phase in (
        "control-plane", "customer-proof", "customer-connector-role", "customer-network") else {}
    if identity_journal and identity_journal.get("configDigest") != config_digest(config):
        raise ValueError("Identity journal belongs to a different exact configuration")
    if phase == "customer-identity":
        result = deploy(customer, customer["bootstrapResourceGroup"], "customer-identity.bicep",
                        {"runId": config["runId"], "identityName": config["customerIdentityName"]}, config["runId"])
        journal["customerIdentity"] = outputs(result)
    elif phase == "control-plane":
        assert_owned_group(provider, provider["dataPlaneResourceGroup"], config["runId"])
        metadata = load_private(ROOT / ".local/apps.metadata.json")
        result = deploy(provider, provider["controlPlaneResourceGroup"], "main.bicep", {
            "runId": config["runId"], "namePrefix": config["namePrefix"],
            "providerDataPlaneResourceGroupId": group_id(provider["subscriptionId"], provider["dataPlaneResourceGroup"]),
            "trustedTenantId": customer["tenantId"],
            "trustedPrincipalId": identity_journal["customerPrincipalId"],
            "trustedClientId": identity_journal["customerClientId"],
            "apiAudience": identity_journal["apiAudience"],
            "nvaSshPublicKey": config.get("nvaSshPublicKey", ""),
            "providerTemplateSha256": metadata["providerTemplateSha256"],
            "approveScmBootstrapException": True,
            "deploymentOperatorCidr": config["deploymentOperatorCidr"],
        }, config["runId"])
        journal["controlPlane"] = outputs(result)
        journal["providerTemplateSha256"] = metadata["providerTemplateSha256"]
        journal["scmBootstrapException"] = {"operatorCidr": config["deploymentOperatorCidr"],
                                          "workerSite": "DenyAll", "scmBasicAuth": False}
    elif phase == "code-deploy":
        assert_owned_group(provider, provider["controlPlaneResourceGroup"], config["runId"])
        version = cli("version")["azure-cli"]
        if tuple(int(v) for v in version.split(".")[:3]) < (2, 48, 1):
            raise ValueError("Azure CLI >=2.48.1 is required for Entra deploy with basic auth disabled")
        metadata = load_private(ROOT / ".local/apps.metadata.json")
        if metadata["providerTemplateSha256"] != journal.get("providerTemplateSha256"):
            raise ValueError("Re-deploy control-plane configuration with the new provider template hash before publishing code")
        package = Path(metadata["packagePath"]).resolve()
        if not package.is_relative_to(ROOT / ".local") or hashlib.sha256(package.read_bytes()).hexdigest() != metadata["packageSha256"]:
            raise ValueError("Deployment ZIP digest differs from locally built artifact")
        for mode in ("api", "worker"):
            app = journal["controlPlane"][mode + "AppName"]
            policy = cli("resource", "show", "--subscription", provider["subscriptionId"],
                         "--ids", group_id(provider["subscriptionId"], provider["controlPlaneResourceGroup"])
                         + f"/providers/Microsoft.Web/sites/{app}/basicPublishingCredentialsPolicies/scm",
                         "--api-version", "2023-12-01")
            if policy.get("properties", {}).get("allow") is not False:
                raise ValueError("SCM basic publishing must remain disabled; no password fallback")
            cli("webapp", "deploy", "--subscription", provider["subscriptionId"],
                "--resource-group", provider["controlPlaneResourceGroup"], "--name", app,
                "--src-path", str(package), "--type", "zip", "--track-status", "false", "--timeout", "600000")
        journal["codePackageSha256"] = metadata["packageSha256"]
    elif phase == "customer-proof":
        identity = journal["customerIdentity"]
        result = deploy(customer, customer["bootstrapResourceGroup"], "customer-proof.bicep", {
            "runId": config["runId"], "customerIdentityId": identity["identityId"],
            "customerIdentityClientId": identity["clientId"],
            "apiUrl": journal["controlPlane"]["apiUrl"], "apiResource": identity_journal["apiResource"],
            "approveDeploymentScriptBackingException": True,
        }, config["runId"])
        journal["proof"] = connector_result(outputs(result)["proofResult"])
    elif phase == "customer-foundation":
        if journal.get("proof", {}).get("status") != "Ready":
            raise ValueError("Customer managed-identity proof must complete before expensive networking")
        encryption_preflight(config)
        result = deploy(customer, customer["dataPlaneResourceGroup"], "customer-foundation.bicep",
                        {"runId": config["runId"], "sshPublicKey": config["workloadSshPublicKey"],
                         **customer_sizing(config)}, config["runId"])
        journal["customerFoundation"] = outputs(result)
    elif phase == "customer-connector-role":
        deploy(customer, customer["dataPlaneResourceGroup"], "customer-connector-role.bicep",
               {"principalId": identity_journal["customerPrincipalId"]}, config["runId"])
        journal["customerConnectorScope"] = group_id(customer["subscriptionId"], customer["dataPlaneResourceGroup"])
    elif phase == "customer-network":
        if journal.get("proof", {}).get("status") != "Ready" or not journal.get("customerFoundation"):
            raise ValueError("Customer network requires completed managed-identity proof and foundation")
        if journal.get("customerConnectorScope") != group_id(customer["subscriptionId"], customer["dataPlaneResourceGroup"]):
            raise ValueError("Customer network connector role must be explicitly bootstrapped on the exact customer group")
        template = load_private(ROOT / ".local/customer-connections.json")
        validate_connection_template(template)
        identity = journal["customerIdentity"]
        result = deploy(customer, customer["bootstrapResourceGroup"], "customer-network.bicep", {
            "runId": config["runId"], "customerIdentityId": identity["identityId"],
            "customerIdentityClientId": identity["clientId"],
            "customerTenantId": customer["tenantId"], "customerSubscriptionId": customer["subscriptionId"],
            "customerResourceGroup": customer["dataPlaneResourceGroup"],
            "customerEndpoints": journal["customerFoundation"]["customerEndpoints"],
            "customerConnectionsTemplate": template,
            "apiUrl": journal["controlPlane"]["apiUrl"], "apiResource": identity_journal["apiResource"],
            "approveDeploymentScriptBackingException": True,
        }, config["runId"])
        journal["networkResult"] = connector_result(outputs(result)["networkResult"])
    save_private(path, journal)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=PHASES)
    parser.add_argument("--config", help="Private .local JSON. See scripts/config.example.json")
    parser.add_argument("--execute", action="store_true", help="Authorize the selected phase only; otherwise offline dry-run")
    parser.add_argument("--approve-scm-bootstrap-exception", action="store_true")
    parser.add_argument("--approve-script-backing-exception", action="store_true")
    args = parser.parse_args(argv)
    if args.phase == "validate-local":
        for template in sorted((ROOT / "infra").rglob("*.bicep")):
            compile_bicep(str(template.relative_to(ROOT / "infra")))
        print("All Bicep files compiled locally; no Azure deployment.")
        return 0
    if not args.config:
        parser.error("--config is required for bootstrap phases")
    config = validate_config(load_private(args.config))
    if not args.execute:
        print(f"DRY RUN {args.phase}: approved exact scopes checked. No Azure calls or changes.")
        if args.phase == "control-plane":
            print("Execution requires explicit worker SCM operator-/32 + Entra-only management exception.")
        if args.phase in ("customer-proof", "customer-network"):
            print("Execution requires separate transient deploymentScripts shared-key backing-storage exception.")
        return 0
    validate_runtime(config, args.phase, args)
    path = ROOT / ".local/bootstrap-journal.json"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        journal = load_private(path) if path.exists() else {"configDigest": config_digest(config)}
        if journal["configDigest"] != config_digest(config):
            raise ValueError("Ownership journal belongs to another exact configuration")
        run_phase(config, args.phase, journal, path, args)
    print(f"Completed {args.phase}; private ownership journal updated. No cleanup performed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, subprocess.CalledProcessError) as exc:
        raise SystemExit("Bootstrap stopped: " + str(exc)) from None
