#!/usr/bin/env python3
"""Customer-UAMI runtime on Azure, not a laptop human-token substitute.

Dry-run validates locally. --execute uses ManagedIdentityCredential(client_id=...)
only. Network mode polls the API then deploys customer connections using that
same customer's narrowly scoped ARM identity. Secrets remain in memory.
"""
from __future__ import annotations
import argparse
import json
import logging
import time
import urllib.parse
import urllib.request
import uuid

from common import ROOT, config_digest, group_id, load_private, save_private, validate_config


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def api_origin(value: str) -> str:
    parts = urllib.parse.urlsplit(value)
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or parts.path not in ("", "/") or parts.query or parts.fragment or parts.port not in (None, 443)):
        raise ValueError("Expected an HTTPS API origin, not a path or credential-bearing URL")
    return value.rstrip("/")


def request(credential, url: str, resource: str, path: str, body=None, key: str | None = None):
    token = credential.get_token(resource.rstrip("/") + "/.default").token
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    if key:
        headers["Idempotency-Key"] = key
    req = urllib.request.Request(url + path, headers=headers,
                                 data=None if body is None else json.dumps(body).encode())
    with urllib.request.build_opener(NoRedirect).open(req, timeout=60) as response:
        return json.load(response)


def poll(credential, url: str, resource: str, operation: dict, wait_seconds: int) -> dict:
    operation_id = str(uuid.UUID(operation["operationId"]))
    deadline = time.monotonic() + wait_seconds
    while operation["status"] not in ("Ready", "Failed", "NeedsAttention"):
        if time.monotonic() >= deadline:
            raise TimeoutError("Bounded wait expired; operation ID is saved for resume")
        time.sleep(10)
        operation = request(credential, url, resource, "/v1/operations/" + operation_id)
    if operation["status"] != "Ready":
        raise RuntimeError("Provider operation did not become Ready; inspect redacted operation status")
    return operation


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--mode", choices=("proof", "network"), default="proof")
    parser.add_argument("--wait-seconds", type=int, default=6900)
    parser.add_argument("--operation-id", help="Resume an existing owner-bound operation")
    parser.add_argument("--execute", action="store_true", help="Run on Azure as the customer UAMI; never falls back to a human token")
    args = parser.parse_args(argv)
    config = validate_config(load_private(args.config))
    if not 60 <= args.wait_seconds <= 6900:
        raise ValueError("Wait must be 60..6900 seconds")
    if args.operation_id:
        uuid.UUID(args.operation_id)
    if not args.execute:
        print(f"DRY RUN customer {args.mode}: no token acquisition, network requests or ARM writes.")
        return 0
    from azure.identity import ManagedIdentityCredential
    from azure.mgmt.resource import ResourceManagementClient

    logging.getLogger("azure").setLevel(logging.WARNING)
    journal = load_private(ROOT / ".local/bootstrap-journal.json")
    identities = load_private(ROOT / ".local/identity-journal.json")
    if journal["configDigest"] != config_digest(config) or identities["configDigest"] != config_digest(config):
        raise ValueError("Private journals do not belong to this exact approved configuration")
    customer = config["customer"]
    url = api_origin(journal["controlPlane"]["apiUrl"])
    resource = identities["apiResource"]
    if resource != "api://" + identities["apiApplicationId"]:
        raise ValueError("API token resource differs from bootstrapped application ID")
    if (args.mode == "network"
            and journal.get("customerConnectorScope") != group_id(
                customer["subscriptionId"], customer["dataPlaneResourceGroup"])):
        raise ValueError("Customer connector scope was not explicitly bootstrapped")
    with ManagedIdentityCredential(client_id=identities["customerClientId"]) as credential:
        if args.operation_id:
            operation = request(credential, url, resource, "/v1/operations/" + args.operation_id)
        else:
            body = {"mode": args.mode, "region": "eastus2", "tier": "lab"}
            if args.mode == "network":
                if journal.get("proof", {}).get("status") != "Ready":
                    raise ValueError("Complete customer managed-identity proof before network provisioning")
                body.update(journal["customerFoundation"]["customerEndpoints"])
            operation = request(credential, url, resource, "/v1/environments", body,
                                key=config["runId"] + "-" + args.mode)
        operation_id = str(uuid.UUID(operation["operationId"]))
        state_path = ROOT / ".local/customer-operation.json"
        save_private(state_path, {"operationId": operation_id, "mode": args.mode})
        operation = poll(credential, url, resource, operation, args.wait_seconds)
        if args.mode == "proof":
            journal["proof"] = {"operationId": operation_id, "status": "Ready"}
            save_private(ROOT / ".local/bootstrap-journal.json", journal)
            print("Customer-UAMI API proof Ready; no customer ARM deployment performed.")
            return 0
        material = request(credential, url, resource, "/v1/environments/" + operation_id + "/connection-material")
        if material.get("environmentId") != operation_id or set(material) != {"environmentId", "ingressSharedKey", "deliverySharedKey"}:
            raise ValueError("Unexpected connection material response")
        template = load_private(ROOT / ".local/customer-connections.json")
        parameters = {"runId": config["runId"], "providerManifest": operation["connectionManifest"],
                      "ingressSharedKey": material["ingressSharedKey"], "deliverySharedKey": material["deliverySharedKey"]}
        with ResourceManagementClient(credential, customer["subscriptionId"]) as arm:
            group = arm.resource_groups.get(customer["dataPlaneResourceGroup"])
            if (group.id.lower() != group_id(customer["subscriptionId"], customer["dataPlaneResourceGroup"]).lower()
                    or (group.tags or {}).get("labRun") != config["runId"]
                    or (group.tags or {}).get("purpose") != "provider-provisioning"):
                raise ValueError("Customer resource group ownership mismatch")
            deployment = arm.deployments.begin_create_or_update(
                customer["dataPlaneResourceGroup"], "customer-connections-" + operation_id,
                {"properties": {"mode": "Incremental", "template": template,
                                "parameters": {key: {"value": value} for key, value in parameters.items()}}})
            deployment.result(timeout=args.wait_seconds)
        save_private(state_path, {"operationId": operation_id, "mode": args.mode, "customerConnections": "Succeeded"})
    print("Customer connections deployed by customer UAMI; no shared keys saved or output.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        # SDK/HTTP exceptions may contain secure parameter bodies. Never echo them.
        raise SystemExit("Customer run stopped. Inspect private operation ID and redacted provider status; no credential fallback.") from None
