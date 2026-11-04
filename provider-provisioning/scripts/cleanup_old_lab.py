#!/usr/bin/env python3
"""Separate old-EW18 cleanup gate. No default cloud calls; never deletes EW21 or new groups.

--read-inventory captures an exact read-only snapshot. --execute additionally
requires the exact old group, fresh matching inventory digest, expected labRun
and fresh source-preservation/denial/cutover evidence from the replacement.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
from pathlib import Path

from common import ROOT, PLAN, cli, digest, group_id, load_private, save_private, validate_config, verify_account
import json


def now():
    return datetime.now(timezone.utc)


def fresh(value: str) -> bool:
    age = now() - datetime.fromisoformat(value)
    return timedelta(0) <= age <= timedelta(hours=72)


def snapshot(context: dict, group: str) -> dict:
    resource = cli("group", "show", "--subscription", context["subscriptionId"], "--name", group)
    resources = cli("resource", "list", "--subscription", context["subscriptionId"], "--resource-group", group)
    rows = sorted(({"id": r["id"], "type": r["type"], "name": r["name"], "tags": r.get("tags") or {}}
                   for r in resources), key=lambda r: r["id"])
    return {"resourceGroupId": resource["id"], "tags": resource.get("tags") or {}, "resources": rows}


def validate_deletion(config: dict, plan: dict, saved: dict, current: dict,
                      evidence: dict, confirmed_group: str, approved_digest: str) -> str:
    old_group = plan["scope"]["oldLabGroup"]
    if confirmed_group != old_group or not old_group.startswith("rg-ravpn-"):
        raise ValueError("Only the exact planned old EW18 group can be confirmed")
    if old_group in {config[side][field] for side, fields in (
            ("provider", ("controlPlaneResourceGroup", "dataPlaneResourceGroup")),
            ("customer", ("bootstrapResourceGroup", "dataPlaneResourceGroup"))) for field in fields}:
        raise ValueError("Replacement groups are never cleanup targets")
    expected_id = group_id(config["provider"]["subscriptionId"], old_group)
    if current["resourceGroupId"].lower() != expected_id.lower():
        raise ValueError("Old group ID mismatch")
    expected_run = config.get("cleanupOldLabRun")
    if not expected_run or current["tags"].get("labRun") != expected_run:
        raise ValueError("Expected old labRun ownership was not explicitly configured")
    if current["tags"].get("purpose") != "routing-appliance-vpn-lab":
        raise ValueError("Old group does not have expected lab purpose")
    if not fresh(saved["capturedAt"]) or digest(saved["inventory"]) != approved_digest or digest(current) != approved_digest:
        raise ValueError("Inventory is stale, changed, or digest was not explicitly approved")
    if (not fresh(evidence["verifiedAt"]) or evidence.get("runId") != config["runId"]
            or evidence.get("replacementProviderGroupId") != group_id(
                config["provider"]["subscriptionId"], config["provider"]["dataPlaneResourceGroup"])
            or not all(evidence.get(k) is True for k in ("ipsecBgp", "sourcePreservation", "denialRecovery", "cutover"))):
        raise ValueError("Fresh replacement verification and cutover evidence required")
    return old_group


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--read-inventory", action="store_true", help="Read exact old group, save private inventory; no deletion")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-resource-group")
    parser.add_argument("--approve-inventory-digest")
    parser.add_argument("--cutover-evidence", help="0600 .local JSON with fresh explicit verification attestations")
    args = parser.parse_args(argv)
    if args.read_inventory and args.execute:
        parser.error("Read/approve inventory in a separate invocation before deletion")
    config = validate_config(load_private(args.config))
    plan = json.loads(PLAN.read_text())
    group = plan["scope"]["oldLabGroup"]
    if not args.read_inventory and not args.execute:
        print("DRY RUN: no cloud calls. Use --read-inventory, then separately approve exact digest/group and cutover evidence.")
        return 0
    if args.execute and not all((args.confirm_resource_group, args.approve_inventory_digest, args.cutover_evidence)):
        parser.error("--execute requires exact --confirm-resource-group, --approve-inventory-digest and --cutover-evidence")
    verify_account(config["provider"])
    current = snapshot(config["provider"], group)
    path = ROOT / ".local/old-lab-inventory.json"
    if args.read_inventory:
        save_private(path, {"capturedAt": now().isoformat(), "inventory": current})
        print("Read-only inventory saved. Approval digest: " + digest(current))
        return 0
    target = validate_deletion(config, plan, load_private(path), current, load_private(args.cutover_evidence),
                               args.confirm_resource_group, args.approve_inventory_digest)
    cli("group", "delete", "--subscription", config["provider"]["subscriptionId"], "--name", target, "--yes")
    print("Only the explicitly approved old EW18 group was deleted. No other cleanup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
