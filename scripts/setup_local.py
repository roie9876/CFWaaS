#!/usr/bin/env python3
"""Create ignored local templates without overwriting approvals or run state."""

import argparse
import json
import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def write_new(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(payload, stream, indent=2)
        stream.write("\n")


def preserve_accounts():
    source = ROOT / "cloudguard-vwan-lab/config.json"
    if not source.is_file():
        raise RuntimeError("No existing local CloudGuard configuration to preserve")
    settings = json.loads(source.read_text())
    accounts = {
        label: {
            "tenant": settings[role]["tenantId"],
            "subscription": settings[role]["subscriptionId"],
        }
        for label, role in (("A", "provider"), ("B", "customer"))
    }
    for entry in accounts.values():
        for value in entry.values():
            if not isinstance(value, str) or str(uuid.UUID(value)) != value or uuid.UUID(value).int == 0:
                raise ValueError("Existing configuration does not contain canonical account identities")
    if accounts["A"]["tenant"] == accounts["B"]["tenant"] or (
        accounts["A"]["subscription"] == accounts["B"]["subscription"]
    ):
        raise ValueError("Existing cross-tenant account scopes are not distinct")
    return accounts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preserve-existing-accounts", action="store_true",
                        help="Migrate existing local CloudGuard account selection; never print it")
    args = parser.parse_args()
    profile = ROOT / ".local/accounts.json"
    if args.preserve_existing_accounts and profile.exists():
        raise RuntimeError("Local account profile already exists; refusing to replace it")
    if not profile.exists():
        accounts = preserve_accounts() if args.preserve_existing_accounts else json.loads(
            (ROOT / "accounts.example.json").read_text(),
        )
        write_new(profile, accounts)
        print("Created ignored account profile; review/fill it locally before cloud operations.")
    for package in ("avnm-faas-lab", "cloudguard-vwan-lab"):
        for example, local in (
            ("config.example.json", "config.json"),
            ("plan.example.json", ".azure/infrastructure-plan.json"),
        ):
            target = ROOT / package / local
            if not target.exists():
                write_new(target, json.loads((ROOT / package / example).read_text()))
                print("Created ignored local template:", package + "/" + local)
    print("Existing local files retained. No cloud calls, deployments or approval changes.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print("ERROR:", error, file=sys.stderr)
        sys.exit(1)
