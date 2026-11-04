# Prepared native CloudGuard/vWAN implementation

See [option 3](../archive/unvalidated-proposals/deployments/03-vwan-cloudguard/README.md) for the diagram and
qualification status. This package is **prepared only**, not a proven live
deployment and not option 4's AVNM preview integration.

## Local setup

From the repository root:

```bash
python3 scripts/setup_local.py
```

Fill ignored `.local/accounts.json`. Set the ignored package `config.json`
provider/customer `tenantId` and `subscriptionId` to those same approved values.
Configuration validation rejects mismatches; it does not silently change target
accounts.

The ignored local plan comes from `plan.example.json` only if absent. Both
`deploymentEnabled` in configuration and `executionApproved` in the plan remain
false by default. Setup does not overwrite existing approvals or state.

## Offline validation

```bash
python3 -B -m unittest discover -s cloudguard-vwan-lab -p 'test_*.py' -v
python3 -B cloudguard-vwan-lab/validate.py
```

Unit tests are independent of live account settings and use example fixtures.
The full validator requires Azure CLI/Bicep and Checkov. If Checkov is missing,
install `requirements-dev.txt` into an ignored isolated virtual environment.
The parameter-file compilation intentionally reads the ignored local
`config.json`; complete local setup first.

```bash
python3 -B cloudguard-vwan-lab/deploy.py
```

The default command only displays a local offline plan. Its output contains
your configured resource identities; do not publish it.

## Before execution

Obtain explicit cost, scope, identity and publisher-permission approval. Review
the staged execution CLI and prerequisite checks rather than changing booleans
and assuming deployment is approved.

`--preflight` queries Azure read-only; `--execute` and cleanup stages modify
resources. No preparation/validation workflow should invoke them automatically.

Publisher templates are fetched from the configured immutable public commit;
publisher-managed resources still require live support, policy and security
qualification. Region, image, SKU and licensing defaults are a reviewed lab
snapshot, not a continuing availability promise.

Run-state fingerprints bind configuration to an exact local deployment. Do not
edit them to bypass resume checks. Keep ignored results and local plans until
approved cleanup completes.
