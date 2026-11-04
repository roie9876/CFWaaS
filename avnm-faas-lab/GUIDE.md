# AVNM direct-peering simulator implementation

See [option 2](../deployments/02-direct-peering-avnm/README.md) for the diagram,
ownership model and evidence boundaries.

## Local setup

From the repository root:

```bash
python3 scripts/setup_local.py
```

Fill the ignored `.local/accounts.json` using your approved provider/customer
tenant and subscription IDs. Alternatively set `FAAS_ACCOUNT_PROFILE` to an
explicit local profile with the same `A`/`B` structure. The profile is required
when resolving account scope or acquiring tokens; no personal defaults ship.

Setup creates missing ignored `config.json` and
`.azure/infrastructure-plan.json` from the example files without overwriting
anything. The example plan is draft and execution-disabled. A real deployment
needs a reviewed plan, explicit scope/cost approval and the CLI execution flag.

Do not alter a retained run's account profile, configuration, approval plan or
results. Resume checks the selected subscriptions against both recorded groups
before constructing the controller or saving state. New runs also record tenant
pins; older retained runs additionally validate recorded customer consent when
available.

## Offline validation

```bash
python3 -B -m unittest discover -s avnm-faas-lab -p 'test_*.py' -v
python3 -B avnm-faas-lab/validate.py
```

Unit tests use synthetic accounts and examples, not private local config.
The full validator additionally requires Azure CLI/Bicep and a local Checkov
installation, discovered in the sibling isolated tool environment or on PATH.
It compiles/scans locally and does not deploy.

The no-argument entrypoint is an offline plan display:

```bash
python3 -B avnm-faas-lab/avnm_lab.py
```

Its local plan metadata can contain private operational information; do not
commit or upload its output.

## Safety and limitations

- The lab is intentionally fixed at two groups of three workload VNets.
- Ubuntu simulates forwarding/filtering; it is not Check Point CloudGuard.
- `--execute`, `--resume-run` and `--cleanup-run` are live-cloud operations.
  Cleanup additionally requires `--confirm-cleanup` and fresh authorization.
- Shared helpers remain in the sibling `cross-tenant-nic-lab` directory for
  compatibility. No historical failed vWAN deployment module is required.
- Keep network and VM deployments separate so a compute redeployment cannot
  wipe AVNM-populated route tables.
- Host encryption/VM extensions have explicit lab scanner exceptions. Read
  `.checkov.yml`; they are not blanket production recommendations.
- Local `README.md`, `REPORT.md`, `.azure/` and `results/` may retain private
  historical evidence and are deliberately not published.
