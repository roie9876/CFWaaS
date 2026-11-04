# Passed prototype archive

These prototypes passed their recorded packet tests; they are **not failed
scenarios** and are **not active deployment candidates**. Historical
measurements and qualification limits are preserved.

- [EW-17: firewall-terminated IPsec](ew17-firewall-terminated-ipsec.md):
  passed packet tests but did not meet the clarified firewall-only requirement.
- [EW-21: Ubuntu/WireGuard overlay](ew21-ubuntu-overlay.md):
  archived by user decision on 2026-10-26, not a deployment candidate.
  The guide preserves measurements, recovery findings, independence caveats
  and historical SSH commands; [SVG](ew21-ubuntu-overlay.svg) and
  [editable Draw.io](ew21-ubuntu-overlay.drawio) preserve its topology.

**Repository archiving does not delete Azure resources.** No cloud cleanup,
runtime/key changes or private-controller relocation is implied by this index.
Environment-bound controllers, evidence and access material remain private/local.

[Active EW-18 guide](../../docs/ew18-managed-vpn.md) ·
[Repository README](../../README.md)
