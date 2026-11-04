# Failed scenarios and historical investigations

These are **executed historical experiments**, not deployment recommendations.
Old cloud labs were deleted with approval. Do not execute these controllers
against old inventories or treat a connected tunnel as inspection proof.
The [working-first README](../../README.md) describes current EW-18 and proven
historical references. The [test register](../../docs/test-register.md) preserves
the full experiment sequence and distinguishes aborts from dataplane results.

## What moved, and why

[EW-19: isolated no-Routing-Appliance test](ew19-no-routing-appliance.md) is a
later retained experiment: native gateway steering bypassed the firewall;
remote full-VNet and subnet prefix variants were rejected for overlap. Its
new lab is separate from and does not modify the working EW-18 control.

| Former path | Archive path | Test IDs | Observed outcome / reason |
| --- | --- | --- | --- |
| `vwan-faas-lab/` | `archive/failed-scenarios/vwan-faas-lab/` | EW-01 | Ordinary third-direct-spoke NVA insertion recirculated with declining TTL; not the managed Routing Appliance product |
| `cross-tenant-nic-lab/` | [cross-tenant-nic-lab/](cross-tenant-nic-lab/GUIDE.md) | AUTH-01–04 | Unrelated auxiliary identities rejected; a shared multitenant identity passed authorization only; foreign NIC/subnet placement still rejected |
| `ipsec-vwan-lab/` | [ipsec-vwan-lab/](ipsec-vwan-lab/GUIDE.md) | EW-03–06 | Static overlap rejected; default-only BGP and per-VNet-table variants did not deliver target E-W traffic to the firewall |
| `classic-gateway-lab/` | `archive/failed-scenarios/classic-gateway-lab/` | EW-08–10 | Baseline no delivery; gateway UDRs restored connectivity but bypassed inspection; remote-private-IP next hop produced effective Drop |
| `deployments/06-customer-vwan-ipsec/` | [deployments/06-customer-vwan-ipsec/](deployments/06-customer-vwan-ipsec/README.md) | EW-03–06 | Failed deployment guide moved with the experiment; not a working scenario |
| Earlier sections of active managed-lab guide | [routing-appliance-vpn-history.md](routing-appliance-vpn-history.md) | EW-11–16 | Initial bypass and later capture-visible loops; superseded by EW-17, not rewritten as passing attempts |

Only historical source/docs/results are relocated. Root `.azure/`, `.local/`,
VS Code tasks and the **entire active `routing-appliance-vpn-lab/` run tree,
SSH keys/configuration and known-host files stay in place**. Historical
package-local `.azure/` approval records also stay at their original paths.
Local-only state/tool directories at old package paths are not duplicate source
packages and are not published.

## Preserved evidence and recovery paths

Raw historical `results/` trees moved with the corresponding old scenario.
Their bytes, saved manifests and embedded absolute/relative paths were **not
rewritten**. For any saved path beginning with a former package path above,
prefix it with `archive/failed-scenarios/` when locating the moved evidence.
An original `ipsec-vwan-lab/results/.../result.json`, for example, is now
`archive/failed-scenarios/ipsec-vwan-lab/results/.../result.json`.
These files remain private and ignored.

This is a filesystem migration map, not permission to resume deleted labs.
Existing archived approval files, where needed for historical analysis, are at
the original package-local `.azure/` path. New execution would require a fresh
reviewed plan; no historical result or approval is renewed by this move.

## Shared helpers are still real dependencies

The active lab and historical references import actual source from the archive:

- `classic-gateway-lab/gateway_lab.py`: VPN/ARM helpers and local validation.
- `ipsec-vwan-lab/ipsec_lab.py` and `ipsec_guest.py`: evidence transport and guests.
- `cross-tenant-nic-lab/lab.py` and `guest_tools.py`: account profiles, ARM
  operations and framed probes.

Consumers resolve the repository root explicitly and use these new paths.
Default account selection still reads **root** `.local/accounts.json`;
active managed-lab plan paths still resolve under **root** `.azure/`.
Archived controller CLIs are historical, not deployment entry points.
No old-path symlinks, empty import stubs or duplicate compatibility packages
mask a missing dependency.

## Not failed tests

- [EW-02 AVNM direct peering](../../deployments/02-direct-peering-avnm/README.md)
  passed its Ubuntu forwarding/isolation acceptance and remains a working
  historical reference.
- [EW-07 native Azure Firewall](../../docs/final-summary.md#5-what-native-routing-intent-did-differently)
  passed native secured-vWAN inspection; it is not external Check Point insertion.
- [Prepared/unvalidated proposals](../unvalidated-proposals/README.md) were never
  run as complete architectures. Service Association Link writes were NOT RUN;
  authorization success alone did not validate foreign-resource placement.
- [EW-17](../prototypes/ew17-firewall-terminated-ipsec.md) passed its bounded
  packet tests but ran VPN on Ubuntu, contrary to the clarified requirement.
  It is preserved as a prototype, not mislabeled failed or the current target.
  EW-18 subsequently passed with all IPsec on managed gateways.
