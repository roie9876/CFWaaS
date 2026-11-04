# Prepared or never-run proposals

These entries are **not failed live tests**. They lack end-to-end runtime
qualification. They are separated from both the
[working scenarios](../../README.md) and [executed failures](../failed-scenarios/README.md).

| Former guide path | New guide | Actual evidence level |
| --- | --- | --- |
| `deployments/01-direct-peering-controller/` | [Own-controller direct peering](deployments/01-direct-peering-controller/README.md) | Documented dataplane matches the proven AVNM pattern; replacement controller never implemented |
| `deployments/03-vwan-cloudguard/` | [Native CloudGuard/vWAN](deployments/03-vwan-cloudguard/README.md) | Prepared automation; never deployed or traffic-tested |
| `deployments/04-vwan-avnm-preview/` | [CloudGuard/vWAN + AVNM](deployments/04-vwan-avnm-preview/README.md) | Unimplemented preview combination; no runtime result |
| `deployments/05-vwan-indirect-spokes/` | [Indirect customer spokes](deployments/05-vwan-indirect-spokes/README.md) | Documented architecture; this cross-tenant variant was never deployed/tested |

The [prepared CloudGuard source package](../../cloudguard-vwan-lab/GUIDE.md)
remains at its existing path, with its local tool environment and approvals
unchanged. It is preparation material, **not a failed or proven deployment**.
Offline tests do not authorize executing it.

The six original option numbers and their
[reference drawings](../../docs/diagrams/README.md) are retained as stable
historical identifiers. Option 2 is the successful AVNM reference and remains
under `deployments/`; option 6 moved into the executed-failure archive.
