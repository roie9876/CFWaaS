# Earlier managed Routing Appliance/VPN attempts: EW-11–16

The active `routing-appliance-vpn-lab/` source and all its run/SSH/state paths
remain in place. This moved historical narrative is not the current topology:
[EW-17 prototype results and the corrected EW-18 requirement](../../docs/test-register.md).
See the [register](../../docs/test-register.md) for the full sequence.

| Test | Changed variable | Outcome |
| --- | --- | --- |
| EW-11 | One real Routing Appliance before the customer gateway, with a provider managed gateway and GatewaySubnet steering toward Ubuntu | HTTP 6/6 even during each firewall block; zero target E-W/FORWARD traffic at Ubuntu: **BYPASS** |
| EW-12 | Vary appliance-egress route Gateway → Drop → Gateway | A-to-B traffic stopped/recovered: positive route-application control, not inspection proof |
| EW-13 | Disable ingress gateway transit and add static remote workload prefixes | 96 E-W capture lines and FORWARD activity, but matching packets returned with declining TTL and neither direction completed: **LOOP** |
| EW-14 | Add a customer GatewaySubnet endpoint-delivery table | 96 lines, declining TTL, end-to-end failure: **LOOP**, then restored |
| EW-15 | Widen provider GatewaySubnet interception from endpoint host routes to VNet prefixes | 96 lines and end-to-end failure: **LOOP**, then restored |
| EW-16 | User-requested retained replay of EW-14 for capture visibility | 48 capture lines per direction, TTL 8 through 3, no ping/HTTP completion: **LOOP**, intentionally retained at that checkpoint |

EW-16 superseded an earlier restoration record **at that time**; final EW-17
retention supersedes EW-16 now. Original raw results and restoration manifests
remain immutable. The capture did not localize the exact internal Azure lookup;
it does not prove the recirculation was inside the managed Routing Appliance.

EW-17 changed the architecture: two distinct **customer** gateway/RIB roles,
direct firewall tunnel termination and a separate delivery hub. It did not merely
repeat the same gateway with another tunnel. Its approved recovery attempts,
local DNS interruption, final bounded fault tests and retained state are
documented in the continuing register, not counted as additional architectures.
