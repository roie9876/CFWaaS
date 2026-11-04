# EW-19: isolated no-Routing-Appliance experiment

**Result: no tested variant qualified as firewall inspection.**
The working EW-18 lab was retained unchanged. This experiment used a separate
resource group, addresses and keys with **four managed VPN gateways, seven VNets,
three VMs and zero Routing Appliances**. This isolated lab was deleted at the
user's request on 2026-10-22; a successful resource-group existence check
returned false. EW-18 remains present with all four gateways Succeeded.
Local test evidence is retained.

## What changed

The customer spokes selected the customer **ingress** gateway as their one
remote gateway and used `VirtualNetworkGateway` UDRs directly. The customer
delivery hub remained peered, but was not the spokes' selected remote gateway.
Provider ingress -> plain firewall -> provider delivery remained separated.
There was no customer/provider peering or VPN termination on the firewall.

## Observations

| Case | Observation | Outcome |
| --- | --- | --- |
| Native direct-gateway selection | Original-source HTTP 6/6; blocking A-to-B on the firewall still left A-to-B 3/3 and reverse 3/3 passing; zero E-W packets at the firewall | **BYPASS**, not inspection |
| Add protected VNet `/16` prefixes as remote provider-site networks | Azure rejected the update with `ConnectionOverlappingAddressSpaces`: remote `10.181.0.0/16` overlaps known local/peered `10.181.0.0/16` | **CONFIGURATION REJECTED**; no data-plane pass |
| Add only protected workload `/24` subnet prefixes | Same error: remote `10.181.0.0/24` overlaps known local/peered `10.181.0.0/16` | **CONFIGURATION REJECTED**; no data-plane pass |

The overlap failure was delivered as an async **Failed** operation under HTTP
200. HTTP acceptance was not treated as successful configuration. The rejected
prefixes remained in a Failed Local Network Gateway resource until the known-good
provider-only prefix set was restored and its Succeeded state reverified.

A transient guest-readiness gate initially stopped capture dispatch before
probes. The resume checked readiness, configured routes, managed connections
and the installed policy; it did not redeploy the lab. The completed native
bypass control and exact-prefix rejection were reused rather than replayed.

## Final disposition

These are the historical EW-19 completion checks; the subsequent EW-20 BGP
continuation below changed only this isolated lab. They describe the state
before the later experiments and the accepted deletion request, not current
retention.

- All four managed connection ends were Connected.
- Zero Routing Appliance resources were verified in the new group's inventory.
- Temporary firewall blocks were removed.
- Rejected prefixes were removed; the site resource was Succeeded with only
  provider networks in its prefix list.
- The isolated lab was retained in its native-bypass baseline for investigation,
  **not left as a qualified security path**.
- No write or peering operation targeted the retained EW-18 group; a read-only
  check confirmed that group and all four of its gateways remained present.

## Interpretation

In the working EW-18 design, source UDRs reach the appliance through ordinary
ingress-hub peering while spokes select delivery as their remote gateway.
Ingress gateway transit can stay disabled.

The tested direct-gateway substitute requires ingress gateway transit. The
ingress gateway then knows the workload prefixes locally: ordinary routing
bypasses inspection, while attempts to declare those same or more-specific
prefixes as remote provider networks were rejected.

**We did not find an appliance-free replacement for this design.** This is not
a proof that every possible Azure architecture without a Routing Appliance is
impossible. [EW-18 remains the verified working reference](../../docs/ew18-managed-vpn.md).

## EW-20: BGP continuation

BGP was configured on all four existing connection ends using the existing
distinct gateway ASNs and actual private BGP addresses. All four real BGP
neighbors and all four IPsec ends established. Static site prefixes were
retained, so this is BGP alongside static routes, not a pure dynamic replacement.

| Gateway | ASN | Advertisements to its original peer |
| --- | --- | --- |
| Customer ingress | 65120 | `172.20.0.0/16`, `10.181.0.0/16`, `10.182.0.0/16` |
| Provider ingress | 65122 | `172.22.0.0/16` |
| Customer delivery | 65121 | `172.21.0.0/16` |
| Provider delivery | 65123 | `172.23.0.0/16`, `172.24.0.0/16` |

The native BGP traffic test still **bypassed** inspection: allowed HTTP6/6;
an A-to-B block left A3/3 and reverse3/3 passing, DROP hits0, E-W capture lines0.
The temporary block was removed. BGP session establishment is not insertion.

Adding `10.180.0.0/14` to PI's existing customer-facing site did not export it
back to that customer peer or produce a learned CI route during the bounded
180-second observation. The exact prior site definition was restored.

The user then explicitly approved a temporary third IPsec link between the
two existing provider gateways, with no new VMs, VNets or gateways. Its static
remote-site aggregate supplied a **separate route origin**; it was not a third
BGP adjacency. Both temporary connection ends became Connected. PI exported
the aggregate and CI accepted it as `EBgp`, next hop `172.22.255.30`, AS path
65122. CI retained its local `Network` workload /16s alongside that /14.

**The actually learned aggregate still showed baseline bypass:** allowed HTTP6/6
preserved source while firewall E-W capture contained zero packets. The
negative-stage probe aborted before dispatch when a transient instance view
omitted VM-A's power status; **deny/recovery is not claimed for this case**.
Fresh reads found all three VMs Running. The temporary block and provider link
were removed. A learned route is not proof it is selected for the workload path.

The bounded more-specific workload `/24` continuation completed after
aggregate-link cleanup. PI's interception UDRs matched those prefixes. PI
exported both workload `/24`s, but CI accepted neither during a 241.5-second
observation. No data-plane inspection pass is claimed. The temporary link was
removed and PI's original interception routes were restored.

A later manual attempt to configure workload `/32`s on CI's remote-site object
also failed with `ConnectionOverlappingAddressSpaces`. Rollback attempts were
blocked by Azure's MFA requirement. The user subsequently requested deletion
of the entire isolated lab; its deletion was subsequently verified. The GatewaySubnet UDR
experiment was not qualified by a completed traffic test. See the
[test register](../../docs/test-register.md#ew-20-bgp-and-ingressdelivery-route-steering)
for the measured results and remaining qualifications.

Microsoft's [BGP FAQ](https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-vpn-faq#bgp)
documents that gateway transit filters exact or more-specific local/peered
VNet prefixes while allowing supersets. These tests distinguish that boundary
from BGP establishment and from a broader route actually forcing inspection.

[Full test register](../../docs/test-register.md) ·
[Failed-scenario index](README.md) · [Working README](../../README.md)
