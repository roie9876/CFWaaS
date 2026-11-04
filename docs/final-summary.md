# Final research summary: Azure E-W traffic inspection

**Historical snapshot through 2026-10-20.** A separately approved managed Routing
Appliance/VPN experiment started on 2026-10-21; see the
[current working EW-18 configuration](ew18-managed-vpn.md)
for its final passing/retained status with managed VPN termination.
The cleanup and conclusions below concern the earlier recorded labs.
The continuing [test register](test-register.md) includes the later managed
Routing Appliance trials, superseded loop-demo state, EW-17 prototype acceptance
and the requirement-compliant EW-18 result.
Consult it before repeating an experiment. The failed source packages and
never-run proposals now have [separate archive indexes](../archive/failed-scenarios/README.md).

**Research date:** 2026-10-20

**Disposition:** research and disposable labs, not a production-qualified product.

**Cleanup:** complete. All 12 recorded lab resource groups across the two approved
subscriptions were verified absent; the final group's fresh ARM request returned
`404 ResourceGroupNotFound`. Shared/pre-existing resources and private local
evidence were preserved.

## Executive conclusion

We found two working inspection mechanisms, but neither establishes the complete
original no-provider-peering Check Point service:

1. **Direct cross-tenant VNet peering plus workload UDRs worked with Ubuntu
   firewall simulators.** AVNM successfully automated connectivity and routing
   for two isolated customer environments. This retains a physical peering
   relationship to each participating workload VNet.
2. **Native secured vWAN plus Azure Firewall and Private Routing Intent worked.**
   It demonstrated managed pre-/post-inspection routing in a single-tenant
   reference, not arbitrary external-NVA insertion.
3. **The tested external VPN firewall approaches did not achieve mandatory E-W
   inspection.** Established IPsec/BGP, successful firewall-own-IP access, and
   successful workload connectivity were all insufficient evidence.

**We did not prove a design that simultaneously keeps the customer hub in the
customer tenant, firewall compute in the provider tenant, avoids customer/provider
VNet peering and customer routing VMs, and forces both E-W directions through an
arbitrary remote Check Point firewall.** Real Check Point software was not
deployed or qualified.

## What we were trying to build

The target was a provider-operated Firewall-as-a-Service:

- Provider tenant **A** owns and operates the firewall deployment.
- Customer tenants **B/C/D** retain their workload VNets and, for the later
  hub-based proposals, their customer-side hub.
- Traffic between customer workload VNets must traverse the assigned firewall
  in both directions, preserve original private source addresses, and avoid
  bypass or recirculation.
- Separate customers/environments may reuse address ranges without mixing
  traffic. The isolation unit is **customer + environment + region**, not just
  customer. The discussed estate was up to 200 environments per customer, with
  roughly 10-200 VNets and a dedicated firewall deployment per environment.
- Minimize manual onboarding/routing work; prefer no customer/provider peering
  and no customer-side routing VM. Customer-internal hub/spoke peering was allowed.
- Ubuntu was explicitly permitted as the routing/filtering emulator.

The wider service discussion included N-S traffic, management, HA and scale.
The decisive experiments summarized here concern **private IPv4 inter-VNet E-W
inspection**; they do not qualify the whole service.

## Experiment ledger

| Experiment | Measured finding | What it establishes |
| --- | --- | --- |
| VM in A with NIC/subnet in B, using auxiliary ARM authorization | Shared-app cross-tenant authentication worked, but foreign NIC/subnet placement was rejected | Authorization does not override resource-placement constraints |
| Ordinary vWAN, two direct workload spokes, ordinary NVA in a third direct spoke | Packet recirculation with declining TTL; E-W inspection failed | This specific third-spoke inter-VNet inspection pattern is explicitly unsupported in Microsoft documentation |
| Direct cross-tenant peering + AVNM-managed UDRs | 150 HTTP + 30 ICMP checks passed across forwarding, selective blocking, restoration and environment isolation | A working cross-tenant dataplane with Ubuntu, subject to physical peering and production qualification |
| Customer vWAN to external Ubuntu over IPsec/BGP | Both tunnel/BGP pairs established; E-W probes failed and target E-W packets did not reach the firewall | A healthy VPN/control plane did not produce the intended inspection path |
| Separate inspection table per vWAN workload, then propagation repair | Native baseline 6/6 HTTP and 6/6 ICMP; inspected attempts 0/6 HTTP and 0/6 ICMP, while provider controls passed 8/8 | Splitting route tables and repairing propagation did not fix the tested external-VPN E-W path |
| Native secured vWAN + Azure Firewall + Private Routing Intent | Inspected HTTP 10/10; selective deny blocked 3/3 A-to-B while allowing 3/3 B-to-A; restored HTTP 10/10; low-TTL ICMP 12/12 | A working native service-insertion reference, not Check Point or cross-tenant ownership qualification |
| Classic VPN gateway on each side, two customer spokes, provider Ubuntu | Workload gateway UDRs enabled 6/6 E-W HTTP; both directional firewall blocks had no effect; FW E-W/FORWARD counters stayed zero | Connectivity worked, but traffic bypassed Ubuntu |
| Workload UDRs directly targeting Ubuntu private IP across VPN | ARM accepted both VirtualAppliance routes; NIC effective next-hop type became None; E-W 0/6, firewall-own-IP controls 2/2, zero E-W at FW | This direct-IP variant blackholed the tested E-W traffic rather than delivering it to Ubuntu; gateway-route rollback recovered 6/6 |

### 1. Cross-tenant NIC and service-association investigation

ARM's `x-ms-authorization-auxiliary` header was the mechanism originally sought.
Combining tokens for unrelated users failed with
`AuxiliaryTokensInvalidUserIdentity`. An approved temporary multitenant
certificate application established a shared application identity in both tenants.

Even with valid primary/auxiliary authorization:

- VM-A referencing NIC-B failed with `ResourceReferenceUsesWrongSubscriptionId`.
- NIC-A referencing subnet-B failed with `InvalidResourceReference`.

No supported foreign-NIC attachment was established. Image/snapshot consumption
must not be conflated with attaching a live foreign-owned disk: **no successful
live cross-tenant disk attachment was established or qualified here**.

Suggested Service Association Link endpoints were not written to without a
verified caller/onboarding, request and cleanup contract. A vendor-specific
managed/SaaS integration is not a generic entitlement to attach foreign NICs.

### 2. Why ordinary third-spoke vWAN insertion failed

We tried inspection/delivery hub-table associations with an ordinary firewall VM
in a third connected VNet. Captures showed repeated packets with declining TTL.
Microsoft's static-routing documentation explicitly excludes using that
third-spoke pattern to inspect traffic between directly connected workload VNets.

This is a restriction on the **specific documented pattern**, not a blanket
claim that every external VPN/NVA topology is prohibited. The exact hidden
Azure lookup responsible for the captured recirculation was not established.

### 3. What the successful AVNM lab proved

The live cross-tenant lab contained two provider firewall simulators and two
isolated customer groups of three workload VNets. Six peering relationships
(12 directional objects) and six route tables converged under AVNM.

Workload UDRs sent protected traffic to the assigned firewall. The firewall
forwarded toward the destination using direct peering reachability. Applying
the workload's inspection steering to the firewall's own delivery subnet was
avoided. Allowed responses retained their original private sources.

The 180 passing checks included selective firewall negative controls and
cross-environment denial, not just successful HTTP. **AVNM is the management
plane, not a packet hop.** It automates peerings/routes; it does not remove them.
Fleet-scale sharding, route conflicts, reconciliation, HA and real CloudGuard
remain separate engineering/qualification work.

### 4. Why IPsec/BGP was not enough

The initial static VPN-site attempt was rejected before tunnel establishment
because remote-site prefixes overlapped local workload address space.
The BGP revision instead exported only a default toward Azure and learned
customer prefixes toward the provider.

Workloads used inspection associations; the VPN retained Default association
for delivery on return. Both tunnels and both BGP sessions became healthy.
Workloads could reach the actual provider IP and a VPN-reachable loopback, but
workload-to-workload inspection probes failed without reaching the firewall.

Separate per-VNet inspection tables received the VPN default. A later
propagation drift was separately identified and repaired using explicit table
IDs. The correctly configured retest still failed. **That later drift is not
an explanation for the earlier correctly configured failure.**

No E-W loop was captured in this VPN experiment, and the exact internal
gateway/hub drop or forwarding decision remains unverified. Firewall-denial,
fail-closed withdrawal and dynamic-VNet lifecycle acceptance were not completed
without a positive inspected-flow prerequisite.

### 5. What native Routing Intent did differently

The approved first-party reference used an Azure Firewall integrated into the
managed vWAN hub, with **Private Routing Intent**, not an ordinary VM in another
VNet. All reference resources were physically in one tenant.

Observed routing views:

```text
Before intent, Default:
  Workload A /16 -> connection A
  Workload B /16 -> connection B

After private intent, ingress/Default:
  RFC1918 aggregates -> integrated Azure Firewall resource

Firewall-specific post-inspection view:
  Workload A /16 -> connection A
  Workload B /16 -> connection B
  0/0           -> Internet
```

The workload connections associated with Default and propagated to None.
The aggregate and destination-specific routes were **not competing in one
ordinary lookup table**. Microsoft documents Routing Intent as programming the
underlying Azure platform; it is managed service insertion, not general-purpose
PBR that can simply target any remote VM.

The direct baseline's 6/6 requests were not counted as inspection proof.
The subsequent allow/deny/restore tests and firewall-specific delivery view
established the native reference. They do **not** establish actual Check Point,
provider/customer compute ownership separation, HA, performance or an external
VPN extension.

### 6. Classic gateways: bypass versus an unusable next hop

The later test replaced vWAN with an ordinary customer hub VNet and a classic
VPN Gateway, plus a second gateway and Ubuntu on the provider side. Two private-IP
workload VMs lived in customer spokes. Only customer-internal peering existed;
there was no customer/provider peering or customer-hub routing VM. All resources
were physically in the approved provider test tenant.

With no workload UDR, the E-W baseline failed 0/6 while VPN-own-IP controls worked.
Exact other-workload `/16 -> VirtualNetworkGateway` UDRs then enabled 6/6 E-W
requests. The provider GatewaySubnet also had exact workload-prefix UDRs toward
Ubuntu. Nevertheless, Ubuntu saw zero E-W packets, and blocking new requests in
either direction on Ubuntu had no effect. The FW capture did see control traffic,
so this was not an inactive capture. This was **bypass**, not successful inspection.

We then changed both workload UDRs to `VirtualAppliance -> FW_PRIVATE_IP`.
ARM stored that configuration, but both NIC effective views reported:

```text
Source:          User
State:           Active
Destination:     other workload /16
Next-hop type:   None
Next-hop IP:     FW_PRIVATE_IP
```

The reported state was Active, not Invalid; the effective **None** next hop
discarded the tested E-W traffic. HTTP failed 0/6 while both own-IP controls and
VPN/BGP remained healthy. Ubuntu saw control traffic but no E-W or FORWARD hits.
The previous gateway UDRs were restored, and E-W recovered 6/6.

Reaching a VM **as an IP destination** through VPN is therefore not proof that
Azure can use it **as a direct NVA forwarding next hop**. The gateway's public IP
shown in some effective-route rows identifies the managed gateway, not the FW.
We did not capture the gateways' internal packet processing, so we do not claim
every hidden forwarding decision was determined.

## General lessons and acceptance criteria

- **Association and propagation are different:** association chooses the route
  view for incoming attachment traffic; propagation publishes reachability.
- **A default route does not beat a more-specific route in the same lookup.**
  Advertising a summary/default is not equivalent to service insertion.
- **Per-VNet hub tables do not create per-VNet gateway instances or BGP sessions.**
  Both workload prefixes may legitimately be advertised through one shared peer.
- **API success is not dataplane success.** Inspect actual effective routes
  and resource-specific pre-/post-inspection views.
- **A healthy VPN or firewall-own-IP probe is a control, not inspection proof.**
  Linux INPUT traffic is different from traffic traversing FORWARD.
- Require correct destination identity, original source preservation, capture/
  counters at the FW, selective denial while controls stay healthy, and recovery.
  Already-failing flows cannot demonstrate a successful firewall block.
- Check both initiation directions. A single selective denial cannot rule out
  asymmetric bypass. Use low-TTL/capture evidence when investigating loops.
- Query vHub effective routes **sequentially**. Concurrent requests for different
  tables on the same hub returned the same async operation/result in this lab.
- Poll legitimate `202`/`null` async responses until a real result exists.
  Gateway advertised-route `peer` belongs in the URI query.
- Private workload agents may still need outbound dependency access. An explicit
  lab-only outbound-access exception was approved for the classic test; no VM
  public IPs or private E-W source NAT were added, and Defender was not disabled.

## What is still unproven

- A real Check Point managed application, licensing, policy and lifecycle.
- Provider-owned compute in A with a native security resource in a customer-owned
  hub in B: the supported product/onboarding and ownership contract needs validation.
- A no-provider-peering external-VPN design meeting all original constraints.
- Production HA/failover, throughput, MTU behavior at scale, IPv6, overlapping
  environments end to end, N-S/inbound-publishing coverage and full fail-closed tests.
- A production SaaS controller managing the discussed estate. AVNM management
  consent/RBAC and automated VNet membership/attachments remain necessary.

Native CloudGuard automation was **prepared, not deployed**. Native AVNM/vWAN
integration and indirect spokes were documented options, not successful combined
cross-tenant experiments. Proposed custom ingress/delivery router overlays were
not deployed and must not be presented as working results.

## Practical disposition

If direct provider peering is acceptable, the direct-peering/UDR dataplane is
the strongest cross-tenant result from this work; AVNM can automate its lifecycle.
Qualify actual Check Point, HA and fleet operations before production use.

If no-provider-peering and customer-owned hubs remain mandatory, obtain a
vendor/Microsoft-backed insertion and ownership contract and test that exact
product. Do not treat the failed VPN variants, visible route copying or a
prepared CloudGuard template as a proven solution.

## Evidence, publication and cleanup

This report publishes anonymized topology, aggregate measurements and conclusions.
Raw runs, cloud/resource identifiers, account mappings, packet captures, keys,
approvals and environment-bound controllers remain local and excluded from Git.
The public-shape implementation entry points remain listed in the
[publication manifest](../publication-manifest.json). New execution requires
fresh authorization; a historical passed test is not a current deployment.

All 12 recorded project lab groups were freshly verified absent on 2026-10-20.
The last group's pre-deletion inventory contained 34 listed resource entries,
including three VMs and two classic VPN gateways; removal was not declared
complete until the group returned ARM `404 ResourceGroupNotFound`.

Earlier cleanup verified removal of 16 recorded active directory objects and
eight temporary scoped role assignments on 2026-10-19. The later native-reference
and classic-gateway labs created no new directory applications or consent grants.
Managed VM identities follow their deleted resource lifecycle; this is not a
tenant-wide identity audit or a claim that unrelated subscriptions are empty.

Three shared/pre-existing resources (monitoring and untracked networking) were
explicitly preserved and rechecked. Repository files, local profiles, keys and
raw evidence were retained privately. The final live plan is execution-disabled,
and the earlier plans remain decommissioned. Historical public-IP/SSH endpoints
must not be reused. No project lab deployment remains retained for inspection.

## Primary references

Documentation was checked during the research; service behavior and support
contracts can change. Measurements above describe these specific lab runs.

- [ARM authentication across tenants](https://learn.microsoft.com/azure/azure-resource-manager/management/authenticate-multi-tenant)
- [Azure network interface constraints](https://learn.microsoft.com/azure/virtual-network/virtual-network-network-interface)
- [vWAN static routes and third-spoke NVA restriction](https://learn.microsoft.com/azure/virtual-wan/static-routes#routing-traffic-to-an-nva-in-a-spoke-virtual-network)
- [Routing Intent and security-resource effective routes](https://learn.microsoft.com/azure/virtual-wan/how-to-routing-policies#effective-routes)
- [Indirect-spoke architecture](https://learn.microsoft.com/azure/virtual-wan/indirect-spoke-architecture)
- [AVNM cross-tenant management](https://learn.microsoft.com/azure/virtual-network-manager/concept-cross-tenant)
- [AVNM user-defined routing](https://learn.microsoft.com/azure/virtual-network-manager/concept-user-defined-route)
- [VPN gateway transit](https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-peering-gateway-transit)
- [Azure UDR and next-hop behavior](https://learn.microsoft.com/azure/virtual-network/virtual-networks-udr-overview)
- [Default outbound access](https://learn.microsoft.com/azure/virtual-network/ip-services/default-outbound-access)

Related repository material:
[architecture and evidence](architecture.md),
[monitoring model](monitoring.md),
[direct peering/AVNM](../deployments/02-direct-peering-avnm/README.md),
[external vWAN/IPsec experiment](../archive/failed-scenarios/deployments/06-customer-vwan-ipsec/README.md).
