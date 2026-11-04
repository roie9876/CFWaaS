# Persistent experiment register

**Updated: 2026-10-21.** This is the continuing index of completed, repeated,
aborted and proposed tests. The [final research summary](final-summary.md) is
the detailed historical snapshot through 2026-10-20; it is not the current lab
state. Raw evidence and exact environment identifiers stay local.

## Read before planning or running another test

1. Find the existing test by topology and variable, not just its name. Use the
   stable IDs below in plans, results and handoffs.
2. If it already ran, cite its result instead of rebuilding it. A repeat needs
   an explicit reason: user-requested demonstration, recovery/control check,
   changed platform/software version, or a genuinely different hypothesis.
3. Before a new test, record its parent test, the changed variable, expected
   discriminating observation, acceptance criteria and restoration/retention
   policy. Do not silently change several variables and call it a controlled
   comparison.
4. Afterwards record observed counts, evidence location, outcome, limitations
   and the configuration actually left active. Preserve failed results.
5. A planned test is not an executed test. An aborted attempt is not a dataplane
   result. Replaying a known failure is not a new architectural finding.

Necessary health controls and allow/deny/recovery phases are not forbidden
repetition: record why they are repeated and which experiment they support.

### Outcome vocabulary

- **PASS:** the stated, bounded acceptance criteria passed; not a claim of full
  product qualification.
- **BYPASS:** connectivity works but required firewall traversal/enforcement does
  not occur.
- **LOOP:** correlated packets repeatedly return with declining TTL.
- **DROP / NO ARRIVAL:** delivery fails; distinguish an effective drop next hop
  from a failure whose internal location is unknown.
- **REJECTED:** Azure rejected the request before the proposed dataplane existed.
- **CONTROL / RECOVERY:** validates a dependency, not E-W inspection.
- **ABORTED:** preconditions or drift checks prevented the planned test.
- **NOT RUN / PROPOSED:** no execution or successful result is claimed.

Packet lines are not unique packets: RX and TX can both appear in a capture.
Multiple repetitions of the same packet with progressively declining TTL are
the relevant loop evidence. Tunnel/BGP health, firewall-own-IP access and
successful HTTP alone never qualify mandatory inspection.

## Authorization and placement tests

Completed by 2026-10-20. Evidence and error details are summarized in
[the cross-tenant investigation](final-summary.md#1-cross-tenant-nic-and-service-association-investigation).

| ID | Test / changed variable | Observed result | Disposition |
| --- | --- | --- | --- |
| AUTH-01 | ARM auxiliary tokens from unrelated user identities | `AuxiliaryTokensInvalidUserIdentity` | REJECTED; do not repeat as a placement test |
| AUTH-02 | Approved shared multitenant certificate application | Shared-identity authorization established in both tenants | PASS for authorization only; temporary identity/grants later cleaned |
| AUTH-03 | VM in A referencing a NIC in B, after AUTH-02 | `ResourceReferenceUsesWrongSubscriptionId` | REJECTED; valid authorization did not remove placement constraints |
| AUTH-04 | NIC in A referencing a subnet in B, after AUTH-02 | `InvalidResourceReference` | REJECTED |

Service Association Link validate/PUT requests were **NOT RUN** without a
verified caller/onboarding and cleanup contract. A live foreign-owned disk
attachment was **NOT qualified**. Neither should be reported as a successful
control for foreign-NIC attachment.

## E-W architecture and routing experiments

### Earlier labs: completed by 2026-10-20, subsequently deleted

| ID | Topology / changed variable | Measured result | Conclusion / evidence |
| --- | --- | --- | --- |
| EW-01 | Ordinary vWAN; two directly attached workload spokes and an ordinary NVA in a third direct spoke | Correlated packets recirculated with declining TTL | LOOP; this documented third-spoke inspection pattern is unsupported. Not the managed Routing Appliance product. [Details](final-summary.md#2-why-ordinary-third-spoke-vwan-insertion-failed) |
| EW-02 | Direct cross-tenant peering and AVNM-managed UDRs; two isolated environments, three workload VNets each | 150 HTTP + 30 ICMP checks passed, including selective denial, recovery, source preservation and isolation | PASS for the Ubuntu lab. Six physical peering relationships remain necessary; AVNM is not a packet hop. [Details](final-summary.md#3-what-the-successful-avnm-lab-proved) |
| EW-03 | Customer vWAN to provider IPsec using static remote workload prefixes | Remote/local address overlap rejected before tunnel establishment | REJECTED, not a packet-forwarding failure. [Details](final-summary.md#4-why-ipsecbgp-was-not-enough) |
| EW-04 | Replace EW-03 with default-only BGP export from the provider | Both IPsec/BGP pairs healthy; provider-own-IP and VPN-only loopback controls worked; target E-W did not arrive at Ubuntu | NO ARRIVAL; no loop captured and exact internal drop/lookup unproven. [Details](final-summary.md#4-why-ipsecbgp-was-not-enough) |
| EW-05 | EW-04 with a separate inspection table per workload connection | Native baseline 6/6 HTTP + 6/6 ICMP; inspected 0/6 HTTP + 0/6 ICMP | NO ARRIVAL; splitting tables did not establish insertion. [Details](final-summary.md#4-why-ipsecbgp-was-not-enough) |
| EW-06 | EW-05 with explicit propagation repair | Inspected retest still 0/6 HTTP + 0/6 ICMP; provider controls 8/8 | NO ARRIVAL; later propagation drift does not explain the earlier correctly configured failure. [Details](final-summary.md#4-why-ipsecbgp-was-not-enough) |
| EW-07 | Native secured vWAN, integrated Azure Firewall and Private Routing Intent | Inspected HTTP 10/10; selective deny blocked 3/3 A-to-B while 3/3 B-to-A passed; restored HTTP 10/10; low-TTL ICMP 12/12 | PASS for the single-tenant native reference; distinct managed pre-/post-inspection views observed. Not Check Point/external insertion qualification. [Details](final-summary.md#5-what-native-routing-intent-did-differently) |
| EW-08 | Classic customer/provider VPN gateways; no workload UDR | E-W HTTP 0/6; VPN-own-IP controls worked | NO DELIVERY baseline; not inspection evidence. [Details](final-summary.md#6-classic-gateways-bypass-versus-an-unusable-next-hop) |
| EW-09 | EW-08 with exact other-workload prefixes to `VirtualNetworkGateway` | E-W HTTP 6/6; both directional firewall blocks had no effect; zero E-W/FORWARD at Ubuntu | BYPASS despite working connectivity. [Details](final-summary.md#6-classic-gateways-bypass-versus-an-unusable-next-hop) |
| EW-10 | EW-09 with workload `VirtualAppliance` next hop set directly to remote Ubuntu | ARM accepted routes; NIC effective routes were User/Active/**None**; E-W HTTP 0/6, own-IP controls 2/2; rollback recovered 6/6 | Effective DROP; destination-IP reachability is not usable NVA-next-hop reachability. [Details](final-summary.md#6-classic-gateways-bypass-versus-an-unusable-next-hop) |

These old cloud labs were removed with approval. Their retained local evidence
remains valid historical evidence, not evidence that resources are running.

### Managed Routing Appliance + VPN: 2026-10-21, retained

All resources in this experiment are physically in one approved test tenant.
Customer/provider are logical roles. There is no customer/provider peering.
The resource is the real `Microsoft.Network/virtualNetworkAppliances` managed
Routing Appliance, not a vWAN hub or a vendor `networkVirtualAppliances` resource.

| ID | Parent / changed variable | Measured result | Conclusion / final state |
| --- | --- | --- | --- |
| EW-11 | EW-09 concept with a real 10-Gbps managed Routing Appliance before the customer gateway | Baseline, steered, directional-block and recovery phases each had E-W HTTP 6/6; Ubuntu E-W/FORWARD/DROP stayed zero | BYPASS. Appliance metrics were aggregate activity, not proof of inspected probes |
| EW-12 | EW-11 investigation: vary only one appliance-egress destination route, Gateway -> Drop -> Gateway | A-to-B ping and 3/3 source-preserving HTTP worked, stopped at 0/3 with Drop, then recovered to 3/3 | CONTROL: the appliance subnet's egress UDR is applied. Restored the user's previous next hop |
| EW-13 | Disable ingress gateway-transit/remote-gateway flags, add static remote workload prefixes to the provider Local Network Gateway, steer via the appliance/customer gateway | 96 E-W capture lines; FORWARD increased both ways; same ICMP sequence/IP ID returned with TTL 8,7,6,5,4,3; ping/HTTP failed | LOOP, but original-source tunnel entry proven. Temporary settings restored |
| EW-14 | EW-13 plus a dedicated customer GatewaySubnet delivery table using endpoint `/32` routes directly toward endpoint IPs | 96 E-W lines and declining TTL; both initiation directions failed | LOOP; endpoint delivery routes did not solve it. Restored original settings at this stage |
| EW-15 | EW-13 with provider GatewaySubnet interception expanded from endpoint `/32` to workload `/16` | 96 E-W lines and declining TTL; end-to-end failure | LOOP; widening the provider interception prefix did not solve it. Temporary settings restored |
| EW-16 | Explicit user-requested replay of EW-14, retained for Ubuntu capture visibility | 48 A-to-B + 48 B-to-A capture lines; TTL 8 through 3; ping/HTTP failed both ways | LOOP; intentionally left active at that checkpoint, subsequently superseded by working EW-17. Not a new hypothesis or an inspection pass |

The private managed-lab guide maps these IDs to the exact local result files.
The earlier consolidated stopping-point record says settings were restored;
**EW-16 superseded that record at its checkpoint; EW-17 now supersedes EW-16**.
Its `allOriginalSettingsRestored=false` is intentional, not a rollback failure.
This paragraph is historical, not the current retained mode or a fresh live
health check. Later portal changes must be checked before any mutation.

The exact internal Azure gateway re-entry/lookup has **not** been localized by
the Ubuntu capture. Do not assert that the loop is specifically inside the
managed Routing Appliance.

## Operational controls, recoveries and aborted attempts

These are not additional successful inspection architectures.

| ID | Issue / action | Observation and reuse guidance |
| --- | --- | --- |
| OPS-01 | Edits to inactive workload tables | No effect while different inspection tables were actually associated. Resolve subnet associations and NIC effective routes before diagnosing the intended table |
| OPS-02 | Mistaken provider address or invalid remote-NVA next hop | Wrong-address ping failed; the actual Ubuntu address responded 3/3. An incorrect VM-A next hop produced an effective drop; corrected only the approved next-hop IP |
| OPS-03 | Appliance-egress table attached to customer GatewaySubnet | Own-IP requests reached Ubuntu and replies left, but replies did not reach VM-A. Clearing only the approved customer GatewaySubnet association restored the control. EW-16 later intentionally attached a different, dedicated delivery table |
| OPS-04 | Private workload outbound dependencies and inherited Defender extension | Approved outbound access plus VM restart recovered dependency reachability; retrying only `forceUpdateTag` preserved onboarding settings and recovered both extensions. Do not disable Defender or treat provisioning failure as an E-W route result |
| OPS-05 | SSH readiness and layered NSGs | Start Ubuntu's socket-activated SSH service through systemd, then validate. Narrow TCP/22 rules are needed at both NIC and attached subnet NSGs. Preserve ARM-pinned host verification and private ProxyJump |
| OPS-06 | Portal drift during guarded experiments | Preconditions aborted several attempts before mutations; these are ABORTED, not dataplane failures. An injected read-only/default `hasBgpOverride=false` also required explicit normalization before retry |
| OPS-07 | EW-17 dependency bootstrap under Azure Run Command | First attempt stopped before package installation because `/bin/sh` rejected Bash `pipefail`. Explicit Bash invocation fixed it; retry installed the missing strongSwan packages. Both attempt records retained. No routing/dataplane result was inferred |

## EW-17: successful firewall-terminated prototype, not the target

**Superseded by EW-18.** These measurements passed, but Ubuntu terminated IPsec,
contrary to the clarified requirement that the firewall only forward/filter.
The [prototype summary](../archive/prototypes/ew17-firewall-terminated-ipsec.md)
preserves that distinction. The following retention statements describe the
historical checkpoint, not the active post-EW-18 mode.

**Final status: PASS for functional inspection and both bounded local SA/UDP
fail-closed checks; working configuration RETAINED.** All resources remain at
the user's request. This final disposition supersedes earlier restoration,
paused/in-progress and EW-16 retention records, without rewriting raw evidence.

| Attempt | Observation | Disposition |
| --- | --- | --- |
| 1 | VMs deallocated before guest tunnel configuration; zero E-W probes | ABORTED, not a routing-design result |
| 2 | Allowed HTTP 6/6 with correct receiver/original source; A-to-B block denied 3/3 while reverse 3/3 passed; reverse block denied 3/3 while A-to-B 3/3 passed; recovered HTTP 6/6; all 16 ICMP probes passed | PASS for functional inspection. Capture recorded 456 E-W lines, including both firewall tunnel interfaces, with no correlated declining-TTL recirculation |
| 2, remaining fault test | Blocking outer VPN packets before graceful SA termination prevented the delete acknowledgement; `swanctl --terminate` hit the harness's 45-second timeout before withdrawal probes | HARNESS FAILURE, not an inspection failure. Original settings/guest configuration restored; no restoration errors. The overall raw result remains false because the complete acceptance sequence did not finish |
| 3 | Non-JSON HTTP 503 while reading the Ubuntu subnet NSG, before guest configuration or probes | ABORTED management-plane read; existing settings restored without errors. Not a routing failure. Added bounded retries for transient GETs only, never blind retries of guest/configuration writes |
| 4 | Fresh allowed HTTP 6/6 passed again. Forced ingress-SA interruption stopped all 6 HTTP attempts and ICMP while both local endpoint controls stayed healthy | Bounded ingress observation passed; recovery interrupted by VM-B Run Command 409 and all three VMs deallocated. Incomplete at this attempt; subsequently recovered with permission |
| 5 | Operator-approved restart/cleanup verified; transient local DNS interrupted control-plane access and was preserved separately; safely continued already-applied state against saved last-writes | PASS: fresh HTTP baseline 6/6; ingress interruption 0/6 expected, restored 6/6; delivery interruption 0/6 expected, restored 6/6; healthy endpoint-local controls; 520 capture lines with no loop; reused attempt 2's passed enforcement evidence |

Do not repeat the passed selective-deny matrix merely because the overall
attempt-2 process exited nonzero. Later completion attempts explicitly reference
that evidence.
These are single-tenant Ubuntu/static-prefix lab findings, not Check Point,
cross-tenant ownership, BGP lifecycle, HA or twenty-VNet qualification.

Final result: `inspectionPassed=true`, `failClosedTested=true`,
`failClosedPassed=true`, `configurationRetained=true`,
`continuedAfterDnsInterruption=true`; no restoration or diagnostic errors.
Final postflight verified all three VM agents/extensions ready, both direct SAs
installed, expected associations, only `xfrm1` workload guest routes, no
temporary blocks and no private-source NAT. This is the last verified state,
not continuous monitoring.

Exactly **one managed Routing Appliance** and **two customer classic VPN
gateways** are in the path. Existing ingress hub `172.28.0.0/16` and the new
dedicated delivery hub `172.29.0.0/16` attach to the same original workload
VNets/VMs; provider Ubuntu in `172.26.0.0/16` directly terminates both tunnels.
The old provider Azure VPN gateway remains retained for controls/management,
outside E-W forwarding. Each workload peers with both customer hubs: four
relationships/eight directional objects; no customer/provider, A/B-direct or
hub-to-hub peering. Source UDRs target the appliance, appliance-subnet UDRs the
ingress gateway. Ingress transit is disabled; delivery transit enabled; spokes
use only delivery's remote gateway. Neither GatewaySubnet has an inspection
UDR/NSG. Both initiation directions and replies follow source → RA → ingress
gateway → T1 → firewall `xfrm0` in / `xfrm1` out → T2 → delivery gateway →
destination.

IPsec transport is tenant-independent and supports cross-tenant endpoints;
there is no tenant data-plane restriction. This exact deployment placed all
roles physically in tenant A, so end-to-end cross-tenant ownership/onboarding
was **not tested**. Local fault injection was bounded SA/UDP interruption,
not BGP withdrawal or long platform convergence. Guest interfaces/routes/filtering
are runtime state; automatic reboot recovery is not implemented/qualified.
Use `sudo tcpdump -ni any icmp` or `xfrm0`/`xfrm1`; default `eth0` sees encrypted
UDP/4500. Actual Check Point/service support remains unqualified.

After attempt 4, all nine existing cloud settings were freshly verified equal
to the original snapshots. Guest cleanup could not complete while Ubuntu was
off, so the raw overall result correctly reports restoration incomplete.
At that checkpoint the working EW-17 configuration was **not left active**.
Core resources remained retained/billable; no VMs were automatically restarted.
No auto-shutdown schedules were found in this lab resource group, and the
available activity-log queries did not establish the shutdown actor/cause.
Do not infer that centralized automation or operator action has been excluded.

The user then explicitly authorized investigation and restart. Azure Resource
Health classifies the stop/deallocation as **Customer Initiated**, not a platform
outage. Explicit-UTC VM audit queries returned start/run-command/health events
but no identifiable deallocation caller; a later ingestion-delay recheck was
also inconclusive. The dedicated DevTestLab schedules API returned an empty
list, no shutdown-related VM tags or matching local shutdown timer names were
found, and no Spot/eviction configuration was returned. The exact initiator
remains unknown; no policy/schedule was disabled by guesswork.

After the authorized restart, guest cleanup initially encountered an absent
iptables-chain check left invalid by reboot. Reading the actual rule list
instead of testing a nonexistent jump target fixed that cleanup case, with a
regression test. Follow-up verification confirmed guest restoration and all
nine cloud snapshots. Earlier failed raw results remain intact.

The dedicated delivery VNet, public IP and gateway were verified `Succeeded`.
The user explicitly acknowledged costs/risks before execution. The trial's route,
peering and tunnel templates passed provider validation/create-only previews.
Before guest tunnel configuration, Azure rejected Run Command with HTTP 409
`OperationNotAllowed`: the firewall VM was no longer running. A subsequent
read-only check found **all three lab VMs deallocated**; the stop cause was not
established. Initial VM-readiness checks had passed earlier.

**No E-W probes or firewall enforcement tests ran.** This is not evidence that
the two-path routing architecture failed. Temporary cloud changes were rolled
back; all nine existing-resource snapshot comparisons were freshly verified
equal. Guest cleanup was also rejected while the VM was off, so the initial
result conservatively reports restoration incomplete. The tunnel-configuration
request itself was rejected before execution; guest state has not been
reverified after power-off. Do not silently rewrite that initial result.

New core resources remain retained/billable. No VMs were restarted automatically.
A resumed EW-17 attempt must record the VM-power-state interruption as its repeat
reason, take fresh snapshots, and recheck agents/extensions immediately before
guest changes. Definite rejected commands must not be treated as executed guest
configuration; uncertain accepted/transport-failed requests still require cleanup.

The user subsequently restarted all three VMs and requested the rerun. Fresh
preparation verified agents/extensions, retained foundation ownership, all nine
original cloud settings, and a clean Ubuntu baseline with no leftover trial
interfaces/routes/configuration. The second attempt reuses the retained gateway
and delivery connection; it does not create another gateway or overwrite that
connection's secure key. Its repeat reason is **recovery from an aborted attempt
with zero E-W probes**, not a repeat of a completed routing experiment.

Read-only preparation on 2026-10-21 verified VM/agent/extension readiness,
captured existing resource/guest observations, passed ARM provider validation,
and previewed exactly three new core resources: delivery VNet, public IP and
gateway. Four new Bicep templates compiled; seven focused guard tests passed.
Checkov reported two passed/zero failed ARM checks, with limited expression/
dependency coverage; this is not a comprehensive security qualification.
No existing routing/guest configuration changed and no E-W probe was run.

- **Parent:** EW-13 through EW-16.
- **Component distinction:** exactly one managed Routing Appliance, on ingress.
  The two separated components are customer VPN gateways, not two Routing
  Appliances. No post-firewall Routing Appliance or same-region appliance
  chaining is proposed; Microsoft documents same-region chaining as unsupported.
  Valid individual gateway placement does not establish support or success for
  the complete experimental inspection path.
- **Changed architecture:** separate customer ingress and delivery gateway VNets;
  the provider firewall directly terminates both IPsec paths. The provider
  managed VPN gateway is not in this proposed forwarding path. Merely adding
  another tunnel to the same gateway/RIB is not this experiment.
- **User-approved placement:** reuse the existing two workload VNets, both
  workload VMs, Ubuntu and the single managed Routing Appliance. Create one
  **new dedicated customer delivery-hub VNet** with its own GatewaySubnet and
  one new VPN gateway. Do **not** put a gateway or GatewaySubnet in VNet-B.
  The earlier suggestion to make VNet-B double as the delivery hub was
  superseded before execution; it was never deployed or tested.
- **Incremental resource/cost boundary:** one VNet, one VpnGw1AZ gateway and its
  Standard public IP, plus required VPN/peering/routing control objects; no new
  VM or Routing Appliance. The verified gateway base increment is approximately
  USD 0.21/hour (USD 5.04/day), excluding public IPs, transfer and other applicable
  charges. The old provider gateway remains billed while retained.
- **Path in both initiation directions:** source -> ingress Routing Appliance/
  gateway -> firewall -> separate delivery gateway -> destination.
- **Firewall routing:** post-inspection workload routes use the delivery path,
  not the ingress tunnel. Use VNet prefixes, not endpoint `/32` delivery routes.
  The initial bounded test uses static VNet prefixes to isolate the forwarding
  hypothesis. BGP/dynamic onboarding remains a separate later acceptance test.
- **Customer routing:** ingress does not learn peered workload prefixes through
  gateway transit; delivery has destination reachability. Each spoke uses at
  most one remote-gateway arrangement. Workload effective routes must select
  inspection rather than bypass through the delivery gateway.
- **Planned delivery attachments:** peer the new delivery-hub VNet with existing
  VNet-A and VNet-B: two peering relationships, four directional ARM objects.
  Keep the existing ingress-hub peerings. Configure forwarding/gateway transit
  for the delivery role, with any spoke remote-gateway use confined to delivery,
  not both hubs. Explicit protected-prefix source UDRs still select the ingress
  Routing Appliance. No customer/provider VNet peering or direct A/B peering is
  required by this plan.   This was the planned wiring; final attempt 5 now verified the bounded path.
- **Discriminating observation:** original-source traffic arrives through the
  firewall's ingress tunnel, leaves through its delivery tunnel, reaches the
  intended receiver and does not recirculate.
- **Pass criteria:** both initiation directions, correct receiver/original
  source, correlated tunnel/forwarding captures, low-TTL delivery, selective
  denial in each direction with healthy controls, recovery, and fail-closed
  behavior during each path's withdrawal.
- **Scale boundary:** two workload VNets first. Twenty-VNet onboarding, HA,
  performance and actual Check Point remain separate unexecuted tests.
- **Deployment boundary:** one additional gateway/public IP and new routing/
  peering/VPN control objects still require scope/cost/risk approval. The existing
  provider gateway stays deployed but is excluded from the proposed E-W path.
  Reusing the lab requires explicit, snapshotted routing/guest changes and
  temporarily replaces the EW-16 capture demo; do not silently assume it stays
  active. Do not delete existing core resources. Fresh snapshots must account
  for any later portal edits.

If this hypothesis cannot be implemented within documented gateway/peering
constraints, record that blocker instead of retrying EW-14 under a new name.

## EW-18: plain firewall, all IPsec on managed gateways

**PASS; retained active and postflight verified.** The user selected the additive
option and explicitly acknowledged cost/risk for unattended testing. All old core
resources were retained. The new private plain firewall sits in a new provider
security VNet; a new provider delivery VNet/gateway completes four managed
gateway roles. No VPN software/configuration is installed on the tested firewall.

| Phase | Measured observation |
| --- | --- |
| Original-source allow | HTTP 6/6, correct receivers |
| A-to-B selective block | 3/3 timed out, reverse 3/3 allowed; 12 DROP hits |
| B-to-A selective block | Reverse 3/3 timed out, A-to-B 3/3 allowed; 12 DROP hits |
| Restore | HTTP 6/6; temporary blocks absent |
| ICMP | 16/16 packets received replies |
| Cleartext capture | 448 E-W lines on plain firewall `eth0`; no recirculation |
| Provider VPN offload | All four managed connection ends Connected; no firewall VPN software/interfaces/listeners, no private-source NAT |
| Ownership boundary | Six internal peering relationships/twelve directional objects; zero customer/provider peering |
| Postflight | All four VM agents ready, expected associations and exclusive provider delivery remote gateway, direct-Ubuntu VPN connections absent, positive forwarding counters |

The requirement is met in this bounded simulator lab. Both initiation directions
and replies use customer ingress -> provider ingress -> plain firewall ->
provider delivery -> customer delivery. Source UDRs still target one managed
Routing Appliance. The **old provider Azure gateway is now in the ingress
datapath**; the legacy Ubuntu is only retained management/rollback infrastructure.

This changed both provider routing-domain separation and VPN termination
placement; it is not a rerun of EW-13's single-provider-gateway loop. Initial
foundation validation: 29 guard tests, compiled Bicep, Checkov 14/0, provider
validation/create-only preview. Final connectivity templates scanned 17/0 with
documented lab exceptions and limited expression coverage. Runtime guard tests
expanded to 33. Old public-package regressions passed after archive relocation.

See the [working guide and topology](ew18-managed-vpn.md). No real Check Point,
cross-tenant deployment execution, HA/performance, scale or BGP/reboot-policy
qualification is claimed. Physical lab roles shared one test tenant; tenant
independence of IPsec is not a cross-tenant ownership test.

## EW-18 planning trace (completed; not a pending proposal)

- **EW-18: managed VPN termination on both sides.** The user requires Ubuntu
  to simulate forwarding/filtering only, without site-to-site VPN. EW-17's
  positive packet/enforcement results do not meet this requirement. The next
  candidate separates provider ingress and delivery gateway VNets as well as
  the customer hubs:
  source -> customer ingress GW -> IPsec -> provider ingress GW -> plain
  firewall -> provider delivery GW -> IPsec -> customer delivery GW -> destination.
  One existing managed Routing Appliance remains before customer ingress.
  Only customer-internal and provider-internal peering is proposed; no
  customer/provider peering. Four gateway roles in this candidate do not mean
  a gateway per workload VNet.
- The provider firewall's security VNet must use only the provider delivery
  gateway remotely and must not have its own gateway. The current Ubuntu
  VNet already contains the old provider gateway. Two implementation choices
  need scope approval: add a plain firewall VM in a new security VNet and a
  provider delivery gateway in another new VNet, retaining all existing core
  resources; or retain the existing Ubuntu VM and explicitly replace/relocate
  its provider gateway through deletion/recreation. Neither choice has been
  deployed at the planning checkpoint. The additive choice below was subsequently
  approved, deployed and passed. Do not repeat the known single-provider-gateway loop test.
- The user selected the **additive** EW-18 option: retain all old core resources,
  add one private plain Ubuntu firewall VM in a new provider security VNet,
  and one provider delivery VPN gateway in another new provider VNet. No new
  Routing Appliance or customer workload VM/VNet is created. New firewall
  administration uses the existing provider SSH jump.
  Foundation preparation passed 29 focused tests, Bicep compilation, Checkov
  14 passed/0 failed with the existing documented lab exceptions, ARM provider
  validation and a create-only preview. No EW-18 resources had been submitted
  at that preparation checkpoint; the later explicit acknowledgement authorized
  execution. The bootstrap contains
  no strongSwan, charon, swanctl or xfrm configuration.
- EW-18 acceptance must include absence of VPN termination on the firewall,
  original-source cleartext on `eth0`, managed gateway/tunnel evidence, both
  initiation directions, selective denial/recovery, and loop/bypass checks.
  These bounded criteria subsequently passed; broader production qualification
  remains separate.

## EW-19: isolated no-Routing-Appliance test

**Completed: no tested variant qualified. EW-18 was retained unchanged.**
The separate approved lab has seven VNets, four managed gateways, two workload
VMs, one plain firewall and zero Routing Appliances. Fresh addresses/keys and
strict group guards prevented use of the existing lab's live objects.

| Case | Measured outcome |
| --- | --- |
| Direct ingress remote gateway | HTTP 6/6 but firewall capture zero; A-to-B block ineffective, both directions still 3/3 passed. **BYPASS** |
| Full protected VNet prefixes remote via provider | **REJECTED:** `ConnectionOverlappingAddressSpaces`, remote /16 against known local/peered /16 |
| More-specific protected workload subnets | **REJECTED:** same error, remote /24 against known local/peered /16 |

An initial transient readiness guard aborted capture dispatch before probes;
the resume verified routes, policy and tunnel health without redeploying.
The completed native bypass and full-prefix rejection were referenced, not
rerun. Azure returned the overlap as async Failed under HTTP200 and persisted
the rejected site definition in Failed state. Each rejected update was guardedly
restored to the known-good provider-only prefix set and Succeeded was verified.
No API acceptance was counted as a dataplane pass.

Historical EW-19 postflight: all four managed connection ends Connected, zero RA
resources, temporary firewall blocks absent, rejected prefixes removed. The lab
was retained in native-bypass baseline, **not a qualified inspection path**.
A read-only check confirmed EW-18 and its four gateways still present. No
write/peering targeted that protected group.

On 2026-10-22 the user requested deletion of the isolated EW-19/EW-20 lab.
Azure completed the resource-group deletion; a successful existence check
returned false, verifying that the group is absent.
EW-18 remains present with all four gateways Succeeded; local evidence is kept.

Validation: six guard/script tests, four compiled Bicep entrypoints, Checkov12/0
with documented exceptions/limited expression coverage. Approved additional
base cost USD0.9024/hour (USD21.6576/day), excluding IPs/disks/transfer/applicable
charges, while both labs are retained.

See [EW-19 failed-scenario details](../archive/failed-scenarios/ew19-no-routing-appliance.md).
The direct-gateway replacement does not preserve EW-18's routing behavior;
this does not prove every possible appliance-free architecture impossible.

## EW-20: BGP and ingress/delivery route steering

**Closed without a qualifying path; lab deletion verified.** The following
records the approved test scope and results. Reuse only the isolated EW-19 group. Preserve
EW-18 unchanged, all four managed gateways, zero Routing Appliances and a plain
firewall with no VPN termination or source NAT. Configure the existing distinct
gateway ASNs and real peer addresses on the four Local Network Gateways, then
enable BGP on all four connection ends. Do not infer sessions from a gateway's
`enableBgp` flag.

Read peer status, learned routes and peer-specific advertised routes from every
gateway. Test the BGP baseline separately from EW-19's static routing results.
Test a bounded `10.180.0.0/14` aggregate covering the two workload networks if
it is advertised and learned; retain only a qualifying inspected path. Verify
original-source delivery, firewall capture, selective denial/recovery and no
loop. Restore a nonqualifying aggregate but retain the requested healthy BGP
configuration. No extra routing VM, gateway or customer/provider peering is
authorized by this test.

Microsoft's [BGP FAQ](https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-vpn-faq#bgp)
states that gateway transit filters matching or more-specific local/peered VNet
prefixes while allowing supersets. BGP is therefore not assumed to defeat the
overlap boundary. Aggregate acceptance/learning and actual inspected forwarding
are separate assertions.

The first peer update was accepted but its polling failed on local DNS. A
fresh read confirmed Succeeded and the exact intended settings before resuming
without replaying that write. Raw evidence is retained locally.

**Measured BGP baseline:** all four real peers and IPsec connection ends
Connected. CI/PI use ASNs65120/65122; CD/PD use ASNs65121/65123.
Retained static site prefixes coexist with BGP; this is not a pure dynamic
replacement. CI advertises its hub plus both workload /16s; PI advertises only
its own hub. CD advertises only its own hub; PD advertises its hub plus the
firewall network. CI's route diagnostic lists both workloads as local
`Network` entries, not received `EBgp` entries from PI. Delivery reachability
continues to rely on retained static workload site prefixes.

Allowed HTTP6/6 preserved source; an A-to-B firewall block left A3/3 and
reverse3/3 passing with zero DROP hits and zero E-W firewall capture lines:
**BYPASS despite established BGP**. Local controls and ICMP remained healthy.

Adding the aggregate to PI's existing customer-facing Local Network Gateway
did not export it back to CI or appear as a learned CI route within the
180-second observation window. The aggregate was removed and the exact prior
BGP site definition/Succeeded state verified.

The user explicitly approved a temporary additional VPN link between the
existing provider gateways to give the aggregate a separate route origin.
No extra VM/gateway/VNet is added. This link uses static remote-site prefixes
to originate the aggregate, while existing customer/provider links carry BGP;
it does not claim a new dynamic routing adjacency where none exists.
Verify connected link ends, PI advertisement and CI `EBgp` acceptance before
another firewall test. Remove only the four owned temporary connection/site
objects after a negative result, with configuration-drift guards.

The separately originated aggregate was actually exported by PI and accepted
by CI: `10.180.0.0/14`, origin `EBgp`, next hop/source peer `172.22.255.30`,
AS path65122. Both temporary VPN connection ends were Connected. CI also
retained local `Network` routes for `10.181.0.0/16` and `10.182.0.0/16`.
This establishes route manipulation, not inspection success by itself.

The subsequent workload `/24` test matched PI's firewall-next-hop UDRs to the
advertised prefixes. Both temporary connection ends were Connected and PI
exported `10.181.0.0/24` and `10.182.0.0/24`, but CI accepted neither during
241.5 seconds of observation. No data-plane inspection success is claimed.
The temporary connection/site objects were removed and PI's original
interception routes were restored.

A later manual workload `/32` static-site update on CI failed with
`ConnectionOverlappingAddressSpaces` (`10.182.0.4/32` against
`10.182.0.0/16`). Attempts to restore CI's original site prefixes were blocked
by MFA enforcement. The user then requested deletion of the isolated lab;
that deletion was completed and verified. The manual GatewaySubnet UDR variant was not
qualified by a completed traffic test.

## EW-21: Ubuntu two-tunnel overlay

**Passed and retained.** The user allowed dedicated hub appliances to terminate
the transport while keeping the firewall plain. Paid VyOS Marketplace purchase
was unavailable; the approved alternative uses ordinary Ubuntu, WireGuard and
Linux policy routing, not repackaged VyOS.

Five VMs and four VNets separate customer PRE/delivery, provider PRE/POST and a
two-interface plain firewall. There are no Azure managed VPN gateways, managed
Routing Appliances, customer/provider peerings or direct workload peerings.
Both initiation directions and responses use the inspection -> firewall ->
delivery pipeline. Matching Azure subnet UDRs are required in addition to guest
routes; effective-route readback gates the data probes.

The completed eleven-phase matrix measured **66 HTTP outcomes: 42 passes and
24 expected denials**, with healthy local controls and original-source/correct-
receiver checks. Selective A-to-B and B-to-A blocks each recorded **9 DROP hits**
while the opposite initiation direction passed. Firewall deny-all and both
tunnel interruptions failed closed; all five recovery phases restored 3/3
delivery in both directions. Firewall capture contained **476 observations** and
no correlated declining-TTL loop.

An initial tunnel-UP-only recovery left the device-bound policy routes absent.
The fix reinstalls the owned routes/forwarding policy; the entire matrix was
subsequently rerun successfully. Guest-observed handshake timestamps and paged
Run Command output avoid control-plane latency/truncation false results.

Final verification found five running VMs, ready guest agents, all five
tenant-managed MDE extensions Succeeded, no guest NAT or firewall VPN, no
temporary block/capture/paging helpers, and restored tunnels. EW-18 remained
untouched with four gateways Succeeded; EW-19 remained deleted.

Validation: 31 focused tests, Bicep compilation, Checkov12 passed/0 failed with
three documented lab exclusions. Private-guest web/DNS/agent egress is a lab
exception needed by tenant security provisioning; public SSH is not required.
The private machinery and raw evidence are retained locally.

This changes the original managed-endpoints constraint and qualifies only the
bounded Ubuntu/IPv4/HTTP simulator, not cross-tenant execution, real Check Point,
HA, fleet scale or other protocols. See [the archived guide](../archive/prototypes/ew21-ubuntu-overlay.md).
Archived by user decision on 2026-10-26, not a deployment candidate; the passed
measurements remain historical evidence. Repository archiving does not delete
Azure resources.

## EW-22: dynamic delivery-prefix lifecycle

**Delivery control-plane milestone passed; full dynamic inspection not qualified.**
The user authorized changes to the retained EW-18 lab. Customer delivery
and provider delivery were configured with BGP and distinct ASNs. Actual
peer status and provider `EBgp` routes were verified before removing the two
workload `/16`s from the provider delivery site's static prefix list.

The customer added `10.173.0.0/16` to an existing workload VNet, synchronized
its customer-delivery peering, and provider delivery learned that prefix.
Customer removal and peering synchronization withdrew it. Configured provider
delivery gateway/site/connection fields and route tables were fingerprinted
and remained unchanged during the customer-only lifecycle.

Final reads: both VPN ends and both peers Connected; original workload
`/16`s learned via customer delivery as `EBgp`; temporary prefix absent; original
customer address space restored. Five focused controller tests passed.

No new VM/VNet was created, no workload VM was started and no data-plane
test was run. This demonstrates address-space propagation on an existing spoke,
not complete VNet onboarding or deletion. Exact-prefix ingress UDRs, forwarding
and NSG dependencies still need a prefix-independent design and end-to-end
qualification. No claim of autonomous arbitrary-prefix inspection is made.

See [EW-18 continuation](ew18-managed-vpn.md#ew-22-dynamic-delivery-continuation).

## EW-23: dynamic firewall delivery without guest BGP

**Passed for the existing single-firewall path.** Removed the two exact
workload UDRs from the firewall delivery table while retaining BGP propagation.
The firewall NIC selected active gateway-propagated workload routes; Ubuntu
used its default Azure next hop, without exact workload guest routes or BGP.
Four phases produced 24 expected HTTP outcomes: 18 source-preserving passes
and six selective denials, with positive DROP counters and recovery.

A temporary customer-only `10.173.0.0/16` addition/removal also appeared and
withdrew in the firewall NIC's effective routes. That prefix had no workload
endpoint, so this did not qualify full new-VNet data-plane onboarding.

## EW-24: two Ubuntu NVAs behind internal HA-ports LB

**Bounded source-preserving transit and fresh-flow failover passed.** Added
one private Ubuntu NVA and one internal Standard LB in the existing security
VNet. One floating-IP HA-ports rule, frontend and NIC-based pool select either
NVA. Provider ingress's existing exact-prefix UDRs now select the LB VIP.
Neither NVA runs BGP or terminates the VPN; Azure supplies learned delivery
routes and guest default routing is unchanged.

The seven-phase matrix recorded 448 fresh TCP outcomes: 384 correct-receiver,
original-source deliveries and 64 expected denials. Both backends were observed
in captures/counters. Selective denial was applied to both NVAs, followed by
recovery. With each backend's health withdrawn in turn, only the survivor
received new flows. Sampled SYN/SYN-ACK backend symmetry passed. Existing
sessions, real Check Point/VMSS, state synchronization and arbitrary-prefix
ingress remain unqualified.

Explicitly approved public IPs were attached to the existing NVA NICs for
update egress after repository HTTPS timed out and tenant Defender installation
failed. No extra NIC/NAT Gateway was added. Both repository checks returned
HTTP 200 and Defender recovered. Private IP/subnet/pool/NSG configuration and
inspection routes were preserved; public SSH was initially denied. The user
subsequently requested any-source TCP/22 on the active lab NSGs for manual
testing. Key-only access with pinned host keys was verified to both NVAs and
both private workloads through NVA1. This explicit lab exposure should be
restricted after testing. Local readiness
checks forwarding/routes, not customer application access from an NVA address.

Final postflight verified running backends, successful Defender extensions,
restored health, no temporary blocks/capture helpers and the LB ingress next
hop. All resources are retained; historical cleanup has not begun. Validation:
34 focused tests and Bicep compilation passed. Private plans/evidence remain
local. See [EW-18 continuations](ew18-managed-vpn.md).

## EW-25: replacement lab, default-only provider ingress

**Bounded ingress milestone; end-to-end dynamic onboarding is not qualified.**
On 2026-11-01, the replacement lab's user-cleared provider ingress
GatewaySubnet route table remained empty. Removing the two workload prefixes
from the provider ingress Local Network Gateway left only the customer ingress
hub prefix configured there. The ingress VPN gateway learned `0.0.0.0/0` from
the provider ingress Route Server, with NVA 0 as next hop; it no longer
listed either workload prefix in its learned-route view.

Before that site-prefix change, east-west ICMP failed 0/3 in both directions.
Afterward, ICMP succeeded 4/4 in both directions, and NVA 0 captured requests
and replies with the original workload source and destination addresses on
both ingress and egress. A temporary NVA 0 rule dropped 3/3 A-to-B echo
requests while B-to-A passed 3/3. The rule was removed and both directions
recovered 3/3. Internet ICMP also passed 3/3 from each workload; unlike
east-west traffic, north-south Internet NAT is permitted by the lab rules.

These are simulator and existing-workload results, not a real Check Point or
new-VNet lifecycle qualification. At this milestone the customer/provider
delivery VPN connections had BGP disabled, and the provider delivery Local
Network Gateway still contained static workload prefixes. The Route Server
default selected NVA 0 rather than the load balancer; HA and failover were not
tested. Provider Internet forwarding and NAT rules also remain scoped to the
two original workload IPs.

With the delivery Route Server's gateway exchange temporarily disabled,
east-west and Internet ICMP still passed 3/3 from each workload. The provider
delivery gateway then accepted a change from ASN `65515` to `65031`, but
immediate tests failed 0/3 for both traffic classes from both workloads,
despite both delivery connections reporting Connected. The NVA NIC still
showed active gateway routes to the workload prefixes. This was an
immediate post-update observation, not proof of a persistent incompatibility;
convergence and the internal forwarding cause were not established.

The gateway ASN and Route Server exchange were restored, after which both
traffic classes recovered 3/3 from both workloads. The customer/provider VPN
connections were not changed to use BGP during this test.

## EW-26: separate managed BGP delivery gateway

**Dynamic delivery control-plane and bounded east-west traffic passed;
Internet return and full VNet lifecycle remain unqualified.** A separate
provider VPN gateway with ASN `65031` was created without a co-located Route
Server. A new S2S connection to the customer delivery gateway, ASN `65021`,
used BGP on both ends. Each new Local Network Gateway contained only the
remote BGP peer's `/32`, not customer workload prefixes. Both VPN ends and
BGP peers reported Connected; the provider gateway learned both original
workload `/16`s as `EBgp` with AS path `65021`.

The provider firewall VNet's gateway transit was temporarily moved from the
original delivery gateway to the new gateway. NVA 0's effective routes for
both workload prefixes selected the new gateway. East-west ICMP passed 3/3 in
each direction, and a subsequent A-to-B capture showed original source and
destination addresses entering and leaving the simulator without NAT.
Internet ICMP failed 0/3 from both workloads and 0/4 in a focused retry.
The simulator capture showed the Internet replies entering and leaving the
guest toward the customer, while the customer workload capture saw requests
but no replies. The loss is downstream of the simulator's guest capture;
the precise Azure forwarding decision is not established.

The original gateway transit was restored, and east-west and Internet ICMP
recovered 3/3 from both workloads. The new BGP tunnel remained isolated for
further diagnosis. The new gateway did not show the default route that the
original gateway learned via Route Server; whether that difference causes the
Internet failure is unproven. Azure rejected adding `0.0.0.0/0` directly to
the new Local Network Gateway's address prefixes, leaving its original
peer-only prefix intact.

A subsequent test configured the documented VPN Gateway default-site setting
on the new gateway. Its learned-route view then included a locally originated
default; the customer gateway did not learn that default from the new peer.
With provider gateway transit temporarily switched to the new gateway, both
existing workloads passed east-west and Internet ICMP 3/3 each. Captures
showed original east-west addresses and Internet SNAT after the simulator saw
the customer source. The simulator subnet's active Internet UDR was verified
before traffic was sent. After a repeat passed, the new gateway transit was
retained; the original delivery path remained as a fallback. This does not
establish why the earlier Internet return failed.

**Deployment boundary:** The source templates were subsequently updated for
one ingress Route Server and a separate BGP delivery gateway, but a fresh
deployment of that source has not yet been qualified. The retained live gateway
has a different resource identity from the gateway named by the template;
redeployment over the existing lab needs an explicit migration plan.

## EW-27: customer-only VNet addition and withdrawal

**East-west lifecycle passed for the simulator; Internet for the new workload
failed.** With the EW-26 BGP delivery path active, a new customer VNet and
private workload were created. Customer-side peering, UDRs, ingress-site
prefixes and narrowly scoped workload NSG rules were configured; no
provider-side per-VNet configuration was added.

The provider VPN gateway learned the new VNet `/16` as `EBgp` through the
customer delivery gateway. The simulator NIC selected the new managed VPN
gateway for that prefix. Provider ARM configuration snapshots taken before,
during and after the lifecycle matched. Both existing workloads and the new
workload passed ICMP 3/3 in each of the four initiation directions; HTTP
receivers reported the original source IP in each direction. Simulator
captures showed the original east-west addresses entering and leaving it.

The new workload's Internet ICMP failed 0/3. The provider Internet-forwarding
NSG rule and simulator Internet NAT rules are scoped to the two original
workload IPs; the new workload does not match them. A controlled capture saw
the new workload's east-west ICMP at the simulator but no Internet ICMP there.
The precise upstream drop was not established.

The customer test VM and VNet were removed, together with the customer-only
test rules and routes. The new `/16` disappeared from the provider gateway's
learned routes and the simulator NIC's effective routes while the BGP peer
remained Connected. Real Check Point inspection, Internet egress for arbitrary
new workloads, and HA remain unqualified.

After cleanup, existing-workload HTTP checks retained the original source IP.
One HTTPS request from workload B failed with an HTTP/2 stream error; subsequent
HTTP/1.1 and HTTP/2 checks passed 3/3 per protocol from each workload, and
two further checks per protocol from workload B passed against a second
endpoint. The cause of the initial error was not established.

## EW-28: lab NSG and generic NAT update

The user authorized unrestricted NSG traffic for this lab and RFC1918-only
customer addresses for the simulator. The unused provider delivery Route
Server, its public IP and its empty subnet were removed. Both simulator NAT
configurations were updated and persisted to cover RFC1918 sources while
excluding RFC1918 destinations from NAT. The ingress Route Server and the
managed customer/provider delivery BGP session remained active.

Allow-any inbound and outbound rules were added to both lab NSGs. A subsequent
Azure Policy `deployIfNotExists` remediation rewrote the provider NSG, after
which its allow-any inbound rule was absent; the provider allow-any outbound
rule and both customer allow-any rules remained. The policy was not modified
or bypassed. The requested live allow-any state is therefore not established.

A second customer-only VNet lifecycle test was started after these changes.
The new `/16` was learned by provider BGP and selected by the simulator NIC,
but the provider configuration snapshot changed when the NSG was remediated.
The user then requested scoped provider rules for RFC1918 east-west traffic
and Internet DNS, HTTP, HTTPS, SSH, ICMP, NTP and QUIC, plus SSH access from
the confirmed operator IP. These were added without changing Azure Policy.
The customer NSG retained its previously authorized allow-any inbound rule.

A private workload in the new VNet subsequently passed east-west ICMP 5/5
in all four initiation directions and HTTP source-identity checks. Its
Internet ICMP passed 5/5; DNS over TCP and UDP, HTTP, HTTPS, an SSH server
banner, NTP, and QUIC version negotiation also passed. Simulator captures
showed unchanged east-west IP addresses and Internet SNAT. Provider ARM
configuration snapshots matched while the workload was added and the test
VNet was removed. Because the VNet existed before the one-time scoped NSG
changes, this repeat does not by itself prove an unchanged provider
configuration for the entire addition phase; EW-27 covers the earlier
customer-only VNet addition and withdrawal.

The test VM, VNet, peerings and customer-only test routes were removed. The
new prefix disappeared from provider BGP and the simulator NIC while BGP
remained connected. Network Watcher allowed the confirmed operator IP to SSH
to all four existing VMs, and each VM's SSH service and lab public key were
present; an actual login from the operator's IP was not tested. The customer
NSG also allows other sources because its allow-any rule remains.

After remediation, the two original workloads passed east-west ICMP 5/5 in
each direction. Internet ICMP passed 5/5 from workload B and initially 4/5
from workload A; a subsequent 20-packet workload A test passed 20/20. The
cause of the initial loss was not established.

## EW-29: temporary inbound DNAT through the BGP delivery path

On 2026-11-01, a source-restricted temporary inbound test used the confirmed
home client address and NVA 0's public IP. ICMP was DNATed to workload A;
TCP port `2222` was DNATed to workload A's SSH port `22`. Both flows were
SNATed to NVA 0's private IP for their return path. These rules applied only
to the external test source, not east-west customer traffic.

The first ping received 4/5 replies. A repeat received its warm-up reply and
10/10 measured replies. Host-key-verified SSH reached workload A and confirmed
the expected private destination and NVA private source. Both ICMP and TCP
DNAT/SNAT counters increased. The initial ping loss was not explained.

All temporary NSG and guest NAT rules, the helper, and its timer were removed;
Network Watcher then denied the temporary SSH port. Both original workloads
subsequently passed east-west and Internet ICMP 5/5, and the delivery BGP
peer remained Connected. This is a bounded Ubuntu-simulator test, not a real
Check Point or HA qualification, and does not provide permanent inbound
publishing. The customer VM sees the NVA private IP as the inbound source.

## EW-30: fresh release deployment and timing

On 2026-11-02, a new customer deployment using the updated release completed
in approximately 87 minutes. Customer authorization took 2 minutes 23 seconds,
customer foundation 27 minutes 56 seconds and provider provisioning 47 minutes
45 seconds. The provider gateway modules took 29 minutes 27 seconds and
27 minutes 24 seconds in parallel; the ingress Route Server module subsequently
took 16 minutes 31 seconds. These stages are not independent samples and their
individual durations must not all be added together.

At inspection, the two customer and two provider VPN connections reported
Connected, and the customer and provider delivery BGP peers reported Connected.
The provider peer's reported connected duration was only a few seconds; this
snapshot does not establish session stability. No lab 14 packet-path, end-to-end
address-preservation, failover or real Check Point tests were performed as part
of this check. The existing lab 12 delivery connection remained connected.

## EW-31: lab 14 east-west and Internet-egress tests

On 2026-11-02, the two customer workloads each passed 70/70 east-west ICMP
requests and 5/5 HTTP requests to the other workload. The HTTP receivers
reported the originating workload's IP address. Simultaneous simulator 0
captures of the initial 10 ICMP requests and replies in each direction showed
the original source and destination on both ingress and egress. Simulator 1
did not observe those packets, so this is not a failover test.

Each workload passed 5/5 Internet ICMP requests, one UDP and one TCP DNS
query, and an HTTP request. Simulator 0 observed each original customer
source before permitted Internet SNAT, and the customer destination restored
on the return path. HTTPS to one Microsoft endpoint passed 21/23 attempts
from workload A and 23/23 from workload B. A later repeat passed 10/10 per
workload to that endpoint and 10/10 per workload to a second endpoint. The
two earlier timeouts remain unexplained.

VPN connections had no attached NAT rules; the workload guests had no NAT
hooks, and both simulators' existing NAT configuration excluded RFC1918
east-west destinations. The provider gateway learned both workload prefixes
via BGP. Both VPN sides reported Connected after the probes. The provider
gateway's BGP metric was 1 in the observed five-minute samples after tunnel
establishment, although its reported peer connected-duration repeatedly
returned only a few seconds while the customer peer reported a longer
duration. Existing provider gateway diagnostics also recorded two IKE errors
during the test window; their cause and any relationship to the HTTPS timeouts
are not established.

The test did not change routing, NSGs, firewall rules or NAT. Temporary packet
captures were removed, and the earlier lab's delivery VPN remained connected.
Internet ingress was not tested because no workload publishing rule was
configured. These are bounded Ubuntu-simulator results, not qualification of
Check Point enforcement, sustained reliability or failover.

## EW-32: parallel provider gateway and Route Server probe

On 2026-11-02, an isolated provider-only VNet was used to test concurrent
creation of an active-active managed VPN gateway and a managed Route Server.
Both succeeded: the gateway took 28 minutes 3 seconds, the Route Server IP
configuration took 14 minutes 38 seconds, and the containing deployment took
28 minutes 14 seconds. For context, lab 14's provider ingress gateway and
Route Server modules ran sequentially and took about 29 and 16 minutes,
respectively. These are different deployments, not a controlled end-to-end
comparison.

Afterward, isolated VNet peerings, a reserved private NIC address and a
Route Server BGP-peer resource were created successfully. There was no BGP
speaker, customer VPN, firewall traffic or address-preservation test in this
probe. It supports a default-off scheduling candidate, but does not qualify
the candidate end to end or establish real Check Point behavior. The named
probe resources were removed after the test without deleting a resource group;
the existing lab 12 and lab 14 delivery connections remained connected.

## EW-33: provider-only managed resource-group probe

On 2026-11-02, with explicit provider-side approval, the Managed Applications
resource provider was registered in the provider subscription. A service-catalog
test application created a new provider-managed resource group containing an
unassociated test route table. A provider identity received Reader on that
managed group; no customer identity or cross-tenant Azure access was granted.
An intentionally synthetic secure parameter was not visible in either of two
management reads. This is not a full secret-handling qualification.

The test definition used a ReadOnly managed-group deny assignment. The provider
Owner was denied permission to add a group-level deletion lock, and the denial
was not bypassed. A CanNotDelete lock was added to the test application itself
because deleting the application would also delete the managed group. The test
application and managed group were deliberately retained. Existing-group
collision behavior, worker deployment permissions and safe lifecycle handling
remain unverified, so this is not a working on-demand provisioning solution.

## EW-34: scoped managed-application identity probe

On 2026-11-02, a new provider-only service-catalog definition with a ReadOnly
deny assignment granted a test managed identity Network Contributor on its
managed group. An Azure Container Instance with no public IP used that identity
to create an unassociated route table in the group. A separate write targeting
the provider control group was denied with an authorization error. This validates
those two operations only; it does not qualify the actual worker's full network,
compute, deployment, or secret permissions.

A temporary custom role permitted the test identity to read and write managed
applications and read definitions at the provider control-group scope, without
subscription-level resource-group write or application delete permissions. The
identity's request created a second managed application and group. The CLI
failed while polling the subscription-scoped asynchronous status endpoint; the
application subsequently reached `Succeeded`, and the same identity could read
that state through the group-scoped application endpoint. A temporary
subscription-scoped status-read role did not make a separate status read
succeed; the service could not verify the original caller. This does not yet
qualify retry, error reporting, crash recovery or polling for failed operations.

ARM validation accepted a request referencing the first test's existing managed
group, but no create was attempted against it. Validation is not evidence that
the create would reject a collision or preserve an existing group.
An application create request that omitted `managedResourceGroupId` was rejected
with `InvalidApplicationManagedResourceGroupId`, so the service did not supply
an automatic group name in that test.
`CanNotDelete` is not accepted as a service-catalog definition lock level in
this subscription; `ReadOnly` and `None` were reported as supported.

The test container and the two temporary custom roles and assignments were
removed. The two test applications, their CanNotDelete locks, their managed
groups, the definition and the test identity remain in the provider subscription.
The first group retains its unassociated route table; the identity retains
platform-granted group-scoped Network Contributor and application-scoped
operator roles. No resource group was automatically deleted. The earlier
EW-33 application and group remain protected; its definition was removed during
the user's separate cleanup. No customer subscription or traffic was involved.

## EW-35: managed-application collision and conditional-write probe

On 2026-11-02, a new provider-only fixture application created a managed group
with no workloads, using a separate test definition with lock level `None`.
Both the fixture application and its group received CanNotDelete locks. A
sentinel tag and an unassociated route table were added inside the group. No
existing deny assignment was changed or bypassed.

The group could not be made unmanaged: setting `managedBy` to null left it
unchanged, and setting it to an empty string returned
`ResourceGroupManagedByMismatch`. A second application targeting the fixture
group failed with `ApplicationManagedResourceGroupAlreadyExists`; the error
stated that a new application must reference a group that does not already
exist. The original managed group, owner, sentinel tags, route table and group
lock were still present after the rejection. This test involved an already
managed group, so it does not independently establish behavior for an existing
unmanaged group or a concurrent creator.

A separate conditional PUT to the existing fixture application, with
`If-None-Match: *`, was accepted and changed that application's test tag. Thus
conditional PUT did not provide create-only protection for the application
name in this test. The update started an ARM deployment in `Complete` mode;
the group-level CanNotDelete lock protected the sentinel route table. The
deployment was explicitly canceled and its state verified as `Canceled`; the
application subsequently reported `Failed`. The group, route table and
deletion locks remained present. Do not rely on managed-application group
collision rejection alone to protect an existing application from an update.

Another fixture used an explicit Incremental deployment policy. An attempted
conditional PUT to its existing application with a different, protected fixture
group returned `ApplicationManagedResourceGroupMismatch`; that application was
not rebound. This does not establish safety if an existing application already
has the same target group.

The newer `2023-07-01` resource-group API also accepted an `If-None-Match: *`
PUT against the owned fixture and changed a test tag. The original fixture tags
were restored afterward. This API version is therefore not a qualified
create-only alternative either.

The fixture definitions, applications, groups, sentinel route table and locks
are retained for investigation; no resource group was automatically deleted.
This is provider-only evidence, not an end-to-end provisioning or networking test.

## EW-36: protected application host and scoped deployment

On 2026-11-02, a provider-only managed application created a separate host
group with a ReadOnly deny assignment. The assignment explicitly excluded one
provider test identity, and also included a condition based on whether the
subject resource ID starts with the host-group scope. Its effect on identities
associated with resources in that group has not been qualified; the host is
not yet proven to be exclusive. The identity received a custom role on that
group granting managed-application read/write and group read, but
not application delete or subscription-level group write. A CanNotDelete lock
and a separate ReadOnly lock on the host application protect the host's group.
An attempted tag update of the host application was rejected with `ScopeLocked`;
the host and child application still reported `Succeeded`. This was a new test
group; the earlier deny assignment and protected applications were not modified.

The test identity created a child application in the host, and Azure created
its separate managed group. With only Reader granted in the child group, the
child failed: Azure reported that `Microsoft.Resources/deployments/write` was
missing in that group. That failed application and group were retained; the
group has a CanNotDelete lock.

A second child definition explicitly used Incremental mode and granted the
test identity Network Contributor in its new group. The same identity created
the second child application and group, and the managed deployment reached
`Succeeded`. The child group's `managedBy` matched the child application and
its ReadOnly deny assignment explicitly excluded the designated test identity
and contained a similar subject-resource condition. An additional Incremental
ARM deployment by that identity created an unassociated route table in the
child group. These tests did not deploy the firewall stack, VMs, customer
connections or secrets.

For diagnosis, a temporary subscription-scoped role granted only
`Microsoft.Solutions/locations/operationStatuses/read`. Capturing and polling
the operation URL with the original identity produced the missing deployment
authorization error and later the successful status. The temporary status role
and test container were removed. The host application, host group, child
applications and groups, test identity, their required scoped roles, definitions
and route table remain. The host application is locked; the system deny
assignment and non-delete host role restrict child-application deletion. The
second child group has a ReadOnly deny assignment; no attempt was made to
bypass it to add a group lock. No group was automatically deleted.

This is a candidate for an exclusive provider-side host, not a released
provisioning implementation. Existing unmanaged-group collisions, concurrent
and crash recovery, the deny-assignment conditions, protecting against
unauthorized application updates, actual worker compute/network permissions,
secret handling and full end-to-end traffic remain unqualified. Isolated mode
remains disabled by default and requires explicit lab-risk approval.

## EW-37: deployment-stack host protection probe

On 2026-11-02, a provider-only deployment stack took management of an existing
test-owned provider group.
The stack was configured with `detachAll`, `denyWriteAndDelete`,
`applyToChildScopes: true`, and one excluded test identity. Its generated
deny assignment nevertheless reported `doNotApplyToChildScopes: true` and
included a deployment-stack service condition. A deliberately invalid
application PUT at the child scope reached the application resource provider
and failed because no managed-group ID was supplied; no application or group
was created. This does not provide the required exclusive host protection.

An attempt to lock the test stack using `az lock create --resource <id>`
mistakenly created a ReadOnly lock at the provider subscription scope. The lock
was removed immediately after the scope error was discovered, and its absence
was verified. The activity log showed it was created at 10:12:13 UTC and
deleted at 10:12:57 UTC; a bounded failure query for that interval showed only
the test's own blocked PUT. Activity logs can be delayed, so this is not proof
that no other operation was affected. A separate lock was then created by its
exact ARM resource scope and verified on the stack itself.

The test stack, its ReadOnly lock, the test group, the host application locks
and the scoped identity role assignment remain. No resource group was
automatically deleted. Do not remove the stack's deny assignment or bypass it
by switching identities to clean up the fixture.

## EW-38: user-approved managed-group lab probe

On 2026-11-02, the user explicitly accepted the lab-only risk associated with
Azure's subject-resource deny condition in the provider host and each provider
environment group, and the residual application-name race. This does not
authorize customer/provider Azure management access, east-west NAT, per-VNet
provider configuration, or automatic resource-group deletion.

The actual experimental allocator ran in a provider-only test container using
the designated provider managed identity. It verified the locked host and
definition, their permissions and the exact approved Azure deny condition, then
created a new managed application and a new provider resource group in the
requested region. Azure granted Network Contributor and Virtual Machine
Contributor only on that group, and the allocator verified the binding and
roles. A read-only subscription-scoped permission to read resource-group
metadata was needed to check the target group before creation; no
subscription-wide group write permission was granted.

A second run against the owned fixture rejected an existing application, then
rejected an existing group for a different operation. It recovered the owned
group, including the in-progress binding case, without issuing an application
write. A separate clean provider host and dedicated identity subsequently
created another new group in the target region with the same checks and scoped
roles. These are bounded collision and
recovery checks, not proof against concurrent hostile name races. The test
groups and their managed applications are retained; no group was automatically
deleted. This test did not deploy gateways, firewall VMs, customer networking,
VPN secrets, or end-to-end traffic.

## EW-39 isolated-group recovery in progress

The customer-15 foundation completed and Azure created its dedicated provider
managed group, but the provider operation failed with `GroupOwnershipError`
before the provider network deployment started. A later read-only verification
passed the group ownership and permission checks. The stored error did not
identify which check failed, so delayed propagation is a possibility, not a
proven root cause.

The source now waits briefly for missing initial group ownership metadata and
missing expected permissions, without accepting mismatched identities, deny
assignments or extra roles. It adds a single customer-authenticated retry of an
eligible failed operation, preserving its original group, allocation, active
limits and lease fencing. Local regression tests passed. The compatible worker,
API and management packages were published; the worker reported healthy and the
API's new retry endpoint rejected an unauthenticated request. Provider/customer
parallel deployment is not enabled, and no deployment-time reduction has been
demonstrated here.

A customer-15 retry was submitted with an older customer connector despite the
release rollout. The customer canceled its root deployment; the nested
connector subsequently failed, and no provider network deployment was started.
The cause of the old template selection is not established. The next management
package checks the compiled network connector before publishing a profile and
labels the matching Portal form as a recovery-enabled release.

After refreshing the management page and issuing another link, the customer
confirmed the recovery-enabled form title and submitted a retry. The exported
template contains the recovery connector, and the non-secret deployment settings
match the previous attempt. Customer authorization and the existing foundation
completed. The provider network deployment succeeded in the original dedicated
group with the original operation ID, and the customer deployment succeeded.
The retry took approximately 60 minutes, including 47 minutes 34 seconds for
provider networking; it reused an existing customer foundation and is not a
fresh-deployment performance comparison.

All four VPN connections reported Connected. The customer delivery BGP peer
reported Connected and received two routes. Each workload passed 10/10
east-west ICMP requests and 5/5 HTTP requests to the other workload; each HTTP
receiver observed the original workload source address. Both workloads passed
5/5 Internet ICMP requests, UDP and TCP DNS queries, and 3/3 HTTPS requests.
Their effective routes pointed east-west and Internet traffic to the customer
Routing Appliance, whose routes pointed to the customer ingress gateway.
No VPN NAT rule attachments were reported, and the customer workload guests'
iptables NAT tables contained no rules.

Azure's managed-application deny assignment blocked operator VM Run Command
on the provider simulators and the provider BGP-status action. Therefore
simulator packet captures, the actual firewall-side addresses, provider BGP
peer state and guest NAT configuration were not independently verified. This
is a bounded Ubuntu-simulator result, not a real Check Point, Internet ingress,
failover, sustained-reliability or production qualification.

After the user requested lab 15 deletion, the customer-side resources and the
lab identity's two group-scoped role assignments were removed. The customer
resource group remains and a resource inventory returned empty; deployment
history was retained. The provider managed group and its resources remain:
Azure's system-protected deny assignment blocks operator deletion, and deleting
the managed application would automatically delete its managed group. Provider
resources, including gateways and VMs, may continue to incur charges. The
provider operation and allocation records were not changed.
On a later user request, a fresh customer resource inventory and subscription
resource search were empty. A direct operator attempt to delete one provider
lab VM failed with `DenyAssignmentAuthorizationFailed`; the protected provider
resources and managed application remained. The empty customer resource group
and deployment history were retained.

## EW-40: Check Point runner image and publisher-identity probes

Date: 2026-11-03. Provider subscription only; no customer resources, Check
Point VMs, firewall policy or traffic were involved.

- Created a provider-only control group with a Basic ACR (admin user and
  anonymous pull disabled; public endpoint with Entra/RBAC-only pulls, as
  approved by the user for this lab).
- Built the runner image in ACR Tasks from a verified context: pinned
  Terraform 1.15.7, Linux provider packages matching the lock `h1` hashes,
  pinned modules and 39 hash-locked wheels. Digest
  `sha256:0ea2891d01474d9455fda3913b1adda3dca0309103bf0259b19de3c90c5b5d5b`.
  The first build (`sha256:0a88ff9d…`) was rejected by the Linux smoke test
  because the non-root user could not read 0700 artifact directories.
- A disposable ACR Task ran the image on Linux as UID 65532: Terraform and
  provider path protections passed; a kernel `memfd` seal blocked writes and
  resizing while a child process read the plan through `/proc/self/fd`; and
  `terraform version`, an offline `init` from the read-only provider mirror
  and `validate` succeeded. ACI, private DNS and the Azure backend were not
  exercised.
- Created a dedicated Check Point publisher identity and a separate
  ReadOnly-locked managed-application definition with eight built-in roles.
  A probe application created an isolated group in East US 2. Azure assigned
  all eight roles to that identity, and the system deny excluded only it.
- The operator's write in that group returned
  `DenyAssignmentAuthorizationFailed`; an ACR Task using the Check Point
  identity created a probe NSG there. The Ubuntu definitions and identities
  were not changed.
- Retained: control group, registry, image, identity, definition, probe
  application and its group with the probe NSG. Deleting the probe
  application would delete its managed group and requires separate approval.

## EW-41: Real Check Point VMs and post-boot configuration by the runner

Date: 2026-11-03. Provider subscription only, in the EW-40 probe group with a
security-network-only foundation (no VPN gateways or Route Server). No
customer resources or traffic were involved.

- The runner ran in ACI in the environment's automation subnet as the Check
  Point identity. It created the private credential, used private Terraform
  state and passed the plan guard. ACI with a VNet accepts only
  `securityContext.privileged`; non-root execution comes from the image.
- Real AzureRM 4.73.0 plans differed from mock plans: the unused image `id`
  and backend NIC public IP are `""`, NIC and data-disk lists are computed on
  create, and `custom_data` is `sha1(base64(...))`. Unchanged VMs report
  `custom_data` and the management password as `""`. The guard re-renders the
  pinned bootstrap and accepts these shapes only where they are safe. It
  reports constant labels, expected addresses, action verbs and schema keys.
- The subscription adds a platform IP tag to new public IPs. Because
  `ip_tags` forces replacement, the module overrides ignore it.
- `Standard_D4ds_v5` and `Standard_D4s_v5` failed with East US 2 capacity
  `SkuNotAvailable`; probes showed the F series available. The gateway runs
  on `Standard_F4s` and management on `Standard_F8s` (both module-supported).
- Image `sha256:f64fc89c…` (logic unchanged in r12 `sha256:b2615bb5…`)
  completed with exit 0. Log: infrastructure ready, management API ready
  (TLS pinned in the private vault on first use), gateway SIC communicating,
  approved baseline policy installed, BGP configured for both configured
  peers with 0 established (no Route Server in this group).
- The installed baseline is the user-approved lab policy: RFC1918 to RFC1918
  accept and log with a manual no-NAT rule; RFC1918 to non-RFC1918 accept and
  log with automatic hide NAT; cleanup drop and log. BGP mirrors the
  simulator: ASN 65050, multihop eBGP to both Route Server peers, no route
  import, and export of only the static default route. Licensing uses the
  Check Point trial period.

## EW-42: Check Point option enabled on the live provider host

Date: 2026-11-03. Provider control resources only.

- Created `faas-cp-env-def-ee498f03` in the host parent group with the same
  eight Check Point publisher authorizations. Granted the existing group
  identity Reader on it and a new read-only role at subscription scope
  (`roleAssignments/read`, `denyAssignments/read`). Existing roles were not
  broadened.
- The worker also requires a **ReadOnly** management lock on the definition.
  The first customer-16 network request failed with `GroupOwnershipError`
  (`OtherOwnershipCheck`) before any group was created, because the definition
  had only a CanNotDelete lock. It now has a ReadOnly lock, as the Ubuntu
  definition does.
- The shared B1 App Service plan (API, worker and management) ran at 80–87%
  memory and peaked at 97%; the management app then failed its startup probe
  and returned 503. The plan was scaled to B2 and Always On was restored on
  the management app; all three apps then answered health checks.
- Attached the Check Point identity to the worker. The release package
  `ac60cdb4…` (Ubuntu provider template still `dfcee6f4…`) was deployed with
  ARM OneDeploy to the API, management and worker. Check Point settings were
  validated locally against that package before they were enabled.
- The worker failed its first startup probe and stayed stopped: Always On
  had drifted to false and public access is denied, so nothing woke it.
  Restoring the template's `alwaysOn: true` brought it up. Worker and API
  console logs now go to `law-faas-admin-ee498f03`.
- The customer form now offers "Check Point CloudGuard BYOL (lab preview)".
  A Check Point customer waits up to 14,100 seconds (`PT4H` script timeout);
  Ubuntu keeps 6,900 seconds (`PT2H`). A full customer deployment with Check
  Point has not run yet.

## EW-43: Customer-16 ping bypasses the intended Check Point path

Date: 2026-11-04. This is a failed inspection-path test, not a successful
Check Point east-west traffic qualification.

- SmartConsole showed management-server control/system events, not gateway
  traffic records. This alone does not distinguish missing log forwarding
  from traffic bypassing the gateway.
- A fresh customer workload test sent 90 ICMP requests from `10.211.0.4` to
  `10.212.0.4`: all 90 succeeded, with roughly 2.9 ms average round-trip time.
- At that time the customer group had no VPN connection resources. Both
  provider connections reported zero ingress and egress bytes; the inspected
  ingress connection reported status `Unknown`.
- The source NIC's effective route for the destination points at the
  customer Routing Appliance. Its subnet has the intended egress route table
  attached. Those control-plane settings do not demonstrate traversal.
- Therefore this ping did not traverse the intended customer-to-provider
  VPN/Check Point path. The exact customer-side forwarding bypass and gateway
  log destination still require separate diagnosis. Existing runner success,
  BGP establishment and installed policy must not be presented as end-to-end
  inspection proof.
- Gateway log-forwarding diagnostics independently confirmed
  `Log-Server Disconnected` and local buffering. The management object used
  its public IP as the log destination. After changing that object to its
  private management IP, database and policy installation succeeded, but
  forwarding still failed: traffic used the gateway backend interface.
- Saved a provider-infrastructure route for `172.22.30.0/24` via
  `172.22.10.1` on the frontend interface. The management log listener on
  TCP 257 was running throughout. After the route correction, TCP sessions
  established, the gateway reported `Log-Server Connected` and
  `Security Gateway is reporting logs as defined`, and a management API
  query returned traffic logs whose origin was the Check Point gateway.
  No anti-spoofing control was disabled, no NAT was added, and user policy
  rules were preserved. These were live repairs; the runner image has not
  yet been updated with management-address and management-route reconciliation.
- The 10:18 customer retry still failed before customer VPN creation. A direct
  run of the worker's observer against the completed Azure container reproduced
  the failure: ACI had released its private IP after termination, even though
  the container had exit code 0, restart count 0, and valid subnet, identity,
  configuration and image evidence. The observer incorrectly required a
  currently allocated IP for terminated containers.
- The observer now permits the absent IP only for validated terminal results;
  running containers still require their private IP. Regression tests passed,
  the live container now validates as completed with exit code 0, and the
  corrected worker package deployed successfully. No runner was relaunched,
  no VPN keys were changed, and the existing customer/provider environments
  were retained. This does not yet establish connected VPNs or inspection.
- The subsequent 10:29 customer deployment succeeded. Both customer and both
  provider VPN connection resources then reported `Connected`; the customer
  delivery BGP peer also reported `Connected`. Fresh post-VPN pings failed,
  while a gateway capture observed the original workload ICMP requests.
  Inspection and bidirectional forwarding are therefore not yet qualified.
- Once the VPNs connected, the management NIC's active default route pointed
  at the provider delivery VPN gateway. Public administrator replies were
  consequently sent toward the VPN. Added a management-subnet route table
  with Internet next hops for only the two approved administrator `/32`
  addresses. Effective routes confirmed those exceptions active alongside
  the retained VPN default and customer routes. The management HTTPS endpoint
  again reached the TLS certificate check; its self-signed certificate remains
  untrusted by the integrated browser. No NSG allowlist, VPN connection,
  customer route or firewall security policy was changed for this repair.

## EW-44: Customer-16 bidirectional Check Point traffic checks

Date: 2026-11-04. Bounded follow-up to EW-43 after all four VPN connection
resources reported connected. This does not erase the earlier bypass or
establish fail-closed behavior.

- New workload checks passed 20/20 ICMP requests in each direction between
  `10.211.0.4` and `10.212.0.4`, with no loss in either measured run.
- Five HTTP requests in each direction reached the existing workload proof
  service on port 8080. The destination returned the unique test path and
  the original source address: `10.211.0.4` for A-to-B and `10.212.0.4` for
  B-to-A. All ten source-address assertions passed.
- A private, TLS-pinned management API query returned gateway-originated
  traffic records showing the original workload addresses and action
  `Accept` on `faas-east-west`. Earlier records for the same pair showed
  `Drop` on `Cleanup rule`. The diagnostic did not change the access policy;
  the cause of the policy-match transition has not been established.
- A follow-up query correlated all ten HTTP tests with gateway `Accept`
  records on port 8080 in both directions. The original source/destination
  addresses were retained in those records, and no translated source or
  destination was reported.
- An HTTPS Internet-egress request from each workload returned the gateway's
  public IP, not the workload public IP. This is a bounded egress check, not
  Internet-ingress or full north-south qualification.
- Earlier gateway captures observed original-address workload ICMP requests.
  Together with the successful receiver checks and gateway logs, this is
  evidence of bounded east-west connectivity and original source-address
  preservation, not just an ARM success or an unverified ping.
- Not covered: selective policy-denial/recovery controls, simultaneous
  ingress/egress packet captures for the successful flows, customer VNet
  addition/removal against the real gateway, failover, full north-south tests,
  licensing longevity, or proof that traffic cannot bypass the firewall when
  the VPN path is unavailable. Those remain separate qualification gates.

## EW-45: Administrator allowlist release and bounded runtime qualification

Date: 2026-11-04. Code-only follow-up to EW-44; no new customer environment
was created and no existing lab networking was redeployed.

- Provider tests: 1,308 passed, 2 skipped; repository tests: 42 passed.
  Publication safety passed for 276 files.
- The new pinned Linux runner verified Terraform/module/provider artifacts
  and parsed the nonempty allowlist using runtime schema 2. Empty allowlists
  retain schema 1 and legacy request digests.
- A private, TLS-pinned management API test accepted the real R82 top-level
  log-destination response and verified the private management object address.
  Management-target `run-script` successfully executed additive
  `cp_conf client add/get` logic for the already approved sources. All existing
  client tokens and the automation client range remained present. Gateway
  policy, SIC and BGP were not changed by this qualification.
- The API, worker and management code uploads completed successfully. The
  worker's runner-image and bundled-foundation hashes were read back, with
  unchanged Ubuntu, private-data and Terraform pins. Existing settings were
  preserved except for those pins and the approved management defaults.
- Public API/management health checks passed. The protected worker still
  denied public requests, as configured; its existing internal Azure health
  metric reported 100%, the instance was READY and application startup
  completed after matching-pin activation. No access restriction was relaxed.
- A fresh customer deployment link was issued by the live management app.
  Both linked artifacts returned HTTP 200. The ARM defaults and comma-separated
  form field contained the two configured sources; the field remained
  Check-Point-only and Ubuntu remained the default firewall. The API credential
  parameter remained secure without a default, and no credential was embedded
  in the link. Signed artifact URLs and credential values were not recorded.
- ARM validation/build passed, but what-if could not read the write-only
  OneDeploy extension with either tested API version or ResourceIdOnly.
  The operator explicitly approved the existing native code-only upload method
  with this limitation documented; the preview failure is not called a pass.
- The existing customer environment still reported Ready with no
  decommission request. The temporary qualification container was deleted;
  the original completed runner and environment records were preserved.
- Still unqualified: a full new-environment deployment with public gateway,
  management/SmartConsole and customer-VM access after VPN convergence.
  EW-44 traffic evidence remains bounded to its recorded runs. This release
  does not add VMSS, HA, fail-closed proof or parallel appliance/VPN provisioning.

## EW-46: Provider Reveal credential connection details

Date: 2026-11-04. Extend the existing provider **Reveal credential** action,
without introducing a new unprotected credentials page or changing gateway
authentication.

- Provider tests: 1,342 passed, 2 skipped; repository tests: 42 passed.
  Publication safety passed for 280 files. Tests cover ownership, explicit
  missing details, wrong/retired bindings, provider-only relay authentication,
  request-Origin enforcement, no-store responses, redirect rejection, no SIC
  transfer and temporary browser clearing.
- The new pinned Linux runner verified prepared artifacts and schema 3.
  A real provider managed-identity token was authenticated using issuer keys
  and the exact application verifier. The initial probe found that v2 tokens
  omit optional `xms_mirid`; exact signed tenant/object/client/audience binding
  remains mandatory and any supplied resource-ID claim must match.
- The bounded live relay read the existing environment's private credential
  and exact owned public-IP resources, then stored only management access
  details in the existing private management vault. The relay completed with
  exit 0. Its identity was separately denied access to the administrator
  customer-list endpoint. No SIC key, guest script, password reset, public
  vault access, directory consent or customer Azure permission was introduced.
- Customer authority read the existing customer-foundation Routing Appliance
  output. Provider authority registered that address as display metadata for
  the owned environment; it was not guessed from a subnet or used to change
  provider routing. New customer connectors register the service-assigned
  address through their own API binding without changing request digests.
- All three code uploads succeeded. Automatic relay remained disabled until
  the live private relay and administrator reveal passed, then the matching
  image/relay settings were enabled and Check Point readiness restored.
  All other app settings were preserved; Always On/Python settings were read
  back. No existing environment runner was relaunched.
- The actual existing **Reveal credential** button displayed the customer UDR
  next hop separately from provider frontend/backend addresses, both HTTPS
  links, usernames, SSH commands and the stored management password with
  show/copy controls. Gateway authentication remained the provider SSH key;
  the panel did not claim a managed gateway web password.
- The real browser automatically hid the panel and cleared its API credential,
  removed the management-password input and removed connection details after
  the reveal interval. Credentials are not persisted in browser storage or
  copied into this register.
- As in EW-45, code publication uses the approved native OneDeploy method;
  ARM's unavailable preview for that write-only operation is not called a pass.
  This is connection-detail delivery qualification, not a new environment,
  gateway-login, fail-closed, VMSS or customer-VNet-lifecycle qualification.

## EW-21 customer-independence continuation

**Bounded RFC1918 lifecycle demonstrated, with an interruption caveat.** A fixed
provider PRE/firewall/POST path was configured once and fingerprinted, including
cloud models, guest routes/rules, persistent configuration and WireGuard settings.
A real new customer VNet/subnet/VM at `192.168.77.0/24` was created, connected and
removed using customer-side changes only.

Five traffic phases passed: 24 correct-receiver/original-source deliveries and
six selective denials, with recoveries and packet evidence. No provider drift
was detected during those phases. Workstation DNS failure interrupted an initial
attempt; a later unexpected VM shutdown interrupted final removal validation.
After user-approved restart, removal tests passed: deleted-prefix terminal
rejection, no bounded-TTL recirculation, healthy original A/B controls, all eight
owned temporary resource IDs absent, temporary A UDR removed.

A redundant DHCP INPUT allow disappeared from the provider router after reboot
while INPUT remained ACCEPT. All other compared provider configuration matched;
this difference was audited, not used to reset the original freeze. Final
evidence is therefore combined across runs, not an uninterrupted lifecycle pass.
Five original VMs and four VNets are retained; a tenant-generated subnet NSG
was left unassociated rather than deleted outside the journal's allowlist.

Provider topology/routing/NSG/WireGuard settings needed no per-VNet update.
Operational firewall test flags and finite captures are explicit measurement
exceptions. Only nonoverlapping RFC1918 IPv4 is covered, not public prefixes,
overlapping tenants, real Check Point or production multi-customer isolation.
See [the archived EW-21 guide](../archive/prototypes/ew21-ubuntu-overlay.md#customer-independence-continuation).

## Not yet executed or qualified

- Dynamic BGP onboarding/withdrawal, long platform-convergence behavior and
  cross-tenant end-to-end ownership qualification. Both EW-17 bounded local
  tunnel-interruption checks and functional inspection passed; those narrower
  results do not qualify these remaining cases.
- Real Check Point/CloudGuard, licensing and supported ownership/onboarding.
- Twenty-VNet or fleet-scale deployment and dynamic membership.
- HA, production throughput, MTU/load qualification, IPv6 and overlapping
  environments for the proposed VPN service.
- Service Association Link onboarding and live foreign-disk attachment.

## Evidence and publication

The historical summary, deployment guides and private local reports/results
are the evidence sources for this register. Exact run mappings and the active
retention manifest remain in the private managed-lab guide/results. Never
publish keys, PSKs, tokens, raw captures, account mappings or live inventories.
No historical result here authorizes another deployment or resource deletion.
