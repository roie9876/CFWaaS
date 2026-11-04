# Customer vWAN to provider IPsec simulator experiment

**Experimental simulator harness.** See [option 6](../deployments/06-customer-vwan-ipsec/README.md)
for the measured disposition. A successful run would not qualify CloudGuard.

This lab was decommissioned on 2026-10-19. The retention behavior documented
below is the harness's failure policy for separately authorized new runs, not
evidence of a currently retained deployment. See the
[final research summary](../../../docs/final-summary.md).

Customer tenant B owns the vWAN, managed S2S VPN gateway and two private workload
VNets. Provider tenant A owns a separate Ubuntu/strongSwan firewall simulator.
There is no cross-tenant VNet peering or provider Azure VPN Gateway.

Intended inspected flow:

```text
Customer B: workload VNet 1
    -> customer vHub (inspection association)
    -> managed S2S VPN / IPsec
Provider A: Ubuntu firewall simulator (decrypt, filter, re-encrypt)
    -> same managed VPN attachment
Customer B: vHub default delivery table -> workload VNet 2
```

The return path is symmetric. A connected tunnel alone is not acceptance.
The experiment must demonstrate distinct effective next hops, correct private
HTTP sources, low-TTL ICMP, successful-flow SYN counters, selective
firewall blocking while IKE remains established, and recovery.

Packet counters include legitimate TCP retransmissions; a count larger than the
number of HTTP requests is not, by itself, evidence of a routing loop.

## Default-only BGP revision

The first static-site attempt was rejected with
`ConnectionOverlappingAddressSpaces`: a declared remote-site customer subnet
overlapped the actual customer VNet. It established **no IPsec tunnel**.
Two successful HTTP requests before the failure were only native-vWAN baseline
traffic, not inspection proof.

The BGP revision reuses the held hub and VMs:

- A new VPN gateway references the existing customer hub. Its assigned public
  and BGP addresses are discovered, not guessed or sorted independently.
- The provider exports **only `0.0.0.0/0`** over BGP.
- Customer VNet connections associate with an inspection table receiving the
  VPN default, not direct routes to the other workload VNets.
- The VPN connection associates with the default delivery table, which learns
  customer VNet prefixes from their Azure attachments.
- The provider learns private customer prefixes dynamically. Its initial
  policy uses a once-configured RFC1918 boundary, not per-VNet entries.
- Two active-active gateway endpoints have two bidirectional IPsec/BGP sessions,
  not separate pre-inspection/post-inspection service-chain tunnels.
- There are no customer UDRs, provider per-VNet static routes, or source NAT.
- Core resources are retained on error. Only the temporary lifecycle probe
  VNet/VM is removed as part of the requested route-withdrawal test.

`bgp_revision.py` is the new entrypoint. Its default mode is offline. Execution
requires an ignored approved `.azure/bgp-plan.json` binding the exact parent
run, account profiles and configuration. `bgp-plan.example.json` is disabled
and does not grant approval.

Acceptance blocks provider forwarding with IKE/BGP up, withdraws the BGP
default, and stops IPsec. Every condition must deny E-W traffic with locally
healthy servers; restoration must recover it.

The lifecycle test attaches a third private VNet, checks inspected traffic,
removes its attachment/resources, and verifies BGP route withdrawal. Provider
VPN, BGP and firewall-rule hashes must remain unchanged throughout.

Azure-side VNet attachment automation is still required. BGP does not attach
new VNets to a hub. The test covers non-overlapping private IPv4 workload
ranges, not arbitrary BYOIP, overlapping underlay addresses or application-policy
changes. Real CloudGuard and production HA remain separate qualifications.

## Safety and approval

Use the existing root setup instructions for an ignored A/B account profile.
For a fresh clone, create only a disabled local plan, without overwriting any
existing approval:

```bash
mkdir -p ipsec-vwan-lab/.azure
cp -n ipsec-vwan-lab/plan.example.json ipsec-vwan-lab/.azure/infrastructure-plan.json
```

The lab uses its reviewed `config.example.json` topology directly. Changing it
invalidates an approved plan's configuration fingerprint.

The no-argument command is offline:

```bash
python3 -B ipsec-vwan-lab/ipsec_lab.py
python3 -B ipsec-vwan-lab/validate.py
```

Execution additionally requires an ignored, explicitly approved
`.azure/infrastructure-plan.json`, exact local account/configuration binding,
`--acknowledge-billing`, and a deliberate cleanup/retention policy.
Resume and cleanup require the exact saved run. Do not infer fresh approval
from a previous unrelated lab's authorization.

Existing `.local/accounts.json` selects A/B. New resource groups use an exact
run-owned namespace and tags. Other runs, their approvals, shared workspaces and
unrelated customer networks are outside this entry point's cleanup scope.

## Secret handling

The per-run IKE PSK is generated locally and stored only in an ignored file with
mode `0600`. It is passed as a Run Command parameter, never embedded in cloud-init,
tracked source, output or evidence. Guest-script/parameter evidence is redacted.
Do not upload raw results or local account/approval files.

Azure ownership operations use the existing authenticated owner sessions, not
new guests, applications, directory permissions or IAM grants.

## Deliberate lab exceptions

- Single burstable Ubuntu simulator, not real CloudGuard or production HA.
- VM extensions remain enabled for authenticated Azure Run Command
  (`CKV_AZURE_50`).
- Both accounts' optional host-encryption feature is unregistered. Omit the
  property rather than registering features; managed OS disks remain
  platform-encrypted, and Trusted Launch/Secure Boot/vTPM remain enabled
  (`CKV_AZURE_97`, `CKV_AZURE_151`).
- The provider has a public VPN endpoint, with inbound UDP 500/4500 restricted
  to the discovered managed gateway public endpoints. No public SSH or HTTP.
- Workloads need no public IP, NAT gateway, package download or customer routing VM.
- IPv4 inter-VNet inspection only. No Internet egress, inbound publishing,
  throughput or automatic provider-HA qualification.

The revised default-only BGP steering and same-attachment hairpin are
**experimental**. No exact Microsoft production support statement was verified.
If actual routing/API validation rejects the pattern, record that failure;
do not hide it behind peering, source NAT or a different topology.
