# EW-17: successful prototype, firewall terminates IPsec

**Disposition:** measured functional success, but **not the required design**.
The firewall must simulate Check Point forwarding/filtering without running
site-to-site VPN. EW-17 used Ubuntu/strongSwan to terminate both tunnels.
Its results remain useful evidence; they do not qualify Azure-managed VPN
termination on the provider side.

## Tested path

```text
source -> one managed Routing Appliance -> customer ingress VPN gateway
       -> IPsec -> Ubuntu xfrm0 -> filtering -> xfrm1 -> IPsec
       -> customer delivery VPN gateway -> destination
```

Each workload VNet peered with both customer hubs. No customer/provider VNet
peering was used. The old provider Azure VPN gateway remained deployed for
controls/management, outside this inspected E-W path.

## Measurements

| Test | Observation |
| --- | --- |
| Allowed original-source HTTP / correct receiver | 6/6 |
| A-to-B selective denial | 3/3 denied; reverse 3/3 allowed |
| B-to-A selective denial | 3/3 denied; reverse 3/3 allowed |
| Allow restoration | 6/6 |
| Low-TTL ICMP in enforcement matrix | 16/16 replies |
| Bounded ingress-SA/UDP interruption | 0/6 HTTP as expected; local controls healthy; recovered 6/6 |
| Bounded delivery-SA/UDP interruption | 0/6 HTTP as expected; local controls healthy; recovered 6/6 |
| Final capture | 520 E-W packet lines, no correlated recirculation |

The final fault-check completion referenced the already-passed enforcement
matrix instead of repeating it. VM shutdowns, a graceful IKE-deletion timeout,
an ARM GET 503 and a local DNS interruption were recorded separately; none
invalidated the successful functional observations.

## Boundaries

- `xfrm0` and `xfrm1` carry cleartext inside Linux; `eth0` carries encrypted
  UDP/4500. An `eth0`-only ICMP capture misses the inspected inner traffic.
- Fault tests were bounded local SA/transport interruptions, not BGP withdrawal,
  long-outage convergence or HA qualification.
- Guest xfrm interfaces/routes/filtering were runtime state; automatic reboot
  recovery was not implemented or qualified.
- IPsec is tenant-independent. This particular deployment used one physical
  test tenant; cross-tenant ownership/onboarding was not exercised end to end.
- No real Check Point, performance or twenty-VNet deployment was qualified.

The corrected gateway-offloaded candidate is **EW-18**. See the
[test register](../../docs/test-register.md) for its actual result and
[main README](../../README.md) for the current configuration. Do not treat
historical retention of EW-17 as a current-state assertion after cutover.
