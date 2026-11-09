# East-west performance test plan

Purpose: measure the **maximum east-west (E-W) throughput** and the **E-W latency
tail (p99.9)** between two customer workload VNets whose traffic is inspected by
the provider Check Point firewall.

Latest results: [E-W performance results](ew-performance-results.md).

Runner: [`scripts/ew_perf_test.py`](../scripts/ew_perf_test.py). It drives both
workload VMs through `az vm run-command`, so it needs only Azure CLI access to
the customer resource group, with no SSH or inbound rule.

## Path under test

```
workload-0 (10.211.0.0/16)
  -> UDR -> customer Routing Appliance (ingress VNet)
  -> customer ingress VPN gateway  ==IPsec==>  provider ingress VPN gateway
  -> Check Point VMSS (frontend/backend load balancers)
  -> provider delivery VPN gateway ==IPsec==>  customer delivery VPN gateway
  -> workload-1 (10.212.0.0/16)
```

Replies take the mirror path. Every E-W packet crosses four VPN gateways, two
IPsec tunnels, two Azure load balancers and one Check Point gateway.

## Expected limits (record the actual values)

| Component | What can cap the result | Where to read it |
|---|---|---|
| Customer VPN gateways | SKU aggregate/tunnel throughput. Subscription governance may downsize the requested SKU (for example VpnGw5AZ to VpnGw2AZ) | `az network vnet-gateway show ... --query sku` |
| Provider VPN gateways | SKU aggregate/tunnel throughput | provider environment group |
| Check Point gateways | VM size, number of running instances, and blades enabled; one IPsec-inspected flow is pinned to one instance | VMSS SKU/capacity, `cpview` |
| Workload VMs | VM size network bandwidth, accelerated networking | `az vm show` |
| MTU | Workload NICs may use MTU 9000, but the VPN path supports roughly 1,400 bytes; TCP must clamp MSS | `prepare` result `mtu`, iperf3 `--mss` |

A single TCP stream is usually limited by one IPsec tunnel and one firewall
core, so the sweep increases parallel streams until throughput stops growing.

## Preconditions

1. Both workload VMs are running, and both Check Point instances that should
   take part are running and healthy behind the load balancers (LB health
   probe on TCP 8117 reports available).
2. All four VPN connections report `Connected`, and the customer delivery BGP
   peer is `Connected`.
3. Firewall policy accepts E-W traffic for the workload ranges (service `Any`,
   or at least ICMP and TCP 5201), and is installed on every running instance.
4. The workload NSG allows private-range inbound (no custom deny above the
   default `AllowVnetInBound`).
5. Nothing else loads the path during the run.

The runner's preflight checks TCP/5201 and ICMP in both directions and
aborts before the load tests if E-W TCP is blocked.

## Test matrix

| ID | Test | Method | Output |
|---|---|---|---|
| EW-PERF-1 | Preflight | TCP connect to 5201 and 5 pings, both directions | pass/fail |
| EW-PERF-2 | Max throughput | iperf3 TCP, 30 s per run (3 s warm-up omitted), parallel streams 1, 4, 8, 16, 32, forward (0 to 1) and reverse (1 to 0) | Gbps received, retransmits, CPU |
| EW-PERF-3 | Idle latency | 20,000 ICMP echoes at 10 ms intervals (about 200 s), 56-byte payload | loss %, min/p50/p90/p99/**p99.9**/max ms |
| EW-PERF-4 | Latency under load | Same as EW-PERF-3 while iperf3 runs 8 streams between the same VMs | as above, plus load Gbps |

Why 20,000 samples: p99.9 is the 20th-worst sample out of 20,000. Fewer than
10,000 samples leave p99.9 decided by a handful of packets.

Percentiles use the nearest-rank method over received replies. Lost echoes
are reported as loss % and are not included in the percentiles.

## How to run

```bash
python3 scripts/ew_perf_test.py \
  --subscription <subscription-id> \
  --resource-group <customer-resource-group> \
  --client-vm vm-customer-workload-0 --server-vm vm-customer-workload-1
```

Useful options:

- `--streams 1,2,4,8,16,32,64`: extend the sweep if throughput is still rising at 32.
- `--duration 60`: longer runs for steadier numbers.
- `--mss 1300`: force a VPN-safe MSS if retransmits are high or throughput collapses.
- `--ping-count 50000 --ping-interval 0.005`: tighter p99.9 (about 250 s per latency run).
- `--skip-throughput` / `--skip-latency`: run one part only.

A full default run takes about 15 minutes. Results go to
`ew-perf-results/ew-perf-<timestamp>.json` and `.md`. That directory is
local output and must not be committed.

## Reading the results

- **Max E-W throughput** is the highest received Gbps across the sweep.
  Report it with its stream count and direction. If forward and reverse
  differ, report both.
- If throughput stops growing as streams increase, the path is saturated.
  Compare against the SKU limits above to name the bottleneck (VPN gateway
  versus firewall versus VM). Rising retransmits at the plateau point to
  drops at that bottleneck.
- **p99.9 latency**: report idle and loaded values. A large gap between
  idle p99.9 and loaded p99.9 means queuing at the bottleneck.
- Record each run in [test-register.md](test-register.md) with the
  environment details (VPN gateway SKUs actually deployed, Check Point VM
  size and running instance count, workload VM size), the exact command and
  the result table.
