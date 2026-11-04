# Monitoring and verification

An AVNM `Deployed` status is not a continuous guarantee of successful inspection.
Use four layers:

| Layer | Proof |
| --- | --- |
| Authorization | Cross-tenant consent and caller access are still valid |
| Applied intent | Correct membership, active configuration and regional deployment |
| Actual network | Connected/synchronized peerings, forwarding flags, subnet associations and destination-specific effective routes |
| Actual protection | Positive reachability, expected denials and firewall inspection evidence |

## Native events and their limits

AVNM categories include:

- `NetworkGroupMembershipChange`: VNet membership additions/removals.
- `ConnectivityConfigurationChange`: applied connectivity configuration changes.
- `RuleCollectionChange`: **security-admin** collection changes, not all manual
  UDR modifications.

Customer-side peering, route-table and subnet CRUD also belongs in that
customer subscription's Activity Log. Collection and alert delivery need
authorized setup. An existing diagnostic export is not proof of notifications.

For ordinary hub-and-spoke peerings, `peeringEnforcement: Enforced` can prevent
outside modification/deletion. It is not a firewall-health monitor. Do not
enable customer-operation restrictions without approval.

`UseExisting` explicitly does not track manual route modifications. Do not
assume a redeployment automatically repairs every customer route conflict.

## Proposed service model - not implemented

For each customer/environment/region, combine:

1. Event-triggered investigation of scoped resource changes.
2. Scheduled desired-versus-observed reconciliation.
3. Destination-specific effective-route checks, including more-specific bypasses.
4. Positive and negative synthetic probes plus firewall telemetry.
5. Incident notifications with explicit ownership and restoration procedures.

Report authorization loss, configuration drift, dataplane failure and stale
verification separately. Stale/unverifiable state is **Unknown**, not healthy.
A failed network must not pass merely because every expected-deny probe times
out; allowed probes must succeed too.

Monitoring identities need explicit approved cross-tenant access and diagnostic
actions. Do not assume a generic Reader role or manager consent supplies every
effective-route API permission.

## References

- [AVNM events](https://learn.microsoft.com/azure/virtual-network-manager/concept-event-logs)
- [Applied configurations](https://learn.microsoft.com/azure/virtual-network-manager/how-to-view-applied-configurations)
- [UDR management](https://learn.microsoft.com/azure/virtual-network-manager/concept-user-defined-route)
- [Peering enforcement](https://learn.microsoft.com/azure/virtual-network-manager/concept-connectivity-configuration#how-to-enforce-peering-by-using-azure-virtual-network-manager)
