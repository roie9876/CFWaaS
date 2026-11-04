# FaaS lab instructions

Apply these requirements to architecture, implementation, experiments, and live
operations across this repository. They apply to approaches being tested as
well as to the final solution. Do not bypass or reinterpret them to make a test
pass; report when an approach cannot satisfy them.

## Customer VNet changes

Customers must be able to add and remove hub or spoke VNets without manual or
automated per-VNet configuration changes on the Check Point/provider side.
This includes provider UDRs, static routes, VPN local-network prefixes or
traffic selectors, Check Point routing, NAT and firewall configuration, and
scripts or API calls that update provider configuration for each VNet.

Automatic protocol behavior, such as BGP route learning and withdrawal, is
allowed. Initial onboarding and configuration are distinct from later per-VNet
changes.

Customers may configure and update their own UDRs, static routes, VNet peerings
within their environment, and other customer-side networking. These changes
must not require a corresponding per-VNet provider-side change.

## Preserve customer IP addresses

For east-west traffic between customer workloads or VNets, the Check Point
firewall must see the original source and destination IP addresses so it can
enforce IP-based rules. Preserve those addresses end to end in both directions.
Do not use source NAT, destination NAT, or masquerading anywhere in an
east-west path, in experiments or in the final solution.

NAT is allowed for north-south traffic, including Internet ingress and egress.
The firewall must still be able to enforce IP-based policy using the customer's
actual workload IP address, rather than only a translated address.
For generic NAT in the Ubuntu lab simulator, customer VNet addresses are
restricted to RFC1918 private ranges. This does not establish support for
non-RFC1918 customer addresses or for real Check Point NAT policies.

## Managed networking

Candidate solutions must use managed Azure networking services for the
required networking functions. Do not deploy or configure an Ubuntu VM or
other custom VM as a VPN gateway or BGP relay, including as a candidate
solution to test.

The actual Check Point security product remains part of the intended
architecture. Workload VMs may generate traffic or collect evidence. The
existing Ubuntu firewall simulator is a test simulator, not proof that the
actual Check Point solution works.

## Tenant and trust boundary

Treat the customer and Check Point as separate organizations, Azure tenants,
and subscriptions. Neither side may receive Azure RBAC, service-principal
permissions, or other Azure management control over the other side. Do not
use cross-tenant VNet peering as a substitute for the VPN, or introduce a
workaround that gives either side control over the other's Azure environment.
VPN authentication, such as a shared key or certificate, is distinct from
granting Azure management access.

## Lab operations

The user authorizes creating, modifying, and deleting lab services needed for
tests in the authorized lab without repeated per-service approval. Identify the
exact lab resources and dependencies first, and preserve unrelated resources
and user changes. The user explicitly permits removing lab NSGs or configuring
them to allow all traffic; this exception applies only to the FaaS lab. Do not
weaken other security controls or automatically delete resource groups.

The user can pause or stop lab work at any time. A pause or stop takes
precedence over the general authorization until the user resumes the work.

For provider-provisioning work, also follow the
[provider provisioning instructions](instructions/provider-provisioning.instructions.md).
