# Customer-initiated provider provisioning

For the current installation workflow, use
[Deploy CFWaaS from zero](getting-started.md). Status paragraphs below describe
the dated experiments they accompany; they are not current installer guarantees.

**Status: implemented and locally validated; customer-initiated Portal/API proof
and full two-tenant East US 2 lab deployment passed live. Bidirectional ping,
source-preserving HTTP and provider NVA packet observations passed on 2026-10-27.
This is not production Check Point or Marketplace qualification.**

**Operational status (2026-10-28):** all five explicitly approved lab resource
groups and the old API/client identities were subsequently removed. Replacement
deployment and independent-authentication experiments are paused. The code below
still requires API credential bootstrap; it is not a completed zero-handoff
onboarding implementation. See the
[audit and cleanup outcome](../provider-provisioning/README.md#audit-and-cleanup-2026-10-28).

## Current Portal onboarding: API-only client

The new browser-management implementation automates provider-side customer
creation, credential custody in a separate private Key Vault, and customer
ARM/Form publication. Its `provider-api-registry` mode resolves exact
client/principal bindings from a management-owned Customers table instead of
overwriting one trusted-client environment record. Provider-wide allocation
records remain transactional. The updated release removes global and per-customer
environment-count ceilings, while retaining active-operation limits; it was
published to the live control plane on 2026-11-02 but has not been separately
qualified live. Legacy single-customer modes remain available.

The management app has explicit provider-admin authentication and provider-only
Graph permissions; the public customer API has neither those Graph permissions
nor access to the management credential vault. The admin UI and registry workflow
are locally tested, but the management installer has not yet passed live Azure
qualification. This does not remove customer secret delivery or constitute
secret-free onboarding. See the
[provider administration setup](../provider-provisioning/README.md#browser-based-provider-administration).

The approved PoC separates service authentication from Azure deployment
permissions:

1. Check Point signs into its tenant only and runs `provider_setup.py` to prepare
   provider RGs, API/worker and a customer-specific API client.
2. The API client is an Entra application in the provider tenant with only
   `FirewallDeployment.Request`, **no Azure RBAC** and no Microsoft Graph
   application permissions. Its credential is not a provider administrator or
   worker credential.
3. Check Point distributes a compiled customer ARM/Form pair through approved
   HTTPS artifact hosting and a Deploy-to-Azure link. No customer subscription
   publication or provider access to customer Azure is needed.
4. The customer uses its own Portal, selects the enrolled RG/SKUs and enters
   the customer-specific API credential through a secure field.
5. Bicep creates a customer UAMI and RG-scoped Network Contributor/Reader using the
   customer's native ARM authority. No customer API enterprise application,
   app-role assignment, directory administrator or external CLI is required.
6. Azure-hosted scripts use the API credential only against the provider Entra
   token endpoint. The resulting access token is for the custom provisioning
   API. Customer ARM calls separately use the customer UAMI.
7. The API checks signature, provider issuer, exact audience, object/client ID,
   app-only identity and API role. Business-customer ownership and quota are
   derived from server enrollment, **not** from the token's provider issuer
   tenant or a customer-supplied ARM target.
8. The provider worker uses its own MI to deploy only the provider RG. It never
   forwards customer credentials to provider ARM.

The provider-only CLI and profile generator do not query customer subscriptions,
use customer Graph tokens or require combined customer/provider journals.
Use `--proof-only` preparation to verify authentication without gateways/VMs
before approving full networking. Customer and provider feature registration
and policy prerequisites remain the responsibility of their respective admins.

The PoC API credential expires after 24 hours, is never defaulted into an
artifact/URL, and passes through `@secure()`/deploymentScripts `secureValue`.
Deliver and retain it through approved protected channels. Certificate-based
authentication, durable protected storage, lifecycle automation and live
negative-permission tests need production qualification.

See the [current deployment guide](../README.md#deploy-the-two-tenant-implementation).
The API-only authentication mechanism passed the live customer-initiated proof;
this is not full-network or production qualification. It uses Microsoft's
[OAuth client credentials flow](https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
and [remote ARM deployment](https://learn.microsoft.com/azure/azure-resource-manager/templates/deploy-to-azure-button).

## Legacy customer-managed-identity proposal

The sections below preserve the original `customer-managed-identity` API mode
and its reasoning. That mode requires customer-owned directory onboarding and
is **not** the new Portal deployment path. In particular, its customer API-role
grant is not required in the current `provider-api-client` model.

The implementation lives in [`provider-provisioning/`](../provider-provisioning/README.md).
Local tests, identity bootstrap, real customer-to-provider authorization and
network qualification are separate gates; none should be inferred from this
design document.

This guide describes a self-service onboarding flow for a provider-hosted
firewall service. A customer starts an authorized deployment in their own Azure
tenant; a provider-operated backend provisions the corresponding provider
resources automatically. No provider employee needs to approve each normal
deployment manually.

This is a custom provisioning API design, not a claim about an existing
Check Point product or Palo Alto's internal implementation. It uses public
Microsoft documentation only. Internal partner-platform material is excluded.
No application, identity, permission grant or cloud resource was created to
produce the original design document. Live execution of the implementation
requires separate authorization.

## 1. Goals and boundaries

- Customers never receive provider deployment credentials or provider Azure RBAC.
- The provider does not need customer Azure RBAC in this model.
- Customer automation performs customer-side Azure operations.
- Provider automation performs provider-side Azure operations.
- An authenticated API exchanges requests, progress and customer-authorized results.
- Provider templates, infrastructure targets and capacity limits stay provider-controlled.
- One-time identity onboarding is distinct from each service deployment.

This automation does not establish whether a firewall traffic-steering topology
works. In particular, the EW-18/EW-24 arbitrary-prefix ingress limitation is
not solved by creating a provisioning API.

The [customer Portal form](../provider-provisioning/portal/customer-form.json)
exposes customer-only sizing: the verified 10-Gbps Routing Appliance option
and independent ingress/delivery VPN SKU dropdowns defaulting to VpnGw1AZ.
Provider sizing remains server-controlled; these customer choices are not
provider API request parameters. See the
[wizard and CLI instructions](../provider-provisioning/README.md#customer-azure-portal-wizard-sizing).

**Original proposal:** provider artifact preparation
and customer-owned onboarding/publication must supply a
complete [Bicep entrypoint](../provider-provisioning/infra/customer-deployment.bicep),
pre-authorized customer identity and self-contained Template Spec published in
the customer subscription. The customer installs no Python/CLI, uses no Cloud
Shell and maintains no local journal. Bicep chains the authorized proof, customer
foundation, provider API orchestration and reciprocal connections. Deployment
scripts execute inside Azure; they do not inherit the customer's browser
identity or bypass one-time directory grants. The customer receives no provider
Azure RBAC merely to open or deploy the Template Spec.

## 2. The two authentication paths

```text
CUSTOMER TENANT                         PROVIDER TENANT

Customer administrator/pipeline         Provider platform administrator
  | prepares customer identity           | prepares worker identity + RBAC
  v                                      v
Bicep deployment script                Provider provisioning worker
  | runs as customer managed identity    | runs as provider managed identity
  |                                      |
  | API access token                     | separate ARM access token
  v                                      v
Provisioning API --> authorized job --> Provider Azure Resource Manager
  |
  +--> operation status and connection manifest --> customer automation
```

The customer token is addressed to the provisioning API. It is not converted
into a provider ARM token. The worker independently authenticates as its own
identity. A client ID or object ID identifies an identity; it is not a
credential and does not let a caller impersonate it.

Signing into Azure Portal does not automatically authorize this separate API,
and a deployment script does not inherit the human's browser session.

## 3. Identities and permissions

### Customer side

| Object/principal | Purpose | Authorization |
| --- | --- | --- |
| Human or pipeline deploying Bicep | Creates customer deployment resources | Azure RBAC on the actual customer resource scopes |
| User-assigned managed identity | Runtime caller of the provisioning API | Custom API app-role assignment |
| Enterprise application for the provider API | Local service principal representing the multitenant API | Provisioned during authorized onboarding/consent |
| Customer directory administrator | Grants the required application access once | Appropriate Entra permission for the selected grant procedure |

The API could expose an illustrative application role:

```text
FirewallDeployment.Request
```

That role must allow application principals and be assigned to the customer
managed identity against the API service principal in the customer tenant.
It is not an Azure built-in role and grants no access to the provider's Azure
resources. The provider must additionally enforce customer entitlement and
operation ownership in its application.

Creating a managed identity uses Azure resource permissions; assigning it an
API application role is a separate Entra operation. Azure Owner/Contributor
does not imply Entra application-administrator privileges.

Microsoft documents Cloud Application Administrator, Application Administrator,
Privileged Role Administrator and appropriate custom roles for different
admin-consent cases; Microsoft Graph application permissions have additional
restrictions. The exact identity, permissions and grant method must be verified
for the PoC rather than assuming any Azure subscription owner can consent.

For Bicep deployment scripts, distinguish:

1. **Deployment principal:** deploys the script resource and its supporting
   storage/container resources.
2. **Script principal:** the user-assigned managed identity used at runtime.

The deployment principal needs identity-assignment permission, such as Managed
Identity Operator scoped to the selected identity. Network Contributor alone
does not cover deployment-script infrastructure. Customer-side networking
permissions must include existing hub/subnet/peering scopes touched by a
brownfield deployment, not just the new resource group.

### Provider side

| Object/principal | Purpose | Authorization |
| --- | --- | --- |
| Multitenant API application | Defines API audience and application roles | Entra application configuration |
| API frontend | Validates callers and accepts bounded operations | Prefer queue access, not infrastructure deployment access |
| Deployment worker managed identity | Runs approved provider deployment templates | Azure RBAC on permitted provider resource scopes |
| Provider bootstrap/onboarding process | Prepares resource groups, identities and role grants | Separately authorized bootstrap permissions |

An initial PoC can use Contributor on a dedicated, pre-created provider
environment resource group. This is broad within that group, not a verified
least-privilege minimum. Contributor does not grant Azure role-assignment
permission. Dependencies outside that group need separate permissions.

Production roles should be derived from actual template operations, with
separate secret data-plane permissions where needed. A worker scoped only to
an existing group cannot create arbitrary new groups or assign itself roles.

A managed identity has an Azure-created backing service principal; identity
creation does not assign deployment RBAC automatically. No new identity is
required for every deployment. Per-customer identities can reduce blast radius,
but attaching them all to one shared worker does not create strong execution
isolation: that worker may be able to use each attached identity.

## 4. One-time onboarding

### Provider preparation

1. Register and configure the multitenant provisioning API.
2. Define application roles and accepted customer/automation callers.
3. Deploy the API, durable operation store, queue and worker.
4. Create/enable worker managed identities and grant scoped provider RBAC.
5. Prepare environment allocation, approved templates and secret storage.
6. Establish the commercial/customer account mapping, quotas and allowed regions.

### Customer preparation

1. Create/select the customer user-assigned managed identity.
2. Provision the provider API's enterprise application in the customer tenant.
3. Assign the required API application role through an authorized Entra process.
4. Register the customer tenant and approved calling identity with the service.
5. Grant the local deployer the necessary Azure deployment/network permissions
   and permission to attach that managed identity.
6. Verify an API token and a harmless authorized request before firewall deployment.

Do not send provider credentials to the customer. Do not request broad directory
read permissions simply to identify a caller. The API must validate token
signature, audience, issuer, expiry and app-role claims, plus the trusted
customer/caller mapping. Issuers must be validated using supported multitenant
token-validation libraries and metadata, not by blindly accepting a tenant ID
supplied in the request body.

## 5. Per-deployment flow

```text
1. Customer foundation Bicep
      -> validate/reuse brownfield resources; create missing customer endpoints
2. Customer script acquires a token for the provisioning API
3. POST an environment request with customer endpoint metadata
4. API authorizes request, reserves entitlement/capacity, records an operation
5. Provider worker obtains its own ARM token and deploys approved provider resources
6. Customer polls the operation; API returns provider endpoint manifest
7. Customer connection Bicep consumes manifest; both sides finish reciprocal links
8. Verify firewall, IPsec, BGP and forwarding readiness
9. Explicitly activate customer traffic-steering routes
```

Provider and customer gateway foundation stages can run in parallel if needed.
The gateways can exist before their reciprocal connection resources are
configured. This breaks the apparent circular dependency between endpoint IPs.

For EW-18-style transport, pair customer ingress with provider ingress, and
customer delivery with provider delivery. ASNs, BGP peer addresses, gateway
mode and IPsec/IKE settings must be validated for the actual deployment model;
do not assume every gateway SKU/mode accepts the same parameters.

### Implemented PoC request

These are custom PoC interfaces, not existing Check Point endpoints. The local
implementation is described in the [project README](../provider-provisioning/README.md).

```http
POST /v1/environments
Authorization: Bearer <token-for-the-provisioning-API>
Idempotency-Key: <unique-request-id>
Content-Type: application/json
```

```json
{
  "region": "eastus2",
  "tier": "lab",
  "mode": "network",
  "customerIngress": {
    "publicIp": "<customer-ingress-public-IP>",
    "bgpAddress": "<customer-ingress-BGP-IP>",
    "asn": 65020
  },
  "customerDelivery": {
    "publicIp": "<customer-delivery-public-IP>",
    "bgpAddress": "<customer-delivery-BGP-IP>",
    "asn": 65021
  }
}
```

The authenticated customer mapping determines provider targets. The API must
not accept arbitrary provider ARM IDs, deployment templates, VM images,
scripts or role assignments from callers.

### Asynchronous result

```http
HTTP/1.1 202 Accepted
Location: /v1/operations/00000000-0000-0000-0000-000000000001
```

The caller polls that authenticated endpoint. Once endpoints are ready, a
nonsecret connection manifest can contain:

```json
{
  "operationId": "00000000-0000-0000-0000-000000000001",
  "environmentId": "00000000-0000-0000-0000-000000000001",
  "status": "Ready",
  "createdAt": 0,
  "updatedAt": 0,
  "connectionManifest": {
    "providerIngress": {
      "publicIp": "<provider-ingress-public-IP>",
      "bgpAddress": "<provider-ingress-BGP-IP>",
      "asn": 65030
    },
    "providerDelivery": {
      "publicIp": "<provider-delivery-public-IP>",
      "bgpAddress": "<provider-delivery-BGP-IP>",
      "asn": 65031
    },
    "firewallVip": "172.22.10.10"
  },
  "error": null
}
```

IDs and timestamps above are illustrative. Actual IDs are generated by the
service and timestamps are Unix seconds. `Pending`, `Running`, `Ready` and
`Failed` are the current API states; transient retries return to `Pending`.
`Ready` means the provider ARM deployment completed with validated outputs,
not that customer connections or inspection tests passed. Proof mode returns
an empty manifest and creates one harmless tagged route table.

The customer automation can pass these values to its connection Bicep module.
It does not need to read the provider's underlying VMs, gateways or subscription.
Every status/result/secret operation must authorize environment ownership;
knowing an operation ID is not authorization.

## 6. Secret exchange and readiness

IPsec shared keys are not part of the ordinary manifest. Use a separately
authenticated, customer/environment-scoped exchange and protected storage.
The implemented endpoint is
`GET /v1/environments/{environmentId}/connection-material`, available only to
the owning authorized identity after a network operation is `Ready`. It requires
a valid access token on each call and returns `Cache-Control: no-store`. It is
not a one-time URL or an expiring PSK.

The provider stores PSKs in Key Vault and pins their version identifiers before
starting ARM deployment so retries cannot silently rotate the selected keys.
Customer automation uses them only in its own secure connection parameters.

Never expose secrets in normal Bicep outputs, operation URLs, logs, queues
without appropriate protection, or checked-in parameter files. Automated
rotation, one-time delivery and durable audit retention remain additional
production work. A Key Vault reference alone does not grant cross-tenant secret
access. The protected API exchange does not grant customer access to the
provider vault.

Future service-level lifecycle gates, distinct from current API job states:

```text
Requested -> Authorized -> CapacityReserved
 -> CustomerEndpointsReady + ProviderEndpointsReady
 -> ConnectionsConfigured -> FirewallReady
 -> IpsecAndBgpReady -> InspectionVerified -> Active
```

Azure deployment success, firewall readiness, customer configuration, tunnel
establishment and inspection success are distinct gates. A gateway reporting
Connected does not prove enforcement. Do not redirect brownfield production
traffic until the relevant acceptance checks pass.

## 7. Isolation, retries and failure handling

- Bind tenant and calling application identity to a trusted service account.
- Authorize every environment operation, not just the initial POST.
- Resolve provider resource targets from server-owned mappings.
- Validate endpoint metadata; it must not be enough to name another customer's endpoint.
- Limit plans, regions, instances, concurrent jobs and spending exposure.
- Reserve quota atomically before provisioning.
- Scope idempotency keys to the customer; reject conflicting payload reuse.
- Enforce entitlements across distinct requests: idempotency alone does not stop
  a caller sending thousands of different provisioning requests.
- Keep queue messages tied to approved operation records; do not execute arbitrary jobs.
- Persist operation progress so scripts can resume after portal closure/token expiry.
- Reauthenticate on polling; never return deployment identity tokens in results.
- Record created-resource lineage and compensate only resources owned by that operation.
- Report partial failures and retained billable resources explicitly.
- Treat cancellation, expiry, retries and eventual deletion as first-class lifecycle operations.

## 8. Relationship to Azure Native Palo Alto integration

Microsoft publicly documents the `PaloAltoNetworks.Cloudngfw` resource provider
and Azure RBAC-controlled firewall resources. Palo Alto documents customer-visible
private firewall endpoints. That model offers an ARM-native service front door.

This proposal instead uses a custom API around Bicep. Publishing a Marketplace
SaaS offer does not automatically implement provider resource deployment, and
an Azure Managed Application's managed resource group is in the customer
subscription, not inherently the provider subscription.

No claim is made about Palo Alto's internal worker identities, RBAC assignments,
deployment templates or proprietary platform implementation.

## 9. Proposed validation sequence

Before deploying a firewall, prove the identity boundary with a harmless job:

1. Establish API consent/app-role assignment and scoped worker RBAC.
2. Customer script calls the API using its managed identity.
3. Provider worker creates a benign test resource in its authorized test group.
4. Return operation status and a nonsecret result manifest.
5. Verify wrong audience, missing role and unregistered customer are rejected.
6. Verify customer A cannot inspect/cancel/read secrets for customer B.
7. Verify arbitrary templates/provider IDs and over-quota requests are rejected.
8. Verify retries do not duplicate resources and the worker cannot write outside scope.
9. Verify revocation/cancellation behavior, including managed-identity token caching.
10. Only then connect the approved firewall templates and secure VPN-key exchange.

Open decisions: API/worker hosting, concrete least-privilege actions, shared versus
isolated workers, identity onboarding procedure, brownfield ownership checks,
secret exchange, billing/entitlement integration and compensation policy.

**Current status: documentation only. No API authentication or cross-tenant
provisioning test has been performed.**

## Public references

Reviewed on 2026-10-26:

- [Managed identities and backing service principals](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
- [Assign an application role to a managed identity](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/assign-app-role-managed-identity-powershell)
- [Multitenant application onboarding](https://learn.microsoft.com/en-us/entra/identity-platform/howto-convert-app-to-be-multi-tenant)
- [Admin consent and authorized directory roles](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/grant-admin-consent)
- [Access tokens and API validation](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- [Azure RBAC identity, role and scope](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview)
- [Bicep deployment-script principals and permissions](https://learn.microsoft.com/en-us/azure/azure-resource-manager/bicep/deployment-script-bicep#configure-the-minimum-permissions)
- [Asynchronous request-reply pattern](https://learn.microsoft.com/en-us/azure/architecture/patterns/async-request-reply)
- [Palo Alto Azure Native resource provider](https://learn.microsoft.com/en-us/azure/partner-solutions/palo-alto/overview)
- [Palo Alto Cloud NGFW model and customer endpoints](https://docs.paloaltonetworks.com/cloud-ngfw-azure/getting-started/introducing-cloud-ngfw-for-azure/cloud-ngfw-for-azure)
- [Marketplace SaaS fulfillment](https://learn.microsoft.com/en-us/partner-center/marketplace-offers/pc-saas-fulfillment-apis)
- [Azure Managed Applications ownership model](https://learn.microsoft.com/en-us/azure/azure-resource-manager/managed-applications/overview)
