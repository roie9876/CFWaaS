# CFWaaS technical operator guide

**New administrator? Start with [Deploy from zero](../docs/getting-started.md).**
This technical reference includes historical experiments as well as current
implementation details. Use the current overview below and EW-44 through EW-46
for recent results; older "unwired" or "not deployed" descriptions record their
original experiment state, not the current release.

This project implements the [customer-initiated provisioning design](../docs/provider-provisioning-flow.md).
It is separate from the existing EW-18 deployment and from the archived EW-21
prototype. The original lab must not be deleted as an incidental deployment
step.

> **Lab-only network exposure:** The source templates request allow-any inbound
> and outbound NSG rules. Public IPs can expose SSH and any other listening
> services. Do not use this configuration outside the lab. Azure Policy can
> reject or remediate these rules; the current provider lab policy removed the
> allow-any inbound rule. Scoped RFC1918 forwarding and operator SSH rules were
> subsequently added on the live provider NSG; the live customer NSG still has
> its previously authorized allow-any rule. No policy or Defender controls
> were disabled.
>
> The simulator's generic Internet NAT assumes RFC1918 customer VNet addresses
> and excludes RFC1918 east-west destinations from NAT. The Check Point baseline
> policy follows the same rule (no NAT between RFC1918 networks, hide NAT to the
> Internet). Only the bounded Check Point traffic tests listed below are
> qualified; non-RFC1918 customer networks and production security are not.

**Current verified release (2026-11-04):** the existing Check Point lab passed
bounded bidirectional original-IP ping/HTTP, matching firewall logs and Internet
egress checks. The administrator allowlist wizard and the existing **Reveal
credential** connection-details panel were published and live-verified.
The panel separates the customer Routing Appliance UDR next hop from provider
firewall IPs and temporarily reveals the management password. Gateway login
remains the provider SSH key; no gateway password is managed.
Fresh-provider end-to-end installation, production fail-closed behavior,
real-gateway VNet lifecycle, HA/VMSS and faster Check Point provisioning remain
unqualified or pending.

**Firewall options:** customers choose the Ubuntu simulator (default) or
**Check Point CloudGuard BYOL (lab preview)**. The Check Point path is enabled
on the live provider host: the worker deploys the foundation and private data,
then a one-shot runner creates the gateway and a separate Security Management
Server and configures SIC, the baseline policy and BGP. VMs, SIC, policy and
BGP configuration were verified in Azure (EW-41, EW-42); bounded customer traffic
verification is recorded in EW-44, with explicit qualification limits.

**Current operational status:** the older lab was deleted on 2026-10-28. The
new guided provider setup and one customer network deployment have since been
exercised in Azure. Customer-1 passed bidirectional E–W tests; setup and
onboarding have needed retries and are not production-qualified. The earlier
acceptance results below concern the preceding lab. Old generated profiles,
artifact URLs and private identity journals must not be replayed as if their
resources or credentials still exist.

**Isolated provider groups: enabled for the lab, not production-qualified.**
The live API and worker use the explicitly opted-in managed-application
allocator. Customer 15 recovered a failed group-ownership operation, deployed
provider networking in its original dedicated group, and passed bounded
workload traffic tests. The customer-side resources have since been deleted at
the user's request; the protected provider group and its billable resources
remain. See [EW-39](../docs/test-register.md#ew-39-isolated-group-recovery-in-progress)
for the verification limits and cleanup blocker.

Azure's resource-group create/update API ignored an `If-None-Match: *` header
in a live empty-group probe; a name check followed by a PUT does not eliminate
a concurrent-create race. The direct subscription-level allocator refuses new
isolated-group creation rather than issuing that unsafe PUT. The separate
managed-application approach below is enabled only with the explicit lab-risk
acknowledgements; its residual name race and Azure-managed deny condition are
not a production security qualification.

A provider-owned Azure Managed Application is a possible alternative to direct
resource-group PUT: Azure creates its managed resource group when the
application is deployed. In provider-only tests, a scoped identity created a
managed application and its new managed group, and a group-scoped Network
Contributor identity created a route table inside its group but was denied
outside it. The CLI's asynchronous operation polling failed with that scoped
provisioner identity; a later scoped application read returned `Succeeded`.
ARM validation also accepted a request targeting an already managed group;
validation does not establish that the actual create would be safe. An actual
create against a protected managed-group fixture was rejected, but a separate
conditional PUT updated an existing fixture application despite
`If-None-Match: *` and started a Complete-mode deployment. Its group-level
deletion lock protected the sentinel resource, and the deployment was canceled.
This does not qualify unmanaged-group collisions or application-name races. See
[EW-33 through EW-36](../docs/test-register.md#ew-33-provider-only-managed-resource-group-probe)
for the test boundaries and retained resources.

In another provider-only test, a ReadOnly-denied managed group served as a
candidate host for child applications. Its system deny contains a
subject-resource condition, so the host is not yet proven exclusive. A separate
ReadOnly lock on the host application blocked a test update. Its explicitly
authorized identity created a child managed group; with Network Contributor
assigned on that child, the managed deployment and an additional Incremental
route-table deployment both succeeded. A first child with only Reader failed
because it lacked deployment write permission. The user accepted the lab-only
risk that Azure's observed subject-resource condition
can exempt resource-associated identities with separately granted or inherited
RBAC in both the host and provider environment groups. The worker must opt in
with `FAAS_MANAGED_HOST_ALLOW_AZURE_CONDITION=true`; only the exact observed
scope-specific condition is accepted. Cross-tenant management access,
east-west NAT and automatic resource-group deletion remain prohibited.
This option has been published for the lab but is not a production security
qualification.
The separate deployment-stack host probe also did not establish child-scope
protection; see [EW-37](../docs/test-register.md#ew-37-deployment-stack-host-protection-probe).

Isolated network operations carry an internal request marker so older workers
reject them instead of silently using the shared group. Publish a compatible
worker before enabling isolated reservations on the API. Do not roll back to
an older worker while isolated operations need to run or resume.

The earlier test definition's ReadOnly deny assignment blocked the provider
Owner from creating a group lock, and the denial was not bypassed. The test
applications have CanNotDelete locks and their managed groups are retained.
Collision handling, actual worker permissions, reliable asynchronous recovery,
and secure parameter handling across all surfaces remain unqualified. Deleting
a managed application also deletes its managed resource group, so any design
must prevent automatic group deletion and preserve the lab's cleanup boundary.
The worker deletes an environment application only for an explicit,
audited administrator decommission request; see
[Browser-based provider administration](#browser-based-provider-administration).
Do not use managed applications to grant either organization control over the
other's tenant.
See the [Managed Applications overview](https://learn.microsoft.com/azure/azure-resource-manager/managed-applications/overview).

## PoC improvement backlog

- [ ] Update the deployment wizard to accept an operator-approved public IP or
  CIDR allowlist for SSH to lab VMs. Apply customer and provider rules under
  their respective authorities, preserve existing access unless explicitly
  changed, and validate the addresses without granting cross-tenant Azure
  permissions. **Wizard published and bounded runtime/fresh-link checks
  passed; complete new-environment admin qualification remains pending.**
  See [Check Point public admin allowlist](#check-point-public-admin-allowlist).
- [ ] Shorten deployments: lab 14 completed ARM deployment in 87 minutes.
  Authorization took about 2 minutes, customer foundation 28 minutes, provider
  provisioning 48 minutes, the remaining connection steps about 6 minutes, and
  script startup and orchestration made up the remaining time.
  A candidate is to reserve one provider environment after authorization and
  start its ingress gateway and Route Server while the customer foundation is
  deploying. Start the provider delivery gateway only when the actual customer
  delivery endpoint is available; create VPN connections only after both sides
  have real endpoints. An optimistic critical-path model using lab 14 timings
  suggests roughly 23 minutes of potential savings, not a measured result.
  This needs an owner-bound, idempotent staged API, safe on-demand group
  creation, preserved existing shared-group operations and a separate live
  qualification. Customer and provider Azure authority must remain separate;
  the change must not add provider configuration per customer VNet or NAT to
  east-west paths. Do not use placeholder endpoints or assume concurrent Azure
  networking operations are supported without testing.
  A separate, smaller experimental option is implemented locally: the provider
  ingress Route Server can be provisioned concurrently with the provider VPN
  gateways; peerings and the BGP peer still wait for their prerequisites.
  An isolated provider-only test provisioned an active-active VPN gateway and
  Route Server concurrently in 28 minutes 14 seconds; the gateway took
  28 minutes 3 seconds and the Route Server IP configuration 14 minutes 38
  seconds. A later isolated peering and BGP-peer resource deployment succeeded,
  but had no BGP speaker or customer traffic. The results are not a controlled
  end-to-end comparison with lab 14.
  `FAAS_PROVIDER_PARALLEL_NETWORKING` defaults to `false` and the selected mode
  is fixed in each operation at reservation, so earlier and legacy operations
  retain the sequential path. This option is not released or end-to-end
  qualified. Do not enable it until compatible API and worker packages have
  both been published and a separate full-network test has passed. Parallel
  operation records deliberately fail validation on older API and worker
  versions; do not roll either component back while such records are needed.
- [ ] Remove artificial environment-count ceilings from provider and customer
  configuration, enrollment validation and the UI. Existing allocation records
  remain intact. Published to the lab control plane on 2026-11-02; the behavior
  has not been separately qualified live. Active-operation limits and Azure
  resource limits still apply.
- [ ] Simplify PoC credentials: configure a lifetime of 1–8,760 hours at
  onboarding or rotation, subject to tenant policy, and permit audited repeat
  reveals by provider administrators. Published to the lab control plane on
  2026-11-02; the workflows have not been separately qualified live.
- [ ] Make E-W and N-S investigation easier: show deployment stages and route
  readiness, collect effective routes and next hops, and provide repeatable
  connectivity and firewall-path tests once the lab is ready.
- [ ] Step 0 provider-administrator selection and route visibility. During
  initial provider setup, when the provider control resource group is created,
  ask which provider-tenant Entra user or administrator group may inspect
  routing. Default to the deploying administrator with an explicit confirmation;
  support selecting a different Check Point administrator or group. Persist
  tenant and object IDs, not a hard-coded lab account or email address, and
  support administrator replacement or revocation.
  - Apply this authorization to existing and future provider environment
    groups without per-customer-VNet configuration or customer-tenant access.
  - Required views: NIC effective routes (including the management VM),
    Route Server effective/learned/advertised routes, VPN gateway learned
    routes, and firewall routes/BGP status. Include refresh and export.
  - The current managed-application deny blocks diagnostic POST actions such
    as `Microsoft.Network/networkInterfaces/effectiveRouteTable/action` and
    `Microsoft.Network/virtualHubs/effectiveRoutes/action`, even when the
    administrator has the corresponding RBAC permission. Another Reader or
    Owner assignment alone does not solve this.
  - Prefer direct Azure Portal route visibility if narrowly scoped diagnostic
    access can coexist with the managed application's protections. Do not
    remove the deny or exempt administrators from all write restrictions.
    If direct access cannot be safely supported, provide an authenticated,
    audited read-only view in the FaaS management portal, using the authorized
    automation identity to run only allowlisted route queries.
  - Acceptance: the administrator selected at Step 0 can view management-NIC
    effective routes and Route Server/VPN routes after VPN/BGP convergence;
    unauthorized or revoked users cannot. Unrelated network changes remain
    denied, and neither organization gains Azure control over the other.
- [ ] Deployment-wizard admin access allowlist. Ask for the public IPs/CIDRs
  allowed to reach the Check Point management server and gateway and the
  customer test VMs, defaulting to the lab operator's office and home `/32`
  addresses from local, uncommitted configuration.
  Apply them per environment: provider NSG and SmartConsole GUI clients by the
  Check Point automation identity, customer NSG, test-VM public IPs and `/32`
  Internet routes by the customer deployment. Never per customer VNet.
  **Code complete, offline-tested; not published or live-qualified.** The
  management subnet also receives source-specific Internet return routes, so
  the VPN default does not capture public admin replies. See the
  [implementation and release requirements](#check-point-public-admin-allowlist).
- [ ] Provider administrator access to each Check Point environment. Today the
  gateway is reachable by SSH (`admin`, provider NVA key) on its public IP; the
  management server accepts SmartConsole only from the automation subnet, its
  NSG blocks the Internet and its password is in the private environment vault.
  Options: an approved admin public IP/CIDR in the management NSG and GUI-client
  list (lab), Azure Bastion in the security VNet, and an audited portal action
  or scoped vault-reader group for the management password. Access is
  per environment, never per customer VNet, and is applied by the Check Point
  automation identity because operators are blocked by the managed deny.
- [ ] Parallelize Check Point provisioning: deploy the security VNet, private
  data and runner (VMs, first boot, SIC, policy) while the VPN gateways and
  Route Server build, and configure BGP last. Estimated saving 30–40 minutes.
- [ ] Address overlap with provider ranges. Every environment uses fixed
  provider ranges (`172.20.0.0/16`, `172.21.0.0/16`, `172.22.0.0/16`, expected
  customer ingress `172.18.0.0/16`) and fixed ASNs (65021, 65031, 65050,
  65515). Environments are isolated, so customers may overlap each other, but a
  customer prefix inside a provider range is misrouted without warning, and
  overlap inside one customer cannot be inspected without east-west NAT.
  Options: move provider infrastructure to a rarely used range such as
  `100.64.0.0/10`; allocate provider ranges and ASNs per environment from a
  provider pool at onboarding; reject overlapping customer endpoints at request
  time and report overlapping BGP-learned prefixes at runtime.

## Browser-based provider administration

**Guided setup:** the private setup host, provider Entra identities and
management app were exercised in the lab. The first provider installation
needed a resource-group workaround and a separate application-publication
retry. Management sign-in and the registry/Graph readiness check succeeded.
The updated guided setup creates future management registrations with ID-token
issuance enabled and implicit access-token issuance disabled. A new private
setup Template Spec is published; its complete fresh-install path has not yet
been requalified end to end. Use the guided button and instructions in the
[new-administrator guide](../docs/getting-started.md#3-install-the-provider-control-plane).

If the management page displays `AdministratorSignInRequired`, its App Service
session may contain an expired ID token. Open the management app's
`/.auth/login/aad?post_login_redirect_uri=%2F` path and sign in again. Do not
copy or share the resulting redirect URL, which can contain a session token.
The updated management package was deployed to the lab and its health endpoint
responded successfully. A browser-like request to the root received a sign-in
redirect; a generic unauthenticated client received a platform-level 401. The
expired-session recovery page and fragment cleanup have not been independently
qualified live.

The management implementation adds a provider-only web UI with **Create
customer**, **Deployment link**, **Reveal credential**, **Rotate**, **Revoke**,
and **Recover / reactivate** actions. Repeat reveal is included in the live
release but has not been separately qualified. Customer credentials are generated in Entra,
stored as versioned secrets in a separate private management Key Vault, and never
returned in customer inventory, audit events or template defaults.

**Validation boundary:** the live readiness check verifies registry access and
Graph identity/API configuration, not all customer credential writes or artifact
publishing. Live customer onboarding and network results are described below;
the preceding lab's acceptance is not evidence for the current installation.

### Alternative manual provider setup: browser only

An authorized provider security/platform administrator performs these steps.
The routine customer-onboarding administrator does not need local Python or CLI.

1. In **Entra > App registrations**, create/configure the provisioning API.
   Define an application role named `FirewallDeployment.Request`, allow
   **Applications**, set its application ID URI to `api://<API-client-ID>`,
   configure v2 access tokens, and include the access-token optional claim
   `idtyp`. These are validated before the management service creates customer
   clients. In the Entra manifest, the relevant fields are
   `api.requestedAccessTokenVersion: 2` and an `optionalClaims.accessToken`
   entry with `name: "idtyp"`. Record the API application ID and role ID.
2. Register a separate, single-provider-tenant management web application.
   Create its automation credential and note its UTC expiry. Enable ID tokens
   for hybrid flows for the App Service sign-in; leave implicit access tokens
   disabled. Register the management app's exact App Service callback URI.
3. Give this management application the Microsoft Graph **application**
   permissions `Application.ReadWrite.OwnedBy`, `Application.Read.All`, and
   `AppRoleAssignment.ReadWrite.All`. A suitably authorized Entra administrator
   must explicitly grant consent. These are privileged directory permissions,
   including tenant-wide capabilities; they are not restricted by Azure RG RBAC.
   Review/approve them before deployment. Never grant them to a customer API
   client or the public provisioning API.
4. Open the private `faas-provider-installer` Template Spec version
   `2026.10.28.3` in the provider subscription. The selected account needs
   read access to that spec.
   Supply the API/management application IDs, API role ID, initial administrator
   user object-ID allowlist, secure management credential/expiry, public SSH key,
   and new control/data RG names. Use new RG names after a previous purge-protected
   vault was deleted; do not silently reuse stale private journals.
5. Explicitly acknowledge the installer deployment-script backing-storage
   exception. The installer deploys infrastructure and uses its own temporary
   Azure-hosted script to publish the three applications **sequentially**, checking
   actual successful active app builds rather than only ARM extension acceptance.
   No administrator workstation scripts are required.
6. Add the installer's `entraRedirectUri` output as a **Web** redirect URI on
   the management app. Open `managementUrl` and sign in as an explicitly
   allowlisted provider administrator. Enforce MFA through provider access policy.

Azure subscription Owner alone does not grant the Entra authority in step 3.
App Service Authentication requires login and a provider principal allowlist;
the backend independently validates the signed ID token, tenant, audience,
expiry and administrator object ID. Browser mutations also require the exact
management origin and JSON requests. The public provisioning API has no routes
for management or credential reveal.

The installer creates no customer resources and no dataplane gateways/VMs.
It creates a provider API app, worker app and management app on a shared B2 plan,
private Operations/Customers tables, two separate private vaults, private
endpoints/DNS, a dedicated artifact account and installer identity/backing
storage. The explicit backing account is retained after the script finishes;
cleanup of the container does not imply deletion of that pre-created account.
Hosting/storage/private endpoints incur charges.

### Day-to-day customer onboarding

The administrator enters customer name, approved tenant/subscription IDs and
credential lifetime, then selects **Create onboarding**.
The service creates one provider-tenant API-only client per business customer,
assigns the fixed FaaS API role, stores its credential in Key Vault and publishes
a self-contained customer ARM/Form pair. No customer Azure/Graph access is used.
The entered subscription is enrollment metadata, not proof of Azure ownership.

The deployed release permits multiple independently credentialed
customers in the same tenant and subscription. Customer names must be distinct
within a tenant, ignoring case, outer whitespace and Unicode compatibility
variants. If onboarding stops at **NeedsAttention**, review the recovery
guidance instead of creating a duplicate name. Use **Recover /
reactivate** only after verifying the existing identity; recovery can disable
the client and replace enrollment-marked credentials.

For newly created directory objects, the management service allows bounded
read-only retries for Graph replication delays. It retries service-principal
creation only after an explicit authorization denial and after checking the
application owner and absence of an existing principal. It similarly reconciles
the exact role assignment after an explicit not-found response. Timeouts,
transport errors and ambiguous writes are not blindly retried.
In the current lab, an additional customer in the same tenant and subscription
reached **Ready** on its first attempt after this change. Earlier attempts
required recovery, so one successful attempt does not establish reliability.

Select **Deployment link** to issue a fresh four-hour, read-only artifact link.
After a release, refresh the management page first; an older open page or
previously issued link can still refer to the earlier customer artifacts.
The recovery-enabled release checks that the customer network template contains
the retry connector before issuing a link. Its Portal form is titled
**FaaS customer deployment - recovery-enabled release**; do not use an older
link to retry an isolated-group ownership failure.

The release includes a **firewall-selection lab preview**. Ubuntu remains the
default and preserves the existing request and idempotency format. The form
offers "Check Point CloudGuard BYOL (lab preview)". If the provider has not
enabled Check Point, the connector rejects it before provider reservation and
customer foundation deployment rather than silently deploying Ubuntu. An attempted deployment can
still create the customer identity, its scoped roles, and the temporary proof
script before that rejection. Older APIs reject the preflight as unavailable.
The intended Check Point option uses a separate provider-owned Security
Management Server per deployment. Separate candidate Bicep and Terraform
configurations now describe the managed VPN/network foundation and the BYOL
gateway and management VMs. When `FAAS_CHECKPOINT_ENABLED` and the
`FAAS_CHECKPOINT_*` worker settings are present, the worker deploys the
foundation and private data, then launches one runner job. The runner applies
Terraform and configures SIC, the approved baseline policy and BGP through the
private Management API (see EW-41 and EW-42 in the test register). BYOL license
activation, cleanup automation and a full customer traffic test are not yet
qualified. Ubuntu behavior is unchanged.
Post-boot reconciliation pins the existing environment's management host object
to its private IP (`172.22.30.4`), ensures it is a gateway log destination without
removing other destinations, and saves the gateway route to `172.22.30.0/24`
through `172.22.10.1`. It publishes changed logging objects, verifies their API
readback, waits for all management database installation tasks, and then installs
the existing policy through the normal baseline workflow. Logging reconciliation
does not recreate either appliance object or alter user rules, administrator
clients, interface anti-spoofing or NAT. Its configuration success marker does
not assert TCP/257 connectivity or prove log ingestion; those need live checks.
The selected design is to generate management credentials per deployment in a
provider-private Key Vault and have the provider administrator activate the
BYOL license. The customer API must not expose those credentials or report the
firewall ready before the required administrative and networking checks.
A local, unwired Key Vault adapter checks provider scope and fresh ARM vault
and private-endpoint evidence. Its lease-fenced journal binds one vault and
stores a SHA-256 fingerprint of the randomly generated credential material
before a single non-retrying write. An uncertain write is reconciled against
that fingerprint and an immutable version, never automatically repeated.
If the write remains unresolved, operator investigation is required. This
adapter has only offline tests; it is not connected to a live worker, and
private DNS, identity permissions, administrator access and license
confirmation remain unimplemented or unverified.
The experimental private-data template describes a separate Key Vault and
Blob state container per provider environment, with public access and storage
shared keys disabled, private endpoints and private DNS. It grants no roles and
has not been deployed. Live secret writes, recovery, private DNS connectivity
and least-privilege access remain unverified. Key Vault purge
protection retains deleted vaults, so recovery and teardown must account for
the retention period. The evidence validators check Key Vault and state-storage
resource properties, retention and private-endpoint bindings, but do not prove
private DNS connectivity or permissions. A separate state verifier can read
those properties through provider-scoped ARM calls; it is not wired to a
runner or the live worker.
The Check Point AzureRM provider does not auto-register resource providers at
subscription scope. A read-only provider-registration preflight is available
locally; it reports missing registrations rather than changing them. Required
registrations must be checked under provider authority before deployment.

For developer-only validation, `scripts/prepare_checkpoint_modules.py` exports
the pinned Check Point v1.6.2 Git snapshot into a new `.local` directory. It
retains the upstream license, removes module-local provider configurations,
requires an existing isolated provider group and explicit Marketplace image
versions, and bundles the candidate Terraform root configuration. The
transitive regions module is pinned to a Git commit with telemetry disabled,
and its telemetry provider is also explicitly disabled;
the generated provider lock includes signed checksums for Linux amd64 and
macOS arm64. The mock probe verifies the lock and installed module contents
before evaluating the plan, without passing Azure credentials to initialization.
It also hashes every installed provider package against its platform-specific
`h1` lock checksum and rejects unexpected files, links and unsupported platforms.
An actual macOS initialization and mirrored Linux archives matched their pins;
the Linux binaries were not executed. These checks do not prove that the
eventual runtime filesystem remains immutable after verification.
An additional unwired runtime check requires each provider file and its
ancestor directories to be protected from the non-root runner before checking
the dependency graph. Its ownership tests are simulated; it does not yet
qualify module-file immutability or a live runner image.
The candidate also disables Check Point upload/download and optional gateway
metrics. Terraform 1.15.7 executable hashes are pinned for Linux amd64 and
macOS arm64; they were checked against the official HTTPS release checksums,
but the release signature was not independently verified.
`scripts/build_checkpoint_runner_context.py` builds a verified, secret-free
Docker context for `checkpoint-runner.Dockerfile`; the image runs
`service.checkpoint_runner_entry` as a non-root user. That entrypoint reads
its private inputs, verifies the pinned Terraform, artifact and providers,
initializes offline from the read-only provider mirror, plans with private
state, applies only the validated sealed plan and discards Terraform output.
The image was built in ACR and smoke-tested on Linux (see
[EW-40](../docs/test-register.md#ew-40-check-point-runner-image-and-publisher-identity-probes));
it has not yet run as an ACI job against Azure state or created firewall VMs.
The runner uses a dedicated Check Point publisher identity, because the
managed-application deny admits only the definition's publisher principal. A
separate Check Point definition grants that identity eight built-in roles in
each Check Point group; the Ubuntu definition is unchanged. From the
`scripts` directory, `../.venv/bin/python -m probe_checkpoint_modules --source
<local-upstream-checkout>` uses that adaptation and Terraform mock providers
with an empty credential environment. Terraform initialization downloads
public dependencies; the probe does not deploy or authenticate to Azure. Its
fixture checks that the two BYOL VMs use the existing group and network without
creating resource groups, VNets, subnets, route tables or NSGs. For existing
VNets the upstream module requires
`address_space` to be empty; supplying a CIDR makes it create a VNet instead.
The probe also verifies that `latest` and a non-FaaS group are rejected. This
mock plan is not a real Check Point deployment or a security qualification.
The source includes a provider-side foundation-output validator that checks the
exact environment group, expected resource IDs, firewall IPs and both Route
Server peer addresses. It is not yet connected to a live Check Point worker.
An additional plan guard rejects unexpected resources, updates, replacements,
imports, drift, unsafe network bindings, unpinned images and unmarked
credentials. It also checks the provider identity, approved SSH key, vault
credential values and pinned VM bootstrap without logging them. It has been
exercised against a real Terraform mock plan, not a live plan, and is not
sufficient by itself to authorize an apply: the runner
must verify its dependencies, identity, scope and lifecycle, and apply the exact
validated saved plan.
The cleanup guard separately accepts only a destroy plan for the exact
Check Point Terraform-owned VM, NIC, public IP and association scope, including
checks on each VM's OS disk and deletion setting; resource groups and managed
applications are never in that allowlist. Its
offline probe derives simulated cleanup actions from mocked state. It has not
validated a real destroy plan or implemented removal of the networking and
private-data foundation, and it cannot clean up the protected Ubuntu lab 15.
An unwired lease-fenced apply journal reserves one job and one plan fingerprint
before a single apply attempt. An uncertain attempt cannot automatically start
again; a successful apply is not firewall readiness or end-to-end validation.
A separate, unwired runner journal binds the environment to one deterministic
container job and specification fingerprint. A local request builder prepares
immutable, secret-free ARM request bytes from validated provider inputs; the
fingerprint binds the complete request and identity references. The request
can be revalidated for changes before use. The read-only ARM observer checks
the expected identity, pinned image, private subnet, DNS and container settings
before recording a running or terminal job result. A job that disappears after
launch is unconfirmed, not permission to relaunch; exit code zero means only
that the container finished. Tests exercise SDK serialization and exact-byte
submission through a mocked transport, not a live container group. The builder
and observer neither launch jobs nor verify registry ownership, artifact
availability, DNS connectivity, role assignments or deny assignments. ARM may
omit write-only secrets from responses, so absence in a response does not prove
that none were supplied at creation.
The eventual launcher must send only a revalidated request and qualify all
these prerequisites before enabling the Check Point path. ACI's create-or-update
API must not overwrite an existing unrelated resource: a safe create-only
mechanism or an explicitly approved ownership model is still required. Journal
fencing alone does not establish that protection. Microsoft documents that
[redeploying an existing container group restarts its containers](https://learn.microsoft.com/azure/container-instances/container-instances-update),
even when the supplied properties are unchanged.
An unwired private-configuration bridge now connects the scoped operation,
validated foundation and bound credential version to the runner request. It
prepares only non-secret settings and credential references, then creates the
private state-account blob with a create-only condition. An existing blob is
accepted only if its bytes match; an ambiguous write can be reconciled without
overwriting it. The Blob SDK uses `If-None-Match: *`, whose
[documented Blob Storage behavior](https://learn.microsoft.com/rest/api/storageservices/specifying-conditional-headers-for-blob-service-operations)
is to fail if the resource already exists. A prospective runner can read the pinned blob and the exact
Key Vault secret version with its user-assigned managed identity, validating
the configuration digest, provider scope and credential fingerprint without
access to the shared Operations table. The runner's verified settings and
credentials can also be passed to the existing strict Terraform plan guard.
These paths have only offline and
mocked-SDK tests: no blob or secret was read or written in Azure. They do not
establish private DNS connectivity, RBAC, managed-application deny compatibility,
registry access or permission to launch or apply. The plan guard does not by
itself bind a JSON plan to the saved binary plan that would be applied.
Microsoft's [ACI managed-identity image-pull guidance](https://learn.microsoft.com/azure/container-instances/using-azure-container-registry-mi)
states that a network-restricted registry requires Trusted Services and that
its private endpoint must be on a different subnet from ACI. This access path
has not been approved or tested; do not relax registry controls to enable it.
The experimental plan workspace copies a private saved plan into a Linux
kernel-sealed memory file and removes its disk copy. It rechecks the seal and
SHA-256 before handing out the file descriptor. Linux seal behavior still
requires verification in the actual managed runner; the macOS tests simulate
those Linux APIs and do not qualify it. Linux-only tests also cover passing the
sealed descriptor through a child process; these tests are skipped on macOS.
The experimental Terraform runtime check also requires a non-root process,
a root-owned non-writable executable, and root-owned non-group/world-writable
parent directories without symlinks. It rechecks the file identity after
walking the protected path. This check is not yet wired to execution and does
not verify the runner image or Terraform provider binaries.
The optional `package_apps.py --checkpoint-source <local-upstream-checkout>`
build includes the compiled foundation and private-data templates, adapted
upstream modules, license and candidate Terraform configuration; its metadata
records both template hashes.
Without that flag, the existing Ubuntu package does not include those assets.
The Check Point path also requires the worker settings, identity and definition
described in EW-42; without them the API reports Check Point as unavailable.
The experimental foundation's firewall NSG contains the lab-only allow-any
rules; its separate management NSG allows only the specified provider-side
firewall, management and automation ranges before denying other inbound
traffic. The automation subnet is delegated to Azure Container Instances,
denies inbound traffic and has a dedicated NAT gateway for its own Internet
egress only. It is not on the customer east-west path; VPN connections do not
configure NAT. It has no runner yet. ACI requires a NAT gateway for outbound
connectivity and does not inherit VNet DNS settings, so the future runner must
explicitly configure and validate DNS. See the [ACI virtual network
requirements](https://learn.microsoft.com/azure/container-instances/container-instances-virtual-network-concepts).
The candidate must not be deployed until the identity/deny-assignment model,
private state, management access, firewall policy, BGP and safe teardown have
been implemented and qualified.
Check Point's [Azure extension support notice](https://support.checkpoint.com/results/sk/sk109613)
lists VM extensions as unsupported for the referenced Gaia releases; Azure
[Run Command depends on the VM agent](https://learn.microsoft.com/azure/virtual-machines/linux/run-command).
Do not assume Run Command is a supported way to configure Gaia or bootstrap
trust. This does not prevent configuration: Check Point supports
[first-boot custom data](https://support.checkpoint.com/results/sk/sk105242),
and the pinned gateway and management modules expose a `bootstrap_script`
input. Check Point also provides a
[management API](https://sc1.checkpoint.com/documents/latest/APIs/index.html),
[Gaia API](https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_Gaia_AdminGuide/Content/Topics-GAG/API-for-Gaia.htm)
and management-driven gateway scripts. Gaia API does not expose every OS
setting, so the exact BGP operations must be verified against the deployed
version. First-boot output can be logged by the appliance; do not put
credentials in the optional bootstrap script or its output. The current
upstream gateway template embeds the SIC key in VM custom data, which
[Microsoft advises against for sensitive values](https://learn.microsoft.com/azure/virtual-machines/custom-data#can-i-place-sensitive-values-in-custom-data).
This credential-delivery issue must be resolved before deploying the candidate.

The candidate restricts the management API to the provider automation subnet.
The first-boot script input is not yet populated, and the post-boot API
workflow, TLS trust, SIC establishment, approved policy, BGP behavior and safe
recovery are not yet implemented or qualified. These are provider-side
environment setup operations, not per-customer-VNet configuration.
The existing managed-application definition grants its publisher Network
Contributor and Virtual Machine Contributor only. Those built-in roles do not
grant the writes needed to create a Key Vault, state account, container group,
managed identity or role assignment. Check Point requires a separately scoped
and verified permission design; do not broaden the Ubuntu definition or
bypass its deny assignment.
Terraform marks the management password and gateway SIC material as sensitive,
but sensitive values can still be present in state and plan JSON. Keep both
private and never log or publish them. Provider-only private state and secret
access controls are required; the shared VPN exchange vault must not be treated
as a management-credential vault.

The release lets an authenticated provider administrator select
**Reveal credential** more than once; each attempt is audited before the private
Key Vault read, and the value clears from the page after 30 seconds. Send the credential
only through an approved secure channel; no secret is placed in the deployment
link. The customer uses the same native Portal/Bicep workflow, with no local
tooling or bootstrap VM.

The Customers registry replaces overwriting a single trusted client's app
settings. Each signed provider-issued API token must map to an exact active
customer/client/principal binding with the required application role. Each
enrollment has immutable subscription and identity bindings. API/worker identities can read this registry but cannot
modify it or access the management credential vault. The management identity
cannot modify Operations state or deploy provider networking.

The updated source tracks allocations transactionally without enforcing a global
or per-customer environment-count ceiling, including for existing enrollments.
Accepted proof, Ready and ambiguous retained deployments remain recorded;
revocation does not delete infrastructure or release an allocation. Active and
running operation limits still apply. The worker processes customers round-robin,
with one ARM operation at a time in this lab. Azure quotas, resource-group
limits and actual capacity are not removed.

The updated API and worker were published to the live lab on 2026-11-02;
the change has not been separately qualified live. Legacy `maxEnvironments` enrollment
fields, configuration values, template parameters, and `FAAS_MAX_ENVIRONMENTS`
or `FAAS_MAX_INSTANCES` app settings no longer impose a limit in the updated
source. Legacy enrollment and app-setting use is logged. Existing deployment
templates and running versions continue to enforce their old limits until
upgraded. Publish the compatible API and worker before updating the management
app or removing old app settings; older versions can otherwise reimpose a cap or
reject a zero setting. Test rollout and rollback before modifying the live lab.
When updating an existing installation, publish the API and worker before the
management app so older workers cannot process new shared-tenant enrollments.
Do not roll back API or worker to a version that lacks shared-tenant support
while such enrollments exist.

### Credential lifecycle and recovery

- The lab release supports a one-time, customer-authenticated retry of an isolated
  network operation that failed with `GroupOwnershipError` while its provider
  group was being created. Rerunning the same customer Portal deployment with
  a newly published compatible template requests that retry. The worker must
  revalidate the existing group before deployment; it will not create a
  replacement group. Other failures remain terminal and require operator review.
  The retry preserves owner binding, allocation, active limits and lease fencing.
  The compatible worker, API and management packages were published to the
  lab; the fresh customer link and end-to-end retry remain unverified.
- **Archive** removes a successfully revoked customer from the active list.
  The immutable identity binding, audit history, allocation state and Azure
  resources remain; archive is not infrastructure deletion or quota release.
- **Decommission provider resource groups → Decommission** lists a customer's isolated
  provider environments and, after an OK/Cancel confirmation, records an
  audited request in the Customers registry. It is available in any enrollment
  status but refuses environments whose provisioning is still pending or
  running. The management app only reads Operations; the worker, the only
  identity excluded from the managed host's deny assignment, deletes the
  bound `faas-env-<id>` application, and Azure then deletes its
  `rg-faas-env-<id>` group. The worker never deletes a resource group directly
  and rejects unbound or foreign groups. On completion the operation becomes
  `Decommissioned` and its allocation is released once. Deletion can take 30
  minutes or more because of VPN gateways. Customer-side resources, Key Vault
  connection secrets and enrollment credentials are not changed. A failed
  decommission is retried only when an administrator requests it again. The
  host role must include `Microsoft.Solutions/applications/delete`; publish
  the compatible worker before adding it, because older workers reject that
  action in the host permission check.
  An incomplete `NeedsAttention` identity must be reconciled before revocation
  or archiving; do not delete its records to bypass verification.
- **Rotate** changes the real Entra credential and saves a pinned Key Vault
  version. In the updated source, select a lifetime between 1 and 8,760 hours
  at onboarding or rotation; tenant policy can reject the requested lifetime.
  The selected duration is retained for later rotation or recovery unless
  changed during rotation. The customer receives the new credential securely. Rotation can
  interrupt new API requests; previously issued Entra access tokens have their
  own lifetime. It is not simply editing a Key Vault value.
- **Revoke** immediately removes the registry authorization and disables the
  real Entra client. It does not delete infrastructure or claim to cancel ARM
  work already accepted.
- For an exposed credential, first revoke its verified client. In the provider
  Entra Portal, verify the application and client IDs, remove only the exposed
  credential from **Certificates & secrets**, and capture the resulting
  credential metadata privately without displaying or copying secret values.
- **Recover / reactivate** verifies persisted application/owner/client bindings,
  disables the client, retires only enrollment-marked credential keys, saves a
  fresh credential and re-enables access. A live operation fence cannot be
  overridden; expired fences require the documented 120-second wait and an
  explicit new recovery attempt.
- If an application's create response was lost before its immutable ID was
  persisted, the service stays **NeedsAttention** and gives Entra Portal
  remediation guidance. It never adopts an application merely by display name
  or blindly retries uncertain directory writes. This exceptional manual repair
  is an explicit limitation, not an unattended-recovery claim.

The provider automation credential used by the management platform is separate
from all customer credentials. Its own expiry/rotation remains a platform
administrator responsibility; Key Vault does not rotate Entra passwords by
itself.

During the 2026-10-30 replacement, a one-time API credential appeared in
browser output. Its client was revoked and independently confirmed disabled;
the provider Portal did not permit removal of the credential with the current
account. An authorized directory administrator must retire that credential.
The verified client and applied-state evidence are in the private recovery
screenshots; do not reuse the credential.

For a lab replacement, the provider administrator creates a new enrollment,
issues its customer deployment link, and the customer administrator deploys
into a new dedicated resource group. Keep the existing lab until the new VPN,
BGP, E-W and N-S tests pass. Afterwards, revoke each verified old test client
and archive it from the active list; separately remove only the explicitly
approved old-lab resources. Capture the final applied-state screenshot in
private local evidence after each manual portal operation. Never capture or
commit the one-time credential or a deployment link containing its SAS.

### Engineering release preparation

Engineering/CI, not the installing administrator, maintains the release package
and publishes the Azure Template Spec. The existing lab release is already
published privately; another organization needs its own release host and setup
Template Spec, not access to that lab's installer. For a future
release using a read-only SAS package URI, engineering can run:

```bash
cd "$(git rev-parse --show-toplevel)/provider-provisioning"
.venv/bin/python scripts/package_apps.py
.venv/bin/python scripts/prepare_provider_installation.py \
  --package-uri-file .local/approved-release-package-uri.json
```

The package URI metadata must refer to the exact new ZIP and its SHA256.
Release preparation presets only package pins/source and nonsensitive defaults,
never the management credential. Generated ARM, read-only package SAS and launch
metadata stay under ignored `.local`. Engineering publishes the generated
provider ARM through its approved release-hosting pipeline; the preparation
command does not claim to publish a working link automatically.

The ZIP includes management startup/UI and compiled customer templates. A
management Docker release must include those engineering-generated template
assets too; the source-only Docker context is not a substitute for the release
bundle. Management browser login currently relies on App Service Authentication;
a standalone Docker container does not provide that login layer by itself.

For this company's lab, dedicated public artifact and installer-backing storage
accounts carry the explicitly user-specified `SecurityControl=Ignore` exception
tag. This does not enable anonymous blobs. Artifact shared keys remain disabled;
only the separate, explicitly acknowledged deployment-script backing account
permits shared keys for Azure Files. Operations storage and both vaults remain
private, without that exception. No policy definitions or Defender controls are
disabled by the deployment.

**Required customer experience: Azure Portal only.** The customer opens a provider
Deploy-to-Azure link backed by one complete Bicep entrypoint. They install no Python
or Azure CLI, use no Cloud Shell, and keep no local configuration or journals.
Azure-hosted deployment scripts perform the HTTP/ARM orchestration inside Azure.
Check Point administrators operate in the provider tenant only; customer
administrators operate in their own tenant only. The independent
`provider-api-client` flow uses a per-customer API-only credential, plus a
different customer UAMI for customer ARM. It needs no customer Graph consent,
shared journals or Check Point access to customer Azure. Provider hosting,
authenticated operation-store access, the customer-initiated Portal proof and
the full two-tenant lab network have been verified live in East US 2. This does
not qualify production Check Point appliances or automated Marketplace onboarding.

## Ownership boundaries

```text
CUSTOMER TENANT                         PROVIDER TENANT

Customer-owned deployment script        Public HTTPS provisioning API
   | API-only OAuth client credential      | validates provider-issued API token
   | token addressed to custom API         | checks caller, ownership and quota
   +-------------------------------------->+ durable operation/outbox
                                           |
                                        Separate deployment worker
                                           | own managed identity
                                           | provider ARM token
                                           v
                                        Approved provider dataplane RG
```

Customer and provider identities are independent. Calling the API does not
give the customer provider-subscription RBAC. The provider worker never uses
the customer's bearer token to deploy infrastructure.

The API-only client lives in the provider Entra tenant but has **no Azure RBAC**.
Its token authorizes only the custom provisioning API. The customer UAMI uses
its own customer-tenant tokens for customer ARM. The API's issuer authority is
the provider tenant; business-customer ownership and quota use the server's
enrollment mapping, not that issuer tenant.

## Intended deployment sequence

1. Validate the local service, templates and permission boundaries.
2. Explicitly bootstrap the provider API application and deployment identities.
3. Create the customer-specific API-only client and grant its custom API role
   inside the provider tenant; assign it no Azure RBAC.
4. Deploy the control plane with scoped state, secret and ARM permissions.
5. Have the customer run the Portal proof using its own deployment identity
   and the separate API-only credential.
6. Verify negative cases: foreign caller, wrong audience, missing role,
   cross-environment access, quota limits and conflicting retries.
7. Create customer network foundations and exchange reciprocal endpoint manifests.
8. Provision provider networking, firewall simulators and connections.
9. Configure customer connections through customer-owned authorization.
10. Qualify source-preserving inspection before activating/cutting over traffic.
11. Only then run a separately authorized cleanup of the old lab.

Existing environment approvals, credentials or directory roles are not inferred
from a successful read-only query. An Entra or Azure policy denial stops the
workflow; it is not worked around using another identity.

## Security requirements

- App-only Entra access tokens with an exact configured API audience.
- Explicit trusted tenant, principal, client and required-role binding.
- No arbitrary customer-supplied provider scopes, templates or scripts.
- API frontend has no provider infrastructure deployment role.
- Worker ARM access restricted to a pre-created provider dataplane group.
- Managed identities for Azure ARM, with a separate customer-specific API-only
  OAuth credential; never provider administrator/worker/ARM credentials.
- Durable quota/idempotency/operation records and conditional worker claims.
- Private access to operation storage and Key Vault, with shared-key access disabled.
- Secrets returned only through an environment-authorized protected operation,
  never ordinary deployment outputs or logs.
- No public SSH access copied from the historical lab's manual-test exception.
  For the current `customer-12` lab, the user separately approved temporary
  SSH access: two customer public IPs, SSH-only NSG rules limited to the
  current client IP, and client-specific Internet return routes on both workload
  tables. The provider firewall NSG has the same single-IP SSH exception. These
  rules are a lab access exception, not part of the deployed templates; the
  public IPs are billable and the return routes bypass inspection for that IP.
- No automatic deletion of existing resource groups.

## Topology and qualification limits

See the [BGP peers and separate traffic-flow diagrams](../docs/provider-routing-topology.md).
The release defines one provider ingress Route Server, a separate managed BGP
delivery gateway and persistent NVA startup configuration. The live API, worker
and management app were updated on 2026-11-02. All three builds reported active;
the worker's bundled template pin and subsequent health metric were verified.
The source-defined Always On setting was restored on the three apps, and the
existing delivery VPN remained connected. A fresh link for the existing lab 12
enrollment was issued after refreshing the management page. Both artifacts
were retrieved; the customer form and embedded BGP connection template matched
the release, and the credential field remained required and secret. Lab 14
subsequently completed ARM deployment with all four VPN connections and both
delivery BGP peers connected at inspection. Bounded east-west and Internet-egress
tests passed through simulator 0; two initial HTTPS attempts timed out before
later repeats succeeded. Internet ingress, failover, real Check Point and a fresh
provider installation still require separate qualification.

The clean split uses four VMs, not the old group's five VMs:

- Customer: ingress/delivery managed VPN gateways, one managed Routing Appliance,
  two private workload VMs and four VNets.
- Provider: ingress/delivery managed VPN gateways, two plain Ubuntu NVA
  simulators behind an internal Standard HA-ports LB and three VNets.

All customer/provider transport is IPsec. There is no cross-side peering and no
VPN termination on the simulated firewall. Customer prefixes used by the test
remain fixed; automating onboarding does not solve arbitrary-prefix ingress
insertion or qualify real Check Point licensing/VMSS/state synchronization.

### Replacement lab results (2026-10-30)

The customer foundation and provider environment `21b09315` deployed
successfully. Both customer and both provider VPN connections reported
Connected; both Ubuntu simulator VMs ran, and NVA 0 established four Route
Server BGP sessions. These are lab simulators, not Check Point appliances.

Both workloads passed east-west ping (10/10 each direction) and HTTP (5/5 each
direction), retaining their source IPs. Temporary count-only rules recorded
traffic in both directions on both NVAs and were removed. Both workloads
received HTTPS IP-echo responses identifying NVA 0's public IP, passed public
ICMP, UDP and TCP DNS, received an NTP reply, and downloaded 1 MB over HTTPS.
The source-restricted external HTTP probe passed 5/5 through NVA 0; Network
Watcher denied an unrelated source. Its temporary NSG and NAT rules were
removed, and post-cleanup east-west and HTTPS tests passed.

Before the provider VPN connections existed, east-west traffic could still
reach the other workload despite the configured Routing Appliance next hop.
Do not treat this lab as fail-closed during deployment or tunnel loss. The
tests above do not establish Check Point inspection, permanent inbound
publishing, arbitrary-prefix support, or NVA failover. Private portal evidence
is retained under `.local/ns-replacement-20261030-v4/`. Obsolete enrollments
were revoked and archived, retaining their audit and allocation records.
The tagged resources for failed provider environments `05d0e410` and
`e3aa7702` and their obsolete proof route tables were removed. The shared
provider data resource group and the replacement environment were retained.

### Historical customer-1 lab results (2026-10-28)

- Four customer/provider VPN connections were connected. E–W ping passed 10/10
  and HTTP passed 20/20 in each direction with the original source address
  retained; an initial capture observed TCP on both NVAs. A later repeat passed
  all ping and HTTP requests, but its TCP capture appeared on only one NVA
  (ICMP appeared on the other), so the repeat did not pass the test's
  both-NVA TCP criterion.
- A scoped pilot from one customer VM to one public Microsoft IPv4 address
  returned TLS-verified HTTP 200 on 5/5 requests. Forward, return and SNAT
  counters increased on both NVAs. This does not provide general WWW egress.
- A dedicated external probe allowed by a source-restricted rule reached the
  customer VM on 5/5 HTTP requests through each NVA. DNAT, SNAT, forward and
  return counters increased; an unrelated source was denied by Network Watcher
  IP-flow verification. Ingress SNAT makes the workload see the NVA address,
  not the external client's original address.

These are temporary lab rules, not generated production N–S configuration.
The Ubuntu NVAs simulate routing and NAT with forwarding permitted; their
counters do not demonstrate Check Point policy inspection or stateful
high-availability failover. A separate experimental VNet/VPN gateway was
started for routing research; it is billable and is not connected to the
customer path. General Internet routing, source preservation, customer
isolation and failover remain to be designed and qualified.

For a temporary external ingress check, the provider administrator adds an
inbound NSG rule restricted to the probe's public IPv4 `/32`, one NVA private
IP and one TCP test port. The customer administrator adds an inbound rule for
that NVA private `/32` to one workload `/32` and its HTTP port. Capture each
applied rule in private evidence. Add matching temporary NVA DNAT/SNAT rules,
test the allowed source and a denied-source control, then remove the NAT and
both NSG rules. Verify removal and capture the final Portal state privately.
The probe does not establish a permanent publishing design or real Check Point
inspection, and ingress SNAT does not preserve the external source address.

On 2026-10-29, three additional HTTPS connections to the scoped pilot address
returned HTTP 400 responses with certificate verification disabled. The matching
NVA 0 NAT counter increased by three; NVA 1's did not change. Workload 0's
attempts to reach three other public HTTPS endpoints timed out. Both workload
subnets have default outbound access disabled and no NAT Gateway; workload 0
also has no public IP. At the time, its effective default route was Internet,
and the Routing Appliance subnet had only the pilot /32 route toward the VPN.
These results do not establish general egress or failover.

Later on 2026-10-29, both workload default routes were changed to the Routing
Appliance. The appliance subnet gained a `0.0.0.0/0` route to the VPN gateway,
and the customer ingress gateway was configured with `lng-customer-ingress` as
its default site. The ingress VPN reported connected after this change. A
provider ingress Route Server was deployed using the existing
`RouteServerSubnet` and public IP. It is billable and has branch-to-branch
exchange enabled. NVA 0 advertised a default route to both Route Server
instances; the provider ingress gateway learned it with NVA 0 as next hop.

Both simulated NVAs also have runtime-only `FAAS_NS_EGRESS29` NAT chains for
the two workload IPs. The chains exclude private and selected special-use
destinations before masquerading remaining traffic on `eth0`; they are not
persisted across reboot. East-west ping subsequently passed 3/3 in each
direction. With source- and destination-restricted temporary NSG rules, each
workload successfully made TLS-verified HTTPS requests to two addresses of the
same public IP-echo service. All four responses were HTTP 200 and reported
NVA 0's public IP. The customer VPN and provider BGP had no destination-specific
route for those addresses. This proves the scoped HTTPS path, not unrestricted
egress, Check Point inspection, or NVA failover.

For `8.8.8.8`, captures showed requests from both workloads reaching NVA 0,
being source-NATed, and receiving replies at the NVA. The replies did not reach
the workloads; adding narrowly scoped return rules at the provider and customer
NSGs did not resolve this, and those two rules were removed. After the NVAs
were restarted, adding `8.8.8.8/32` temporarily to the customer delivery local
gateway, with workload routes pinned to the Routing Appliance and scoped
return rules, also failed to restore ping replies. Those diagnostic routes,
prefix and return rules were removed. The separate provider ICMP and HTTPS
probe rules were subsequently removed after a broader rule was approved.

Both provider NVAs were subsequently deallocated outside this test, closing the
SSH sessions and withdrawing the BGP default. They were restarted at the
operator's request, and the runtime NAT and NVA 0 BGP configuration were
restored. The provider gateway relearned the default and both workloads again
received HTTP 200 from both scoped HTTPS addresses, reporting NVA 0's public
IP. The source-restricted inbound-pilot rules were restored, but the external
probe VM remains deallocated, so that pilot was not retested. The cause of the
deallocation has not been confirmed. The BGP and NAT settings are still
runtime-only, and unrestricted egress and failover remain unverified.

Later on 2026-10-29, the operator approved an inbound provider NSG rule
allowing all protocols and ports from the two workload IPs to the `Internet`
service tag. Both workloads then reached three public HTTPS services with
HTTP 200; each service reported NVA 0's public IP. Public UDP DNS and ICMP
still timed out, although TCP DNS to the same resolver succeeded for both
workloads. A synchronized UDP capture showed the request and its
source-NATed form reaching NVA 0, the DNS reply returning to the NVA, and the
reverse-NATed reply leaving it, but no reply arriving at the workload NIC.
Temporary, source-restricted UDP reply rules on both NSGs did not fix the
test and were removed, as were the now-redundant destination-specific probe
rules. The all-protocol rule remains active; it does not provide actual
firewall inspection or establish failover.

A subsequent UDP source comparison reached workload 0 when sent from NVA 0's
private IP, but not when the NVA locally translated the source to `1.1.1.1`.
In a separate same-subnet control, both source variants appeared in NVA 0 and
NVA 1 captures. The synthetic packets do not establish how the platform treats
forwarded DNS replies or identify the dropping hop. The temporary SNAT and NSG
rules were removed. Both workloads still passed HTTPS, TCP DNS and east-west
ping after cleanup.

Further tests on 2026-10-29 used private observer VMs on each side of the
delivery VPN. Synthetic UDP packets with public and private sources crossed
both provider and customer VNet peerings. Across the delivery VPN, sources
within `172.21.0.0/16` and `172.22.0.0/16` arrived, while the tested sources
outside those prefixes did not. The customer observer's effective NSG allowed
both. Adding `1.1.1.1/32` temporarily to the customer delivery local gateway
did not change the result. A temporary route on the provider delivery
`GatewaySubnet` to the synthetic source via NVA 0 allowed that source through;
removing the route reproduced the drop. The same test with a real DNS reply
from `1.1.1.1` failed without its source route and succeeded with it. This
isolates the failure to source-route handling on the provider delivery gateway
path; the internal Azure mechanism is not established. The diagnostic route
table and source-specific routes were removed.

A temporary VXLAN return overlay connected NVA 0 to a private customer
delivery VM at `172.19.1.4`. NVA 0 routed the two customer `/16` prefixes
through the overlay during the test; it still routed Internet destinations
directly out. The overlay endpoints were limited to UDP port 4789 between
their private IPs, and the observer forwarded Internet replies only to the two
workload IPs.
No temporary workload inbound exception was required for the tested replies.
Both workloads passed UDP DNS, UDP NTP, ICMP, TCP DNS and HTTPS, with HTTPS
reporting NVA 0's public IP. A 1,319-byte DNSSEC UDP response and 1 MB HTTPS
downloads passed after raising the overlay MTU to 1,450. Fragmented 2 KB and
4 KB pings timed out; the workload fragments did not appear at NVA 0, and
direct fragmented pings from NVA 0 also timed out.

At the operator's request, the VXLAN endpoints, NVA overlay routes, customer
observer VM, disk, NIC, subnet, NSG and provider overlay NSG rules were removed.
The original delivery path was restored, and the customer delivery VPN remained
connected. The overlay was a diagnostic workaround, not a production or HA
design. At that stage NVA 0's BGP and NAT were runtime-only.
NVA 1 failover, real firewall inspection, and all-protocol or arbitrary-size
traffic have not been established. The provider-side observer and temporary
source-comparison rules and routes were removed.

The separate provider Route Server and its co-located active-active VPN gateway
were subsequently used for a delivery-path test. A new non-BGP site-to-site
connection links that gateway to the existing customer delivery gateway, and the
NVA VNet's remote gateway was switched from the original provider delivery
gateway to the test gateway. Both provider test peerings permit forwarded
traffic; the test gateway peering also permits gateway transit. The original
delivery connection remains present. The provider test local gateway contains
static customer prefixes, so onboarding additional customer networks has not
been proven automatic.

NVA 0 advertised `0.0.0.0/0` to both instances of the provider delivery Route
Server, and the test gateway learned it. A `0.0.0.0/0 -> Internet` UDR on the
NVA subnet protected its own egress; no default UDR was placed on a gateway
subnet. With no VXLAN or customer forwarding VM and no resolver-specific NSG
rules, both workloads passed UDP DNS, UDP NTP, ICMP and three HTTPS endpoints,
all reporting NVA 0's public IP. A 1,319-byte UDP DNS response and 1 MB HTTPS
downloads passed. Both east-west ping directions passed and appeared on NVA 0.
A scoped UDP DNS deny on the Ubuntu simulator blocked the selected query while
another resolver remained reachable; the counter incremented and traffic
recovered after the deny was removed. These tests do not qualify Check Point
inspection, HA or arbitrary packet sizes; 2 KB fragmented pings still failed.

Withdrawing only the provider delivery Route Server's BGP default caused DNS
and Internet ping to fail while east-west ping remained healthy. The route was
restored and both Route Server instances again supplied the default, but before
the recovery traffic checks could complete, NVA 0 was deallocated by another
principal at 22:48 UTC on 2026-10-29. NVA 1 was already deallocated. NVA 0's
FRR BGP and NAT settings were runtime-only, so the ingress and delivery BGP
defaults were subsequently absent and both workloads' DNS, ping and HTTPS
checks failed. The new gateway connections, Route Server, peerings and NVA
Internet safeguard remain in place and may incur charges. The provider-only
probe VM, NIC, disk, subnet, NSG and probe route table were removed. The prior
cross-tenant VNet-to-VNet attempt was rejected for linked authorization, and a
customer local gateway for a separate BGP attempt rejected ASN 65515.

On 2026-10-30, the operator authorized restarting NVA 0. Its source-restricted
workload NAT, filtered BGP advertisements to both Route Servers, and scoped
HTTPS pilot MSS rules were restored in memory. Both gateways relearned the
default via NVA 0, whose own Internet route remained active. Both workloads
then passed ICMP and UDP NTP, and reached three HTTPS IP-echo services through
NVA 0's public IP. One initial UDP DNS query to `1.1.1.1` timed out on workload
0; the next ten queries passed on each workload. Both workloads also passed a
1,319-byte UDP DNS response, a 1 MB HTTPS download and 3/3 east-west pings.
NVA 1 remained deallocated. The separate inbound-publishing pilot was not
restored or retested in this recovery.

Later on 2026-10-30, the current NVA 0's FRR configuration was saved and an
ordered systemd unit was installed to restore the two workload NAT rules and
the scoped pilot MSS rules before FRR starts. After an NVA reboot, the startup
services were active and all four Route Server BGP sessions re-established.
Both workloads reached an HTTPS IP-echo endpoint through the provider public IP,
passed 3/3 Internet ICMP probes, and passed 3/3 east-west pings in each
direction. NVA 1 remains deallocated; the inbound pilot remains untested and
the new deployment definition has not yet been exercised in a fresh lab.
A subsequent reboot exposed a systemd ordering cycle involving FRR and
`network-online.target`; the persistence unit and fresh-lab startup ordering
were corrected. A further clean reboot restored all four peers and both NAT
jumps without an ordering-cycle log, and both workloads again passed HTTPS
IP-echo and 2/2 east-west pings.

Azure VPN Gateway does not advertise a learned default route to other BGP peers.
Azure also does not support a `0.0.0.0/0` UDR on `GatewaySubnet`. See the
Microsoft documentation for
[Route Server and VPN gateway integration](https://learn.microsoft.com/azure/route-server/expressroute-vpn-support)
[gateway subnet requirements](https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-about-vpn-gateway-settings#gateway-subnet),
and [VPN Gateway BGP and routing](https://learn.microsoft.com/azure/vpn-gateway/vpn-gateway-vpn-faq#bgp).

The customer subscription, provider subscription and protected historical group
are private configuration, not hardcoded deployment targets in public examples.
The authenticated worker's ARM target comes from provider configuration, never
from an incoming customer request.

## Cost warning before live execution

The control-plane proof and the full networking test have very different costs.
At the default SKU selections, the following are public USD consumption rates,
not a complete quote:

| Component | Count | Rate per instance-hour | 730-hour subtotal |
| --- | ---: | ---: | ---: |
| Central US Linux App Service B2 plan | 1 | $0.035 | $25.55 |
| East US 2 VpnGw1AZ gateways | 4 | $0.21 | $613.20 |
| East US 2 Linux Standard_B1ms VMs | 4 | $0.0208 | $60.74 |

These three components alone total approximately **$699.49/month** while
running. Storage, disks, public IPs, private endpoints, DNS, load balancing,
transactions, traffic and other supporting resources are **additional**.
The current lab's provider plan runs on B2, and the
separate experimental gateway and external probe are additional billable
resources. Retaining other labs during validation also retains their costs.
Stopping VMs does not stop managed VPN gateway or App Service plan charges.

Sources: Azure Retail Prices API for
[Central US B2](https://prices.azure.com/api/retail/prices?$filter=serviceName%20eq%20%27Azure%20App%20Service%27%20and%20armRegionName%20eq%20%27centralus%27%20and%20skuName%20eq%20%27B2%27%20and%20priceType%20eq%20%27Consumption%27),
[East US 2 VpnGw1AZ](https://prices.azure.com/api/retail/prices?$filter=serviceName%20eq%20%27VPN%20Gateway%27%20and%20armRegionName%20eq%20%27eastus2%27%20and%20skuName%20eq%20%27VpnGw1AZ%27%20and%20priceType%20eq%20%27Consumption%27)
and [East US 2 B1ms](https://prices.azure.com/api/retail/prices?$filter=serviceName%20eq%20%27Virtual%20Machines%27%20and%20armRegionName%20eq%20%27eastus2%27%20and%20armSkuName%20eq%20%27Standard_B1ms%27%20and%20priceType%20eq%20%27Consumption%27).
Verify rates and actual template SKUs again before deployment. Prices and
availability can change; use the [Azure Pricing Calculator](https://azure.microsoft.com/pricing/calculator/)
for a complete estimate.

## Implementation versus live verification

The implementation has passed **406 project tests**, **37 repository tests**,
compilation of all **22 Bicep templates**, and publication checks. The source and
prepared customer forms pass Microsoft's UI Form Definition schema. Checkov
reports **91 passed, zero failed, 28 explicitly documented skips**, with zero
parsing errors.
The final application ZIP was rebuilt and its exact compiled provider-template
hash validated by the worker's runtime loader.

Provider-only live checks verified API/client registration, sequential successful
API/worker builds, authenticated operation-store readiness, a `404` for an
absent operation, rejection of unauthenticated readiness requests, and a `403`
for the API-only client's provider ARM access. Published proof ARM/Form downloads
return `200` and match their hashes. The customer administrator subsequently
completed the Portal proof; the corresponding provider operation returned
`Ready` and its ARM deployment succeeded. Check Point did not access customer
Azure to verify it. Full-network ARM/Form files are separately published and
hash/schema checked; publishing them does not deploy their resources.
The subsequent full-network retry and traffic acceptance passed as described
below. A later, separately approved cleanup removed both lab generations; see
the cleanup outcome below.

### Live two-tenant acceptance: 2026-10-27

The customer and provider parent deployments both reached **Succeeded**, and
the customer deployment/API operation reported **Ready**. No further redeployment
was needed after the host-encryption prerequisite fix.

| Check | Measured result |
| --- | --- |
| Customer and provider VPN connections | All four `Connected`, provisioning `Succeeded` |
| Workload and NVA VMs | All four running, guest agents ready, cloud-init complete |
| Guest services | Both workload HTTP receivers and both NVA forwarding/health services active |
| Workload A to B ping | 10/10 replies, 0% packet loss |
| Workload B to A ping | 10/10 replies, 0% packet loss |
| Workload A to B HTTP | 20/20 HTTP 200; receiver saw original source `10.211.0.4` |
| Workload B to A HTTP | 20/20 HTTP 200; receiver saw original source `10.212.0.4` |
| Provider forwarding-path observation | Both NVAs captured original-address TCP packets in both directions across the test flows |
| ICMP forwarding-path observation | An NVA captured workload ICMP in both directions |
| Workload effective routes | Peer workload `/16` selected the customer RA's service-assigned primary IP |
| NVA effective routes | Both workload `/16` prefixes selected `VirtualNetworkGateway` |
| Delivery BGP | Peers connected; provider learned both workload prefixes via eBGP from customer delivery |
| Ingress connections | BGP disabled, preserving the intended static ingress design |

Packet collection was bounded and metadata-only: workload source/destination,
protocol and counts, not payloads. Temporary capture units and metric files were
removed after testing. Each flow uses one NVA, not both in series. Observing
different flows on both NVAs is not a failover or state-synchronization test.

The original failure was the customer subscription's unregistered
`Microsoft.Compute/EncryptionAtHost` feature. The operator registered it with
explicit customer-admin authorization, refreshed Compute registration, and the
customer retried the same incremental deployment/RG. Completed gateways were
retained; no host encryption, Defender, NSG or SSH controls were weakened.
The later monitoring and Run Command tests used explicitly authorized operator
user sessions on both sides, not provider-service access to customer Azure.

Private structured test evidence is retained in `.local/acceptance-results.json`,
outside Git. Acceptance is limited to this East US 2, fixed-prefix, Ubuntu
route-only simulation. Real Check Point filtering/licensing/VMSS/state sync,
failure recovery, other regions and fully automated Marketplace enrollment
remain separate qualifications. These live-test resources were subsequently
removed in the approved cleanup.

### Audit and cleanup: 2026-10-28

The suspected secret exposure in commit `cc8c5c0` was investigated without
printing credentials. No confirmed API secret, real SAS bearer URL or SSH
private key was found in the commit or locally reachable Git history. The
actual old API credential had zero exact matches. Private `.local` configuration,
credentials and journals were untracked and ignored. Public Azure identifiers
and dummy test signatures are not authentication secrets.

This conclusion is limited to the inspected Git content. It does not establish
that a credential was never exposed in an editor selection, chat, screenshot,
terminal or external log. The old API credential was therefore removed before
deleting its application. Both lab-owned app registrations and both associated
service principals were verified absent through Microsoft Graph.

The user explicitly approved deletion of five exact resource groups: the
provider control plane, provider dataplane, customer deployment, older VPN lab
and an additional confirmed lab VNet/NSG group. All five were verified deleted.
Unrelated groups, shared Network Watcher/domain/governance resources, local
SSH keys and subscription feature registrations were preserved. Key Vault
soft-delete/purge protection was not bypassed.

Graph cleanup initially failed with a Conditional Access Evaluation challenge
against an old cached token. A fresh, isolated operator sign-in resolved it;
the temporary authentication cache was removed without clearing the operator's
global Azure sessions. No Git history rewrite was justified by the findings.

The user then chose **stop after cleanup**. No replacement resources,
authentication prototype or new end-to-end deployment were created. The
current code still uses customer-specific API credential bootstrap: it does
**not** implement fully independent Marketplace onboarding. Lighthouse was
rejected because granting the provider customer Azure access violates the
required boundary. Alternative bootstrap designs remain unimplemented and
unqualified; no unsupported cross-tenant federation workaround is claimed.

Future deployment requires fresh authorized configuration and explicit handling
of stale private journals, expired artifact URLs and revoked credentials.
Preserve old local evidence rather than silently rebinding it to new identities.

### Private dependency DNS

Both VNet-integrated apps explicitly set `WEBSITE_DNS_SERVER=168.63.129.16` to
use Azure DNS and the control VNet's linked private DNS zones. In the provider
live check, configured VNet integration and approved private endpoints alone
still produced an operation-store `ServiceResponseTimeoutError`; explicit DNS
restored authenticated Table access. This setting is part of
[`infra/main.bicep`](infra/main.bicep), not a requirement to make Operations
storage public or broaden its RBAC.

Use the authenticated `/v1/readiness` endpoint to check operation-store access;
`/healthz` alone does not establish dependency health. Readiness reports safe
error classifications, never credentials or raw dependency response bodies.

### Explicit PoC policy exceptions

Checkov exceptions are scoped to individual resources and justified in the
Bicep source; they are not a global scanner bypass:

| Controls | Reason |
| --- | --- |
| `CKV_AZURE_36` | Private storage has no public access or trusted-services bypass. |
| `CKV_AZURE_43` | Storage name is `st` plus ARM's 13-character lowercase `uniqueString`; the computed name follows naming rules. |
| `CKV_AZURE_206` | Approved lab storage is LRS, not regional disaster recovery. |
| `CKV_AZURE_225`, `CKV_AZURE_212` | The approved single-instance B2 control plane is deliberately not HA or zone redundant. |
| `CKV_AZURE_222` | Public API HTTPS is intentional. Worker site ingress denies all; operator-/32 SCM needs separate execution approval. |
| `CKV_AZURE_17` | Authentication uses app-only Entra tokens, not incoming client certificates. |
| `CKV_AZURE_18` | HTTP/2 is explicitly enabled and asserted against compiled ARM. |
| `CKV_AZURE_50` | Tenant-managed security extensions must remain enabled; no arbitrary VM extensions are deployed by these templates. |

The two runtime exceptions requiring explicit approval are:

1. Keep worker **SCM management** reachable from the operator's public `/32`,
   with Entra publishing authorization and basic authentication disabled.
   Worker application ingress still denies all.
2. Let customer `deploymentScripts` create its **own transient ACI and
   shared-key backing storage**. This does not reopen public access or enable
   shared keys on the provider's private operations account.

These require dedicated CLI approval flags as well as `--execute`. No code
silently weakens either boundary to recover from a deployment error.

### Live network prerequisites

VMs enable Trusted Launch, Secure Boot, vTPM and host encryption. Read-only
preflight confirmed host-encryption support for the lab SKU, but the
`Microsoft.Compute/EncryptionAtHost` feature was initially **NotRegistered**.
After explicit approval, provider registration completed and was verified as
**Registered**. The first customer network deployment later failed both workload
VMs because the customer feature was still **NotRegistered**, despite the earlier
reported status. With separate, explicit one-time lab authorization, the operator
used their own customer-admin session to register it and verified **Registered**.
`Microsoft.Compute` was re-registered on both sides to propagate the feature.
No provider service identity received customer access or additional RBAC.
This lab exception is not a production onboarding requirement. Feature
registration is a separate authorized subscription change, not something the
provider worker can perform with its RG-scoped role.

The customer administrator can check/register the feature through
**Subscriptions > their subscription > Preview features**, with the state filter
set to **All**, when that feature is exposed in the Portal. Not all features are
listed; the customer reported this feature was absent. Automatic UI-only
subscription-feature bootstrap is not implemented by this PoC. After registering
a feature, refresh its resource provider registration to propagate it; do not
unregister the provider. See Microsoft's
[feature registration guidance](https://learn.microsoft.com/azure/azure-resource-manager/management/preview-features).
Customer administrators must also
confirm provider registration, regional quota/SKU availability and applicable
policies in their own subscription before full deployment. Provider checks
cannot establish those customer-side conditions.

The deployed configuration has no general implicit Internet egress; the
single-destination pilot above is an explicit temporary exception. Tenant-managed
Defender/security-agent installation and update connectivity must be verified
before qualification. Do not disable Defender or policy, or silently introduce
public SSH/NAT, to turn a failed readiness check into a success.

Only delivery connections exchange BGP routes. Ingress connections retain the
static, fixed-prefix steering design; enabling BGP on every connection would
change the topology being recreated.

### Local service development

Use Python 3.12 and an isolated virtual environment:

```bash
cd "$(git rev-parse --show-toplevel)/provider-provisioning"
python3.12 -m venv .venv
source .venv/bin/activate
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q tests/test_service.py
.venv/bin/python -m pip check
```

The tests inject test-only dependencies. Normal startup uses
`ManagedIdentityCredential` and real Azure SDK clients, with no CLI-user or
client-secret fallback. Supply App Service settings from
[`service/environment.example`](service/environment.example); do not paste
production settings into that example. Start each app from this directory with
`bash startup-api.sh` or `bash startup-worker.sh`, using the environment's Python
interpreter. These commands alone are not a local Azure authentication emulator.

### Application contract

| Endpoint | Purpose |
| --- | --- |
| `GET /healthz` | Safe process liveness |
| `POST /v1/environments` | Reserve an authenticated operation with `Idempotency-Key` |
| `GET /v1/operations/{operationId}` | Owner-authorized status and nonsecret manifest |
| `GET /v1/environments/{environmentId}/connection-material` | Owner-authorized network PSKs; `Cache-Control: no-store` |

A minimal request is `{"mode":"proof"}`. Network mode additionally requires
`customerIngress` and `customerDelivery`, each containing `publicIp`,
`bgpAddress` and `asn`. Region is restricted to `eastus2` and tier to `lab`;
unknown fields are rejected. The operation and environment IDs are the same.
The service never accepts a provider resource group, subscription, deployment
template or ARM credential in a request.

Requests record allocations atomically with their operation and durable job.
Reusing a key with the same request returns the existing operation; changing the
body returns a conflict. A successful environment retains its allocation
record. There is deliberately no delete/cancel API in this PoC. The updated
release has no global or customer allocation-count ceiling, but preserves
active-operation limits. It was published to the live lab on 2026-11-02; the
behavior has not been separately qualified live.

The worker requires the exact SHA-256 of its bundled, compiled provider ARM
template before network mode is available. Proof mode creates one tagged route
table only and needs neither the network template nor an NVA SSH key. Missing
network configuration produces an explicit failed operation, not fake endpoints.

## Administration ownership and current limitations

| Actor | Permitted scope and tools |
| --- | --- |
| Check Point administrator | Provider tenant/subscription only; Python/CLI on the provider workstation or CI/CD |
| Customer administrator | Customer tenant/subscription only; customer-owned Portal/onboarding and authorization |
| Customer end user | Prepared Azure Portal/Bicep wizard; no local tools, provider Azure RBAC or directory-admin role |

Local build, tests and packaging are provider/development activities and do not
require either Azure tenant login. Provider Azure commands authenticate only to
the provider tenant. Customer directory grants, customer RG creation, customer
feature registration and publication into customer RGs are customer-owned
operations, never tasks for a Check Point login.

The legacy `bootstrap.py groups` and customer Graph/CLI phases remain
coordinated-lab tooling and are not used in the independent flow.
`provider_setup.py` operates only in the provider tenant/subscription;
`prepare_customer_portal.py` now reads provider journals and provider feature
state only. Customer identifiers are enrollment metadata, not customer Azure
access. See the
[role-separated deployment guide](../README.md#deploy-the-two-tenant-implementation).

### Check Point preparation: no customer login

After local validation/packaging, and only after live execution approval:

```bash
az login --tenant "$PROVIDER_TENANT_ID"
python scripts/provider_setup.py groups --config .local/config.json --execute
python scripts/provider_setup.py api --config .local/config.json --execute
python scripts/provider_setup.py api-client --config .local/config.json --execute
python scripts/provider_setup.py control-plane --config .local/config.json \
  --execute --approve-scm-bootstrap-exception
```

Only provider RGs and provider-directory objects are created by these commands.
The API-only client requests only `FirewallDeployment.Request`; no Azure RBAC
is assigned to it. Its 24-hour PoC secret is saved only in private
`.local/customer-api-credential.json`, never printed or included in artifacts.
Issue it to the correct customer through an approved secure channel.
`api-client --rotate-credential` explicitly replaces a known credential; an
ambiguous write or expired/missing credential stops instead of silently
generating replacements. Audit effective permissions before live qualification.

The customer enters this API credential in a required PasswordBox. It is
`@secure()` in Bicep and a deploymentScripts `secureValue`; it is not an Azure
password, provider worker credential or customer-directory grant.
It goes to the provider Entra token endpoint only. The API receives the
resulting audience-restricted bearer token, not the client secret.

### Protected package publication: ARM OneDeploy

Direct `code-deploy` uses SCM and may be denied when the runtime's network
relay/egress IP differs from the operator `/32`. Keep the restrictions and basic
authentication settings intact. The approved alternative is a pull deployment:

```bash
python scripts/provider_artifacts.py host --config .local/config.json \
  --publisher-principal-id "$PROVIDER_PUBLISHER_OBJECT_ID" \
  --publisher-principal-type User --execute
python scripts/provider_artifacts.py upload --config .local/config.json \
  --file .local/apps.zip --blob-name packages/provider-apps.zip \
  --uri-output .local/apps-pull-uri.json --execute
python scripts/provider_setup.py code-deploy --config .local/config.json \
  --package-uri-file .local/apps-pull-uri.json --execute
```

The publishing principal is the Check Point operator/CI identity, not the
API-only client. Blob Data Contributor is scoped only to the artifact account.
The host uses a private container, disabled anonymous/shared-key access, and
HTTPS read-only user-delegation SAS. Hosting's public routing is a deliberate
artifact-download exception, never an exception on Operations storage.
`provider-code.bicep` keeps the SAS in a secure parameter and changes only the
owned apps' OneDeploy extensions. No SAS enters process arguments, logs or
ordinary outputs.

Use an immutable version/hash blob name and a new private URI output file after
each package rebuild. Existing same-hash blobs may be reused; different content
is never overwritten. The host checks ownership and preview scope before
deployment and refuses the API-only client as an Azure publisher.
If actual networking is disabled by security automation, publishing stops; the
helper does not override policies or re-enable networking.

For ongoing production operation, qualify certificate authentication,
customer-controlled protected storage and automated rotation/revocation.
Entra credential removal does not itself revoke every already-issued access
token immediately. No API-client credential should ever receive Azure RBAC.

### Check Point public admin allowlist

**Published on 2026-11-04; runner and fresh-link checks passed.**
Public administrator access after a complete new-environment deployment is
still a qualification gate, not an established result.
The Check Point wizard has an optional comma-separated `adminAllowedSources`
field for up to 16 public unicast IPv4 hosts or network-aligned CIDRs.
Bare hosts become `/32`; duplicates are removed. Private, shared, loopback,
link-local, documentation, reserved and multicast ranges, IPv6, malformed
entries and `/0` fail explicitly before customer network deployment.
Ubuntu remains the default. Empty/absent lists retain the original Ubuntu and
Check Point request digests, runner schema 1 and legacy lab networking.
Nonempty lists require Check Point and at least runner schema 2. The optional
provider connection-details relay uses schema 3; empty/legacy configurations
remain compatible when that relay is not enabled.

Office/home defaults come from `adminAllowedSources` in the ignored local
configuration for `prepare_customer_portal.py`, or from the management app's
JSON-array `FAAS_ADMIN_ALLOWED_SOURCES` setting for `ProfilePublisher`.
`provider-management.bicep` exposes the same optional array parameter.
The source example is empty: never commit actual operator addresses, UPNs,
passwords, API credentials or SSH private keys. Customers can edit or clear
the prefilled values; switching to Ubuntu sends an empty list.

For **new Check Point environments**, the approved list configures:

- Provider NSG child rules: gateway TCP 22/443; management TCP
  22/443/18190/19009. Private provider/automation access remains allowed,
  including `172.22.40.0/23`. Child-rule deployment does not replace
  user-owned NSG rules.
- A source-scoped gateway HTTPS/SSH access rule with logging, separate from
  the existing east-west/no-NAT and Internet egress rules. Conflicting
  existing admin objects/rules stop configuration rather than being replaced;
  an existing cleanup rule must already drop. The admin path does not reset
  an uninitialized gateway's SIC object.
- Management SmartConsole clients through the officially documented
  [`cp_conf client add/get`](https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_SecurityManagement_AdminGuide/Content/Topics-SECMG/CLI/cp_conf-client.htm)
  commands, executed on the management server through private Management API
  `run-script`. CIDRs use dotted netmasks. Only `add` is used: existing clients
  and the automation client subnet are not replaced. A missing task, command
  failure or failed readback blocks completion; there is no `Any` fallback,
  direct configuration-file edit or server restart.
- Provider management-subnet and gateway/automation route-table Internet
  exceptions for those public source prefixes. Customer-owned deployments
  create Standard public IPs for both test VMs, SSH-only admin NSG allows and
  matching Internet return exceptions on both workload route tables.
  Empty lists create no customer test-VM public IPs or admin return exceptions.

SIC and logs continue to use the **private management IP**; the management
public IP is for administration only. These are fixed per-environment admin
sources, not provider configuration per customer VNet. No east-west NAT or
cross-tenant Azure permissions are introduced. Existing user access rules are
preserved, not revoked; this feature is not an allowlist-editing API for
already provisioned environments.

Release and new-environment qualification checklist:

1. Publish compatible API, worker and management packages, including the new
   validator, compiled customer ARM/Form and compiled Check Point foundation.
   The publisher rejects incomplete source propagation. Old foundation
   artifacts explicitly block nonempty lists before provider resource changes.
2. Compile/validate the exact release foundation artifact and set
   `FAAS_CHECKPOINT_FOUNDATION_TEMPLATE_SHA256` to the hash of its bundled
   bytes, retaining the matching `FAAS_CHECKPOINT_FOUNDATION_TEMPLATE_PATH`.
   Do not reuse a hash from a different compiler/build.
3. Separately rebuild/publish the runner image with these Python changes and
   update `FAAS_CHECKPOINT_IMAGE_SHA256` to that image's actual digest.
   Schema 2 requires the new runner; schema 1 remains valid for empty lists.
   Terraform/module/provider/schema pins and `ARTIFACT_SHA256` are unchanged:
   this feature does not modify the prepared pinned Terraform artifacts.
   The Check Point private-data template/pin is unchanged.
4. Configure the approved local office/home defaults, then republish customer
   profiles to obtain fresh links. Never insert credentials into those links.
5. Qualify public management HTTPS/SSH/SmartConsole, gateway HTTPS/SSH and both
   customer test-VM SSH paths and their effective Internet return routes after
   VPN/BGP convergence. Real R82 management-target script execution/client
   readback passed the bounded runtime test, but SmartConsole login and the
   complete new-environment access paths remain unverified. Unsupported
   execution stays blocked, not reported successful. Retest the
   existing source-preserving east-west policy, logging and gateway egress.

The release updated the existing API, worker and management application code,
with matching runner-image and bundled-foundation pins. A private Linux
qualification job verified schema 2, the real R82 log-destination response and
management-target additive client commands, preserving existing clients and
the automation range. The temporary job was removed. A newly issued customer
link returned both artifacts successfully with the configured defaults,
Ubuntu still selected by default and no embedded API credential.

The worker remains publicly denied; readiness was checked through its existing
Azure internal health probe and startup evidence, not by opening access.
ARM what-if could not preview the write-only OneDeploy operation; the operator
approved the existing native code-only publication method with that limitation
documented. No existing lab networking, gateway policy, SIC or BGP was changed
by publication. This does not release VMSS or parallel appliance/VPN provisioning.
See [EW-45](../docs/test-register.md#ew-45-administrator-allowlist-release-and-bounded-runtime-qualification).

### Reveal credential: routing and Check Point connection details

**Published and live-verified on 2026-11-04.** The existing lab's actual
Routing Appliance address and private management credential were populated
without changing VM authentication or network configuration. New environments
publish these details through their customer connector and provider runner.

The existing **Reveal credential** action also displays the selected customer's
owned Check Point environments. It is not a new unprotected credentials page.
The signed provider-administrator identity, exact request Origin and existing
customer binding are required. Reads are audited and responses are `no-store`.
Passwords clear after 30 seconds, on Clear now, navigation, tab hiding or another
portal action. They are never added to customer lists, deployment links,
Operations rows or browser storage.

The panel separates:

- **Customer UDR next hop:** the actual customer Routing Appliance address,
  reported by customer-owned deployment automation, with next-hop type
  `VirtualAppliance`. Workload routes need remote workload prefixes as well as
  the default route; a default alone does not override more-specific peerings.
  Customer peering/gateway-transit configuration and BGP propagation still
  matter. The provider firewall backend address is **not** this next hop.
- **Management:** public/private IPs, HTTPS link, SSH command, username `admin`
  and the stored generated management password.
- **Gateway:** public/frontend/backend IPs, HTTPS link, SSH command and username
  `admin`. The deployment uses the provider SSH key; it does not manage a
  gateway password. A manually configured web password is neither reset nor
  guessed by this feature.

The customer connector registers its service-assigned Routing Appliance IP
through its own authenticated `/v1/operations/{id}/routing` endpoint. This is
display metadata only: it does not change provisioning request digests, provider
routes or NAT, and requires no provider update when adding a customer VNet.
Older environments without this metadata report the missing address explicitly;
an authorized provider administrator can register a customer-supplied address
through `/admin/customers/{id}/environments/{environment}/routing`.

The portal cannot directly reach isolated environment vaults. When explicitly
configured, the provider runner reads the existing private credential locally,
discovers the exact owned public-IP resources and publishes **only** management
access details over authenticated TLS to `/internal/checkpoint-access`.
It does not transmit the SIC key. The target verifies the existing provider API
token audience, provider tenant and exact publisher managed-identity client and
object IDs, then checks the operation/customer/group binding. The managed-
identity resource claim is checked against the configured resource ID when
present; the live v2 issuer does not always emit that optional claim.
It stores the details in the existing **private management Key Vault** using
the management app's existing permissions. No customer Azure permission, new
Entra consent, public vault access or relaxed network restriction is required.

Enable the paired worker relay settings and three pinned management identity
settings documented in [environment.example](service/environment.example).
App Service Authentication must retain the administrator allowlist and admit
only the exact additional publisher principal/API audience. Application-level
administrator routes remain user-only; publisher access is limited to the
internal write-only relay. `provider-management.bicep` exposes matching optional
parameters. Missing publication, a retired environment, wrong binding or vault
failure is explicit; there is no password fallback or automatic reset.

### Customer Azure Portal wizard: sizing

[`portal/customer-form.json`](portal/customer-form.json) is an Azure Portal
Form view definition for the complete
[`customer-deployment.bicep`](infra/customer-deployment.bicep) template. It exposes
customer region and sizing dropdowns, plus the native subscription/RG picker:

| Dropdown | Options | Default |
| --- | --- | --- |
| Customer resource region | East US 2, East US, North Europe, West Europe, Israel Central | East US 2 |
| Routing Appliance bandwidth | 10 Gbps only, the existing verified option | 10 Gbps |
| Customer ingress VPN gateway | VpnGw1AZ, VpnGw2AZ, VpnGw3AZ, VpnGw4AZ, VpnGw5AZ | VpnGw1AZ |
| Customer delivery VPN gateway | VpnGw1AZ, VpnGw2AZ, VpnGw3AZ, VpnGw4AZ, VpnGw5AZ | VpnGw1AZ |

The gateway default is the lowest-priced **compatible new-deployment** SKU, not
the cheapest SKU regardless of features. Basic is excluded because it does not
support BGP; delivery requires BGP and this implementation keeps both gateways
compatible with the same endpoint contract. VpnGw1AZ uses Generation1;
VpnGw2AZ through VpnGw5AZ use Generation2.

Only 10 Gbps is currently exposed for the Routing Appliance by user decision.
Its public API does not provide a verified size/price catalog, so no cheaper
size or price is invented. The bandwidth dropdown is ready for additional
verified sizes later.

These choices affect **customer resources only**. Provider gateways retain
their provider-controlled VpnGw1AZ default; sizing fields are not forwarded to
the provider API. A larger customer SKU does not remove a provider-side
throughput limit. Availability, quota and policy still need live verification,
and arbitrary resizing of existing gateways is not qualified.

Region options are checked against Azure's provider-advertised Routing
Appliance/gateway locations and three-zone public-IP support. They are a
compatible catalog, not proof of capacity or live inspection in every region.
Customer feature/quota/policy validation remains local to the customer.
Gateway/VM/RA and customer connection locations all follow the selected region;
automation execution stays in East US 2.

Developer/coordinated-lab configurations accept the same selections in `.local/config.json`;
this is not a customer end-user setup step:

```json
{
  "routingApplianceBandwidthGbps": 10,
  "customerIngressVpnGatewaySku": "VpnGw1AZ",
  "customerDeliveryVpnGatewaySku": "VpnGw1AZ"
}
```

Omitting them uses the defaults above. Invalid options fail locally, and ARM
`allowedValues` also enforce them independently of the UI. Sizing changes do
not reset the ownership journal.

The customer Bicep creates its UAMI, Network Contributor and metadata-only
Reader on its selected customer RG
using the customer's native ARM authority. The API role belongs to the
different API-only client in the provider tenant. No customer-directory API
role grant or pre-onboarded customer identity is needed.

The customer deployer needs Owner, or Contributor plus Role Based Access Control
Administrator, on the enrolled RG to create resources and local role
assignments. The end user needs no directory administrator role, provider
Azure RBAC, local Python or CLI.

After provider configuration/code publication, prepare a proof-only profile:

```bash
python scripts/prepare_customer_portal.py --config .local/config.json \
  --execute --proof-only --output .local/customer-proof
```

This needs no VM host-encryption registration, NVA SSH key or customer Azure
access. Proof mode creates no VPN gateways/VMs. For the later full-network
profile, omit `--proof-only`; it checks **provider** feature registration only.
Preparation reads `.local/provider-journal.json` and
`.local/provider-identity.json` and creates:

- `.local/customer-portal/azuredeploy.json`: complete self-contained ARM template.
- `.local/customer-portal/uiFormDefinition.json`: customer form with onboarding
  values preset and technical identity/API parameters hidden.
- `.local/customer-portal/profile.json`: scope, permission requirements and hashes.

For `--output .local/customer-proof`, the files are under that directory instead.
Do not upload raw `customer-deployment.bicep`, private `config.json` or
`uiFormDefinition.json` into an ARM JSON template editor. Only the compiled
`azuredeploy.json` is an ARM template. The normal one-click Portal link loads
the generated ARM JSON **and** form, rather than asking the customer to upload
files. Proof-only preparation restricts `deploymentMode` to `proof`, not just
its default, so the standard editor cannot accidentally switch it to network.

The prepared template includes the compiled reciprocal connection template as
base64 data; it has no dependency on local files at customer deployment time.
It contains no provider credential or IPsec shared key. Keep per-customer
profiles private; they contain customer identity metadata and are not Git
artifacts. The administrator may preset an existing workload SSH public key.

Developers can preview a prepared template and form in the
[Form view sandbox](https://aka.ms/form/sandbox), choosing `CustomTemplate`.
Previewing a form does not deploy resources. The form JSON is validated
against Microsoft's published Form view schema. Earlier versions of the form
were deployed through the Portal for the scoped acceptance above. The new
SSH selector has been tested separately in Portal; a full deployment using it
and production onboarding remain separate qualifications.

Check Point hosts the two prepared files on its approved HTTPS artifact
service. For private blobs, use short-lived read-only single-blob SAS URLs,
not customer Azure RBAC or account keys. Never publish the API secret in the
template, form or URL. Hosting/upload/SAS issuance are provider-owned tasks;
this tool does not automatically create or publish an artifact host.

Save published `templateUri`/`formUri` in a `0600`
`.local/artifact-uris.json`. Re-run preparation with `--artifact-uris` to save a
private `launch.json` containing the encoded Portal deployment link. Use the
same profile mode/output path so the hosted files match the generated pair.
Do not print SAS links into public logs. The link format follows Microsoft's
[custom Portal offering example](https://techcommunity.microsoft.com/blog/azurearchitectureblog/creating-a-custom-and-secure-azure-portal-offering/3038344)
and [Deploy to Azure](https://learn.microsoft.com/azure/azure-resource-manager/templates/deploy-to-azure-button).
No customer Template Spec publication, provider Azure RBAC or customer CLI
is required.

### Customer end-user steps: no commands

1. Open Check Point's **Deploy to Azure** link.
2. Select the **enrolled customer subscription**, then create or select a
   dedicated RG. Its name is not fixed or restricted to a `rg-faas-` prefix.
3. Choose the **customer resource region** and Routing Appliance/VPN SKUs.
   For SSH, generate a new key pair in the wizard, select an existing Azure SSH
   key, or paste a public OpenSSH key. Download and securely keep any generated
   private key; it is not recoverable from the form. SSH is not needed for a
   proof-only profile. The updated selector is included in newly published
   customer deployment links.
4. Enter the customer-specific API credential in its secure field and
   acknowledge temporary Azure-hosted execution/backing storage.
5. Select **Review + Create**, then **Create**.
6. Monitor the Azure deployment and its operation ID/status outputs.

After correcting a failed proof, the customer administrator can select
**Redeploy** on the failed deployment and re-enter the API credential in its
secure field. A retry uses the same operation identity; it does not reset a
provider operation already in a terminal failed state. Capture the resulting
deployment status in private evidence without the credential or deployment URL.

For the October 2026 lab recovery only, the customer administrator can upload
the privately prepared, validated proof-and-connector resume template through
the Azure Portal custom template editor, select the existing customer lab RG,
and enter the newly enrolled API client ID and credential in the secure field.
This recovery template reuses the existing customer identity and gateways; it
does not recreate the foundation. Record the final deployment state in private
evidence with credentials and deployment links hidden. This is a lab recovery
procedure, not the normal customer deployment offering.

For deployment-order diagnosis, a provider administrator can upload the
private dependency-probe template in the provider Portal, select the provider
data RG, and verify its output and deployment status. The probe creates one
empty, tagged NSG with no subnet or NIC association. After capturing private
evidence, delete that exact probe NSG and verify its removal.

Bicep first runs a proof that checks the customer account, subscription, chosen
RG safety and API
authorization **before** creating customer gateways/VMs. It then creates the
foundation and passes its endpoint outputs directly into the network connector.
That Azure-hosted connector calls the provider API, waits for the provider
worker, obtains protected connection material and creates customer connections.
No local journal, copied template file, SDK installation or additional customer
command is needed. Bicep creates the customer UAMI/local RG role using customer
ARM authority. Network Contributor handles connections; a second Reader role
on the same RG inventories resource metadata, rejecting foreign network/VM
resources before foundation creation or enrollment tagging. It grants no
customer Graph permissions or API roles. The per-RG run ID is stable on retry
but distinct between groups. Proof-only
mode stops before foundation/network creation; the full profile continues.

Customer-side `Ready` is still ARM completion, not traffic qualification.
Directory grants, registered features, quota/policy and private workload update
egress are customer-administrator prerequisites on the customer side; provider
prerequisites belong to the Check Point administrator. The wizard does not
bypass these permissions.

References, checked 2026-10-26:
[Portal forms](https://learn.microsoft.com/azure/azure-resource-manager/templates/template-specs-create-portal-forms),
[dropdown behavior](https://learn.microsoft.com/azure/azure-resource-manager/managed-applications/microsoft-common-dropdown),
[VPN SKU/generation/BGP support](https://learn.microsoft.com/azure/vpn-gateway/about-gateway-skus)
and the [East US 2 VPN gateway retail rates](https://prices.azure.com/api/retail/prices?$filter=serviceName%20eq%20%27VPN%20Gateway%27%20and%20armRegionName%20eq%20%27eastus2%27%20and%20meterName%20eq%20skuName%20and%20priceType%20eq%20%27Consumption%27).
Recheck prices before deployment.

Prepare a mode-0600 `.local/config.json` from
[`scripts/config.example.json`](scripts/config.example.json), replacing
illustrative identity IDs, group names, operator public `/32` and SSH public
keys. Keep the approved private `.azure/infrastructure-plan.json` on the
authorized deployment workstation; it binds the actual two tenant/subscription
contexts. Neither file belongs in Git.
Customer identifiers in a lab configuration are metadata, not authorization to
log into the customer tenant. Do not exchange local journals as an informal
onboarding interface or require one administrator to hold both tenant roles.

Run IDs, tenant/subscription scopes and resource names are immutable once
journaled. Operator IP, public SSH keys and capacity can be explicitly updated
without resetting the ownership journal. A bound API application ID cannot be
silently replaced. Review control-plane configuration again before publishing
a new template hash.

### Validate and package locally

These paths are relative to the project, not the repository root or a
`.local/` directory. Re-enter the correct folder even if you navigated elsewhere
to edit configuration:

```bash
cd "$(git rev-parse --show-toplevel)/provider-provisioning"
source .venv/bin/activate
python scripts/bootstrap.py validate-local
python -m pytest -q tests
python scripts/package_apps.py
```

The package and metadata are saved in ignored `.local/`. Never publish that
directory, a generated parameter file or a runtime journal.

### Legacy bootstrap helper ownership: reference only

This is **not** a supported role-separated installation sequence. It identifies
the actual authority used by the current lab helpers; it does not instruct a
Check Point administrator to run customer phases.

| Helper/phase | Actual authority | Required handling |
| --- | --- | --- |
| `bootstrap.py groups` | Both Azure subscriptions | Split before using with independent administrators |
| `bootstrap_identity.py provider` | Provider-directory authority | Check Point administrator only |
| `bootstrap.py control-plane` / `code-deploy` | Provider Azure authority, but dependent on current combined journal state | Check Point operations after the enrollment-handoff dependency is removed |
| `bootstrap_identity.py customer` | Customer-directory authority | Replace local CLI with customer-owned onboarding; never run as a Check Point identity |
| `bootstrap.py customer-identity` / `customer-connector-role` | Customer Azure authority | Customer-owned setup/authorization, not provider preparation |
| `bootstrap.py customer-proof` | Customer Azure authority | The composed customer Bicep can run proof inside Azure after onboarding |

No directory role is automatically granted to get around a permission denial.
Customer directory operations must remain customer-authorized. Local CLI
helpers are not a substitute for the missing Portal-only onboarding flow.

The proof Bicep runs a customer-owned deployment script as the customer UAMI.
That script obtains an API token, submits a durable request and polls it. The
provider worker independently creates one tagged route table using its own ARM
identity. No managed VPN gateways or lab VMs are created in this stage.
Billable control-plane resources remain after the proof; cleanup is separate.

### Legacy phased customer CLI helpers

The `customer-foundation`, `customer-connector-role` and `customer-network`
Python phases require customer-context CLI access and local lab journals.
They are development helpers, **not** customer end-user deployment steps or a
permitted Check Point fallback. Customer deployment must use its own Portal/
Bicep workflow after customer-controlled onboarding and publication are ready.

[`customer-network.bicep`](infra/customer-network.bicep) uses the same shared
connector as the proof. It obtains customer gateway endpoints, triggers the
provider API, waits for the worker's manifest, fetches protected connection
material and deploys customer connections using the customer's own scoped
identity. Secure parameter files exist only in private ephemeral container
storage and are removed; ordinary script outputs contain only operation ID and
status. No manually prepared runner VM or provider Azure credential is needed.

`Ready` from this connector means ARM connections were deployed, **not** that
tunnels, BGP, cloud-init, Defender or inspection passed. Verify both directions,
original sources, selective denial/recovery and fresh-flow backend failover
before cutover. The old lab is not modified by these commands.

### Separate old-lab cleanup

[`cleanup_old_lab.py`](scripts/cleanup_old_lab.py) defaults to an offline
dry-run. Deletion requires a separately captured, fresh inventory, an exact
group confirmation and digest, the historical ownership tag, and explicit
replacement/cutover verification evidence. It does not delete EW-21 or
replacement groups. No cleanup command has been executed.

Private plans, execution approvals, generated credentials, per-run evidence
and subscription mappings belong in ignored `.azure/`, `.local/` or `results/`
directories. Do not publish them.
