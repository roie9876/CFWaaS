# Deploy CFWaaS from zero

This guide is for a new administrator. Read the prerequisites before starting:
the solution creates billable Azure resources and requires privileged provider
directory approval.

## 0. Understand the two sides

**Provider** means the organization that operates the firewall.
**Customer** means the organization whose workloads use that firewall.
They have separate Azure tenants and subscriptions.

| Person | Works in | Responsibility |
|---|---|---|
| Provider release engineer | Provider only | Build and publish the installable release and pinned runner |
| Provider platform/security administrator | Provider only | Approve directory permissions, install hosting and enable Check Point |
| Provider onboarding/firewall administrator | Provider only | Onboard customers, operate policy and view connection details |
| Customer administrator | Customer only | Deploy customer resources and configure customer routes/peerings |

One person can fill several roles in a lab, but must sign into the correct
tenant for each operation. Do **not** grant the provider access to customer
Azure or vice versa. A VPN shared key is not an Azure management permission.

> **Important:** the GitHub source alone is not a ready-made public installer.
> A provider-owned release account, package and setup Template Spec must exist
> first. Do not copy a deployment button or subscription ID from somebody
> else's lab. If your organization already has an approved setup link, go to
> [step 3](#3-install-the-provider-control-plane).

## 1. Prerequisites

### Accounts and permission

- A provider Azure subscription and a **different customer tenant/subscription**.
- An approved provider administrator account with MFA.
- Provider permission to deploy at the required subscription/RG scopes and
  create role assignments. Subscription **Owner**, or the equivalent combination
  of resource permissions and RBAC administration, is normally needed for
  initial setup. Scope it down after setup where the design allows.
- A provider Entra administrator authorized to approve the Graph permissions
  shown during setup. **Azure subscription Owner is not Entra administrator.**
- Customer **Owner**, or **Contributor plus Role Based Access Control
  Administrator**, on its approved deployment scope. Resource-provider/feature
  registration may require a separate customer subscription administrator.
- Customer tenant ID, subscription ID and an agreed name for the enrollment.
  These IDs are not secrets, but must be correct.

### Azure capacity, policy and cost

- Current control-plane location: **Central US**. Current provider Check Point
  dataplane: **East US 2**. Customer locations are limited to the wizard's
  supported list; do not assume arbitrary regions work.
- Enough quota/capacity for four BGP-capable VPN gateways, Routing Appliance,
  Route Server, two customer VMs and provider firewall VMs. The current lab
  Check Point sizes are gateway `Standard_F4s` and management `Standard_F8s`.
  Availability of these sizes is not guaranteed.
- `Microsoft.Compute/EncryptionAtHost` registered in **each side's own
  subscription**. The VMs must retain host encryption. The deployment does not
  bypass policy or grant cross-tenant access to register it.
- Relevant Azure resource providers registered and the managed Routing
  Appliance service/API available in the selected customer region.
- Policy approval for private endpoints, private vault/state storage and the
  narrowly scoped public artifact/deployment-script backing-storage exceptions.
  Do not disable governance or copy the lab's exception tag indiscriminately.
- A budget approval. VPN gateways, Routing Appliance, Route Server, hosting,
  private endpoints and storage can keep charging when VMs are stopped.
- Provider acceptance of Check Point Marketplace terms and BYOL/trial licensing.
  Trial expiry and BYOL activation are the firewall administrator's responsibility.

### Network and access planning

- Use nonoverlapping RFC1918 IPv4 ranges within an environment.
  Review [the routing topology](provider-routing-topology.md); automatic
  customer/provider overlap handling is not implemented.
- Know the administrator's **current public IPv4 address or approved CIDR**.
  An office VPN can change the address Azure sees.
- Have a customer workload **SSH public key**. Keep the matching private key
  private. Never paste a private key into an ARM field.
- Decide where credentials will be securely delivered and who can reveal them.
  Do not use chat messages, GitHub issues, ordinary email or deployment URLs.

### Software for the release engineer only

The installing provider administrator and routine customer administrator use
Azure Portal; they do not need local Python or CLI once a release exists.

The person preparing a source release needs Git, Azure CLI with Bicep, Python
3.12 and the repository's development dependencies. A registry build can build
the Linux runner without a local Docker daemon. Use an organization-approved
workstation and private local configuration.

```bash
git clone https://github.com/roie9876/CFWaaS.git
cd CFWaaS/provider-provisioning
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
```

Do not install extra tooling on a customer's machine to work around an
incomplete provider release.

## 2. Prepare your organization's provider release

**Who:** provider release engineer, before handing an install link to an
administrator. This is the engineering part, not a fully automated one-click
workflow.

1. Run the offline checks described in [Contributing](../CONTRIBUTING.md).
   Resolve failures before uploading artifacts.
2. Build the application ZIP. For Check Point, first obtain the exact upstream
   revision required by the preparation script, then include it:

   ```bash
   .venv/bin/python scripts/package_apps.py \
     --checkpoint-source /path/to/verified-checkpoint-checkout
   ```

   Output is private under `.local/`, including SHA256 metadata. Preserve the
   upstream license and notices. Do not commit generated packages or state.
3. Prepare the approved provider artifact host using
   `scripts/provider_artifacts.py`. Its `host` and `upload` commands are
   **dry-run unless `--execute` is passed**. Supply your own private configuration,
   provider subscription and publisher identity. Read `--help` and review the
   exact target before executing.
4. Publish the exact package at its immutable SHA256 path in the provider's
   private blob container. Do not enable anonymous blobs. Private Operations
   storage and Key Vault are different resources and must stay private.
5. Register the secretless setup client with
   `scripts/register_setup_client.py`, then prepare the setup template with
   `scripts/prepare_setup_release.py`. Registration is explicit, provider-only
   and does not grant administrator consent on the user's behalf.
6. Publish the generated setup template as a provider-owned Azure **Template
   Spec**, and give the installing administrator read access to that spec.
   Supply the template's actual `setupUrl`/deployment link through the approved
   distribution process.

For exact inputs and the alternative manual path, see
[engineering release preparation](../provider-provisioning/README.md#engineering-release-preparation)
and [manual provider setup](../provider-provisioning/README.md#alternative-manual-provider-setup-browser-only).
There is not yet a tested generic script that performs every release,
Check Point identity and license step for a brand-new organization.

**Ready to continue when:** the administrator can open its organization's
Template Spec, and the package/hash belong to the same reviewed release.

## 3. Install the provider control plane

**Who:** authorized provider platform administrator.

1. Sign into **Azure Portal in the provider directory**.
2. Open the provider-owned setup Template Spec supplied in step 2 and select
   **Deploy**. Choose the correct provider subscription and a new dedicated
   setup resource group. Read the cost/storage acknowledgement before creating.
3. Wait for successful deployment and application publication. Open **Outputs**
   and select **`setupUrl`**.
4. Select **Sign in and review permissions**. Review the application identity
   and permissions shown by Microsoft sign-in. A suitably authorized provider
   directory administrator must approve the required consent.
5. Select **Create provider setup**. Generated credentials and the NVA SSH key
   belong in the private provider vault, not in this guide.
6. Select **Open provider deployment wizard**. Choose new dedicated control
   and dataplane resource-group names, review cost and storage exceptions,
   then deploy.
7. When the deployment and application publication finish, open the output
   **`managementUrl`**. Sign in as an explicitly allowlisted provider
   administrator and select **Check setup readiness**.

Setup creates the API, worker, management portal and supporting private data
services. It **does not** create a customer's VPN gateways or workload VMs.

**Expected result:** the provider portal loads and readiness verifies the
registry plus Graph/API identity configuration. This check is not a firewall
traffic test and does not prove every later credential write will succeed.

If sign-in expires, select **Sign in again**. Never share the redirected URL.
If setup reports **NeedsAttention**, follow its recovery guidance; do not
blindly create replacement directory objects or reuse old journals.

## 4. Enable the Check Point option

**Who:** provider platform/firewall operator. This is a separate one-time
engineering task; the initial provider wizard does not yet do all of it.

1. Accept Marketplace terms for the pinned gateway/management image plans.
   See [the technical Check Point guidance](../provider-provisioning/README.md).
2. Put the runner image in your provider Azure Container Registry. The runner
   only pulls from an Azure registry with its managed identity, so copy the
   prebuilt public image there; you do not need Docker or a local build:

   ```bash
   az acr import --name <provider-acr-name> \
     --source ghcr.io/roie9876/cfwaas-checkpoint-runner@sha256:99650f47611fc1199dce5e5dda100ddbc819c93ef1df419f4d17fb11cbed1a2f \
     --image faas-checkpoint-runner:1.0.0
   ```

   The digest stays the same after import; pin that **exact digest**, not the
   tag. Its bundled licenses are listed in
   [Third-party notices](../THIRD_PARTY_NOTICES.md#prebuilt-check-point-runner-image).
   To build it yourself instead, use
   `scripts/build_checkpoint_runner_context.py` and the existing runner
   Dockerfile, then pin the digest of your own image.
3. Configure the dedicated provider Check Point publisher identity and separate
   managed-application definition, its eight approved roles and its required
   ReadOnly definition lock. Do not broaden an unrelated Ubuntu identity.
4. Attach the identity to the worker. Deploy the compatible ZIP and configure
   `FAAS_CHECKPOINT_*` settings with the **exact bundled template hashes**.
   Keep new Check Point requests disabled until runtime/readiness checks pass.
5. Configure administrator source defaults and the optional provider-only
   connection-details relay described in
   [environment.example](../provider-provisioning/service/environment.example).
   Keep the management app's provider administrator allowlist. The relay uses
   only the pinned provider identity; it gets no customer Azure access.
6. Verify private vault/DNS/state access, registry pull, the runner's role scope
   and matching package/image/template pins. Only then enable
   `FAAS_CHECKPOINT_ENABLED` on the compatible API and worker.

**Expected result:** the customer wizard can select Check Point without an
unavailable-firewall error. That still does not mean a new environment passed
traffic tests. Full fresh-provider Check Point installation remains a
qualification gap; get release-engineering help rather than guessing identity
IDs or disabling checks.

## 5. Onboard and deploy a customer

### Provider administrator

1. Open the provider management portal.
2. Under **Onboard a customer**, enter its name, tenant ID, subscription ID and
   approved credential lifetime.
3. Select **Create onboarding** and wait for **Ready**.
4. Select **Deployment link**. Share that customer's fresh Azure Portal link.
   It expires; issue a new one if needed, especially after a release.
5. Select **Reveal credential**. Deliver **only the customer API credential**
   to the customer through an approved secure channel. Keep provider firewall
   credentials private.

### Customer administrator

1. Sign into **Azure Portal in the customer directory**.
2. Open the deployment link. Confirm tenant/subscription and use a new dedicated
   customer resource group.
3. Choose the firewall. **Ubuntu simulator is the default**; explicitly choose
   **Check Point** when requested and enabled.
4. Supply the customer API credential and workload SSH **public** key. For
   Check Point, review/edit the public administrator IP/CIDR allowlist.
5. Review the permissions, cost and backing-storage acknowledgement; deploy.
6. Wait for the complete customer deployment and both sides' VPN connections.
   VPN gateways often take tens of minutes; the workflow can take over an hour.
   Do not start a duplicate deployment merely because gateway creation is slow.

The customer's own deployment identity makes customer Azure changes. The
customer API credential authorizes a provider API request, not customer Azure
access for the provider. Do not exchange RBAC roles or directory permissions.

## 6. Find routing and login details

**Provider portal → customer → Reveal credential** shows temporary access
details for that customer's owned Check Point environments.

| Displayed item | Meaning |
|---|---|
| Customer API credential | Used by the customer deployment, not a VM password |
| Customer UDR next hop | Actual assigned customer Routing Appliance IP; next-hop type `VirtualAppliance` |
| Management | HTTPS link, public/private IPs, `admin` username and generated management password |
| Gateway | HTTPS link, public/frontend/backend IPs, `admin` username and provider SSH-key login command |

Select **Show password** or **Copy management password** only when needed.
The panel clears after **30 seconds**, on **Clear now**, tab hiding or navigation.
Do not screenshot, log or paste those credentials into chat.

**Gateway web password:** the deployment does not manage one. A manually
configured password is unchanged; the reveal panel does not recover or reset it.
Use the approved provider SSH private key for the documented login method.

**Customer UDRs:** on workload subnets, point the required remote workload
prefixes and `0.0.0.0/0` at the **customer Routing Appliance**. Do not use the
provider firewall private/public IP. A default route alone does not beat a more
specific peering route. Configure customer-side peering/gateway transit and keep
BGP propagation enabled as required by the topology.

For a new customer VNet, the customer manages its own routes/peerings; the
provider must not add per-VNet UDRs, firewall NAT entries or VPN selectors.
Do not add NAT to solve an east-west return-path issue.

If the next hop is **not registered**, check the customer's
`customer-foundation` output **`routingAppliancePrivateIp`**. Never guess `.4`.
Older deployments may need a metadata-only registration. If private connection
details are unavailable, the provider operator must check the private relay;
the portal will not invent a password.

## 7. Check that it really works

Do not stop at an ARM **Succeeded** or API **Ready** response.

1. Verify both ingress and delivery VPN paths on both sides.
2. Verify both firewall-to-Route-Server BGP sessions and delivery VPN BGP.
3. Inspect customer UDRs and effective routes. Managed-environment denies can
   block effective-route actions even for an Azure Owner; do not remove denies
   or broaden identity access as a workaround.
4. Send ping **and HTTP** traffic between customer workloads in both directions.
5. Verify the destination sees the **original customer source address** and
   correlate the traffic with gateway **Accept** logs and the correct rule.
6. Test Internet egress and verify the expected firewall public egress IP.
7. Check administrator access again **after** VPN/BGP convergence. A reachable
   login page alone does not prove successful login.

Fail-closed behavior, real Check Point VNet lifecycle, HA/VMSS, selective policy
denial, overlapping networks and a complete new installation are not qualified
by the bounded existing-lab tests. See [the test register](test-register.md).

## 8. Troubleshoot and clean up safely

| Symptom | First action |
|---|---|
| Administrator sign-in required | Select **Sign in again** in the provider portal |
| Expired deployment link | Provider issues a fresh **Deployment link** |
| Check Point unavailable | Provider checks step 4, compatible versions and readiness |
| NeedsAttention enrollment | Read the exact recovery guidance; do not create a duplicate identity |
| VPN gateway still creating | Check the deployment state; do not blindly redeploy |
| Ping works but no firewall logs | Treat it as possible bypass; check routes, policy, logging and actual traversal |
| HTTPS works but login fails | Use the correct management credential, not the customer API credential |
| VM SSH denied | Check approved source IP, correct key/user and Internet return route after convergence |
| Cannot inspect effective routes | Respect managed denies; use the approved diagnostics path |

To retire a lab, first identify the exact customer and provider environment.
An explicit provider **Decommission** request can delete the owned managed
application and therefore its entire managed resource group. Read the
confirmation carefully. Customer-side resources and enrollment revocation
are separate operations. Never delete unrelated/shared resource groups or
assume credential revocation stops infrastructure charges.

Keep the previous working lab until the replacement passes the relevant tests.
No cleanup command should run automatically just because you read this guide.
