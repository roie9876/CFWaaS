# Security and publication policy

## Private does not mean non-sensitive

Keep credentials, customer identities and operational evidence out of this
repository even when its GitHub visibility is private. Do not run a deployment,
create a remote, upload files or push as part of a documentation/validation job.

## Never commit

- Access/refresh tokens, signed assertions, passwords, secrets, connection
  strings, SAS signatures, private keys or certificate/key bundles.
- Real tenant/subscription/application/object IDs, account emails, tenant
  domains, workstation home paths or workload public-IP inventories.
- Azure CLI caches, environment files, local approvals, deployment state,
  `.azure` directories, raw results, event logs, packet captures or exports.
- Existing customer/workspace diagnostic settings, screenshots or full reports
  that contain operational resource identifiers.
- Virtual environments, downloaded tools, editor state or unreviewed archives.

Use generic placeholders in examples. Public Azure built-in role-definition
identifiers can be explicitly allowlisted because they are not customer
identities. Documentation/private test networks do not authorize copying a real
network inventory into an example.

## Layered controls

1. A deny-by-default root ignore policy prevents incidental file inclusion.
2. An exact publication manifest defines intended tracked files.
3. The local publication checker inspects content without printing matched
   secrets and rejects sensitive paths and common identifying/secret patterns.
4. Local commit/push hooks and a GitHub validation workflow run that checker.
5. Human review remains necessary. Heuristics cannot prove the absence of all
   sensitive information, especially arbitrary text or encoded payloads.

Hooks can be bypassed locally. Configure the GitHub validation workflow as a
required branch check and restrict bypass permissions after the private remote
is created. No remote policy is configured by local repository preparation.

History checks cover branches, tags, remote-tracking refs and HEAD. At push
time the hook instead scans all ancestors of the exact outgoing ref tips,
including a custom tool ref if it is explicitly pushed. This avoids blocking
normal pushes on unrelated local editor checkpoints without exempting sensitive
metadata in any commit that is actually being uploaded.

## Local configuration and authentication

Keep real environment configuration in ignored files. Use interactive Azure
login or an explicitly authorized workload identity; do not put authentication
material in a tracked JSON/Bicep/parameter file.

The certificate-based multi-tenant helper can create temporary identities and
scoped role assignments when explicitly approved for a lab. Its source is not
a credential. Generated keys/certificates, approval records and identity
inventories are private runtime material and must remain excluded.

Do not silently add guests, directory permissions, subscription features or
subscription-wide grants. Review publisher-required permissions separately.

## Existing local infrastructure

Repository preparation must not destroy or modify live Azure resources.
Preserve ignored local configuration and exact saved-run paths needed for
resume/cleanup. Do not delete old state merely to make a Git status look tidy.

Existing shared monitoring workspaces/settings are not lab-owned cleanup
targets. A generic architecture document must not disclose their identifiers.

## Incident handling

If a credential was committed or uploaded:

1. Stop sharing/pushing and restrict access.
2. Revoke/rotate the credential through the owner; deleting the file is not
   credential rotation.
3. Review Git history, refs, pull requests, forks, CI artifacts and caches.
4. Coordinate an approved history-removal procedure and incident response.

If only internal metadata was exposed, involve the data owner before assuming
that private visibility makes the exposure acceptable.

Do not paste a suspected secret into an issue, chat, build log or scanner
exception. Report the file path/category to the authorized maintainer.
