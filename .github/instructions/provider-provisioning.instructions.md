---
description: "Provider/customer FaaS lab boundaries, storage requirements, and deployment preferences."
applyTo: "provider-provisioning/**"
---

- Keep customer Azure operations under customer authority and provider operations under provider authority. Never grant the provider customer Azure access as an onboarding shortcut.
- The user has authorized creating, modifying, and deleting services needed for tests in both lab subscriptions without repeated per-service approval. Identify exact resources and dependencies, preserve unrelated resources and user changes, and do not automatically delete resource groups. The user explicitly permits removing lab NSGs or allowing all traffic in them. Interactive authentication, privileged Entra consent, weakening other security controls, and tenant-boundary violations are not authorized by this lab permission.
- This company's default storage requirement is private networking. Keep Operations storage and Key Vault private.
- For this lab's explicitly public artifact-hosting Blob Storage account and the separately approved Azure deployment-script backing account, the user specified the exception tag `SecurityControl=Ignore`. Do not edit policy definitions, disable governance/Defender, enable anonymous blobs, or apply the exception indiscriminately to private state storage. Artifact shared keys stay disabled; only the declared deployment-script backing exception permits shared keys on its separate account.
- Provider administrators should use browser-based setup/onboarding. Customer administrators should use the compiled ARM/Form deployment link and their API credential, not local Python, Azure CLI, or shared private journals.
- Customer API credentials are generated in provider Entra and stored in the management credential Key Vault. Do not put secret values in Git, logs, ordinary outputs, deployment links, customer lists, or browser storage.
