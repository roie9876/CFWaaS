# Shared Azure lab helpers

The directory name is retained for compatibility with local saved-run paths.
Its published source supplies:

- `lab.py`: explicit account-profile loading, token-safe ARM transport,
  asynchronous-operation handling and scoped lab helpers.
- `app_identity.py`: explicitly approved temporary multitenant certificate
  identity provisioning/cleanup.
- `guest_tools.py`: guest-result framing and HTTP probe generation, without a
  deployment entrypoint.

No account selection or credential ships in these helpers. Real profiles,
certificates, identity evidence and role-assignment inventories are local-only.

The historical NIC experiment is not an available product architecture.
Keeping helper APIs compatible does not establish support for attaching a
foreign NIC/subnet to a provider VM. Do not run historical experiment commands
as a substitute for an approved deployment plan.
