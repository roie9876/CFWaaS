# Contributing

## Keep the boundary clear

- Provider resources belong to tenant A.
- Customer workload resources belong to tenants B/C/D and their own approved
  scopes.
- A customer/environment/region is an explicit isolation and ownership unit.
- Label evidence as lab-tested, prepared, documented, preview or rejected.
- A successful ARM deployment is not a successful traffic-inspection test.

## Local workflow

1. Use ignored local configuration for real accounts and approvals.
2. Make changes only in publication-manifest paths; add intentional new source
   paths to the manifest before staging.
3. Run `python3 -m unittest discover -s tests -v`.
4. Run `python3 scripts/check_publication.py --worktree`.
5. Stage only the reviewed publication files, then run
   `python3 scripts/check_publication.py --staged`.
6. Review the staged diff locally before committing. Do not paste private
   working-tree content into a remote review service.

For provider/runtime changes, run its tests **from its own directory**:

```bash
cd provider-provisioning
.venv/bin/python -m pytest -q
```

The `service` imports are relative to that working directory. Running the same
suite from the repository root without the module path configured is not an
equivalent invocation.

Implementation-specific offline validation is described in each executable
lab's README. No validation workflow may authenticate to Azure or invoke a
deployment/cleanup.

## Documentation and diagrams

Use simple icon-based Draw.io diagrams with self-contained SVG previews:

- A pale-blue provider container explicitly labeled **tenant A**.
- Separate customer containers explicitly labeled **tenant B**, **C**, **D**,
  with blue clouds for workload VNets.
- Solid attachment lines; describe management separately from the packet path.
- A dedicated firewall cell per environment.
- No real subscription IDs, emails, domains, public addresses or run IDs.

Keep the presentation landscape and compact, with large labels/icons. GitHub's
image viewer limits preview height; increasing SVG pixel dimensions alone does
not improve readability. The regression tests check aspect ratio and the
projected size of essential labels in a height-limited browser preview.

Keep native vHub connections distinct from ordinary VNet peerings. Never draw
an ordinary external-spoke firewall as if it had native vWAN service insertion.

Edit the uncompressed `.drawio` sources in `docs/diagrams/` with Draw.io desktop
or the VS Code Draw.io extension. Do not save compressed XML or embed arbitrary
images/attachments: source text must remain publication-inspectable.

The SVGs are exported locally using the installed Draw.io desktop executable:

```bash
python3 scripts/render_diagrams.py
# Or: python3 scripts/render_diagrams.py --drawio /path/to/drawio
```

The exporter uses verified built-in Azure icons, converts them into inline SVG
vectors, and keeps native SVG text. It rejects unresolved/external images and
does not embed opaque diagram payloads, base64 images or workstation metadata.
No Draw.io MCP server is needed for the local desktop fallback.

Never upload private architecture/evidence to an external rendering service.
Rerun publication checks after regeneration. CI checks the committed sources and
SVGs without Draw.io, a browser or Azure credentials.

## Deployment changes

Require explicit environment-specific approval for infrastructure changes,
costs, identities, role grants, feature registrations or failure injection.
Preserve existing local evidence and recovery state.

Original CFWaaS contributions use the [MIT license](LICENSE). Review
[third-party terms](THIRD_PARTY_NOTICES.md) and attribution before copying
publisher code into the repository; the project license does not relicense it.
