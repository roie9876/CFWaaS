# Third-party notices

The repository's [MIT license](LICENSE) applies to original CFWaaS contributions.
It does not replace third-party licenses or grant rights to vendor products,
trademarks, Azure services or Check Point software.

## Check Point deployment modules

Check Point modules are obtained separately from the pinned upstream revision
declared in
[prepare_checkpoint_modules.py](provider-provisioning/scripts/prepare_checkpoint_modules.py).
The preparation process verifies the upstream checkout and retains its
Apache-2.0 license in generated private artifacts. Retain the upstream license,
copyright notices and modification notices when redistributing those artifacts.
The source checkout and generated artifacts must not be added to this repository
merely to publish it.

Check Point appliance images and BYOL/trial licensing remain subject to the
publisher's terms; the CFWaaS MIT license does not license them.

## Tools, dependencies and architecture symbols

Python packages, Terraform providers, Azure CLI, Draw.io and their symbol
libraries retain their respective licenses. Architecture symbols and vendor
names identify the services shown; they do not imply vendor endorsement.
Do not treat this file as relicensing third-party artwork.

## Prebuilt Check Point runner image

The public `ghcr.io/roie9876/cfwaas-checkpoint-runner` image bundles, in
addition to CFWaaS code (MIT):

- Terraform 1.15.7 under the Business Source License 1.1, with its license in
  `/opt/faas/licenses/terraform/LICENSE.txt`. Your use must comply with that
  license, including its additional-use limits.
- The adapted Check Point modules (Apache-2.0) with their license and
  modification notice in `/opt/faas/checkpoint/`.
- Terraform providers `hashicorp/azurerm`, `hashicorp/null`,
  `hashicorp/random`, `azure/azapi` and `azure/modtm` (MPL-2.0), as published
  by the Terraform Registry. Source code is available from each provider's
  public GitHub repository at the pinned version.
- Python packages listed in the image's requirements lock, each with its
  license in its `*.dist-info` directory under `/opt/faas/site/`.
- The Microsoft Azure Linux Python base image and its packages.

The image contains no Check Point appliance software or licenses.
