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
