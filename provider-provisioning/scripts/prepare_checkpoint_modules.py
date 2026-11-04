#!/usr/bin/env python3
"""Prepare pinned Check Point modules for offline integration tests; never deploy."""
from __future__ import annotations

import argparse
import hashlib
import io
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile

from common import ROOT

sys.path.insert(0, str(ROOT))
from service.checkpoint_dependencies import PROVIDER_LOCK_SHA256, REGIONS_COMMIT, REGIONS_SOURCE

UPSTREAM_COMMIT = "03de9506cb5591d9186e47288ecc7a9def19809c"
UPSTREAM_TREE = "3b3820583c04c393cc23d898b11c8fae8259cf33"
COMMON_MAIN_SHA256 = "5ea1c620fd12f3f4aec301f2c9d3f77b0faccaa3aa46895f7e57f9e3f4df3873"
VERSION_FILES = {
    "management": "be58f30155358eaa9ea4c083257e934f780d17d0e9ea6f91d9b4560c94285bf7",
    "single-gateway": "3f450b39203645e42936f5af851396207dd82c477508b6fc1e3ed32b455de3c8",
}
LOCAL_ROOT = ROOT / ".local"
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_FILES = 100

INPUTS = r'''# FaaS adaptation of Check Point v1.6.2. See ../../LICENSE.
variable "faas_existing_resource_group_id" {
  type = string

  validation {
    condition = can(regex(
      "(?i)^/subscriptions/[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}/resourcegroups/rg-faas-env-[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
      var.faas_existing_resource_group_id
    ))
    error_message = "Use an isolated FaaS environment resource group ID."
  }
}

variable "faas_image_version" {
  type = string

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.faas_image_version))
    error_message = "Use an explicit Marketplace image version."
  }
}
'''

OVERRIDE = '''# FaaS adaptation of Check Point v1.6.2. See ../../LICENSE.
module "common" {
  create_resource_group = false
  resource_group_id     = var.faas_existing_resource_group_id
  vm_os_version         = var.faas_image_version
}

# Azure may add platform IP tags to new public IPs; ip_tags forces replacement, so a
# re-plan after a partial apply would otherwise replace the firewall and management IPs.
resource "azurerm_public_ip" "public_ip" {
  lifecycle {
    ignore_changes = [ip_tags]
  }
}
'''

NOTICE = f"""FaaS adaptation of Check Point CloudGuard Terraform modules v1.6.2.
Source: https://github.com/CheckPointSW/terraform-azure-cloudguard-network-security
Pinned commit: {UPSTREAM_COMMIT}
The Apache-2.0 upstream license is included in LICENSE.
The management and single-gateway versions.tf files were modified to remove
module-local provider configurations. The common regions module source is
pinned to commit {REGIONS_COMMIT}, with telemetry disabled as in upstream.
Added FaaS inputs and override files use an existing FaaS environment group,
require an explicit image version and ignore platform-assigned public IP tags.
This artifact is incomplete: firewall policy, BGP and safe orchestration are
not implemented. Do not apply it to a live environment.
"""


class PreparationError(ValueError):
    pass


def _git(source: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(source), *args], capture_output=True, check=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreparationError("Unable to read the pinned upstream Git repository") from exc
    return result.stdout


def _extract(archive: bytes, destination: Path) -> None:
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise PreparationError("Upstream archive exceeds the size limit")
    total, files = 0, 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts
                    or path.parts[0] not in {"modules", "LICENSE"}):
                raise PreparationError("Unexpected upstream archive path")
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            elif member.isfile():
                files += 1
                total += member.size
                if files > MAX_FILES or total > MAX_ARCHIVE_BYTES:
                    raise PreparationError("Upstream archive contents exceed the limit")
                source = tar.extractfile(member)
                if source is None:
                    raise PreparationError("Upstream archive contains an unreadable file")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with target.open("xb") as stream:
                    shutil.copyfileobj(source, stream)
            else:
                raise PreparationError("Upstream archive contains a link or unsupported entry")
    if not (destination / "LICENSE").is_file():
        raise PreparationError("Upstream license is missing")


def _adapt(destination: Path) -> None:
    common = destination / "modules/common/common/main.tf"
    original_common = common.read_bytes()
    old_regions = (b'  source  = "Azure/avm-utl-regions/azurerm"\n'
                   b'  version = "0.5.1"')
    new_regions = b'  source = "' + REGIONS_SOURCE.encode() + b'"'
    if (hashlib.sha256(original_common).hexdigest() != COMMON_MAIN_SHA256
            or original_common.count(old_regions) != 1
            or original_common.count(b'enable_telemetry          = false') != 1):
        raise PreparationError("Unexpected upstream regions module configuration")
    common.write_bytes(original_common.replace(old_regions, new_regions, 1))
    for name, digest in VERSION_FILES.items():
        directory = destination / "modules" / name
        versions = directory / "versions.tf"
        original = versions.read_bytes()
        if hashlib.sha256(original).hexdigest() != digest:
            raise PreparationError("Unexpected upstream provider configuration")
        marker = b'\nprovider "azapi" {'
        if original.count(marker) != 1 or original.count(b'provider "azurerm" {') != 1:
            raise PreparationError("Unexpected upstream provider blocks")
        prefix = original.split(marker, 1)[0].rstrip() + b"\n"
        versions.write_bytes(
            b"# FaaS modification: providers are configured by the calling root module.\n" + prefix)
        (directory / "faas_variables.tf").write_text(INPUTS)
        (directory / "faas_override.tf").write_text(OVERRIDE)
    lock = ROOT / "infra/checkpoint/.terraform.lock.hcl"
    if hashlib.sha256(lock.read_bytes()).hexdigest() != PROVIDER_LOCK_SHA256:
        raise PreparationError("Terraform provider lock mismatch")
    for name in ("main.tf", "variables.tf", ".terraform.lock.hcl"):
        shutil.copyfile(ROOT / "infra" / "checkpoint" / name, destination / name)
    (destination / "FAAS-UPSTREAM-NOTICE.txt").write_text(NOTICE)


def prepare(source: Path, output: Path) -> None:
    source = source.resolve(strict=True)
    local = LOCAL_ROOT.resolve(strict=True)
    output = output.resolve()
    if output.parent != local:
        raise PreparationError("Output must be a new direct child of provider-provisioning/.local")
    if output.exists():
        raise PreparationError("Output already exists; choose a new path")
    if (_git(source, "rev-parse", "HEAD").decode().strip() != UPSTREAM_COMMIT
            or _git(source, "rev-parse", f"{UPSTREAM_COMMIT}^{{tree}}").decode().strip() != UPSTREAM_TREE):
        raise PreparationError("Upstream repository is not at the pinned release")
    archive = _git(source, "archive", "--format=tar", UPSTREAM_COMMIT, "--",
                   "LICENSE", "modules/common", "modules/management", "modules/single-gateway")
    output.mkdir(mode=0o700)
    try:
        _extract(archive, output)
        _adapt(output)
    except (OSError, tarfile.TarError, PreparationError):
        shutil.rmtree(output)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="Local Git checkout of the pinned upstream release")
    parser.add_argument("--output", required=True, type=Path, help="New directory directly under .local")
    args = parser.parse_args()
    try:
        prepare(args.source, args.output)
    except (OSError, PreparationError, tarfile.TarError) as exc:
        raise SystemExit(f"Module preparation failed: {type(exc).__name__}: {exc}") from None
    print("Prepared experimental modules locally; no deployment was performed.")


if __name__ == "__main__":
    main()
