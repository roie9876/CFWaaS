#!/usr/bin/env python3
"""Build deployment ZIP offline. Azure CLI Bicep compilation is local, never deployment."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
from uuid import uuid4
import zipfile

from common import ROOT, compile_bicep, save_private
import prepare_checkpoint_modules

sys.path.insert(0, str(ROOT))
from service.checkpoint_dependencies import (
    ARTIFACT_SHA256, PROVIDER_LOCK_SHA256, REGIONS_COMMIT, verify_checkpoint_artifact,
)
from service.checkpoint_terraform import TERRAFORM_RELEASES, TERRAFORM_VERSION


def validate_runtime_template(path: Path, sha256: str) -> None:
    interpreter = ROOT / "service/.venv/bin/python"
    # Uses only an in-memory public-only validation key, never generates a private key
    # or replaces the operator's actual deployment key/configuration.
    code = '''
import sys
from pathlib import Path
from uuid import UUID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from service.config import WorkerSettings
from service.templates import Templates
public = Ed25519PublicKey.from_public_bytes(bytes(range(32))).public_bytes(
    Encoding.OpenSSH, PublicFormat.OpenSSH).decode()
Templates(WorkerSettings(str(UUID(int=1)), "rg-validation-only",
    Path(sys.argv[1]), sys.argv[2], public))
'''
    subprocess.run([str(interpreter) if interpreter.exists() else sys.executable,
                    "-c", code, str(path), sha256], cwd=ROOT, capture_output=True, check=True)


def validate_checkpoint_template(template: bytes) -> None:
    code = '''
import json
import sys
from service.templates import Templates
Templates.validate_checkpoint_foundation(json.load(sys.stdin))
'''
    subprocess.run([sys.executable, "-c", code], cwd=ROOT, input=template,
                   capture_output=True, check=True)


def validate_checkpoint_private_data_template(template: bytes) -> None:
    code = '''
import json
import sys
from service.templates import Templates
Templates.validate_checkpoint_private_data(json.load(sys.stdin))
'''
    subprocess.run([sys.executable, "-c", code], cwd=ROOT, input=template,
                   capture_output=True, check=True)


def package(output: Path, checkpoint_source: Path | None = None) -> dict:
    output = output.resolve()
    if not output.is_relative_to(ROOT / ".local"):
        raise ValueError("Package must be written under provider-provisioning/.local")
    template = compile_bicep("provider-dataplane.bicep")
    customer_template = json.loads(compile_bicep("customer-connections.bicep"))
    customer_deployment = compile_bicep("customer-deployment.bicep")
    peering_customer = compile_bicep("peering-customer.bicep")
    provider_guided = compile_bicep("provider-guided-installation.bicep")
    template_sha256 = hashlib.sha256(template).hexdigest()
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    validation_path = output.parent / "provider-template.json"
    save_private(validation_path, json.loads(template))
    # Pin and validate the exact bytes, not a reserialized equivalent.
    validation_path.write_bytes(template)
    validate_runtime_template(validation_path, template_sha256)
    source = sorted(path for path in (ROOT / "service").rglob("*.py")
                    if not any(part.startswith(".") or part == "__pycache__"
                               for part in path.relative_to(ROOT / "service").parts))
    source.append(ROOT / "service/templates/proof.json")
    source.extend(sorted((ROOT / "service/static").glob("*.html")))
    startup = [ROOT / "startup-api.sh", ROOT / "startup-worker.sh", ROOT / "startup-management.sh",
               ROOT / "startup-provider-setup.sh"]
    if not all(path.is_file() for path in startup):
        raise ValueError("API, worker, management and setup startup scripts are required")
    checkpoint_template = None
    checkpoint_private_template = None
    prepared = None
    try:
        if checkpoint_source is not None:
            checkpoint_template = compile_bicep("provider-checkpoint-foundation.bicep")
            validate_checkpoint_template(checkpoint_template)
            checkpoint_private_template = compile_bicep("provider-checkpoint-private-data.bicep")
            validate_checkpoint_private_data_template(checkpoint_private_template)
            target = prepare_checkpoint_modules.LOCAL_ROOT / ("checkpoint-package-" + uuid4().hex)
            prepare_checkpoint_modules.prepare(checkpoint_source, target)
            prepared = target
            verify_checkpoint_artifact(prepared)
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in source + startup + [ROOT / "requirements.txt"]:
                if "__pycache__" not in path.parts:
                    archive.write(path, path.relative_to(ROOT))
            archive.writestr("service/templates/provider.json", template)
            archive.writestr("service/templates/customer.json", customer_deployment)
            archive.writestr("service/templates/peering-customer.json", peering_customer)
            archive.writestr("service/templates/customer-connections.json",
                             json.dumps(customer_template, separators=(",", ":")))
            archive.writestr("service/templates/customer-form.json",
                             (ROOT / "portal/customer-form.json").read_bytes())
            archive.writestr("service/templates/provider-guided.json", provider_guided)
            archive.writestr("service/templates/provider-guided-form.json",
                             (ROOT / "portal/provider-guided-form.json").read_bytes())
            if prepared is not None and checkpoint_template is not None and checkpoint_private_template is not None:
                archive.writestr("service/templates/checkpoint-foundation.json", checkpoint_template)
                archive.writestr("service/templates/checkpoint-private-data.json", checkpoint_private_template)
                for path in sorted(prepared.rglob("*")):
                    if path.is_file():
                        archive.write(path, "checkpoint/" + path.relative_to(prepared).as_posix())
    finally:
        if prepared is not None and prepared.exists():
            shutil.rmtree(prepared)
    output.chmod(0o600)
    metadata = {"providerTemplateSha256": template_sha256,
                "packageSha256": hashlib.sha256(output.read_bytes()).hexdigest(),
                "packagePath": str(output), "includesManagement": True}
    if checkpoint_template is not None and checkpoint_private_template is not None:
        metadata.update(includesCheckpointPreview=True,
                        checkpointFoundationSha256=hashlib.sha256(checkpoint_template).hexdigest(),
                        checkpointPrivateDataSha256=hashlib.sha256(checkpoint_private_template).hexdigest(),
                        checkpointProviderLockSha256=PROVIDER_LOCK_SHA256,
                        checkpointArtifactSha256=ARTIFACT_SHA256,
                        checkpointTerraformVersion=TERRAFORM_VERSION,
                        checkpointTerraformLinuxSha256=TERRAFORM_RELEASES[("Linux", "x86_64")]["binary_sha256"],
                        checkpointRegionsCommit=REGIONS_COMMIT,
                        checkpointModuleCommit=prepare_checkpoint_modules.UPSTREAM_COMMIT)
    save_private(output.with_suffix(".metadata.json"), metadata)
    save_private(output.parent / "customer-connections.json", customer_template)
    return metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".local/apps.zip")
    parser.add_argument("--checkpoint-source", type=Path, help="Pinned upstream checkout for an experimental preview bundle")
    args = parser.parse_args(argv)
    result = package(args.output, args.checkpoint_source)
    print("ZIP built; SHA256 pin and package location saved alongside the package.")
    return result


if __name__ == "__main__":
    main()
