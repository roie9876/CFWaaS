#!/usr/bin/env python3
"""Build a verified, secret-free Docker context for the Check Point runner; never deploys or pushes."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

from common import ROOT
import prepare_checkpoint_modules

sys.path.insert(0, str(ROOT))
from service.checkpoint_dependencies import (
    PROVIDER_PACKAGES, verify_checkpoint_artifact, verify_checkpoint_dependencies,
)
from service.checkpoint_terraform import TERRAFORM_RELEASES, TERRAFORM_VERSION, verify_terraform_release

TARGET = "linux_amd64"
TERRAFORM_URL = (f"https://releases.hashicorp.com/terraform/{TERRAFORM_VERSION}/"
                 f"terraform_{TERRAFORM_VERSION}_linux_amd64.zip")
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
WHEEL = re.compile(r"(?P<name>[A-Za-z0-9_.]+)-(?P<version>[A-Za-z0-9_.!+]+)-.+\.whl")


class ContextError(ValueError):
    pass


def _isolated_env(home: Path) -> dict[str, str]:
    return {"HOME": str(home), "PATH": os.defpath, "TF_IN_AUTOMATION": "true", "TF_LOG": "off",
            "TF_CLI_CONFIG_FILE": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0", "CHECKPOINT_DISABLE": "1"}


def _run(command: list[str], env: dict[str, str], timeout: int = 600) -> None:
    try:
        subprocess.run(command, env=env, capture_output=True, check=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        raise ContextError(f"Build step failed: {Path(command[0]).name} {command[1] if len(command) > 1 else ''}") from None


def _install_linux_providers(checkpoint: Path, terraform: str, home: Path) -> None:
    mirror = home / "mirror"
    _run([terraform, f"-chdir={checkpoint}", "providers", "mirror", f"-platform={TARGET}", str(mirror)],
         _isolated_env(home))
    providers = checkpoint / ".terraform/providers"
    shutil.rmtree(providers)
    for namespace, name, version, executable in PROVIDER_PACKAGES:
        archive = mirror / "registry.terraform.io" / namespace / name / f"terraform-provider-{name}_{version}_{TARGET}.zip"
        destination = providers / "registry.terraform.io" / namespace / name / version / TARGET
        destination.mkdir(parents=True)
        expected = {executable} | ({"LICENSE.txt"} if namespace == "hashicorp" else set())
        with zipfile.ZipFile(archive) as source:
            names = {item.filename for item in source.infolist() if not item.is_dir()}
            if names != expected:
                raise ContextError("Unexpected provider archive layout")
            for filename in sorted(names):
                with source.open(filename) as src, (destination / filename).open("xb") as dst:
                    shutil.copyfileobj(src, dst)
                (destination / filename).chmod(0o555 if filename == executable else 0o444)


def _terraform_binary(destination: Path) -> str:
    release = TERRAFORM_RELEASES[("Linux", "x86_64")]
    with urllib.request.urlopen(TERRAFORM_URL, timeout=60) as response:
        archive = response.read(MAX_DOWNLOAD_BYTES + 1)
    if len(archive) > MAX_DOWNLOAD_BYTES or hashlib.sha256(archive).hexdigest() != release["archive_sha256"]:
        raise ContextError("Terraform archive does not match its pin")
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        if {item.filename for item in source.infolist()} != {"terraform", "LICENSE.txt"}:
            raise ContextError("Unexpected Terraform archive layout")
        binary = source.read("terraform")
        license_text = source.read("LICENSE.txt")
    if hashlib.sha256(binary).hexdigest() != release["binary_sha256"]:
        raise ContextError("Terraform binary does not match its pin")
    destination.parent.mkdir(parents=True)
    destination.write_bytes(binary)
    destination.chmod(0o555)
    licenses = destination.parent.parent / "licenses/terraform"
    licenses.mkdir(parents=True)
    (licenses / "LICENSE.txt").write_bytes(license_text)
    return hashlib.sha256(binary).hexdigest()


def _wheels(output: Path, home: Path) -> None:
    wheels = output / "wheels"
    _run([sys.executable, "-m", "pip", "download", "--disable-pip-version-check", "--no-cache-dir",
          "--only-binary=:all:", "--platform", "manylinux_2_28_x86_64", "--platform", "manylinux2014_x86_64",
          "--python-version", "3.12", "--implementation", "cp", "-d", str(wheels),
          "-r", str(ROOT / "requirements.txt")], {**_isolated_env(home), "PATH": os.environ.get("PATH", os.defpath)},
         timeout=900)
    lines = []
    for wheel in sorted(wheels.glob("*.whl")):
        match = WHEEL.fullmatch(wheel.name)
        if match is None:
            raise ContextError("Unexpected wheel name")
        digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
        lines.append(f"{match['name']}=={match['version']} --hash=sha256:{digest}")
    if not lines or len(lines) != len(list(wheels.iterdir())):
        raise ContextError("Unexpected wheel download contents")
    (output / "runner-requirements.lock").write_text("\n".join(lines) + "\n")


def _application(output: Path) -> None:
    service = output / "app/service"
    service.mkdir(parents=True)
    for path in sorted((ROOT / "service").glob("*.py")):
        shutil.copyfile(path, service / path.name)
    licenses = output / "licenses"
    licenses.mkdir(exist_ok=True)
    shutil.copyfile(ROOT.parent / "LICENSE", licenses / "CFWaaS-LICENSE")
    shutil.copyfile(ROOT.parent / "THIRD_PARTY_NOTICES.md", licenses / "THIRD_PARTY_NOTICES.md")


def build(source: Path, output: Path) -> dict:
    local = prepare_checkpoint_modules.LOCAL_ROOT.resolve(strict=True)
    output = output.resolve()
    if output.parent != local or output.exists():
        raise ContextError("Output must be a new direct child of provider-provisioning/.local")
    executable = shutil.which("terraform")
    if not executable:
        raise ContextError("Pinned Terraform is required to resolve modules")
    terraform = str(Path(executable).resolve(strict=True))
    verify_terraform_release(Path(terraform))
    output.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix="checkpoint-context-", dir=local) as temporary:
            home = Path(temporary)
            for topology, directory in (("single", "checkpoint"), ("vmss", "checkpoint-vmss")):
                checkpoint = output / directory
                staging = local / (output.name + "-" + directory)
                prepare_checkpoint_modules.prepare(source, staging, topology)
                shutil.move(str(staging), checkpoint)
                verify_checkpoint_artifact(checkpoint, topology)
                _run([terraform, f"-chdir={checkpoint}", "init", "-backend=false", "-input=false",
                      "-lockfile=readonly", "-no-color"], _isolated_env(home))
                _install_linux_providers(checkpoint, terraform, home)
                # Git reflogs record the builder's name, login and host; the image is redistributable.
                for reflog in (checkpoint / ".terraform/modules").glob("*/.git/logs"):
                    shutil.rmtree(reflog)
                verify_checkpoint_dependencies(checkpoint, TARGET, topology)
                verify_checkpoint_artifact(checkpoint, topology)
            terraform_sha256 = _terraform_binary(output / "bin/terraform")
            _wheels(output, home)
            _application(output)
            shutil.copyfile(ROOT / "checkpoint-runner.Dockerfile", output / "Dockerfile")
        metadata = {"terraformLinuxSha256": terraform_sha256, "providerTarget": TARGET,
                    "dockerfileSha256": hashlib.sha256((output / "Dockerfile").read_bytes()).hexdigest(),
                    "requirementsLockSha256": hashlib.sha256(
                        (output / "runner-requirements.lock").read_bytes()).hexdigest()}
        (output / "context-metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
        return metadata
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        for directory in ("checkpoint", "checkpoint-vmss"):
            shutil.rmtree(local / (output.name + "-" + directory), ignore_errors=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="Pinned upstream Check Point Git checkout")
    parser.add_argument("--output", required=True, type=Path, help="New directory directly under .local")
    args = parser.parse_args()
    try:
        build(args.source, args.output)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Runner context build failed: {type(exc).__name__}: {exc}") from None
    print("Built a verified runner context locally; nothing was deployed or pushed.")


if __name__ == "__main__":
    main()
