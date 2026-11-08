#!/usr/bin/env python3
"""Prepare a private, offline peering release over an exact live management ZIP."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import zipfile

from common import ROOT, compile_bicep

OVERLAY = (
    "checkpoint_foundation.py", "checkpoint_gaia.py", "checkpoint_runner.py",
    "checkpoint_runner_config.py", "checkpoint_runner_entry.py", "config.py", "management.py",
    "models.py", "templates.py", "peering_lab.py", "peering_templates.py",
)


def private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(value, stream, indent=2)


def prepare(base: Path, state_path: Path, output: Path):
    output = output.resolve()
    if not output.is_relative_to(ROOT / ".local") or output.exists():
        raise ValueError("Choose a new output directory under provider-provisioning/.local")
    state = json.loads(state_path.read_text())
    worker = state["worker"]["settings"]
    registry = worker["FAAS_CHECKPOINT_REGISTRY_SERVER"]
    digest = worker["FAAS_CHECKPOINT_IMAGE_SHA256"]
    if (not re.fullmatch(r"[a-z0-9-]+\.azurecr\.io", registry)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)):
        raise ValueError("Invalid pinned runner base")
    output.mkdir(mode=0o700, parents=True)
    updates = {"service/" + name: (ROOT / "service" / name).read_bytes() for name in OVERLAY}
    updates["service/static/management.html"] = (ROOT / "service/static/management.html").read_bytes()
    updates["service/templates/peering-customer.json"] = compile_bicep("peering-customer.bicep")
    candidate = output / "candidate"
    candidate.mkdir(mode=0o700)
    untouched = {}
    with zipfile.ZipFile(base) as source, zipfile.ZipFile(
            output / "apps.zip", "w", compression=zipfile.ZIP_DEFLATED) as target:
        if len(source.infolist()) > 5000 or sum(item.file_size for item in source.infolist()) > 128 * 1024 * 1024:
            raise ValueError("Base management release exceeds limits")
        seen = set()
        for entry in source.infolist():
            path = PurePosixPath(entry.filename)
            if (path.is_absolute() or ".." in path.parts or entry.filename in seen
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError("Unsafe or duplicate ZIP entry")
            seen.add(entry.filename)
            if entry.is_dir():
                target.writestr(entry, b"")
                continue
            original = source.read(entry)
            value = updates.pop(entry.filename, original)
            if value == original:
                untouched[entry.filename] = hashlib.sha256(original).hexdigest()
            target.writestr(entry, value)
            destination = candidate.joinpath(*path.parts)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes(value)
        for name, value in updates.items():
            target.writestr(name, value)
            destination = candidate / name
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes(value)
    (output / "apps.zip").chmod(0o600)
    with zipfile.ZipFile(output / "apps.zip") as archive:
        for name, expected in untouched.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != expected:
                raise ValueError("A preserved live asset changed")
        for name, setting in (
                ("checkpoint-foundation.json", "FAAS_CHECKPOINT_FOUNDATION_TEMPLATE_SHA256"),
                ("checkpoint-private-data.json", "FAAS_CHECKPOINT_PRIVATE_TEMPLATE_SHA256")):
            if hashlib.sha256(archive.read("service/templates/" + name)).hexdigest() != worker[setting]:
                raise ValueError("Live Check Point template and worker pin differ")
    context = output / "runner-context"
    app = context / "app/service"
    app.mkdir(mode=0o700, parents=True)
    for name in OVERLAY:
        if name not in ("management.py", "peering_lab.py", "peering_templates.py"):
            shutil.copyfile(ROOT / "service" / name, app / name)
    dockerfile = (
        f"FROM {registry}/faas-checkpoint-runner@sha256:{digest}\n"
        "COPY --chown=0:0 --chmod=0444 app/service/*.py /opt/faas/app/service/\n"
        "USER 65532:65532\n")
    (context / "Dockerfile").write_text(dockerfile)
    manifest = {
        "baseSha256": hashlib.sha256(base.read_bytes()).hexdigest(),
        "packageSha256": hashlib.sha256((output / "apps.zip").read_bytes()).hexdigest(),
        "overlayAssets": ["service/" + name for name in OVERLAY] + [
            "service/static/management.html", "service/templates/peering-customer.json"],
        "preservedAssetCount": len(untouched),
        "baseRunnerImage": f"{registry}/faas-checkpoint-runner@sha256:{digest}",
    }
    private_json(output / "manifest.json", manifest)
    print("Prepared management ZIP and runner overlay; existing live assets and template pins preserved.")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-package", required=True, type=Path)
    parser.add_argument("--release-state", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    prepare(arguments.base_package, arguments.release_state, arguments.output)


if __name__ == "__main__":
    main()
