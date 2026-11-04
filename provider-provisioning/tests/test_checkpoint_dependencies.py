import base64
import hashlib
import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from service import checkpoint_dependencies as dependencies
from service import checkpoint_terraform as terraform


@pytest.fixture
def initialized(tmp_path, monkeypatch):
    root = tmp_path / "prepared"
    root.mkdir()
    lock = b"fixture-lock"
    (root / ".terraform.lock.hcl").write_bytes(lock)
    monkeypatch.setattr(dependencies, "PROVIDER_LOCK_SHA256", hashlib.sha256(lock).hexdigest())
    module_dir = root / ".terraform/modules"
    module_dir.mkdir(parents=True)
    entries = [{"Key": key, "Source": source, "Dir": path}
               for key, (source, path) in dependencies.EXPECTED_MODULES.items()]
    (module_dir / "modules.json").write_text(json.dumps({"Modules": entries}))
    content = b'output "fixture" { value = true }\n'
    digest = hashlib.sha256()
    digest.update(b"main.tf\0")
    digest.update(hashlib.sha256(content).digest())
    monkeypatch.setattr(dependencies, "REGIONS_RUNTIME_SHA256", digest.hexdigest())
    for key in dependencies.REGIONS_KEYS:
        module = module_dir / key
        module.mkdir()
        (module / "main.tf").write_bytes(content)
    packages = {}
    for (namespace, name, version, executable), _hashes in dependencies.PROVIDER_PACKAGES.items():
        package = root / ".terraform/providers/registry.terraform.io" / namespace / name / version / "linux_amd64"
        package.mkdir(parents=True)
        names = {executable} | ({"LICENSE.txt"} if namespace == "hashicorp" else set())
        digest = hashlib.sha256()
        for filename in sorted(names):
            data = f"{namespace}/{name}/{filename}".encode()
            path = package / filename
            path.write_bytes(data)
            path.chmod(0o755 if filename == executable else 0o644)
            digest.update((hashlib.sha256(data).hexdigest() + "  " + filename + "\n").encode())
        packages[(namespace, name, version, executable)] = {
            "linux_amd64": "h1:" + base64.b64encode(digest.digest()).decode()}
    monkeypatch.setattr(dependencies, "PROVIDER_PACKAGES", packages)
    monkeypatch.setattr(dependencies.platform, "system", lambda: "Linux")
    monkeypatch.setattr(dependencies.platform, "machine", lambda: "x86_64")
    return root


def test_accepts_exact_lock_graph_and_module_checksums(initialized):
    dependencies.verify_checkpoint_dependencies(initialized)


def test_provider_package_hashes_are_present_in_pinned_lock():
    lock = (Path(__file__).resolve().parents[1] / "infra/checkpoint/.terraform.lock.hcl").read_text()
    assert hashlib.sha256(lock.encode()).hexdigest() == dependencies.PROVIDER_LOCK_SHA256
    for (namespace, name, version, _executable), hashes in dependencies.PROVIDER_PACKAGES.items():
        section = lock.split(f'provider "registry.terraform.io/{namespace}/{name}" {{', 1)[1].split("\n}", 1)[0]
        assert f'version     = "{version}"' in section
        assert set(hashes) == {"linux_amd64", "darwin_arm64"}
        assert all(f'"{value}"' in section for value in hashes.values())


@pytest.mark.parametrize("mutation", ["changed", "extra", "missing", "symlink", "hardlink",
                                      "not_executable", "oversize", "unsupported"])
def test_provider_package_verifier_rejects_tampering(initialized, monkeypatch, mutation):
    namespace, name, version, executable = next(iter(dependencies.PROVIDER_PACKAGES))
    package = initialized / ".terraform/providers/registry.terraform.io" / namespace / name / version / "linux_amd64"
    binary = package / executable
    if mutation == "changed":
        binary.write_bytes(b"PRIVATE-VALUE")
    elif mutation == "extra":
        (package / "extra").write_bytes(b"PRIVATE-VALUE")
    elif mutation == "missing":
        binary.unlink()
    elif mutation == "symlink":
        binary.unlink()
        binary.symlink_to(initialized / "outside")
    elif mutation == "hardlink":
        os.link(binary, initialized / "hardlink")
    elif mutation == "not_executable":
        binary.chmod(0o644)
    elif mutation == "oversize":
        with binary.open("wb") as stream:
            stream.truncate(dependencies.MAX_PROVIDER_FILE_BYTES + 1)
    else:
        monkeypatch.setattr(dependencies.platform, "machine", lambda: "unsupported")
    with pytest.raises(dependencies.CheckpointDependencyError) as error:
        dependencies.verify_checkpoint_dependencies(initialized)
    assert "PRIVATE-VALUE" not in str(error.value)


@pytest.fixture
def terraform_binary(tmp_path, monkeypatch):
    binary = tmp_path / "terraform"
    content = b"fixture-executable"
    binary.write_bytes(content)
    binary.chmod(0o555)
    monkeypatch.setattr(terraform.platform, "system", lambda: "Linux")
    monkeypatch.setattr(terraform.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(terraform, "TERRAFORM_RELEASES", {
        ("Linux", "x86_64"): {"binary_sha256": hashlib.sha256(content).hexdigest(),
                               "archive_sha256": "a" * 64}})
    return binary


def test_terraform_runtime_requires_pinned_readonly_executable(terraform_binary, monkeypatch):
    monkeypatch.setattr(terraform, "verify_checkpoint_protected_path", lambda *_args: None)
    terraform.verify_terraform_runtime(terraform_binary)
    terraform_binary.chmod(0o755)
    terraform.verify_terraform_release(terraform_binary)
    with pytest.raises(terraform.CheckpointTerraformError, match="read-only"):
        terraform.verify_terraform_runtime(terraform_binary)


@pytest.mark.parametrize("mutation", ["changed", "symlink", "not_executable", "unsupported"])
def test_terraform_runtime_rejects_untrusted_binaries_without_echoing_values(terraform_binary, monkeypatch, mutation):
    binary = terraform_binary
    if mutation == "changed":
        binary.chmod(0o755)
        binary.write_bytes(b"PRIVATE-VALUE")
    elif mutation == "symlink":
        link = binary.parent / "link"
        link.symlink_to(binary)
        binary = link
    elif mutation == "not_executable":
        binary.chmod(0o444)
    else:
        monkeypatch.setattr(terraform.platform, "machine", lambda: "unsupported")
    with pytest.raises(terraform.CheckpointTerraformError) as error:
        terraform.verify_terraform_runtime(binary)
    assert "PRIVATE-VALUE" not in str(error.value)


def trusted_runtime_metadata(monkeypatch, unsafe_directory=None, unsafe_owner=None, unsafe_file=None):
    real_fstat = os.fstat

    def trusted_fstat(fd):
        actual = real_fstat(fd)
        directory = stat.S_ISDIR(actual.st_mode)
        permissions = 0o755 if directory else 0o555
        if unsafe_directory is not None and actual.st_ino == unsafe_directory:
            permissions = 0o777
        if unsafe_file is not None and actual.st_ino == unsafe_file:
            permissions = 0o777
        owner = 1 if unsafe_owner is not None and actual.st_ino == unsafe_owner else 0
        return SimpleNamespace(
            st_mode=stat.S_IFMT(actual.st_mode) | permissions, st_uid=owner,
            st_dev=actual.st_dev, st_ino=actual.st_ino, st_nlink=actual.st_nlink,
            st_size=actual.st_size, st_mtime_ns=actual.st_mtime_ns)

    monkeypatch.setattr(terraform.os, "fstat", trusted_fstat)
    monkeypatch.setattr(terraform.os, "geteuid", lambda: 65532)


def test_terraform_runtime_requires_root_owned_nonwritable_path(terraform_binary, monkeypatch):
    trusted_runtime_metadata(monkeypatch)
    terraform.verify_terraform_runtime(terraform_binary)


@pytest.mark.parametrize("mutation", ["writable_parent", "foreign_parent", "foreign_binary", "parent_symlink",
                                      "binary_changed", "root_runner"])
def test_terraform_runtime_rejects_replaceable_paths(terraform_binary, monkeypatch, mutation):
    binary = terraform_binary
    unsafe_directory = binary.parent.stat().st_ino if mutation == "writable_parent" else None
    unsafe_owner = (binary.parent.stat().st_ino if mutation == "foreign_parent"
                    else binary.stat().st_ino if mutation == "foreign_binary" else None)
    if mutation == "parent_symlink":
        link = binary.parent.parent / "linked-directory"
        link.symlink_to(binary.parent, target_is_directory=True)
        binary = link / binary.name
    trusted_runtime_metadata(monkeypatch, unsafe_directory, unsafe_owner)
    if mutation == "binary_changed":
        verify = terraform.verify_terraform_release
        def verify_then_change(path):
            result = verify(path)
            path.touch()
            return result
        monkeypatch.setattr(terraform, "verify_terraform_release", verify_then_change)
    elif mutation == "root_runner":
        monkeypatch.setattr(terraform.os, "geteuid", lambda: 0)
    with pytest.raises(terraform.CheckpointTerraformError):
        terraform.verify_terraform_runtime(binary)


def test_terraform_runtime_rejects_setuid_executable(terraform_binary):
    terraform_binary.chmod(0o4555)
    with pytest.raises(terraform.CheckpointTerraformError, match="read-only"):
        terraform.verify_terraform_runtime(terraform_binary)


@pytest.mark.parametrize("mutation", ["none", "writable_parent", "writable_binary", "foreign_binary", "root_runner"])
def test_provider_runtime_requires_protected_paths(initialized, monkeypatch, mutation):
    namespace, name, version, executable = next(iter(dependencies.PROVIDER_PACKAGES))
    binary = initialized / ".terraform/providers/registry.terraform.io" / namespace / name / version / "linux_amd64" / executable
    unsafe_directory = binary.parent.stat().st_ino if mutation == "writable_parent" else None
    unsafe_file = binary.stat().st_ino if mutation == "writable_binary" else None
    unsafe_owner = binary.stat().st_ino if mutation == "foreign_binary" else None
    trusted_runtime_metadata(monkeypatch, unsafe_directory, unsafe_owner, unsafe_file)
    if mutation == "root_runner":
        monkeypatch.setattr(terraform.os, "geteuid", lambda: 0)
    if mutation == "none":
        dependencies.verify_checkpoint_provider_runtime(initialized)
    else:
        with pytest.raises(dependencies.CheckpointDependencyError, match="not protected"):
            dependencies.verify_checkpoint_provider_runtime(initialized)


def fixture_artifact_digest(root):
    digest = hashlib.sha256()
    path = root / ".terraform.lock.hcl"
    digest.update(b".terraform.lock.hcl\0")
    digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def test_artifact_verifier_excludes_only_initialized_terraform_data(initialized, monkeypatch):
    monkeypatch.setattr(dependencies, "ARTIFACT_SHA256", fixture_artifact_digest(initialized))
    dependencies.verify_checkpoint_artifact(initialized)
    (initialized / ".terraform/modules/gateway.common.regions/main.tf").write_text("changed")
    dependencies.verify_checkpoint_artifact(initialized)
    with pytest.raises(dependencies.CheckpointDependencyError, match="checksum"):
        dependencies.verify_checkpoint_dependencies(initialized)


@pytest.mark.parametrize("mutation", ["changed", "extra", "symlink", "terraform_symlink"])
def test_artifact_verifier_rejects_tampering(initialized, monkeypatch, tmp_path, mutation):
    monkeypatch.setattr(dependencies, "ARTIFACT_SHA256", fixture_artifact_digest(initialized))
    if mutation == "changed":
        (initialized / ".terraform.lock.hcl").write_text("PRIVATE-VALUE")
    elif mutation == "extra":
        (initialized / "extra.tf").write_text("PRIVATE-VALUE")
    elif mutation == "symlink":
        (initialized / "extra.tf").symlink_to(tmp_path / "foreign")
    else:
        target = tmp_path / "terraform-data"
        (initialized / ".terraform").rename(target)
        (initialized / ".terraform").symlink_to(target, target_is_directory=True)
    with pytest.raises(dependencies.CheckpointDependencyError) as error:
        dependencies.verify_checkpoint_artifact(initialized)
    assert "PRIVATE-VALUE" not in str(error.value)


@pytest.mark.parametrize("mutation", [
    "lock", "manifest_json", "missing_module", "duplicate_module", "foreign_source", "foreign_directory",
    "unexpected_module", "modified_module", "extra_hcl", "module_symlink", "lock_symlink", "oversize_lock",
])
def test_rejects_modified_dependencies_without_echoing_values(initialized, mutation, tmp_path):
    manifest_path = initialized / ".terraform/modules/modules.json"
    manifest = json.loads(manifest_path.read_text())
    modules = manifest["Modules"]
    region = next(item for item in modules if item["Key"] == "gateway.common.regions")
    module = initialized / ".terraform/modules/gateway.common.regions"
    if mutation == "lock":
        (initialized / ".terraform.lock.hcl").write_text("PRIVATE-VALUE")
    elif mutation == "oversize_lock":
        (initialized / ".terraform.lock.hcl").write_bytes(b"x" * (256 * 1024 + 1))
    elif mutation == "manifest_json":
        manifest_path.write_text("PRIVATE-VALUE")
    elif mutation == "missing_module":
        modules.remove(region)
    elif mutation == "duplicate_module":
        modules.append(dict(region))
    elif mutation == "foreign_source":
        region["Source"] = "PRIVATE-VALUE"
    elif mutation == "foreign_directory":
        region["Dir"] = "../../PRIVATE-VALUE"
    elif mutation == "unexpected_module":
        modules.append({"Key": "other", "Source": "./outside", "Dir": "../outside"})
    elif mutation == "modified_module":
        (module / "main.tf").write_text("PRIVATE-VALUE")
    elif mutation == "extra_hcl":
        (module / "extra.tf.json").write_text("{}")
    elif mutation == "module_symlink":
        (module / "main.tf").unlink()
        (module / "main.tf").symlink_to(tmp_path / "foreign")
    else:
        (initialized / ".terraform.lock.hcl").unlink()
        (initialized / ".terraform.lock.hcl").symlink_to(tmp_path / "foreign")
    if mutation not in {"manifest_json", "lock", "oversize_lock", "modified_module", "extra_hcl",
                        "module_symlink", "lock_symlink"}:
        manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(dependencies.CheckpointDependencyError) as error:
        dependencies.verify_checkpoint_dependencies(initialized)
    assert "PRIVATE-VALUE" not in str(error.value)
