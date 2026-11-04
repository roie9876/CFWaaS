"""Verify initialized Check Point Terraform dependencies before evaluating a plan."""
import base64
import hashlib
import json
import os
import platform
import stat
from pathlib import Path

from .checkpoint_terraform import CheckpointTerraformError, verify_checkpoint_protected_path


REGIONS_COMMIT = "11db114e93a8ba28ba576998ac8a312833ef1c2d"
REGIONS_SOURCE = (
    "git::https://github.com/Azure/terraform-azurerm-avm-utl-regions.git?ref=" + REGIONS_COMMIT
)
REGIONS_RUNTIME_SHA256 = "67085f266d119d4be5a1456e7506ece4d40b86599e304783794099e531f1f883"
PROVIDER_LOCK_SHA256 = "41161ca94f8e5450ede0d9b333d81d720e3abbe8e17dde202267a2cfb3211d65"
ARTIFACT_SHA256 = "f4b0ba117a723c4171409ab3d0b90bd8a5997de9737c1458e6ea9eaa50d75960"
PROVIDER_PACKAGES = {
    ("azure", "azapi", "2.7.0", "terraform-provider-azapi_v2.7.0"): {
        "linux_amd64": "h1:9zm0JfFV0ytSrVU2keJhcOjYQmxc/Qe6rFufuXQh8qk=",
        "darwin_arm64": "h1:EbRurv5AIeJI6p/yT+SItZvut6AJyvke91i7cdoLdXc=",
    },
    ("azure", "modtm", "0.4.0", "terraform-provider-modtm_v0.4.0"): {
        "linux_amd64": "h1:AZf16AqJYD0dj9TXCMim1pJlaSAY0qZOAXV5CJ02wR8=",
        "darwin_arm64": "h1:QPvxep0fmss0+xUk2Im8Y1n+iRl2C9q+wmq6YWi5yIY=",
    },
    ("hashicorp", "azurerm", "4.73.0", "terraform-provider-azurerm_v4.73.0_x5"): {
        "linux_amd64": "h1:bOt0T0oW3ANoIVaSJ+zsHI8VCDEhic6x3jkyM2Bodrk=",
        "darwin_arm64": "h1:LLRGDDS4yuuxi1UmE/1ceGXWYiDGKJFQgcFxQAlPKv8=",
    },
    ("hashicorp", "null", "3.3.2", "terraform-provider-null_v3.3.2_x5"): {
        "linux_amd64": "h1:IQ1qrkht1sC1nibUR+AJ3ulryyhVDHfCHZhoJi0sg2Y=",
        "darwin_arm64": "h1:/Wbz7DHFO92KAqyDBMxGA8nwOJYECM8iLGhR7+wVWhQ=",
    },
    ("hashicorp", "random", "3.6.3", "terraform-provider-random_v3.6.3_x5"): {
        "linux_amd64": "h1:Fnaec9vA8sZ8BXVlN3Xn9Jz3zghSETIKg7ch8oXhxno=",
        "darwin_arm64": "h1:zG9uFP8l9u+yGZZvi5Te7PV62j50azpgwPunq2vTm1E=",
    },
}
MAX_PROVIDER_FILE_BYTES = 512 * 1024 * 1024
REGIONS_KEYS = {"gateway.common.regions", "management.common.regions"}
EXPECTED_MODULES = {
    "": ("", "."),
    "gateway": ("./modules/single-gateway", "modules/single-gateway"),
    "management": ("./modules/management", "modules/management"),
}
for parent in ("gateway", "management"):
    EXPECTED_MODULES.update({
        f"{parent}.common": ("../common/common", "modules/common/common"),
        f"{parent}.common.regions": (REGIONS_SOURCE, f".terraform/modules/{parent}.common.regions"),
        f"{parent}.custom_image": ("../common/custom-image", "modules/common/custom-image"),
        f"{parent}.network_security_group": ("../common/network-security-group", "modules/common/network-security-group"),
        f"{parent}.vm_boot_diagnostics_storage": ("../common/storage-account", "modules/common/storage-account"),
        f"{parent}.vnet": ("../common/vnet", "modules/common/vnet"),
    })
VMSS_EXPECTED_MODULES = {**EXPECTED_MODULES, "gateway": ("./modules/vmss", "modules/vmss")}
VMSS_ARTIFACT_SHA256 = "0b23dd8fed59393768c3c964b8de6da08a8365250b93331568b07a65959f70fe"


def _topology(topology: str) -> bool:
    if topology not in ("single", "vmss"):
        raise CheckpointDependencyError("Unsupported Check Point topology")
    return topology == "vmss"


class CheckpointDependencyError(ValueError):
    pass


def _provider_file_hash(path: Path) -> str:
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 1 <= before.st_size <= MAX_PROVIDER_FILE_BYTES
                or (path.name.startswith("terraform-provider-")
                    and (not before.st_mode & 0o111 or before.st_mode & (stat.S_ISUID | stat.S_ISGID)))):
            raise CheckpointDependencyError("Invalid Check Point provider package")
        digest, total = hashlib.sha256(), 0
        while chunk := os.read(fd, 1024 * 1024):
            total += len(chunk)
            if total > MAX_PROVIDER_FILE_BYTES:
                raise CheckpointDependencyError("Invalid Check Point provider package")
            digest.update(chunk)
        after = os.fstat(fd)
        if (total != before.st_size or
                (before.st_dev, before.st_ino, before.st_mode, before.st_nlink, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_size, after.st_mtime_ns)):
            raise CheckpointDependencyError("Check Point provider package changed during verification")
        return digest.hexdigest()
    except OSError:
        raise CheckpointDependencyError("Unable to read Check Point provider package") from None
    finally:
        if fd is not None:
            os.close(fd)


def _provider_target(target: str | None) -> str:
    if target is None:
        target = {("Linux", "x86_64"): "linux_amd64", ("Darwin", "arm64"): "darwin_arm64"}.get(
            (platform.system(), platform.machine()))
    if target not in {"linux_amd64", "darwin_arm64"}:
        raise CheckpointDependencyError("Unsupported Check Point provider platform")
    return target


def verify_checkpoint_provider_packages(directory: Path, target: str | None = None) -> None:
    """Verify installed package contents against platform-specific h1 hashes in the pinned lock."""
    target = _provider_target(target)
    root = directory / ".terraform/providers"
    if any(path.is_symlink() or not path.is_dir() for path in (directory, directory / ".terraform", root)):
        raise CheckpointDependencyError("Invalid Check Point provider directory")
    packages = {}
    expected_directories = {Path(".")}
    expected_files = set()
    for (namespace, name, version, executable), hashes in PROVIDER_PACKAGES.items():
        base = Path("registry.terraform.io") / namespace / name / version / target
        names = {executable} | ({"LICENSE.txt"} if namespace == "hashicorp" else set())
        packages[base] = (names, hashes[target])
        expected_files.update(base / item for item in names)
        expected_directories.update([base, *base.parents])
    found_directories, found_files = set(), set()

    def fail_walk(error: OSError) -> None:
        raise error

    try:
        for current, dirs, files in os.walk(root, followlinks=False, onerror=fail_walk):
            path = Path(current)
            found_directories.add(path.relative_to(root))
            for name in dirs:
                if (path / name).is_symlink():
                    raise CheckpointDependencyError("Invalid Check Point provider directory")
            found_files.update((path / name).relative_to(root) for name in files)
            if len(found_directories) > len(expected_directories) or len(found_files) > len(expected_files):
                raise CheckpointDependencyError("Unexpected Check Point provider package")
    except OSError:
        raise CheckpointDependencyError("Unable to inspect Check Point provider packages") from None
    if found_directories != expected_directories or found_files != expected_files:
        raise CheckpointDependencyError("Unexpected Check Point provider package")
    for base, (names, expected_hash) in packages.items():
        digest = hashlib.sha256()
        for name in sorted(names):
            digest.update((_provider_file_hash(root / base / name) + "  " + name + "\n").encode())
        actual = "h1:" + base64.b64encode(digest.digest()).decode("ascii")
        if actual != expected_hash:
            raise CheckpointDependencyError("Check Point provider package checksum mismatch")


def verify_checkpoint_provider_runtime(directory: Path, topology: str = "single") -> None:
    """Require immutable provider paths and verify the initialized dependency graph."""
    target = _provider_target(None)
    root = directory / ".terraform/providers/registry.terraform.io"
    for namespace, name, version, executable in PROVIDER_PACKAGES:
        base = root / namespace / name / version / target
        names = {executable} | ({"LICENSE.txt"} if namespace == "hashicorp" else set())
        for filename in names:
            path = base / filename
            fd = None
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                info = os.fstat(fd)
                verify_checkpoint_protected_path(path, info)
            except (OSError, CheckpointTerraformError):
                raise CheckpointDependencyError("Check Point provider runtime path is not protected") from None
            finally:
                if fd is not None:
                    os.close(fd)
    verify_checkpoint_dependencies(directory, topology=topology)


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise CheckpointDependencyError("Invalid Check Point dependency file")
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError:
        raise CheckpointDependencyError("Unable to read Check Point dependency file") from None
    if len(data) > limit:
        raise CheckpointDependencyError("Invalid Check Point dependency file")
    return data


def verify_checkpoint_artifact(directory: Path, topology: str = "single") -> None:
    expected_digest = VMSS_ARTIFACT_SHA256 if _topology(topology) else ARTIFACT_SHA256
    if directory.is_symlink() or not directory.is_dir():
        raise CheckpointDependencyError("Invalid Check Point artifact directory")
    files = []
    def fail_walk(error: OSError) -> None:
        raise error

    try:
        for root, dirs, names in os.walk(directory, followlinks=False, onerror=fail_walk):
            root_path = Path(root)
            for name in dirs:
                if (root_path / name).is_symlink():
                    raise CheckpointDependencyError("Invalid Check Point artifact directory")
            if root_path == directory and ".terraform" in dirs:
                dirs.remove(".terraform")
            for name in names:
                files.append(root_path / name)
                if len(files) > 100:
                    raise CheckpointDependencyError("Check Point artifact has unexpected files")
    except OSError:
        raise CheckpointDependencyError("Unable to read Check Point artifact") from None
    digest, total = hashlib.sha256(), 0
    for path in sorted(files):
        content = _read_bounded(path, 8 * 1024 * 1024)
        total += len(content)
        if total > 8 * 1024 * 1024:
            raise CheckpointDependencyError("Check Point artifact exceeds its size limit")
        digest.update(path.relative_to(directory).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
    if digest.hexdigest() != expected_digest:
        raise CheckpointDependencyError("Check Point artifact checksum mismatch")


def verify_checkpoint_dependencies(directory: Path, target: str | None = None, topology: str = "single") -> None:
    expected_modules = VMSS_EXPECTED_MODULES if _topology(topology) else EXPECTED_MODULES
    if any(path.is_symlink() for path in (directory, directory / ".terraform", directory / ".terraform/modules")):
        raise CheckpointDependencyError("Invalid Check Point dependency directory")
    lock = _read_bounded(directory / ".terraform.lock.hcl", 256 * 1024)
    if hashlib.sha256(lock).hexdigest() != PROVIDER_LOCK_SHA256:
        raise CheckpointDependencyError("Check Point provider lock mismatch")
    manifest_path = directory / ".terraform/modules/modules.json"
    try:
        manifest = json.loads(_read_bounded(manifest_path, 256 * 1024))
    except (ValueError, TypeError):
        raise CheckpointDependencyError("Invalid Check Point module manifest") from None
    entries = manifest.get("Modules") if isinstance(manifest, dict) else None
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        raise CheckpointDependencyError("Invalid Check Point module manifest")
    keys = [item.get("Key") for item in entries]
    if (len(entries) != len(expected_modules) or not all(isinstance(key, str) for key in keys)
            or set(keys) != set(expected_modules)
            or any((item.get("Source"), item.get("Dir")) != expected_modules[item["Key"]] for item in entries)):
        raise CheckpointDependencyError("Unexpected Check Point module graph")
    selected = [item for item in entries if item["Key"] in REGIONS_KEYS]
    for item in selected:
        key = item["Key"]
        expected = ".terraform/modules/" + key
        if item.get("Source") != REGIONS_SOURCE or item.get("Dir") != expected:
            raise CheckpointDependencyError("Unexpected Check Point region module")
        module = directory / expected
        if module.is_symlink() or not module.is_dir():
            raise CheckpointDependencyError("Invalid Check Point region module directory")
        files = sorted(path for path in module.iterdir() if path.name.endswith((".tf", ".tf.json")))
        if not 1 <= len(files) <= 32:
            raise CheckpointDependencyError("Invalid Check Point region module files")
        digest = hashlib.sha256()
        for path in files:
            content = _read_bounded(path, 2 * 1024 * 1024)
            digest.update(path.name.encode("utf-8"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(content).digest())
        if digest.hexdigest() != REGIONS_RUNTIME_SHA256:
            raise CheckpointDependencyError("Check Point region module checksum mismatch")
    verify_checkpoint_provider_packages(directory, target)
