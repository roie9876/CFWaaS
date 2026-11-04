"""Verify the exact Terraform release intended for the Check Point runner."""
import hashlib
import os
import platform
import stat
from pathlib import Path


TERRAFORM_VERSION = "1.15.7"
TERRAFORM_RELEASES = {
    ("Linux", "x86_64"): {
        "archive_sha256": "73bbb8f5188ad75d4fb853fd100ae4d7e146ef7af7db18776109642fdb7759d2",
        "binary_sha256": "15cc5bba01dbcf61c3c18236014d3a5323f919a484a77be288de5c9835feb9fc",
    },
    ("Darwin", "arm64"): {
        "archive_sha256": "711791bf41365137a9a4adbf3e4c4a18dd7389d45c6a3039e3c6946bc750080e",
        "binary_sha256": "4bb36f1edd88ffb5a508e8b65ca00f89fbdc8d5143bafc2f43c9d5cc40e1d262",
    },
}
MAX_BINARY_BYTES = 160 * 1024 * 1024


class CheckpointTerraformError(ValueError):
    pass


def verify_terraform_release(binary: Path) -> os.stat_result:
    release = TERRAFORM_RELEASES.get((platform.system(), platform.machine()))
    if release is None:
        raise CheckpointTerraformError("Unsupported Check Point Terraform platform")
    fd = None
    try:
        fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111
                or not 1 <= before.st_size <= MAX_BINARY_BYTES):
            raise CheckpointTerraformError("Invalid Check Point Terraform executable")
        digest, total = hashlib.sha256(), 0
        while chunk := os.read(fd, 1024 * 1024):
            total += len(chunk)
            if total > MAX_BINARY_BYTES:
                raise CheckpointTerraformError("Invalid Check Point Terraform executable")
            digest.update(chunk)
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or digest.hexdigest() != release["binary_sha256"]):
            raise CheckpointTerraformError("Check Point Terraform executable checksum mismatch")
        return after
    except OSError:
        raise CheckpointTerraformError("Unable to read Check Point Terraform executable") from None
    finally:
        if fd is not None:
            os.close(fd)


def verify_terraform_runtime(binary: Path) -> None:
    if os.geteuid() == 0:
        raise CheckpointTerraformError("Check Point Terraform runner must not run as root")
    info = verify_terraform_release(binary)
    if info.st_mode & (0o222 | stat.S_ISUID | stat.S_ISGID):
        raise CheckpointTerraformError("Check Point Terraform executable must be read-only")
    verify_checkpoint_protected_path(binary, info)


def verify_checkpoint_protected_path(binary: Path, expected: os.stat_result) -> None:
    if (os.geteuid() == 0 or not binary.is_absolute() or ".." in binary.parts or len(binary.parts) < 2
            or not stat.S_ISREG(expected.st_mode) or expected.st_uid != 0
            or expected.st_mode & (0o222 | stat.S_ISUID | stat.S_ISGID)):
        raise CheckpointTerraformError("Check Point Terraform executable path is not protected")
    directory_fd = executable_fd = None
    try:
        directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for component in binary.parts[1:-1]:
            directory = os.fstat(directory_fd)
            if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
                    or directory.st_mode & 0o022):
                raise CheckpointTerraformError("Check Point Terraform executable path is not protected")
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        directory = os.fstat(directory_fd)
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or directory.st_mode & 0o022):
            raise CheckpointTerraformError("Check Point Terraform executable path is not protected")
        executable_fd = os.open(binary.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        actual = os.fstat(executable_fd)
        if ((actual.st_dev, actual.st_ino, actual.st_mode, actual.st_uid, actual.st_size, actual.st_mtime_ns)
                != (expected.st_dev, expected.st_ino, expected.st_mode, expected.st_uid,
                    expected.st_size, expected.st_mtime_ns)):
            raise CheckpointTerraformError("Check Point Terraform executable changed after verification")
    except OSError:
        raise CheckpointTerraformError("Unable to verify Check Point Terraform executable path") from None
    finally:
        if executable_fd is not None:
            os.close(executable_fd)
        if directory_fd is not None:
            os.close(directory_fd)
