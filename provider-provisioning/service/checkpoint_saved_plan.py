"""Private, Linux-sealed Terraform plan snapshots for a future runner."""
import fcntl
import hashlib
import os
import platform
import re
import stat
import tempfile
from pathlib import Path


MAX_PLAN_BYTES = 64 * 1024 * 1024


class CheckpointPlanStorageError(ValueError):
    pass


class SealedCheckpointPlan:
    def __init__(self, fd: int, sha256: str, size: int) -> None:
        if (type(fd) is not int or fd < 0 or not isinstance(sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", sha256)
                or type(size) is not int or not 1 <= size <= MAX_PLAN_BYTES):
            raise CheckpointPlanStorageError("Invalid Check Point plan snapshot")
        self._fd = fd
        self.sha256 = sha256
        self.size = size

    def __repr__(self) -> str:
        return "<SealedCheckpointPlan>"

    def fileno(self) -> int:
        if self._fd < 0:
            raise CheckpointPlanStorageError("Check Point plan snapshot is closed")
        try:
            required = ("F_GET_SEALS", "F_SEAL_WRITE", "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL")
            if platform.system() != "Linux" or any(not hasattr(fcntl, name) for name in required):
                raise CheckpointPlanStorageError("Linux sealed plan support is required")
            info = os.fstat(self._fd)
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o400 or info.st_nlink != 0
                    or info.st_size != self.size or fcntl.fcntl(self._fd, fcntl.F_GET_SEALS) & seals != seals):
                raise CheckpointPlanStorageError("Invalid Check Point plan snapshot")
            os.lseek(self._fd, 0, os.SEEK_SET)
            digest, total = hashlib.sha256(), 0
            while chunk := os.read(self._fd, 1024 * 1024):
                total += len(chunk)
                if total > self.size:
                    raise CheckpointPlanStorageError("Invalid Check Point plan snapshot")
                digest.update(chunk)
            if total != self.size or digest.hexdigest() != self.sha256:
                raise CheckpointPlanStorageError("Check Point plan snapshot checksum mismatch")
            os.lseek(self._fd, 0, os.SEEK_SET)
        except OSError:
            raise CheckpointPlanStorageError("Unable to read Check Point plan snapshot") from None
        return self._fd

    def path(self) -> str:
        return f"/proc/self/fd/{self.fileno()}"

    def close(self) -> None:
        if self._fd >= 0:
            fd, self._fd = self._fd, -1
            os.close(fd)

    def __enter__(self) -> "SealedCheckpointPlan":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class CheckpointPlanWorkspace:
    def __init__(self, parent: Path) -> None:
        try:
            self._temporary = tempfile.TemporaryDirectory(prefix="checkpoint-plan-", dir=parent)
        except OSError:
            raise CheckpointPlanStorageError("Unable to create Check Point plan workspace") from None
        self.path = Path(self._temporary.name)
        self._closed = False

    @property
    def plan_file(self) -> Path:
        if self._closed:
            raise CheckpointPlanStorageError("Check Point plan workspace is closed")
        return self.path / "checkpoint.tfplan"

    def seal(self) -> SealedCheckpointPlan:
        if self._closed:
            raise CheckpointPlanStorageError("Check Point plan workspace is closed")
        directory_fd = source_fd = sealed_fd = None
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            directory_fd = os.open(self.path, flags)
            directory = os.fstat(directory_fd)
            if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid()
                    or stat.S_IMODE(directory.st_mode) != 0o700):
                raise CheckpointPlanStorageError("Invalid Check Point plan workspace")
            source_fd = os.open("checkpoint.tfplan", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            before = os.fstat(source_fd)
            mode = stat.S_IMODE(before.st_mode)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                    or before.st_nlink != 1 or not 1 <= before.st_size <= MAX_PLAN_BYTES
                    or not mode & 0o400 or mode & 0o177):
                raise CheckpointPlanStorageError("Invalid private Check Point plan file")
            required = ("memfd_create", "MFD_CLOEXEC", "MFD_ALLOW_SEALING")
            seal_names = ("F_ADD_SEALS", "F_GET_SEALS", "F_SEAL_WRITE",
                          "F_SEAL_GROW", "F_SEAL_SHRINK", "F_SEAL_SEAL")
            if (platform.system() != "Linux" or any(not hasattr(os, name) for name in required)
                    or any(not hasattr(fcntl, name) for name in seal_names)):
                raise CheckpointPlanStorageError("Linux sealed plan support is required")
            sealed_fd = os.memfd_create("faas-checkpoint-plan", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            digest, total = hashlib.sha256(), 0
            while chunk := os.read(source_fd, 1024 * 1024):
                total += len(chunk)
                if total > MAX_PLAN_BYTES:
                    raise CheckpointPlanStorageError("Check Point plan exceeds its size limit")
                digest.update(chunk)
                remaining = memoryview(chunk)
                while remaining:
                    written = os.write(sealed_fd, remaining)
                    if written <= 0:
                        raise CheckpointPlanStorageError("Unable to snapshot Check Point plan")
                    remaining = remaining[written:]
            after = os.fstat(source_fd)
            current = os.stat("checkpoint.tfplan", dir_fd=directory_fd, follow_symlinks=False)
            if (total != before.st_size or
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or
                    (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)):
                raise CheckpointPlanStorageError("Check Point plan changed during snapshot")
            os.fchmod(sealed_fd, 0o400)
            seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            fcntl.fcntl(sealed_fd, fcntl.F_ADD_SEALS, seals)
            if fcntl.fcntl(sealed_fd, fcntl.F_GET_SEALS) & seals != seals:
                raise CheckpointPlanStorageError("Check Point plan snapshot is not sealed")
            os.unlink("checkpoint.tfplan", dir_fd=directory_fd)
            if os.fstat(source_fd).st_nlink != 0:
                raise CheckpointPlanStorageError("Check Point plan file could not be isolated")
            os.lseek(sealed_fd, 0, os.SEEK_SET)
            result = SealedCheckpointPlan(sealed_fd, digest.hexdigest(), total)
            sealed_fd = None
            return result
        except OSError:
            raise CheckpointPlanStorageError("Unable to isolate Check Point plan") from None
        finally:
            for fd in (source_fd, directory_fd, sealed_fd):
                if fd is not None:
                    os.close(fd)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._temporary.cleanup()

    def __enter__(self) -> "CheckpointPlanWorkspace":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
