import hashlib
import errno
import os
import platform
import stat
import subprocess
import sys
import tempfile

import pytest

from service import checkpoint_saved_plan as plans


@pytest.fixture
def simulated_linux_seals(monkeypatch):
    monkeypatch.setattr(plans.platform, "system", lambda: "Linux")
    monkeypatch.setattr(plans.os, "MFD_CLOEXEC", 1, raising=False)
    monkeypatch.setattr(plans.os, "MFD_ALLOW_SEALING", 2, raising=False)
    codes = {"F_ADD_SEALS": 1001, "F_GET_SEALS": 1002, "F_SEAL_WRITE": 4,
             "F_SEAL_GROW": 8, "F_SEAL_SHRINK": 16, "F_SEAL_SEAL": 32}
    for name, value in codes.items():
        monkeypatch.setattr(plans.fcntl, name, value, raising=False)
    seals = {}

    def memfd(_name, _flags):
        fd, path = tempfile.mkstemp()
        os.unlink(path)
        return fd

    def fake_fcntl(fd, command, argument=0):
        if command == codes["F_ADD_SEALS"]:
            seals[fd] = argument
            return 0
        if command == codes["F_GET_SEALS"]:
            return seals.get(fd, 0)
        raise AssertionError("Unexpected fcntl command")

    monkeypatch.setattr(plans.os, "memfd_create", memfd, raising=False)
    monkeypatch.setattr(plans.fcntl, "fcntl", fake_fcntl)
    return seals


def write_plan(workspace, data=b"fixture-plan", mode=0o600):
    workspace.plan_file.write_bytes(data)
    workspace.plan_file.chmod(mode)


def test_snapshot_seals_exact_bytes_and_removes_disk_copy(tmp_path, simulated_linux_seals):
    with plans.CheckpointPlanWorkspace(tmp_path) as workspace:
        write_plan(workspace)
        original = workspace.plan_file
        with workspace.seal() as snapshot:
            assert not original.exists()
            assert snapshot.size == len(b"fixture-plan")
            assert snapshot.sha256 == hashlib.sha256(b"fixture-plan").hexdigest()
            assert snapshot.sha256 not in repr(snapshot)
            assert os.read(snapshot.fileno(), snapshot.size) == b"fixture-plan"
            assert stat.S_IMODE(os.fstat(snapshot.fileno()).st_mode) == 0o400
            assert snapshot.path() == f"/proc/self/fd/{snapshot.fileno()}"
            assert simulated_linux_seals[snapshot.fileno()] == 60
        with pytest.raises(plans.CheckpointPlanStorageError, match="closed"):
            snapshot.fileno()
    assert not workspace.path.exists()


def test_snapshot_requires_linux_seals_and_preserves_input_on_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(plans.platform, "system", lambda: "Darwin")
    with plans.CheckpointPlanWorkspace(tmp_path) as workspace:
        write_plan(workspace)
        with pytest.raises(plans.CheckpointPlanStorageError, match="Linux sealed"):
            workspace.seal()
        assert workspace.plan_file.read_bytes() == b"fixture-plan"


def test_snapshot_fails_closed_when_kernel_does_not_confirm_seals(tmp_path, simulated_linux_seals, monkeypatch):
    monkeypatch.setattr(plans.fcntl, "fcntl", lambda _fd, command, *_args:
                        0 if command == plans.fcntl.F_GET_SEALS else 0)
    with plans.CheckpointPlanWorkspace(tmp_path) as workspace:
        write_plan(workspace)
        with pytest.raises(plans.CheckpointPlanStorageError, match="not sealed"):
            workspace.seal()
        assert workspace.plan_file.read_bytes() == b"fixture-plan"


def test_snapshot_revalidates_its_digest_and_kernel_seals(tmp_path, simulated_linux_seals):
    with plans.CheckpointPlanWorkspace(tmp_path) as workspace:
        write_plan(workspace)
        with workspace.seal() as snapshot:
            fd = snapshot.fileno()
            snapshot.sha256 = "0" * 64
            with pytest.raises(plans.CheckpointPlanStorageError, match="checksum"):
                snapshot.fileno()
            snapshot.sha256 = hashlib.sha256(b"fixture-plan").hexdigest()
            simulated_linux_seals[fd] = 0
            with pytest.raises(plans.CheckpointPlanStorageError, match="snapshot"):
                snapshot.fileno()


@pytest.mark.parametrize("mode", [0o000, 0o644, 0o700, 0o777])
def test_snapshot_rejects_nonprivate_or_executable_plan(tmp_path, mode):
    with plans.CheckpointPlanWorkspace(tmp_path) as workspace:
        write_plan(workspace, mode=mode)
        with pytest.raises(plans.CheckpointPlanStorageError):
            workspace.seal()
        assert workspace.plan_file.exists()


def test_snapshot_rejects_nonprivate_workspace(tmp_path):
    with plans.CheckpointPlanWorkspace(tmp_path) as workspace:
        write_plan(workspace)
        workspace.path.chmod(0o755)
        with pytest.raises(plans.CheckpointPlanStorageError, match="workspace"):
            workspace.seal()
        workspace.path.chmod(0o700)


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_snapshot_never_removes_unrelated_link_target(tmp_path, kind):
    target = tmp_path / "keep"
    target.write_bytes(b"keep")
    with plans.CheckpointPlanWorkspace(tmp_path) as workspace:
        if kind == "symlink":
            workspace.plan_file.symlink_to(target)
        else:
            target.chmod(0o600)
            os.link(target, workspace.plan_file)
        with pytest.raises(plans.CheckpointPlanStorageError):
            workspace.seal()
        assert target.read_bytes() == b"keep"


@pytest.mark.parametrize("size", [0, plans.MAX_PLAN_BYTES + 1])
def test_snapshot_rejects_empty_or_oversize_plan(tmp_path, size):
    with plans.CheckpointPlanWorkspace(tmp_path) as workspace:
        with workspace.plan_file.open("wb") as stream:
            stream.truncate(size)
        workspace.plan_file.chmod(0o600)
        with pytest.raises(plans.CheckpointPlanStorageError, match="private"):
            workspace.seal()


def test_snapshot_accepts_exact_size_limit(tmp_path, simulated_linux_seals):
    with plans.CheckpointPlanWorkspace(tmp_path) as workspace:
        with workspace.plan_file.open("wb") as stream:
            stream.truncate(plans.MAX_PLAN_BYTES)
        workspace.plan_file.chmod(0o600)
        with workspace.seal() as snapshot:
            assert snapshot.size == plans.MAX_PLAN_BYTES


def test_workspace_is_closed_after_exit(tmp_path):
    with plans.CheckpointPlanWorkspace(tmp_path) as workspace:
        assert workspace.path.exists()
    with pytest.raises(plans.CheckpointPlanStorageError, match="closed"):
        _ = workspace.plan_file
    with pytest.raises(plans.CheckpointPlanStorageError, match="closed"):
        workspace.seal()


@pytest.mark.skipif(platform.system() != "Linux" or not hasattr(os, "memfd_create"),
                    reason="requires real Linux memfd seals")
def test_real_linux_kernel_prevents_plan_writes_and_resize(tmp_path):
    with plans.CheckpointPlanWorkspace(tmp_path) as workspace:
        write_plan(workspace)
        with workspace.seal() as snapshot:
            with pytest.raises(OSError) as write_error:
                os.write(snapshot.fileno(), b"changed")
            assert write_error.value.errno == errno.EPERM
            with pytest.raises(OSError) as resize_error:
                os.ftruncate(snapshot.fileno(), 0)
            assert resize_error.value.errno == errno.EPERM
            assert os.read(snapshot.fileno(), snapshot.size) == b"fixture-plan"


@pytest.mark.skipif(platform.system() != "Linux" or not hasattr(os, "memfd_create"),
                    reason="requires real Linux memfd seals")
def test_real_linux_sealed_plan_is_readable_but_not_writable_after_exec(tmp_path):
    child = """
import errno
import os
import sys
with open(sys.argv[1], "rb") as plan:
    assert plan.read() == b"fixture-plan"
try:
    os.write(int(sys.argv[2]), b"changed")
except OSError as error:
    assert error.errno == errno.EPERM
else:
    raise AssertionError("sealed plan was writable")
"""
    with plans.CheckpointPlanWorkspace(tmp_path) as workspace:
        write_plan(workspace)
        with workspace.seal() as snapshot:
            fd = snapshot.fileno()
            subprocess.run([sys.executable, "-c", child, snapshot.path(), str(fd)],
                           pass_fds=(fd,), capture_output=True, check=True)
