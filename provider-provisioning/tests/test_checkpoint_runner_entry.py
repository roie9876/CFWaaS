import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from service import checkpoint_runner_entry as entry
from service.checkpoint_plan import CheckpointPlanError
from service.checkpoint_runner_config import CheckpointRunnerConfigError
from service.checkpoint_saved_plan import CheckpointPlanStorageError

SIC = "s" * 48
PASSWORD = "Aa1!PRIVATE-PASSWORD"


def runtime_inputs():
    config = SimpleNamespace(
        providerSubscriptionId="00000000-0000-0000-0000-000000000001",
        providerTenantId="00000000-0000-0000-0000-000000000002",
        runnerClientId="00000000-0000-0000-0000-000000000003",
        providerGroupId="/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-x",
        environmentId="00000000-0000-0000-0000-000000000004",
        providerSshPublicKey="ssh-ed25519 fixture", gatewayImageVersion="1.2.3", managementImageVersion="1.2.3",
        gatewayVmSize="Standard_D4ds_v5", managementVmSize="Standard_D4ds_v5",
        stateBlobEndpoint="https://stcpaaaaaaaaaaaaa.blob.core.windows.net/", stateContainer="terraform-state")
    return SimpleNamespace(config=config, credentials=SimpleNamespace(sic_key=SIC, management_password=PASSWORD))


class Sealed:
    def __init__(self, log):
        self.log = log

    def fileno(self):
        return 7

    def path(self):
        return "/proc/self/fd/7"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.log.append("sealed-closed")


class Workspace:
    def __init__(self, parent, log, fail=False):
        self.plan_file = Path(parent) / "checkpoint.tfplan"
        self.log, self.fail = log, fail

    def seal(self):
        if self.fail:
            raise CheckpointPlanStorageError("PRIVATE-VALUE")
        self.log.append("sealed")
        return Sealed(self.log)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.log.append("workspace-closed")


@pytest.fixture
def runner(tmp_path, monkeypatch):
    artifact = tmp_path / "artifact"
    (artifact / ".terraform/modules/fixture").mkdir(parents=True)
    (artifact / ".terraform/modules/fixture/main.tf").write_text("fixture")
    for name in ("verify_terraform_runtime", "verify_checkpoint_artifact", "verify_checkpoint_provider_runtime"):
        monkeypatch.setattr(entry, name, Mock())
    summary = SimpleNamespace(needs_apply=True)
    validate = Mock(return_value=summary)
    monkeypatch.setattr(entry, "validate_checkpoint_runner_plan", validate)
    calls, log, configured = [], [], []

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        stage = command[2]
        stdout = json.dumps({"fixture": "plan"}).encode() if stage == "show" else b"PRIVATE-OUTPUT"
        return subprocess.CompletedProcess(command, 0, stdout, b"PRIVATE-OUTPUT")

    def run(**overrides):
        options = dict(environment={}, artifact=artifact, terraform=Path("/opt/terraform"),
                       work_parent=tmp_path, execute=execute, read_inputs=lambda _env: runtime_inputs(),
                       workspace_factory=lambda parent: Workspace(parent, log),
                       configure=lambda inputs: configured.append(inputs))
        options.update(overrides)
        return entry.run_checkpoint_runner(**options)

    return SimpleNamespace(run=run, calls=calls, log=log, validate=validate, summary=summary, configured=configured,
                           artifact=artifact, execute=execute, tmp_path=tmp_path)


def test_runner_plans_validates_and_applies_only_the_sealed_plan(runner):
    assert runner.run() == entry.EXIT_OK
    stages = [command[2] for command, _ in runner.calls]
    assert stages == ["init", "plan", "show", "apply"]
    init, plan, show, apply = (command for command, _ in runner.calls)
    assert "-lockfile=readonly" in init and "-get=false" in init
    assert any(argument.startswith("-plugin-dir=") for argument in init)
    assert "-backend-config=use_msi=true" in init
    assert "-backend-config=key=checkpoint/00000000-0000-0000-0000-000000000004.tfstate" in init
    assert show[-1] == apply[-1] == "/proc/self/fd/7"
    assert runner.calls[2][1]["pass_fds"] == runner.calls[3][1]["pass_fds"] == (7,)
    assert runner.validate.call_args.args[1] == {"fixture": "plan"}
    assert runner.log.index("sealed") < runner.log.index("sealed-closed") < runner.log.index("workspace-closed")
    assert not list(runner.tmp_path.glob("checkpoint-run-*"))


def test_runner_never_places_credentials_in_arguments_or_unneeded_stages(runner):
    runner.run()
    for command, kwargs in runner.calls:
        assert all(SIC not in argument and PASSWORD not in argument for argument in command)
        assert kwargs["capture_output"] is True and kwargs["umask"] == 0o077 and kwargs["close_fds"] is True
        assert kwargs["env"]["PATH"] == "/usr/bin:/bin" and "TF_LOG" not in kwargs["env"]
        assert not any(name.startswith("AZURE_") or name == "ARM_CLIENT_SECRET" for name in kwargs["env"])
        has_secret = SIC in kwargs["env"].values() or PASSWORD in kwargs["env"].values()
        assert has_secret is (command[2] in {"plan", "apply"})


def test_runner_skips_apply_for_noop_plan(runner):
    runner.summary.needs_apply = False
    assert runner.run() == entry.EXIT_OK
    assert [command[2] for command, _ in runner.calls] == ["init", "plan", "show"]


@pytest.mark.parametrize("error", [CheckpointPlanError("PRIVATE-VALUE"), ValueError("PRIVATE-VALUE")])
def test_runner_refuses_to_apply_rejected_plan(runner, error):
    runner.validate.side_effect = error
    assert runner.run() == entry.EXIT_PLAN
    assert [command[2] for command, _ in runner.calls] == ["init", "plan", "show"]


@pytest.mark.parametrize("failed_stage", ["init", "plan", "show", "apply"])
def test_runner_stops_on_terraform_failure_without_retry(runner, failed_stage):
    calls = []

    def execute(command, **kwargs):
        calls.append(command[2])
        if command[2] == failed_stage:
            return subprocess.CompletedProcess(command, 1, b"PRIVATE-OUTPUT", b"PRIVATE-OUTPUT")
        return runner.execute(command, **kwargs)

    assert runner.run(execute=execute) == entry.EXIT_TERRAFORM
    assert calls[-1] == failed_stage and calls.count(failed_stage) == 1


def test_runner_handles_timeouts_and_invalid_plan_json(runner):
    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 1)

    assert runner.run(execute=timeout) == entry.EXIT_TERRAFORM

    def bad_json(command, **kwargs):
        if command[2] == "show":
            return subprocess.CompletedProcess(command, 0, b"PRIVATE-VALUE", b"")
        return runner.execute(command, **kwargs)

    assert runner.run(execute=bad_json) == entry.EXIT_PLAN


def test_runner_rejects_bad_inputs_and_runtime_before_terraform(runner, monkeypatch):
    def bad_inputs(_env):
        raise CheckpointRunnerConfigError("PRIVATE-VALUE")

    assert runner.run(read_inputs=bad_inputs) == entry.EXIT_INPUTS
    entry.verify_terraform_runtime.side_effect = entry.CheckpointTerraformError("PRIVATE-VALUE")
    assert runner.run() == entry.EXIT_RUNTIME
    assert runner.calls == []


def test_runner_fails_closed_when_plan_cannot_be_sealed(runner):
    log = []
    result = runner.run(workspace_factory=lambda parent: Workspace(parent, log, fail=True))
    assert result == entry.EXIT_RUNTIME
    assert [command[2] for command, _ in runner.calls] == ["init", "plan"]


def test_runner_rejects_symlinked_module_copy(runner, tmp_path):
    (runner.artifact / ".terraform/modules/link").symlink_to(tmp_path)
    assert runner.run() == entry.EXIT_RUNTIME
    assert runner.calls == []


def test_runner_reports_only_constant_plan_rejection_reason(runner, capsys):
    runner.validate.side_effect = CheckpointPlanError("Invalid Check Point plan variables")
    assert runner.run() == entry.EXIT_PLAN
    err = capsys.readouterr().err
    assert err.strip() == "checkpoint-runner exit=40 reason=Invalid Check Point plan variables"
    runner.validate.side_effect = ValueError(SIC)
    assert runner.run() == entry.EXIT_PLAN
    err = capsys.readouterr().err
    assert SIC not in err and PASSWORD not in err and err.strip() == "checkpoint-runner exit=40"


def test_runner_configures_after_infrastructure_and_reports_constant_reason(runner, capsys):
    assert runner.run() == entry.EXIT_OK and len(runner.configured) == 1

    def fail(_inputs):
        raise entry.CheckpointGaiaError("Gateway SIC was not established")

    assert runner.run(configure=fail) == entry.EXIT_CONFIGURE
    assert "exit=50 reason=Gateway SIC was not established" in capsys.readouterr().err


def test_runner_does_not_configure_when_the_plan_is_rejected(runner):
    runner.validate.side_effect = entry.CheckpointPlanError("Unexpected Check Point plan resources")
    assert runner.run() == entry.EXIT_PLAN and runner.configured == []
