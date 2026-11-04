from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from service.provider_bootstrap import BootstrapError
from service.provider_bootstrap_vault import ProviderBootstrapVault


MANAGEMENT = "faas-mgmt-" + "b" * 32
SSH = "faas-ssh-" + "c" * 24


def secret(name=MANAGEMENT, version="a" * 32, value="unit-value"):
    return SimpleNamespace(name=name, value=value, properties=SimpleNamespace(version=version))


def test_vault_writes_and_verifies_only_exact_version_without_logging_values():
    client = Mock()
    client.set_secret.return_value = secret()
    client.get_secret.return_value = secret()
    vault = ProviderBootstrapVault(client)
    version = vault.write(MANAGEMENT, "unit-value", "2099-01-01T00:00:00+00:00")
    vault.verify(MANAGEMENT, version)
    assert version == "a" * 32
    assert client.set_secret.call_args.kwargs["expires_on"] == datetime(2099, 1, 1, tzinfo=timezone.utc)
    assert client.set_secret.call_args.kwargs["logging_enable"] is False
    assert client.set_secret.call_args.kwargs["retry_total"] == 0
    client.get_secret.assert_called_once_with(MANAGEMENT, version,
                                              logging_enable=False, retry_total=0)


@pytest.mark.parametrize("name", ["other", "", "customer-000", "../provider-nva-ssh"])
def test_vault_refuses_unrelated_secret_names_without_io(name):
    client = Mock()
    vault = ProviderBootstrapVault(client)
    with pytest.raises(BootstrapError):
        vault.write(name, "unit-value")
    with pytest.raises(BootstrapError):
        vault.verify(name, "a" * 32)
    client.set_secret.assert_not_called()
    client.get_secret.assert_not_called()


def test_vault_failures_never_expose_secret_and_never_blindly_retry(caplog):
    client = Mock()
    client.set_secret.side_effect = RuntimeError("unit-private-data-never-log")
    vault = ProviderBootstrapVault(client)
    with pytest.raises(BootstrapError) as error:
        vault.write(SSH, "unit-private-data-never-log")
    assert error.value.code == "BootstrapVaultWriteFailed"
    assert "unit-private-data-never-log" not in str(error.value)
    assert "unit-private-data-never-log" not in caplog.text
    assert client.set_secret.call_count == 1


def test_vault_detects_wrong_version_and_missing_value():
    client = Mock()
    client.get_secret.return_value = secret(version="b" * 32)
    vault = ProviderBootstrapVault(client)
    with pytest.raises(BootstrapError) as error:
        vault.verify(MANAGEMENT, "a" * 32)
    assert error.value.code == "BootstrapVaultVerificationFailed"
    client.get_secret.return_value = secret(value="")
    with pytest.raises(BootstrapError):
        vault.verify(MANAGEMENT, "a" * 32)
