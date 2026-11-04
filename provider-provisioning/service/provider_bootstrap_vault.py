"""Private Key Vault adapter for provider setup material."""
import logging
import re
from datetime import datetime

from azure.keyvault.secrets import SecretClient

from .provider_bootstrap import BootstrapError

logger = logging.getLogger("faas.provider-bootstrap-vault")


class ProviderBootstrapVault:
    NAME_PATTERN = re.compile(r"(?:faas-mgmt-[a-f0-9]{32}|faas-ssh-[a-f0-9]{24})")

    def __init__(self, client: SecretClient) -> None:
        self.client = client

    def write(self, name: str, value: str, expires_at: str | None = None) -> str:
        if (not isinstance(name, str) or not self.NAME_PATTERN.fullmatch(name)
                or not isinstance(value, str) or not 1 <= len(value) <= 25000):
            raise BootstrapError(400, "BootstrapVaultInputInvalid")
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00")) if expires_at else None
            if expiry is not None and expiry.tzinfo is None:
                raise ValueError("Expiry must include a timezone")
            result = self.client.set_secret(name, value, expires_on=expiry, logging_enable=False,
                                            retry_total=0)
            version = result.properties.version
            if result.name != name or not isinstance(version, str) or not re.fullmatch(r"[a-f0-9]{32}", version):
                raise ValueError("Unexpected Key Vault version")
            return version
        except (TypeError, ValueError):
            raise BootstrapError(502, "BootstrapVaultWriteFailed") from None
        except Exception as error:
            logger.warning("code=BootstrapVaultWriteFailed type=%s", type(error).__name__)
            raise BootstrapError(502, "BootstrapVaultWriteFailed") from None

    def verify(self, name: str, version: str) -> None:
        if (not isinstance(name, str) or not self.NAME_PATTERN.fullmatch(name)
                or not isinstance(version, str) or not re.fullmatch(r"[a-f0-9]{32}", version)):
            raise BootstrapError(400, "BootstrapVaultInputInvalid")
        try:
            result = self.client.get_secret(name, version, logging_enable=False, retry_total=0)
            if result.name != name or result.properties.version != version or not result.value:
                raise ValueError("Unexpected Key Vault secret")
        except (TypeError, ValueError):
            raise BootstrapError(502, "BootstrapVaultVerificationFailed") from None
        except Exception as error:
            logger.warning("code=BootstrapVaultVerificationFailed type=%s", type(error).__name__)
            raise BootstrapError(502, "BootstrapVaultVerificationFailed") from None
