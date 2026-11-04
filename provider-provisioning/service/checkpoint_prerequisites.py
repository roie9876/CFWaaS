"""Provider-only, read-only prerequisites for the experimental Check Point path."""
from typing import Callable

from azure.core.credentials import TokenCredential
from azure.core.exceptions import AzureError
from azure.mgmt.resource import ResourceManagementClient

from .config import uuid_text


REQUIRED_PROVIDERS = (
    "Microsoft.Compute",
    "Microsoft.Network",
    "Microsoft.Storage",
    "Microsoft.KeyVault",
    "Microsoft.ContainerInstance",
    "Microsoft.ManagedIdentity",
    "Microsoft.Solutions",
)


class CheckpointPrerequisiteError(Exception):
    def __init__(self, code: str, provider: str | None = None) -> None:
        self.code, self.provider = code, provider
        super().__init__(code)


class CheckpointProviderRegistration:
    def __init__(self, provider_subscription: str, credential: TokenCredential) -> None:
        self.subscription = uuid_text(provider_subscription)
        self.client = ResourceManagementClient(
            credential, self.subscription, logging_enable=False,
            retry_total=0, connection_timeout=5, read_timeout=20)

    def verify(self, check: Callable[[], None]) -> None:
        for namespace in REQUIRED_PROVIDERS:
            check()
            try:
                provider = self.client.providers.get(namespace)
            except AzureError:
                raise CheckpointPrerequisiteError("ProviderRegistrationUnavailable", namespace) from None
            observed_name = getattr(provider, "namespace", None)
            observed_state = getattr(provider, "registration_state", None)
            if (not isinstance(observed_name, str) or observed_name.lower() != namespace.lower()
                    or not isinstance(observed_state, str)):
                raise CheckpointPrerequisiteError("ProviderRegistrationInvalid", namespace)
            if observed_state != "Registered":
                raise CheckpointPrerequisiteError("ProviderNotRegistered", namespace)
        check()

    def close(self) -> None:
        self.client.close()
