from dataclasses import replace

from .auth import Owner
from .config import Customer, Settings
from .enrollment import CustomerBinding, EnrollmentRegistry
from .store import Backend, DomainError, Store


class CustomerStores:
    def __init__(self, backend: Backend, settings: Settings,
                 registry: EnrollmentRegistry) -> None:
        self.backend, self.settings, self.registry = backend, settings, registry

    def bound(self, binding: CustomerBinding) -> Store:
        settings = replace(
            self.settings,
            customer=Customer(binding.tenant, binding.principal, binding.client),
            customer_allocation_key=binding.allocation_key or binding.tenant,
        )
        return Store(self.backend, settings)

    def for_owner(self, owner: Owner) -> Store:
        binding = self.registry.lookup(owner.client, owner.principal)
        if binding is None or binding.tenant != owner.tenant:
            raise DomainError(404, "NotFound")
        return self.bound(binding)
