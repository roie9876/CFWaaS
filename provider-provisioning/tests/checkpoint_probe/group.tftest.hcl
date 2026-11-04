mock_provider "azurerm" {
  mock_data "azurerm_subnet" {
    defaults = {
      address_prefixes = ["172.22.10.0/24"]
    }
  }
}
mock_provider "azapi" {}
mock_provider "random" {}

run "existing_group" {
  command = plan

  override_data {
    target = module.management.module.vnet.data.azurerm_subnet.frontend[0]
    values = {
      id               = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Network/virtualNetworks/vnet-cp-security-00000000/subnets/management"
      address_prefixes = ["172.22.30.0/24"]
    }
  }

  override_data {
    target = module.gateway.module.vnet.data.azurerm_subnet.frontend[0]
    values = {
      id               = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Network/virtualNetworks/vnet-cp-security-00000000/subnets/firewall-frontend"
      address_prefixes = ["172.22.10.0/24"]
    }
  }

  override_data {
    target = module.gateway.module.vnet.data.azurerm_subnet.backend[0]
    values = {
      id               = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Network/virtualNetworks/vnet-cp-security-00000000/subnets/firewall-backend"
      address_prefixes = ["172.22.20.0/24"]
    }
  }

  assert {
    condition     = module.management.resource_group_id == "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003"
    error_message = "Management must use the existing group."
  }

  assert {
    condition     = module.gateway.resource_group_id == "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003"
    error_message = "Gateway must use the existing group."
  }
}
