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
  command = apply

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
  override_resource {
    target = module.gateway.azurerm_public_ip.public_ip
    values = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Network/publicIPAddresses/cp-gateway-00000000" }
  }
  override_resource {
    target = module.management.azurerm_public_ip.public_ip
    values = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Network/publicIPAddresses/cp-management-00000000" }
  }
  override_resource {
    target = module.gateway.azurerm_network_interface.nic
    values = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Network/networkInterfaces/cp-gateway-00000000-eth0" }
  }
  override_resource {
    target = module.gateway.azurerm_network_interface.nic1
    values = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Network/networkInterfaces/cp-gateway-00000000-eth1" }
  }
  override_resource {
    target = module.management.azurerm_network_interface.nic
    values = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Network/networkInterfaces/cp-management-00000000-eth0" }
  }
  override_resource {
    target = module.gateway.azurerm_virtual_machine.single_gateway_vm_instance[0]
    values = {
      id              = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Compute/virtualMachines/cp-gateway-00000000"
      identity        = { tenant_id = "00000000-0000-0000-0000-000000000002", principal_id = "00000000-0000-0000-0000-000000000006" }
      storage_os_disk = { managed_disk_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Compute/disks/cp-gateway-00000000" }
    }
  }
  override_resource {
    target = module.management.azurerm_virtual_machine.mgmt_vm_instance
    values = {
      id              = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Compute/virtualMachines/cp-management-00000000"
      identity        = { tenant_id = "00000000-0000-0000-0000-000000000002", principal_id = "00000000-0000-0000-0000-000000000007" }
      storage_os_disk = { managed_disk_id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Compute/disks/cp-management-00000000" }
    }
  }
  override_resource {
    target = module.gateway.azurerm_network_interface_security_group_association.security_group_association
    values = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Network/networkInterfaces/cp-gateway-00000000-eth0|/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Network/networkSecurityGroups/nsg-cp-firewall-00000000" }
  }
  override_resource {
    target = module.management.azurerm_network_interface_security_group_association.security_group_association
    values = { id = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Network/networkInterfaces/cp-management-00000000-eth0|/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-faas-env-00000000-0000-0000-0000-000000000003/providers/Microsoft.Network/networkSecurityGroups/nsg-cp-management-00000000" }
  }
}
