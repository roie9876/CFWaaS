terraform {
  required_version = "= 1.15.7"

  backend "azurerm" {
    use_azuread_auth = true
    use_msi          = true
  }

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "= 4.73.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "= 2.7.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "= 3.6.3"
    }
    null = {
      source  = "hashicorp/null"
      version = "= 3.3.2"
    }
    modtm = {
      source  = "azure/modtm"
      version = "= 0.4.0"
    }
  }
}

provider "azurerm" {
  subscription_id                 = var.provider_subscription_id
  tenant_id                       = var.provider_tenant_id
  client_id                       = var.provider_managed_identity_client_id
  use_msi                         = true
  resource_provider_registrations = "none"
  features {}
}

provider "azapi" {
  subscription_id = var.provider_subscription_id
  tenant_id       = var.provider_tenant_id
  client_id       = var.provider_managed_identity_client_id
  use_msi         = true
}

provider "modtm" {
  enabled = false
}

locals {
  suffix        = substr(var.environment_id, 0, 8)
  group_name    = reverse(split("/", var.provider_group_id))[0]
  security_vnet = "vnet-cp-security-${local.suffix}"
  network_scope = "${var.provider_group_id}/providers/Microsoft.Network"
}

module "management" {
  source = "./modules/management"

  subscription_id                 = var.provider_subscription_id
  tenant_id                       = var.provider_tenant_id
  resource_group_name             = local.group_name
  faas_existing_resource_group_id = var.provider_group_id
  faas_image_version              = var.management_image_version
  mgmt_name                       = "cp-management-${local.suffix}"
  location                        = "eastus2"
  authentication_type             = "Password"
  admin_password                  = var.management_admin_password
  vm_size                         = var.management_vm_size
  os_version                      = "R82"
  vm_os_sku                       = "mgmt-byol"
  vm_os_offer                     = "check-point-cg-r82"
  allow_upload_download           = false
  zone                            = ""
  enable_ipv6                     = false
  vnet_name                       = local.security_vnet
  existing_vnet_resource_group    = local.group_name
  subnet_name                     = "management"
  address_space                   = ""
  subnet_prefix                   = "172.22.30.0/24"
  management_GUI_client_network   = "172.22.40.0/23"
  mgmt_enable_api                 = "gui_clients"
  nsg_id                          = "${local.network_scope}/networkSecurityGroups/nsg-cp-management-${local.suffix}"
  storage_account_deployment_mode = "None"
}

# Two fixed BYOL gateways: public LB (eth0) and internal HA-ports LB at 172.22.20.4 (eth1).
module "gateway" {
  source = "./modules/vmss"

  subscription_id                 = var.provider_subscription_id
  tenant_id                       = var.provider_tenant_id
  resource_group_name             = local.group_name
  faas_existing_resource_group_id = var.provider_group_id
  faas_image_version              = var.gateway_image_version
  vmss_name                       = "cp-vmss-${local.suffix}"
  location                        = "eastus2"
  authentication_type             = "SSH Public Key"
  admin_SSH_key                   = var.provider_admin_ssh_public_key
  sic_key                         = var.sic_key
  vm_size                         = var.gateway_vm_size
  os_version                      = "R82"
  vm_os_sku                       = "sg-byol"
  vm_os_offer                     = "check-point-cg-r82"
  allow_upload_download           = false
  enable_custom_metrics           = false
  configuration_template_name     = "faas-vmss-${local.suffix}"
  management_name                 = "cp-management-${local.suffix}"
  management_interface            = "eth0-private"
  management_IP                   = "172.22.30.4"
  availability_zones_num          = "0"
  orchestration_mode              = "Uniform"
  number_of_vm_instances          = "2"
  minimum_number_of_vm_instances  = "2"
  maximum_number_of_vm_instances  = "2"
  vnet_name                       = local.security_vnet
  existing_vnet_resource_group    = local.group_name
  frontend_subnet_name            = "firewall-frontend"
  backend_subnet_name             = "firewall-backend"
  address_space                   = ""
  subnet_prefixes                 = ["172.22.10.0/24", "172.22.20.0/24"]
  enable_ipv6                     = false
  nsg_id                          = "${local.network_scope}/networkSecurityGroups/nsg-cp-firewall-${local.suffix}"
  instance_level_public_ipv4      = true
  storage_account_deployment_mode = "None"
  sku                             = "Standard"
  deployment_mode                 = "Standard"
  backend_lb_IP_address           = 4
}

output "managementPrivateIp" {
  value = module.management.private_ip_address
}

output "managementVmId" {
  value = module.management.vm_id
}

output "gatewayScaleSetId" {
  value = module.gateway.vmss_id
}

output "internalLoadBalancerIp" {
  value = module.gateway.backend_lb_private_ip
}

output "publicLoadBalancerIp" {
  value = module.gateway.frontend_lb_public_ip
}
