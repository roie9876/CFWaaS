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

module "gateway" {
  source = "./modules/single-gateway"

  subscription_id                 = var.provider_subscription_id
  tenant_id                       = var.provider_tenant_id
  resource_group_name             = local.group_name
  faas_existing_resource_group_id = var.provider_group_id
  faas_image_version              = var.gateway_image_version
  single_gateway_name             = "cp-gateway-${local.suffix}"
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
  zone                            = ""
  extended_zone                   = "None"
  enable_ipv6                     = false
  vnet_name                       = local.security_vnet
  existing_vnet_resource_group    = local.group_name
  frontend_subnet_name            = "firewall-frontend"
  backend_subnet_name             = "firewall-backend"
  frontend_private_ip             = "172.22.10.4"
  backend_private_ip              = "172.22.20.4"
  address_space                   = ""
  subnet_prefixes                 = ["172.22.10.0/24", "172.22.20.0/24"]
  management_GUI_client_network   = "172.22.40.0/23"
  nsg_id                          = "${local.network_scope}/networkSecurityGroups/nsg-cp-firewall-${local.suffix}"
  storage_account_deployment_mode = "None"
}

output "managementPrivateIp" {
  value = module.management.private_ip_address
}

output "gatewayFrontendPrivateIp" {
  value = module.gateway.frontend_private_ip_address
}

output "managementVmId" {
  value = module.management.vm_id
}

output "gatewayVmId" {
  value = module.gateway.vm_id
}
