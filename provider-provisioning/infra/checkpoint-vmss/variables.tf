variable "provider_subscription_id" {
  type = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", var.provider_subscription_id))
    error_message = "Use a canonical provider subscription ID."
  }
}

variable "provider_tenant_id" {
  type = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", var.provider_tenant_id))
    error_message = "Use a canonical provider tenant ID."
  }
}

variable "provider_managed_identity_client_id" {
  type = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", var.provider_managed_identity_client_id))
    error_message = "Use a canonical provider managed-identity client ID."
  }
}

variable "provider_group_id" {
  type = string

  validation {
    condition = can(regex(
      "(?i)^/subscriptions/${var.provider_subscription_id}/resourcegroups/rg-faas-env-[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$",
      var.provider_group_id
    ))
    error_message = "Use an isolated environment group in the provider subscription."
  }
}

variable "environment_id" {
  type = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$", var.environment_id))
    error_message = "Use a canonical environment ID."
  }
}

variable "provider_admin_ssh_public_key" {
  type = string

  validation {
    condition = can(regex(
      "^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256) [A-Za-z0-9+/]+={0,3}( .*)?$",
      var.provider_admin_ssh_public_key
    ))
    error_message = "A supported provider administrator SSH public key is required."
  }
}

variable "sic_key" {
  type      = string
  sensitive = true

  validation {
    condition     = length(var.sic_key) >= 12
    error_message = "A Check Point SIC key of at least 12 characters is required."
  }
}

variable "management_admin_password" {
  type      = string
  sensitive = true

  validation {
    condition = (
      length(var.management_admin_password) >= 16
      && length(var.management_admin_password) <= 72
      && can(regex("^[A-Za-z0-9!@#%_+-]+$", var.management_admin_password))
      && can(regex("[A-Z]", var.management_admin_password))
      && can(regex("[a-z]", var.management_admin_password))
      && can(regex("[0-9]", var.management_admin_password))
      && can(regex("[!@#%_+-]", var.management_admin_password))
    )
    error_message = "Use an ASCII management password with uppercase, lowercase, a digit and a supported special character."
  }
}

variable "gateway_image_version" {
  type = string

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.gateway_image_version))
    error_message = "Use an explicit Marketplace image version."
  }
}

variable "management_image_version" {
  type = string

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.management_image_version))
    error_message = "Use an explicit Marketplace image version."
  }
}

variable "gateway_vm_size" {
  type = string
}

variable "management_vm_size" {
  type = string
}
