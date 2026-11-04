targetScope = 'resourceGroup'

param location string = 'centralus'
param runId string
@description('Public-client application used for the provider administrator device-code consent flow.')
param bootstrapApplicationId string
@description('Object ID of the user who initiated the subscription deployment.')
param administratorObjectId string
@description('Tenant ID of the user who initiated the subscription deployment.')
param administratorTenantId string
@description('Provider-owned account containing the immutable release ZIP and private installer artifacts.')
param releaseStorageAccountName string
param releaseStorageResourceGroupName string
@minLength(64)
@maxLength(64)
param codePackageSha256 string
@minLength(64)
@maxLength(64)
param providerTemplateSha256 string

var suffix = uniqueString(resourceGroup().id)
var setupName = 'faas-setup-${suffix}'
var managementName = 'faas-mgmt-${suffix}'
var codePackageUri = 'https://${releaseStorageAccountName}.blob.${environment().suffixes.storage}/deployment-artifacts/releases/${codePackageSha256}/apps.zip'
var tags = { purpose: 'provider-setup', labRun: runId }

resource network 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: 'vnet-faas-setup'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: ['10.247.0.0/24'] }
    subnets: [
      {
        name: 'integration'
        properties: {
          addressPrefix: '10.247.0.0/26'
          delegations: [{ name: 'web', properties: { serviceName: 'Microsoft.Web/serverFarms' } }]
        }
      }
      { name: 'private-endpoints', properties: { addressPrefix: '10.247.0.64/27' } }
    ]
  }
}
resource state 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  //checkov:skip=CKV_AZURE_36:Private Table endpoint with disabled public access deliberately has no trusted-services bypass.
  //checkov:skip=CKV_AZURE_43:stsetup plus the 13 lowercase alphanumeric uniqueString characters is a valid account name.
  //checkov:skip=CKV_AZURE_206:Disposable lab setup state uses LRS; disaster recovery is outside this PoC.
  name: 'stsetup${suffix}'
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    publicNetworkAccess: 'Disabled'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    networkAcls: { defaultAction: 'Deny', bypass: 'None' }
  }
}
resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: state
  name: 'default'
}
resource setupTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: 'Bootstrap'
}
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kvsetup-${suffix}'
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    enablePurgeProtection: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: 'Disabled'
    networkAcls: { defaultAction: 'Deny', bypass: 'None' }
  }
}
var privateLinks = [
  { name: 'table', target: state.id, zone: 'privatelink.table.${environment().suffixes.storage}' }
  { name: 'vault', target: vault.id, zone: 'privatelink.vaultcore.azure.net' }
]
resource zones 'Microsoft.Network/privateDnsZones@2024-06-01' = [for link in privateLinks: {
  name: link.zone
  location: 'global'
  tags: tags
}]
resource dnsLinks 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [for (link, i) in privateLinks: {
  parent: zones[i]
  name: 'setup'
  location: 'global'
  properties: { registrationEnabled: false, virtualNetwork: { id: network.id } }
}]
resource privateEndpoints 'Microsoft.Network/privateEndpoints@2025-05-01' = [for link in privateLinks: {
  name: 'pe-faas-setup-${link.name}'
  location: location
  tags: tags
  properties: {
    subnet: { id: '${network.id}/subnets/private-endpoints' }
    privateLinkServiceConnections: [{
      name: link.name
      properties: { privateLinkServiceId: link.target, groupIds: [link.name] }
    }]
  }
}]
resource zoneGroups 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2025-05-01' = [for (link, i) in privateLinks: {
  parent: privateEndpoints[i]
  name: 'default'
  properties: { privateDnsZoneConfigs: [{ name: link.name, properties: { privateDnsZoneId: zones[i].id } }] }
}]
resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  //checkov:skip=CKV_AZURE_225:Single-instance lab setup uses Basic B1 and is not a production HA service.
  name: 'plan-faas-setup'
  location: location
  tags: tags
  kind: 'linux'
  sku: { name: 'B1', tier: 'Basic', capacity: 1 }
  properties: { reserved: true }
}
resource app 'Microsoft.Web/sites@2023-12-01' = {
  //checkov:skip=CKV_AZURE_222:Setup page must be publicly reachable; privileged actions require explicit provider Entra sign-in and consent.
  //checkov:skip=CKV_AZURE_212:Single-instance B1 lab setup is not production HA.
  //checkov:skip=CKV_AZURE_17:Administrator authorization uses Entra device-code OAuth, not incoming client certificates.
  //checkov:skip=CKV_AZURE_18:HTTP/2 is explicitly enabled on the owning application.
  name: setupName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    virtualNetworkSubnetId: '${network.id}/subnets/integration'
    vnetRouteAllEnabled: true
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      appCommandLine: 'bash startup-provider-setup.sh'
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      http20Enabled: true
      healthCheckPath: '/healthz'
      scmIpSecurityRestrictionsUseMain: false
      scmIpSecurityRestrictionsDefaultAction: 'Deny'
      scmIpSecurityRestrictions: []
      appSettings: [
        { name: 'WEBSITE_DNS_SERVER', value: '168.63.129.16' }
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
        { name: 'FAAS_SETUP_TENANT_ID', value: tenant().tenantId }
        { name: 'FAAS_SETUP_SUBSCRIPTION_ID', value: subscription().subscriptionId }
        { name: 'FAAS_SETUP_CLIENT_ID', value: bootstrapApplicationId }
        { name: 'FAAS_SETUP_ADMINISTRATOR_ID', value: administratorObjectId }
        { name: 'FAAS_SETUP_ADMINISTRATOR_TENANT_ID', value: administratorTenantId }
        { name: 'FAAS_SETUP_ORIGIN', value: 'https://${setupName}.azurewebsites.net' }
        { name: 'FAAS_SETUP_MANAGEMENT_ORIGIN', value: 'https://${managementName}.azurewebsites.net' }
        { name: 'FAAS_SETUP_TABLE_ENDPOINT', value: state.properties.primaryEndpoints.table }
        { name: 'FAAS_SETUP_VAULT_URL', value: vault.properties.vaultUri }
        { name: 'FAAS_SETUP_VAULT_NAME', value: vault.name }
        { name: 'FAAS_SETUP_VAULT_GROUP', value: resourceGroup().name }
        { name: 'FAAS_SETUP_RELEASE_ACCOUNT_URL', value: 'https://${releaseStorageAccountName}.blob.${environment().suffixes.storage}' }
        { name: 'FAAS_SETUP_RELEASE_GROUP', value: releaseStorageResourceGroupName }
        { name: 'FAAS_SETUP_PACKAGE_URI', value: codePackageUri }
        { name: 'FAAS_SETUP_PACKAGE_SHA256', value: codePackageSha256 }
        { name: 'FAAS_SETUP_TEMPLATE_SHA256', value: providerTemplateSha256 }
      ]
    }
  }
}
resource scmPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: app
  name: 'scm'
  properties: { allow: false }
}
resource ftpPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: app
  name: 'ftp'
  properties: { allow: false }
}
resource tableRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: setupTable
  name: guid(setupTable.id, app.id, 'setup-state')
  properties: {
    principalId: app.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3')
  }
}
resource vaultRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, app.id, 'setup-secrets')
  properties: {
    principalId: app.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
  }
}
output setupUrl string = 'https://${app.properties.defaultHostName}'
output appName string = app.name
output principalId string = app.identity.principalId
