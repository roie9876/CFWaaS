targetScope = 'resourceGroup'

@description('Experimental private Check Point credential vault and Terraform state. No roles are granted by this template.')
@allowed(['eastus2'])
param location string = 'eastus2'
@minLength(36)
@maxLength(36)
param environmentId string

var suffix = take(environmentId, 8)
var unique = uniqueString(resourceGroup().id, environmentId)
var tags = { purpose: 'provider-provisioning-checkpoint-private-data', environmentId: environmentId }

resource network 'Microsoft.Network/virtualNetworks@2025-05-01' existing = {
  name: 'vnet-cp-security-${suffix}'
}
resource privateSubnet 'Microsoft.Network/virtualNetworks/subnets@2025-05-01' existing = {
  parent: network
  name: 'private-endpoints'
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kvcp${unique}'
  location: location
  tags: tags
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    enablePurgeProtection: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: 'Disabled'
    networkAcls: { defaultAction: 'Deny', bypass: 'None' }
  }
}
resource state 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stcp${unique}'
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    defaultToOAuthAuthentication: true
    publicNetworkAccess: 'Disabled'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    networkAcls: { defaultAction: 'Deny', bypass: 'None' }
  }
}
resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: state
  name: 'default'
  properties: {
    isVersioningEnabled: true
    deleteRetentionPolicy: { enabled: true, days: 7 }
    containerDeleteRetentionPolicy: { enabled: true, days: 7 }
  }
}
resource stateContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'terraform-state'
  properties: { publicAccess: 'None' }
}
var privateLinks = [
  { name: 'vault', target: vault.id, zone: 'privatelink.vaultcore.azure.net' }
  { name: 'blob', target: state.id, zone: 'privatelink.blob.${environment().suffixes.storage}' }
]
resource zones 'Microsoft.Network/privateDnsZones@2024-06-01' = [for link in privateLinks: {
  name: link.zone
  location: 'global'
  tags: tags
}]
resource dnsLinks 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [for (link, i) in privateLinks: {
  parent: zones[i]
  name: 'checkpoint-${suffix}'
  location: 'global'
  tags: tags
  properties: { registrationEnabled: false, virtualNetwork: { id: network.id } }
}]
resource endpoints 'Microsoft.Network/privateEndpoints@2025-05-01' = [for link in privateLinks: {
  name: 'pe-cp-${link.name}-${suffix}'
  location: location
  tags: tags
  properties: {
    subnet: { id: privateSubnet.id }
    privateLinkServiceConnections: [{
      name: link.name
      properties: { privateLinkServiceId: link.target, groupIds: [link.name] }
    }]
  }
}]
resource zoneGroups 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2025-05-01' = [for (link, i) in privateLinks: {
  parent: endpoints[i]
  name: 'default'
  properties: { privateDnsZoneConfigs: [{ name: link.name, properties: { privateDnsZoneId: zones[i].id } }] }
}]

output credentialVaultId string = vault.id
output credentialVaultUri string = vault.properties.vaultUri
output stateStorageId string = state.id
output stateBlobEndpoint string = state.properties.primaryEndpoints.blob
output stateContainerName string = stateContainer.name
output credentialPrivateEndpointId string = endpoints[0].id
output statePrivateEndpointId string = endpoints[1].id
