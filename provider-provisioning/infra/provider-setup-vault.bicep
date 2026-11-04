targetScope = 'resourceGroup'
param location string = 'centralus'
param runId string
param vaultName string
param administratorObjectId string

var tags = { purpose: 'provider-release-bootstrap', labRun: runId }
resource network 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: 'vnet-faas-release-private'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: ['10.247.0.0/24'] }
    subnets: [{ name: 'private-endpoints', properties: { addressPrefix: '10.247.0.0/27' } }]
  }
}
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
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
resource zone 'Microsoft.Network/privateDnsZones@2024-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
  tags: tags
}
resource zoneLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = {
  parent: zone
  name: 'provider-release'
  location: 'global'
  properties: { registrationEnabled: false, virtualNetwork: { id: network.id } }
}
resource endpoint 'Microsoft.Network/privateEndpoints@2025-05-01' = {
  name: 'pe-faas-release-vault'
  location: location
  tags: tags
  properties: {
    subnet: { id: '${network.id}/subnets/private-endpoints' }
    privateLinkServiceConnections: [{
      name: 'vault'
      properties: { privateLinkServiceId: vault.id, groupIds: ['vault'] }
    }]
  }
}
resource zoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2025-05-01' = {
  parent: endpoint
  name: 'default'
  properties: { privateDnsZoneConfigs: [{ name: 'vault', properties: { privateDnsZoneId: zone.id } }] }
}
resource administrator 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, administratorObjectId, 'bootstrap-secret-read')
  properties: {
    principalId: administratorObjectId
    principalType: 'User'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
  }
}
output vaultId string = vault.id
output vaultUri string = vault.properties.vaultUri
