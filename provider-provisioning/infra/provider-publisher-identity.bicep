targetScope = 'resourceGroup'
param location string
param runId string
var suffix = uniqueString(resourceGroup().id)
resource publisher 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-provider-publisher-${suffix}'
  location: location
  tags: { purpose: 'provider-provisioning', labRun: runId }
}
resource publishingRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, publisher.id, 'site-publishing')
  properties: {
    principalId: publisher.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'de139f84-1756-47ae-9be6-808fbbe84772')
  }
}
output id string = publisher.id
output principalId string = publisher.properties.principalId
