targetScope = 'resourceGroup'
param storageAccountName string
param publisherPrincipalId string
resource releaseAccount 'Microsoft.Storage/storageAccounts@2023-05-01' existing = {
  name: storageAccountName
}
resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: releaseAccount
  name: guid(releaseAccount.id, publisherPrincipalId, 'release-blob-reader')
  properties: {
    principalId: publisherPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1')
  }
}
