targetScope = 'resourceGroup'
@description('Customer UAMI object ID. Deploy ONLY to the pre-created customer dataplane resource group.')
param principalId string
// Network Contributor includes Microsoft.Resources/deployments/* as well as Microsoft.Network/*.
// It grants no customer compute operations and no provider permissions.
resource connector 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, principalId, 'customer-network-connector')
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4d97b98b-1d4f-4787-a291-c67834d212e7')
  }
}
