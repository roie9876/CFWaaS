targetScope = 'resourceGroup'
@allowed(['eastus2'])
param location string = 'eastus2'
param runId string
param identityName string
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityName
  location: location
  tags: { purpose: 'provider-provisioning-customer-auth', labRun: runId }
}
output identityId string = identity.id
output principalId string = identity.properties.principalId
output clientId string = identity.properties.clientId
