targetScope = 'resourceGroup'

@allowed(['centralus'])
param location string = 'centralus'
param runId string
@description('Provider publishing operator, NEVER the API-only customer client.')
param publisherPrincipalId string
@allowed(['User', 'ServicePrincipal'])
param publisherPrincipalType string

resource artifacts 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  //checkov:skip=CKV_AZURE_35:External ARM/wizard downloaders need public routing; private blobs, disabled shared keys and read-only user-delegation SAS still enforce authentication.
  //checkov:skip=CKV_AZURE_59:Dedicated authenticated artifact downloads require external reachability; anonymous blob access and shared keys are explicitly disabled and verified.
  //checkov:skip=CKV_AZURE_36:No trusted-services bypass is needed; every request requires Entra or a read-only user-delegation SAS.
  //checkov:skip=CKV_AZURE_43:stfaasart plus uniqueString is a globally unique 22-character lowercase alphanumeric name.
  //checkov:skip=CKV_AZURE_206:Approved disposable provider artifact host uses LRS; it is not the Operations state account.
  name: 'stfaasart${uniqueString(resourceGroup().id)}'
  location: location
  tags: { purpose: 'provider-provisioning', labRun: runId, SecurityControl: 'Ignore' }
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    defaultToOAuthAuthentication: true
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    networkAcls: { defaultAction: 'Allow', bypass: 'None' }
  }
}
resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: artifacts
  name: 'default'
  properties: {
    cors: {
      corsRules: [{
        allowedOrigins: ['https://portal.azure.com']
        allowedMethods: ['GET', 'HEAD', 'OPTIONS']
        allowedHeaders: ['*']
        exposedHeaders: ['Content-Type', 'ETag']
        maxAgeInSeconds: 300
      }]
    }
    isVersioningEnabled: true
    deleteRetentionPolicy: { enabled: true, days: 7 }
    containerDeleteRetentionPolicy: { enabled: true, days: 7 }
  }
}
resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobs
  name: 'deployment-artifacts'
  properties: { publicAccess: 'None' }
}
resource publisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(artifacts.id, publisherPrincipalId, 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  scope: artifacts
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: publisherPrincipalId
    principalType: publisherPrincipalType
  }
}

output accountName string = artifacts.name
output blobEndpoint string = artifacts.properties.primaryEndpoints.blob
output containerName string = container.name
output accountId string = artifacts.id
