targetScope = 'resourceGroup'

@allowed(['centralus'])
param location string = 'centralus'
param runId string = 'faas-guided-bootstrap'
param bootstrapApplicationId string
param releaseStorageAccountName string
param releaseStorageResourceGroupName string
@minLength(64)
@maxLength(64)
param codePackageSha256 string
@minLength(64)
@maxLength(64)
param providerTemplateSha256 string
@description('The setup publisher uses temporary Azure-hosted execution and a separate shared-key backing storage account.')
@allowed([true])
param approveDeploymentScriptBackingException bool

var packageUri = 'https://${releaseStorageAccountName}.blob.${environment().suffixes.storage}/deployment-artifacts/releases/${codePackageSha256}/apps.zip'
module host 'provider-setup-host.bicep' = {
  name: 'provider-setup-host'
  params: {
    location: location
    runId: runId
    bootstrapApplicationId: bootstrapApplicationId
    administratorObjectId: deployer().objectId
    administratorTenantId: deployer().tenantId
    releaseStorageAccountName: releaseStorageAccountName
    releaseStorageResourceGroupName: releaseStorageResourceGroupName
    codePackageSha256: codePackageSha256
    providerTemplateSha256: providerTemplateSha256
  }
}
module setupAccess 'provider-setup-release-access.bicep' = {
  name: 'provider-setup-release-access'
  scope: resourceGroup(releaseStorageResourceGroupName)
  params: {
    storageAccountName: releaseStorageAccountName
    setupPrincipalId: host.outputs.principalId
  }
}
module publisher 'provider-publisher-identity.bicep' = {
  name: 'provider-setup-publisher'
  params: { location: location, runId: runId }
}
module releaseAccess 'provider-release-access.bicep' = {
  name: 'provider-setup-package-reader'
  scope: resourceGroup(releaseStorageResourceGroupName)
  params: {
    storageAccountName: releaseStorageAccountName
    publisherPrincipalId: publisher.outputs.principalId
  }
}
module publication 'provider-installation-code.bicep' = {
  name: 'provider-setup-publication'
  params: {
    location: location
    runId: runId
    appNames: [host.outputs.appName]
    codePackageUri: packageUri
    codePackageSha256: codePackageSha256
    publisherIdentityId: publisher.outputs.id
    releaseStorageAccountName: releaseStorageAccountName
    approveDeploymentScriptBackingException: approveDeploymentScriptBackingException
  }
  dependsOn: [setupAccess, releaseAccess]
}
output setupUrl string = host.outputs.setupUrl
output codePublicationStatus string = publication.outputs.status
