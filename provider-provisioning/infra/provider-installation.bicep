targetScope = 'subscription'

@minLength(3)
@maxLength(20)
param namePrefix string = 'faas-admin'
param runId string
param controlResourceGroupName string
param dataResourceGroupName string
@description('Prepare identities for isolated provider environments without activating them.')
param prepareIsolatedEnvironments bool = false
@description('Acknowledge subscription-wide group write and constrained Contributor delegation.')
param approveEnvironmentDelegation bool = false
@allowed(['centralus'])
param controlLocation string = 'centralus'
param apiApplicationId string
param apiRoleId string
param managementApplicationId string
@description('Optional reserved management web app name for a preconfigured Entra callback.')
param managementAppName string = ''
@secure()
param managementApplicationSecret string
@description('Private setup vault containing the guided-installation credential; empty for the manual installer.')
param setupVaultResourceGroupName string = ''
param setupVaultName string = ''
param managementSecretName string = ''
param managementSecretVersion string = ''
param managementCredentialExpiresOn string
@description('Provider administrator user object IDs, not customer identities.')
@minLength(1)
@maxLength(50)
param administratorObjectIds array
@description('Provider simulator SSH PUBLIC key. No private key or password.')
param nvaSshPublicKey string
@minValue(0)
@description('Deprecated and ignored; retained for compatibility with existing deployments.')
param providerEnvironmentLimit int = 0
@minLength(64)
@maxLength(64)
param providerTemplateSha256 string
@description('Provider release package URL. The installer uses its managed identity for an unsigned private blob, or an explicitly supplied read-only user-delegation SAS.')
@secure()
param codePackageUri string
@minLength(64)
@maxLength(64)
param codePackageSha256 string
@description('Provider-owned release account and RG. Leave empty when an explicitly supplied read-only SAS is used.')
param releaseStorageAccountName string = ''
param releaseStorageResourceGroupName string = ''
@description('Explicit exception: the Azure-hosted installer uses its own public-route, shared-key backing storage. Operations and credential vaults stay private.')
@allowed([true])
param approveDeploymentScriptBackingException bool

var tags = { purpose: 'provider-provisioning', labRun: runId }
resource control 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: controlResourceGroupName
  location: controlLocation
  tags: tags
}
resource dataplane 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: dataResourceGroupName
  location: 'eastus2'
  tags: tags
}
module platform 'main.bicep' = {
  name: 'provider-control-platform'
  scope: control
  params: {
    location: controlLocation
    namePrefix: namePrefix
    runId: runId
    providerDataPlaneResourceGroupId: dataplane.id
    trustedTenantId: tenant().tenantId
    trustedPrincipalId: apiApplicationId
    trustedClientId: apiApplicationId
    apiAuthMode: 'provider-api-registry'
    apiAudience: apiApplicationId
    maxEnvironments: providerEnvironmentLimit
    nvaSshPublicKey: nvaSshPublicKey
    providerTemplateSha256: providerTemplateSha256
    approveScmBootstrapException: false
    prepareIsolatedEnvironments: prepareIsolatedEnvironments
    approveEnvironmentDelegation: approveEnvironmentDelegation
  }
}
module management 'provider-management.bicep' = {
  name: 'provider-management-platform'
  scope: control
  params: {
    location: controlLocation
    runId: runId
    namePrefix: namePrefix
    appServicePlanId: platform.outputs.appServicePlanId
    integrationSubnetId: platform.outputs.integrationSubnetId
    privateEndpointSubnetId: platform.outputs.privateEndpointSubnetId
    vaultPrivateDnsZoneId: platform.outputs.vaultPrivateDnsZoneId
    customersTableId: platform.outputs.customersTableId
    tableEndpoint: platform.outputs.tableEndpoint
    apiUrl: platform.outputs.apiUrl
    apiApplicationId: apiApplicationId
    apiRoleId: apiRoleId
    managementApplicationId: managementApplicationId
    providerDataPlaneResourceGroupId: dataplane.id
    managementAppName: managementAppName
    managementApplicationSecret: managementApplicationSecret
    setupVaultResourceGroupName: setupVaultResourceGroupName
    setupVaultName: setupVaultName
    managementSecretName: managementSecretName
    managementSecretVersion: managementSecretVersion
    managementCredentialExpiresOn: managementCredentialExpiresOn
    administratorObjectIds: administratorObjectIds
  }
}
module setupCredentialAccess 'provider-setup-management-access.bicep' = if (!empty(setupVaultName)) {
  name: 'provider-setup-management-access'
  scope: resourceGroup(setupVaultResourceGroupName)
  params: {
    vaultName: setupVaultName
    secretName: managementSecretName
    managementPrincipalId: management.outputs.principalId
  }
}
module artifacts 'provider-artifacts.bicep' = {
  name: 'provider-artifact-platform'
  scope: control
  params: {
    location: controlLocation
    runId: runId
    publisherPrincipalId: management.outputs.principalId
    publisherPrincipalType: 'ServicePrincipal'
  }
}
module publisher 'provider-publisher-identity.bicep' = {
  name: 'provider-publisher-identity'
  scope: control
  params: { location: controlLocation, runId: runId }
}
module releaseAccess 'provider-release-access.bicep' = if (!empty(releaseStorageAccountName) && !empty(releaseStorageResourceGroupName)) {
  name: 'provider-release-package-reader'
  scope: resourceGroup(releaseStorageResourceGroupName)
  params: {
    storageAccountName: releaseStorageAccountName
    publisherPrincipalId: publisher.outputs.principalId
  }
}
module publication 'provider-installation-code.bicep' = {
  name: 'provider-application-publication'
  scope: control
  params: {
    location: controlLocation
    runId: runId
    appNames: [platform.outputs.apiAppName, platform.outputs.workerAppName, management.outputs.appName]
    codePackageUri: codePackageUri
    codePackageSha256: codePackageSha256
    publisherIdentityId: publisher.outputs.id
    releaseStorageAccountName: releaseStorageAccountName
    approveDeploymentScriptBackingException: approveDeploymentScriptBackingException
  }
  dependsOn: [artifacts, releaseAccess, setupCredentialAccess]
}
output managementUrl string = management.outputs.managementUrl
output entraRedirectUri string = management.outputs.redirectUri
output provisioningApiUrl string = platform.outputs.apiUrl
output codePublicationStatus string = publication.outputs.status
