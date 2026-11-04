targetScope = 'resourceGroup'

@description('Provider-only release resource group that holds the private bootstrap vault and package.')
param releaseStorageResourceGroupName string
param releaseStorageAccountName string
@description('Resource group containing the private bootstrap Key Vault.')
param setupVaultResourceGroupName string
param setupVaultName string
@description('Unique management credential secret name created by the verified setup.')
param managementSecretName string
@description('Verified Key Vault version of the management credential.')
param managementSecretVersion string
param apiApplicationId string
param apiRoleId string
param managementApplicationId string
param managementAppName string
param managementCredentialExpiresOn string
param administratorObjectIds array
param nvaSshPublicKey string
param codePackageSha256 string
param providerTemplateSha256 string
@secure()
param codePackageUri string
param runId string = 'faas-admin-installation'
param namePrefix string = 'faas-admin'
param dataResourceGroupName string = 'rg-faas-admin-data'
param prepareIsolatedEnvironments bool = false
param approveEnvironmentDelegation bool = false
@allowed([true])
param approveDeploymentScriptBackingException bool

module installer 'provider-installation.bicep' = {
  name: 'guided-provider-installation'
  scope: subscription()
  params: {
    namePrefix: namePrefix
    runId: runId
    controlResourceGroupName: resourceGroup().name
    dataResourceGroupName: dataResourceGroupName
    prepareIsolatedEnvironments: prepareIsolatedEnvironments
    approveEnvironmentDelegation: approveEnvironmentDelegation
    apiApplicationId: apiApplicationId
    apiRoleId: apiRoleId
    managementApplicationId: managementApplicationId
    managementAppName: managementAppName
    managementApplicationSecret: ''
    setupVaultResourceGroupName: setupVaultResourceGroupName
    setupVaultName: setupVaultName
    managementSecretName: managementSecretName
    managementSecretVersion: managementSecretVersion
    managementCredentialExpiresOn: managementCredentialExpiresOn
    administratorObjectIds: administratorObjectIds
    nvaSshPublicKey: nvaSshPublicKey
    codePackageUri: codePackageUri
    codePackageSha256: codePackageSha256
    providerTemplateSha256: providerTemplateSha256
    releaseStorageAccountName: releaseStorageAccountName
    releaseStorageResourceGroupName: releaseStorageResourceGroupName
    approveDeploymentScriptBackingException: approveDeploymentScriptBackingException
  }
}

output managementUrl string = installer.outputs.managementUrl
output entraRedirectUri string = installer.outputs.entraRedirectUri
output provisioningApiUrl string = installer.outputs.provisioningApiUrl
output codePublicationStatus string = installer.outputs.codePublicationStatus
