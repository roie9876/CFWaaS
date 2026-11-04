targetScope = 'resourceGroup'
param location string
param runId string
@minLength(1)
@maxLength(3)
param appNames array
@secure()
param codePackageUri string
param codePackageSha256 string
param publisherIdentityId string
param releaseStorageAccountName string = ''
@description('An explicit retry identifier for a previously failed publication; leave empty for normal installation.')
param publicationAttempt string = ''
@allowed([true])
param approveDeploymentScriptBackingException bool

var suffix = uniqueString(resourceGroup().id)
var tags = { purpose: 'provider-provisioning', labRun: runId }
resource backing 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  //checkov:skip=CKV_AZURE_35:Explicitly approved deployment-script backing exception requires public-route Azure Files; Operations remains private.
  //checkov:skip=CKV_AZURE_59:Dedicated bootstrap account uses the user-authorized lab tag exception, shared-key Azure Files, and no anonymous blobs.
  //checkov:skip=CKV_AZURE_43:stfaasboot plus the 13 lowercase alphanumeric uniqueString characters is a valid 23-character account name.
  //checkov:skip=CKV_AZURE_206:Disposable lab installation backing storage uses LRS; disaster recovery is outside this PoC.
  name: 'stfaasboot${suffix}'
  location: location
  tags: union(tags, { SecurityControl: 'Ignore' })
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowSharedKeyAccess: approveDeploymentScriptBackingException
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    networkAcls: { defaultAction: 'Allow', bypass: 'None' }
  }
}
resource install 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'provider-publish-apps'
  location: location
  tags: tags
  kind: 'AzureCLI'
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${publisherIdentityId}': {} } }
  properties: {
    azCliVersion: '2.77.0'
    timeout: 'PT2H'
    cleanupPreference: 'Always'
    retentionInterval: 'P1D'
    forceUpdateTag: '${codePackageSha256}-${publicationAttempt}'
    storageAccountSettings: {
      storageAccountName: backing.name
      storageAccountKey: backing.listKeys().keys[0].value
    }
    environmentVariables: [
      { name: 'FAAS_PACKAGE_URI', secureValue: codePackageUri }
      { name: 'FAAS_PACKAGE_SHA256', value: codePackageSha256 }
      { name: 'FAAS_RELEASE_STORAGE_ACCOUNT', value: releaseStorageAccountName }
      { name: 'FAAS_PROVIDER_SUBSCRIPTION', value: subscription().subscriptionId }
      { name: 'FAAS_PROVIDER_CONTROL_GROUP', value: resourceGroup().name }
      { name: 'FAAS_PROVIDER_APPS', value: string(appNames) }
    ]
    scriptContent: 'set -eu\ncd "$HOME"\npython3 - <<\'FAAS_PUBLISH_PY\'\n${loadTextContent('cloud-init/publish-provider.py')}\nFAAS_PUBLISH_PY\n'
  }
}
output status string = install.properties.outputs.status
