targetScope = 'resourceGroup'

param location string = 'centralus'
param runId string
param namePrefix string
param appServicePlanId string
param integrationSubnetId string
param privateEndpointSubnetId string
param vaultPrivateDnsZoneId string
param customersTableId string
param tableEndpoint string
param apiUrl string
param apiApplicationId string
param apiRoleId string
param managementApplicationId string
@description('Optional preapproved management app hostname. Empty retains the original generated name.')
param managementAppName string = ''
@secure()
param managementApplicationSecret string
param setupVaultResourceGroupName string = ''
param setupVaultName string = ''
param managementSecretName string = ''
param managementSecretVersion string = ''
@description('UTC expiry of the provider automation credential, as shown in Entra.')
param managementCredentialExpiresOn string
@minLength(1)
@maxLength(50)
param administratorObjectIds array
@description('Optional public IPv4 office/home admin sources prefilled in newly published Check Point customer wizards.')
@maxLength(16)
param adminAllowedSources array = []
@description('Exact provider Check Point managed identity permitted to publish access details. No customer identity is permitted.')
param checkpointRelayClientId string = ''
param checkpointRelayPrincipalId string = ''
param checkpointRelayIdentityId string = ''

var suffix = uniqueString(resourceGroup().id)
var tags = { purpose: 'provider-provisioning', labRun: runId }
var appName = empty(managementAppName) ? '${namePrefix}-admin-${suffix}' : managementAppName
var artifactAccountName = 'stfaasart${suffix}'
var usesSetupVault = !empty(setupVaultName)
var setupVaultId = resourceId(setupVaultResourceGroupName, 'Microsoft.KeyVault/vaults', setupVaultName)
var managementSecretUri = usesSetupVault
  ? 'https://${setupVaultName}${environment().suffixes.keyvaultDns}/secrets/${managementSecretName}/${managementSecretVersion}'
  : automationSecret.properties.secretUriWithVersion

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kvm-${suffix}'
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
resource automationSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = if (!usesSetupVault) {
  parent: vault
  name: 'management-automation'
  properties: {
    value: managementApplicationSecret
    contentType: 'application/entra-client-secret'
    attributes: { exp: dateTimeToEpoch(managementCredentialExpiresOn) }
  }
}
resource setupVaultEndpoint 'Microsoft.Network/privateEndpoints@2025-05-01' = if (usesSetupVault) {
  name: '${namePrefix}-setup-vault'
  location: location
  tags: tags
  properties: {
    subnet: { id: privateEndpointSubnetId }
    privateLinkServiceConnections: [{
      name: 'setup-vault'
      properties: { privateLinkServiceId: setupVaultId, groupIds: ['vault'] }
    }]
  }
}
resource setupVaultDns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2025-05-01' = if (usesSetupVault) {
  parent: setupVaultEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [{ name: 'vault', properties: { privateDnsZoneId: vaultPrivateDnsZoneId } }]
  }
}
resource endpoint 'Microsoft.Network/privateEndpoints@2025-05-01' = {
  name: '${namePrefix}-management-vault'
  location: location
  tags: tags
  properties: {
    subnet: { id: privateEndpointSubnetId }
    privateLinkServiceConnections: [{
      name: 'vault'
      properties: { privateLinkServiceId: vault.id, groupIds: ['vault'] }
    }]
  }
}
resource dns 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2025-05-01' = {
  parent: endpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [{ name: 'vault', properties: { privateDnsZoneId: vaultPrivateDnsZoneId } }]
  }
}
resource app 'Microsoft.Web/sites@2023-12-01' = {
  //checkov:skip=CKV_AZURE_222:Admin UI intentionally serves public HTTPS with required provider-tenant Easy Auth and independent JWT/OID validation.
  //checkov:skip=CKV_AZURE_212:Approved single-instance B1 lab platform is not an HA production service.
  //checkov:skip=CKV_AZURE_17:Administrator authentication is Entra OAuth, not incoming client-certificate authentication.
  name: appName
  location: location
  tags: tags
  kind: 'app,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: appServicePlanId
    virtualNetworkSubnetId: integrationSubnetId
    vnetRouteAllEnabled: true
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      appCommandLine: 'bash startup-management.sh'
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      http20Enabled: true
      healthCheckPath: '/healthz'
      cors: { allowedOrigins: ['https://${appName}.azurewebsites.net'] }
      scmIpSecurityRestrictionsUseMain: false
      scmIpSecurityRestrictionsDefaultAction: 'Deny'
      scmIpSecurityRestrictions: []
      appSettings: [
        { name: 'WEBSITE_DNS_SERVER', value: '168.63.129.16' }
        { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
        { name: 'FAAS_MANAGEMENT_TENANT_ID', value: tenant().tenantId }
        { name: 'FAAS_MANAGEMENT_CLIENT_ID', value: managementApplicationId }
        { name: 'FAAS_MANAGEMENT_CLIENT_SECRET', value: '@Microsoft.KeyVault(SecretUri=${managementSecretUri})' }
        { name: 'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET', value: '@Microsoft.KeyVault(SecretUri=${managementSecretUri})' }
        { name: 'FAAS_ADMIN_OBJECT_IDS', value: string(administratorObjectIds) }
        { name: 'FAAS_MANAGEMENT_ORIGIN', value: 'https://${appName}.azurewebsites.net' }
        { name: 'FAAS_TABLE_ENDPOINT', value: tableEndpoint }
        { name: 'FAAS_MANAGEMENT_VAULT_URL', value: vault.properties.vaultUri }
        { name: 'FAAS_ARTIFACT_ACCOUNT_URL', value: 'https://${artifactAccountName}.blob.${environment().suffixes.storage}' }
        { name: 'FAAS_ADMIN_ALLOWED_SOURCES', value: string(adminAllowedSources) }
        { name: 'FAAS_CHECKPOINT_RELAY_CLIENT_ID', value: checkpointRelayClientId }
        { name: 'FAAS_CHECKPOINT_RELAY_PRINCIPAL_ID', value: checkpointRelayPrincipalId }
        { name: 'FAAS_CHECKPOINT_RELAY_IDENTITY_ID', value: checkpointRelayIdentityId }
        { name: 'FAAS_API_URL', value: apiUrl }
        { name: 'FAAS_API_APPLICATION_ID', value: apiApplicationId }
        { name: 'FAAS_API_ROLE_ID', value: apiRoleId }
      ]
    }
  }
}
resource authentication 'Microsoft.Web/sites/config@2023-12-01' = {
  //checkov:skip=CKV_AZURE_13:This is authsettingsV2 with platform.enabled and globalValidation.requireAuthentication; scanner expects legacy authsettings.
  //checkov:skip=CKV_AZURE_63:This resource configures authentication, not web logging. Sensitive request/response body logging stays disabled.
  //checkov:skip=CKV_AZURE_65:Detailed error responses are intentionally suppressed to protect credentials; errors expose safe codes only.
  //checkov:skip=CKV_AZURE_66:Credential-bearing request tracing is intentionally not enabled on this authentication settings resource.
  //checkov:skip=CKV_AZURE_80:Authentication settings are not a .NET runtime; the owning app explicitly runs Linux Python 3.12.
  //checkov:skip=CKV_AZURE_88:Authentication settings do not describe filesystem mounts; the owning app uses platform-managed hosting storage.
  //checkov:skip=CKV_AZURE_222:Authenticated administrator HTTPS must be reachable; authsettingsV2 is not a public-network setting.
  parent: app
  name: 'authsettingsV2'
  properties: {
    platform: { enabled: true }
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'RedirectToLoginPage'
      redirectToProvider: 'azureactivedirectory'
      excludedPaths: ['/healthz']
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: managementApplicationId
          clientSecretSettingName: 'MICROSOFT_PROVIDER_AUTHENTICATION_SECRET'
          openIdIssuer: uri(environment().authentication.loginEndpoint, '${tenant().tenantId}/v2.0')
        }
        validation: {
          allowedAudiences: empty(checkpointRelayPrincipalId) ? [managementApplicationId] : [managementApplicationId, apiApplicationId]
          defaultAuthorizationPolicy: {
            allowedPrincipals: {
              identities: concat(administratorObjectIds, empty(checkpointRelayPrincipalId) ? [] : [checkpointRelayPrincipalId])
            }
          }
        }
      }
    }
    login: {
      allowedExternalRedirectUrls: ['https://${appName}.azurewebsites.net']
      tokenStore: { enabled: true }
    }
    httpSettings: { requireHttps: true }
  }
}
resource scmPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: app
  name: 'scm'
  properties: { allow: false }
}
resource ftpPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: app
  name: 'ftp'
  properties: { allow: false }
}
resource vaultRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, app.id, 'management-secrets')
  properties: {
    principalId: app.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
  }
}
resource customers 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' existing = {
  name: '${split(customersTableId, '/')[8]}/default/Customers'
}
resource customersRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: customers
  name: guid(customersTableId, app.id, 'management-customer-registry')
  properties: {
    principalId: app.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3')
  }
}
resource operations 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' existing = {
  name: '${split(customersTableId, '/')[8]}/default/Operations'
}
// Read-only: the management app lists provider environments; only the worker changes Operations.
resource operationsReaderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: operations
  name: guid(operations.id, app.id, 'management-operations-read')
  properties: {
    principalId: app.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '76199698-9eea-4c19-bc75-cec21354c6b6')
  }
}
output appName string = app.name
output principalId string = app.identity.principalId
output managementUrl string = 'https://${app.properties.defaultHostName}'
output redirectUri string = 'https://${app.properties.defaultHostName}/.auth/login/aad/callback'
