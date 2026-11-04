targetScope = 'resourceGroup'

@allowed(['centralus'])
param location string = 'centralus'
@minLength(3)
@maxLength(20)
param namePrefix string
param runId string
@description('Exact ID of the separately pre-created provider dataplane RG. Worker cannot create RGs.')
param providerDataPlaneResourceGroupId string
@description('Business customer tenant used for enrollment, ownership and state partitioning in both auth modes.')
param trustedTenantId string
@description('Enrolled caller object ID: customer managed identity in legacy mode, provider-tenant API-only service principal in provider-api-client mode.')
param trustedPrincipalId string
@description('Enrolled caller client ID; provider-api-client credentials are never supplied to the provider service.')
param trustedClientId string
@allowed(['customer-managed-identity', 'provider-api-client', 'provider-api-registry'])
param apiAuthMode string = 'customer-managed-identity'
param apiAudience string
@minValue(0)
@description('Deprecated and ignored; retained for compatibility with existing deployments.')
#disable-next-line no-unused-params
param maxEnvironments int = 0
@description('Optional for proof-only bootstrap. Network mode remains disabled without a valid public key and template hash.')
param nvaSshPublicKey string = ''
@description('SHA256 of the compiled provider template included by scripts/package_apps.py.')
@maxLength(64)
param providerTemplateSha256 string = ''
@description('Explicit exception to disabled worker publicNetworkAccess: only SCM management is IP-allowlisted; worker site denies all.')
param approveScmBootstrapException bool = false
@description('Bootstrap operator public IPv4 /32, never 0.0.0.0/0. scripts/bootstrap.py validates before deployment.')
param deploymentOperatorCidr string = ''
@description('Prepare separate managed identities for future isolated provider environments. Activation is a separate step.')
param prepareIsolatedEnvironments bool = false
@description('Acknowledge subscription-wide group write and constrained role delegation to the deployment identity.')
param approveEnvironmentDelegation bool = false

var tags = { purpose: 'provider-provisioning', labRun: runId }
var rgParts = split(providerDataPlaneResourceGroupId, '/')
var dataPlaneSubscription = rgParts[2]
var dataPlaneGroup = rgParts[4]
var suffix = uniqueString(resourceGroup().id)
var integrationId = '${network.id}/subnets/integration'
var privateEndpointId = '${network.id}/subnets/private-endpoints'
// Invalid direct ARM parameters fail closed instead of accidentally broadening SCM.
var approvedOperatorCidr = endsWith(deploymentOperatorCidr, '/32') && length(split(deploymentOperatorCidr, '.')) == 4 ? deploymentOperatorCidr : 'INVALID-OPERATOR-IPV4-32'
var stateSettings = [
  { name: 'WEBSITE_DNS_SERVER', value: '168.63.129.16' }
  { name: 'FAAS_TABLE_ENDPOINT', value: storage.properties.primaryEndpoints.table }
  { name: 'FAAS_TABLE_NAME', value: 'Operations' }
  { name: 'FAAS_VAULT_URL', value: vault.properties.vaultUri }
  { name: 'FAAS_TRUSTED_TENANT_ID', value: trustedTenantId }
  { name: 'FAAS_AUTH_MODE', value: apiAuthMode }
  { name: 'FAAS_AUTHORITY_TENANT_ID', value: apiAuthMode == 'customer-managed-identity' ? trustedTenantId : tenant().tenantId }
  { name: 'FAAS_API_AUDIENCE', value: apiAudience }
  { name: 'FAAS_TRUSTED_PRINCIPAL_ID', value: trustedPrincipalId }
  { name: 'FAAS_TRUSTED_CLIENT_ID', value: trustedClientId }
  { name: 'FAAS_REQUIRED_ROLE', value: 'FirewallDeployment.Request' }
  { name: 'SCM_DO_BUILD_DURING_DEPLOYMENT', value: 'true' }
]

resource network 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: '${namePrefix}-control'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: ['10.240.0.0/24'] }
    subnets: [
      {
        name: 'integration'
        properties: {
          addressPrefix: '10.240.0.0/26'
          delegations: [{ name: 'web', properties: { serviceName: 'Microsoft.Web/serverFarms' } }]
        }
      }
      {
        name: 'private-endpoints'
        properties: { addressPrefix: '10.240.0.64/27', privateEndpointNetworkPolicies: 'Disabled' }
      }
    ]
  }
}
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  //checkov:skip=CKV_AZURE_36:Private endpoints and disabled public access deliberately do not enable a trusted-services bypass.
  //checkov:skip=CKV_AZURE_43:Name is st plus the 13 lowercase alphanumeric characters returned by uniqueString.
  //checkov:skip=CKV_AZURE_206:Approved lab uses Standard_LRS; regional disaster recovery is outside this PoC.
  name: 'st${suffix}'
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: { name: 'Standard_LRS' }
  properties: {
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    publicNetworkAccess: 'Disabled'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    networkAcls: { defaultAction: 'Deny', bypass: 'None' }
  }
}
resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = {
  parent: storage
  name: 'default'
}
resource operations 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: 'Operations'
}
resource customers 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = {
  parent: tableService
  name: 'Customers'
}
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-${suffix}'
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    publicNetworkAccess: 'Disabled'
    networkAcls: { defaultAction: 'Deny', bypass: 'None' }
  }
}
var privateLinks = [
  { name: 'table', target: storage.id, zone: 'privatelink.table.${environment().suffixes.storage}' }
  { name: 'vault', target: vault.id, zone: 'privatelink.vaultcore.azure.net' }
]
resource zones 'Microsoft.Network/privateDnsZones@2024-06-01' = [for link in privateLinks: {
  name: link.zone
  location: 'global'
  tags: tags
}]
resource dnsLinks 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [for (link, i) in privateLinks: {
  parent: zones[i]
  name: 'control'
  location: 'global'
  properties: { registrationEnabled: false, virtualNetwork: { id: network.id } }
}]
resource endpoints 'Microsoft.Network/privateEndpoints@2025-05-01' = [for link in privateLinks: {
  name: '${namePrefix}-${link.name}'
  location: location
  tags: tags
  properties: {
    subnet: { id: privateEndpointId }
    privateLinkServiceConnections: [{
      name: link.name
      properties: { privateLinkServiceId: link.target, groupIds: [link.name] }
    }]
  }
}]
resource zoneGroups 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2025-05-01' = [for (link, i) in privateLinks: {
  parent: endpoints[i]
  name: 'default'
  properties: { privateDnsZoneConfigs: [{ name: link.name, properties: { privateDnsZoneId: zones[i].id } }] }
}]
resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  //checkov:skip=CKV_AZURE_225:Approved single-instance Basic B1 lab plan does not support zone redundancy.
  name: '${namePrefix}-plan'
  location: location
  tags: tags
  kind: 'linux'
  sku: { name: 'B2', tier: 'Basic', capacity: 1 }
  properties: { reserved: true }
}
resource groupProvisioner 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (prepareIsolatedEnvironments && approveEnvironmentDelegation) {
  name: '${namePrefix}-group-provisioner-${suffix}'
  location: location
  tags: tags
}
resource groupDeployer 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = if (prepareIsolatedEnvironments && approveEnvironmentDelegation) {
  name: '${namePrefix}-group-deployer-${suffix}'
  location: location
  tags: tags
}
var appModes = ['api', 'worker']
resource apps 'Microsoft.Web/sites@2023-12-01' = [for mode in appModes: {
  //checkov:skip=CKV_AZURE_222:API intentionally accepts authenticated public HTTPS; worker site denies all and SCM requires explicit operator-/32 exception.
  //checkov:skip=CKV_AZURE_212:Approved single-instance B2 PoC is not a highly available control plane.
  //checkov:skip=CKV_AZURE_17:App-only Entra bearer tokens authorize this API; client-certificate authentication is not its protocol.
  //checkov:skip=CKV_AZURE_18:http20Enabled is explicitly true; verify the compiled-template HTTP/2 assertion.
  name: '${namePrefix}-${mode}-${suffix}'
  location: location
  tags: tags
  kind: 'app,linux'
  identity: mode == 'worker' && prepareIsolatedEnvironments && approveEnvironmentDelegation ? {
    type: 'SystemAssigned, UserAssigned'
    userAssignedIdentities: {
      '${groupProvisioner!.id}': {}
      '${groupDeployer!.id}': {}
    }
  } : { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    virtualNetworkSubnetId: integrationId
    siteConfig: {
      linuxFxVersion: 'PYTHON|3.12'
      alwaysOn: true
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      ftpsState: 'Disabled'
      http20Enabled: true
      appCommandLine: 'bash startup-${mode}.sh'
      healthCheckPath: '/healthz'
      ipSecurityRestrictionsDefaultAction: mode == 'api' ? 'Allow' : 'Deny'
      ipSecurityRestrictions: []
      scmIpSecurityRestrictionsUseMain: false
      scmIpSecurityRestrictionsDefaultAction: 'Deny'
      scmIpSecurityRestrictions: approveScmBootstrapException ? [{
        name: 'approved-bootstrap-operator'
        action: 'Allow'
        priority: 100
        ipAddress: approvedOperatorCidr
      }] : []
      appSettings: concat(stateSettings, [
        { name: 'FAAS_MODE', value: mode }
      ], mode == 'api' ? [] : [
        { name: 'FAAS_PROVIDER_SUBSCRIPTION_ID', value: dataPlaneSubscription }
        { name: 'FAAS_PROVIDER_RESOURCE_GROUP', value: dataPlaneGroup }
        { name: 'FAAS_PROVIDER_TEMPLATE_PATH', value: 'service/templates/provider.json' }
        { name: 'FAAS_PROVIDER_TEMPLATE_SHA256', value: providerTemplateSha256 }
        { name: 'FAAS_NVA_SSH_PUBLIC_KEY', value: nvaSshPublicKey }
      ], mode == 'worker' && prepareIsolatedEnvironments && approveEnvironmentDelegation ? [
        { name: 'FAAS_GROUP_SUBSCRIPTION_ID', value: dataPlaneSubscription }
        { name: 'FAAS_GROUP_PROVISIONER_CLIENT_ID', value: groupProvisioner!.properties.clientId }
        { name: 'FAAS_GROUP_DEPLOYER_CLIENT_ID', value: groupDeployer!.properties.clientId }
        { name: 'FAAS_GROUP_DEPLOYER_PRINCIPAL_ID', value: groupDeployer!.properties.principalId }
      ] : [])
    }
  }
}]
resource scmPolicies 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = [for (mode, i) in appModes: {
  parent: apps[i]
  name: 'scm'
  properties: { allow: false }
}]
resource ftpPolicies 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = [for (mode, i) in appModes: {
  parent: apps[i]
  name: 'ftp'
  properties: { allow: false }
}]
resource tableRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (mode, i) in appModes: {
  scope: operations
  name: guid(operations.id, apps[i].id, 'table-data')
  properties: {
    principalId: apps[i].identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3')
  }
}]
resource vaultRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (mode, i) in appModes: {
  scope: vault
  name: guid(vault.id, apps[i].id, 'secrets')
  properties: {
    principalId: apps[i].identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', mode == 'api' ? '4633458b-17de-408a-b874-0445c86b69e6' : 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
  }
}]
resource customerReaders 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (mode, i) in appModes: {
  scope: customers
  name: guid(customers.id, apps[i].id, 'enrollment-read')
  properties: {
    principalId: apps[i].identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '76199698-9eea-4c19-bc75-cec21354c6b6')
  }
}]
module workerRole 'modules/worker-role.bicep' = {
  name: 'worker-data-plane-role'
  scope: resourceGroup(dataPlaneSubscription, dataPlaneGroup)
  params: { principalId: apps[1].identity.principalId }
}
module environmentGroupRoles 'modules/environment-group-roles.bicep' = if (prepareIsolatedEnvironments && approveEnvironmentDelegation) {
  name: 'environment-group-roles-${suffix}'
  scope: subscription(dataPlaneSubscription)
  params: {
    provisionerPrincipalId: groupProvisioner!.properties.principalId
    deployerPrincipalId: groupDeployer!.properties.principalId
    approveSubscriptionDelegation: true
  }
}
output apiUrl string = 'https://${apps[0].properties.defaultHostName}'
output apiAppName string = apps[0].name
output workerAppName string = apps[1].name
output workerPrincipalId string = apps[1].identity.principalId
output providerDataPlaneScope string = providerDataPlaneResourceGroupId
output appServicePlanId string = plan.id
output integrationSubnetId string = integrationId
output privateEndpointSubnetId string = privateEndpointId
output vaultPrivateDnsZoneId string = zones[1].id
output customersTableId string = customers.id
output tableEndpoint string = storage.properties.primaryEndpoints.table
