targetScope = 'resourceGroup'

@allowed(['eastus2', 'eastus', 'northeurope', 'westeurope', 'israelcentral'])
param location string = 'eastus2'
@allowed(['proof', 'network'])
param deploymentMode string = 'network'
@allowed(['ubuntu', 'checkpoint-byol', 'checkpoint-vmss'])
param firewallType string = 'ubuntu'
@description('Up to 16 public IPv4 admin hosts/CIDRs. Bare hosts are normalized to /32. Check Point only.')
@maxLength(16)
param adminAllowedSources array = []
@minLength(3)
@maxLength(32)
param runId string
param sshPublicKey string
@allowed([10])
param routingApplianceBandwidthGbps int = 10
@allowed(['VpnGw1AZ', 'VpnGw2AZ', 'VpnGw3AZ', 'VpnGw4AZ', 'VpnGw5AZ'])
param customerIngressVpnGatewaySku string = 'VpnGw1AZ'
@allowed(['VpnGw1AZ', 'VpnGw2AZ', 'VpnGw3AZ', 'VpnGw4AZ', 'VpnGw5AZ'])
param customerDeliveryVpnGatewaySku string = 'VpnGw1AZ'
@allowed(['standard', 'high-performance'])
param workloadVmProfile string = 'standard'
param enrolledCustomerResourceGroupId string = ''
param expectedCustomerSubscriptionId string
param expectedCustomerTenantId string
param apiUrl string
param apiResource string
param apiAuthorityTenantId string
param apiClientId string
@description('Customer-specific API-only credential; not an Azure administrator or ARM deployment credential.')
@secure()
param apiClientSecret string
@description('Provider-prepared compiled customer connection template, encoded to preserve its inner ARM expressions.')
param customerConnectionsTemplateBase64 string
@description('Customer accepts temporary Azure-hosted script execution and its separate shared-key backing storage.')
@allowed([true])
param approveDeploymentScriptBackingException bool

var oldTags = resourceGroup().?tags ?? {}
var deploymentRunId = '${take(runId, 18)}-${uniqueString(resourceGroup().id, runId)}'
var scopeMatches = subscription().subscriptionId == expectedCustomerSubscriptionId && tenant().tenantId == expectedCustomerTenantId && (empty(enrolledCustomerResourceGroupId) || toLower(resourceGroup().id) == toLower(enrolledCustomerResourceGroupId))
var tagsMatch = (oldTags.?labRun ?? deploymentRunId) == deploymentRunId && (oldTags.?purpose ?? 'provider-provisioning') == 'provider-provisioning'
resource enrollmentTags 'Microsoft.Resources/tags@2021-04-01' = if (scopeMatches && tagsMatch) {
  name: 'default'
  properties: { tags: union(oldTags, { purpose: 'provider-provisioning', labRun: deploymentRunId }) }
  dependsOn: [proof]
}
resource caller 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-customer-${uniqueString(resourceGroup().id, runId)}'
  location: 'eastus2'
  tags: { purpose: 'provider-provisioning-customer-auth', labRun: deploymentRunId }
}
resource customerScopeReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, caller.id, 'customer-scope-reader')
  properties: {
    principalId: caller.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')
  }
}
resource customerNetworkRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, caller.id, 'customer-network-connector')
  properties: {
    principalId: caller.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4d97b98b-1d4f-4787-a291-c67834d212e7')
  }
}

module proof 'customer-proof.bicep' = {
  name: 'customer-authorization-proof'
  params: {
    location: location
    runId: deploymentRunId
    customerIdentityId: caller.id
    customerIdentityClientId: caller.properties.clientId
    apiUrl: apiUrl
    apiResource: apiResource
    apiAuthMode: 'provider-api-client'
    apiAuthorityTenantId: apiAuthorityTenantId
    apiClientId: apiClientId
    apiClientSecret: apiClientSecret
    approveDeploymentScriptBackingException: approveDeploymentScriptBackingException
    firewallType: firewallType
    adminAllowedSources: adminAllowedSources
    validateCustomerScope: true
    customerTenantId: tenant().tenantId
    expectedCustomerTenantId: expectedCustomerTenantId
    expectedCustomerSubscriptionId: expectedCustomerSubscriptionId
    customerSubscriptionId: subscription().subscriptionId
    customerResourceGroup: resourceGroup().name
    enrolledCustomerResourceGroupId: enrolledCustomerResourceGroupId
    enrollCustomerScope: true
  }
  dependsOn: [customerNetworkRole, customerScopeReader]
}

module foundation 'customer-foundation.bicep' = if (deploymentMode == 'network') {
  name: 'customer-foundation'
  params: {
    location: location
    runId: deploymentRunId
    sshPublicKey: sshPublicKey
    routingApplianceBandwidthGbps: routingApplianceBandwidthGbps
    customerIngressVpnGatewaySku: customerIngressVpnGatewaySku
    customerDeliveryVpnGatewaySku: customerDeliveryVpnGatewaySku
    workloadVmProfile: workloadVmProfile
    adminAllowedSources: firewallType != 'ubuntu' ? adminAllowedSources : []
  }
  dependsOn: [proof, enrollmentTags]
}

module network 'customer-network.bicep' = if (deploymentMode == 'network') {
  name: 'customer-provider-connection'
  params: {
    location: location
    executionLocation: 'eastus2'
    runId: deploymentRunId
    customerIdentityId: caller.id
    customerIdentityClientId: caller.properties.clientId
    customerTenantId: tenant().tenantId
    expectedCustomerTenantId: expectedCustomerTenantId
    expectedCustomerSubscriptionId: expectedCustomerSubscriptionId
    customerSubscriptionId: subscription().subscriptionId
    customerResourceGroup: resourceGroup().name
    enrolledCustomerResourceGroupId: enrolledCustomerResourceGroupId
    customerEndpoints: deploymentMode == 'network' ? foundation!.outputs.customerEndpoints : {}
    customerRoutingApplianceIp: deploymentMode == 'network' ? foundation!.outputs.routingAppliancePrivateIp : ''
    customerConnectionsTemplate: base64ToJson(customerConnectionsTemplateBase64)
    apiUrl: apiUrl
    apiResource: apiResource
    apiAuthMode: 'provider-api-client'
    apiAuthorityTenantId: apiAuthorityTenantId
    apiClientId: apiClientId
    apiClientSecret: apiClientSecret
    approveDeploymentScriptBackingException: approveDeploymentScriptBackingException
    firewallType: firewallType
    adminAllowedSources: adminAllowedSources
  }
}

output operationId string = deploymentMode == 'proof' ? proof.outputs.proofResult.operationId : network!.outputs.networkResult.operationId
output status string = deploymentMode == 'proof' ? proof.outputs.proofResult.status : network!.outputs.networkResult.status
