targetScope = 'resourceGroup'
@allowed(['eastus2', 'eastus', 'northeurope', 'westeurope', 'israelcentral'])
param location string = 'eastus2'
@description('Azure-hosted automation region; connection resources still use the customer-selected location.')
param executionLocation string = location
param runId string
param customerIdentityId string
param customerIdentityClientId string
param customerTenantId string
param expectedCustomerTenantId string = ''
param expectedCustomerSubscriptionId string = ''
param customerSubscriptionId string
param customerResourceGroup string
param enrolledCustomerResourceGroupId string = ''
@allowed(['ubuntu', 'checkpoint-byol', 'checkpoint-vmss'])
param firewallType string = 'ubuntu'
@maxLength(16)
param adminAllowedSources array = []
@allowed(['VpnGw1AZ', 'VpnGw2AZ', 'VpnGw3AZ', 'VpnGw4AZ', 'VpnGw5AZ'])
param providerVpnGatewaySku string = 'VpnGw1AZ'
param customerEndpoints object
param customerRoutingApplianceIp string = ''
@description('Locally compiled trusted customer-connections.bicep; no shared keys are included.')
param customerConnectionsTemplate object
param apiUrl string
param apiResource string
@allowed(['customer-managed-identity', 'provider-api-client'])
param apiAuthMode string = 'customer-managed-identity'
param apiAuthorityTenantId string = ''
param apiClientId string = ''
@secure()
param apiClientSecret string = ''
@description('Separate temporary ACI/shared-key supporting storage; never the private operations account.')
@allowed([true])
param approveDeploymentScriptBackingException bool
@minValue(60)
// Check Point provisioning adds managed VPN gateways, Route Server and appliance first boot.
@maxValue(14100)
param waitSeconds int = firewallType != 'ubuntu' ? 14100 : 6900
param networkAttemptTag string = utcNow()
resource network 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'customer-network-connector'
  location: executionLocation
  tags: { purpose: 'provider-provisioning-customer-auth', labRun: runId }
  kind: 'AzureCLI'
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${customerIdentityId}': {} } }
  properties: {
    azCliVersion: '2.77.0'
    timeout: firewallType != 'ubuntu' ? 'PT4H' : 'PT2H'
    cleanupPreference: 'Always'
    retentionInterval: 'P1D'
    forceUpdateTag: networkAttemptTag
    environmentVariables: [
      { name: 'FAAS_CONNECTOR_MODE', value: 'network' }
      { name: 'FAAS_FIREWALL_TYPE', value: firewallType }
      { name: 'FAAS_ADMIN_ALLOWED_SOURCES', value: string(adminAllowedSources) }
      { name: 'FAAS_PROVIDER_VPN_GATEWAY_SKU', value: providerVpnGatewaySku }
      { name: 'FAAS_API_URL', value: apiUrl }
      { name: 'FAAS_API_RESOURCE', value: apiResource }
      { name: 'FAAS_AUTH_MODE', value: apiAuthMode }
      { name: 'FAAS_API_AUTHORITY_TENANT_ID', value: apiAuthorityTenantId }
      { name: 'FAAS_API_CLIENT_ID', value: apiClientId }
      { name: 'FAAS_API_CLIENT_SECRET', secureValue: apiClientSecret }
      { name: 'FAAS_CUSTOMER_CLIENT_ID', value: customerIdentityClientId }
      { name: 'FAAS_CUSTOMER_TENANT_ID', value: customerTenantId }
      { name: 'FAAS_EXPECTED_CUSTOMER_TENANT_ID', value: expectedCustomerTenantId }
      { name: 'FAAS_EXPECTED_CUSTOMER_SUBSCRIPTION_ID', value: expectedCustomerSubscriptionId }
      { name: 'FAAS_CUSTOMER_LOCATION', value: location }
      { name: 'FAAS_CUSTOMER_SUBSCRIPTION_ID', value: customerSubscriptionId }
      { name: 'FAAS_CUSTOMER_RESOURCE_GROUP', value: customerResourceGroup }
      { name: 'FAAS_ENROLLED_CUSTOMER_SCOPE', value: enrolledCustomerResourceGroupId }
      { name: 'FAAS_CUSTOMER_ENDPOINTS', value: string(customerEndpoints) }
      { name: 'FAAS_CUSTOMER_ROUTING_APPLIANCE_IP', value: customerRoutingApplianceIp }
      { name: 'FAAS_CONNECTIONS_TEMPLATE', value: string(customerConnectionsTemplate) }
      { name: 'FAAS_WAIT_SECONDS', value: string(waitSeconds) }
      { name: 'FAAS_RUN_ID', value: runId }
      { name: 'FAAS_BACKING_APPROVED', value: string(approveDeploymentScriptBackingException) }
    ]
    // Keep ephemeral secure-parameter files off the supporting Azure Files mounts.
    scriptContent: 'set -euo pipefail\ncd "$HOME"\npython3 - <<\'FAAS_CONNECTOR_PY\'\n${loadTextContent('../scripts/customer_connector.py')}\nFAAS_CONNECTOR_PY\n'
  }
}
output networkResult object = {
  operationId: network.properties.outputs.operationId
  status: network.properties.outputs.status
}
