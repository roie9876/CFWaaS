targetScope = 'resourceGroup'
@allowed(['eastus2', 'eastus', 'northeurope', 'westeurope', 'israelcentral'])
param location string = 'eastus2'
param runId string
param customerIdentityId string
param customerIdentityClientId string
param apiUrl string
param apiResource string
@allowed(['customer-managed-identity', 'provider-api-client'])
param apiAuthMode string = 'customer-managed-identity'
param apiAuthorityTenantId string = ''
param apiClientId string = ''
@secure()
param apiClientSecret string = ''
param validateCustomerScope bool = false
param customerTenantId string = ''
param expectedCustomerTenantId string = ''
param expectedCustomerSubscriptionId string = ''
param customerSubscriptionId string = ''
param customerResourceGroup string = ''
param enrolledCustomerResourceGroupId string = ''
param enrollCustomerScope bool = false
@allowed(['ubuntu', 'checkpoint-byol'])
param firewallType string = 'ubuntu'
@maxLength(16)
param adminAllowedSources array = []
@description('Separate exception: Azure deploymentScripts auto-creates temporary ACI + shared-key supporting storage. It never uses the private operations account. Requires explicit approval.')
@allowed([true])
param approveDeploymentScriptBackingException bool
@minValue(60)
@maxValue(6900)
param waitSeconds int = 600
@description('A new bounded retry reruns the script while the API idempotency key remains the run ID.')
param proofAttemptTag string = utcNow()
resource proof 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'customer-api-proof'
  location: location
  tags: { purpose: 'provider-provisioning-customer-auth', labRun: runId }
  kind: 'AzureCLI'
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${customerIdentityId}': {} } }
  properties: {
    azCliVersion: '2.77.0'
    timeout: 'PT2H'
    cleanupPreference: 'Always'
    retentionInterval: 'P1D'
    forceUpdateTag: proofAttemptTag
    environmentVariables: [
      { name: 'FAAS_API_URL', value: apiUrl }
      { name: 'FAAS_API_RESOURCE', value: apiResource }
      { name: 'FAAS_AUTH_MODE', value: apiAuthMode }
      { name: 'FAAS_API_AUTHORITY_TENANT_ID', value: apiAuthorityTenantId }
      { name: 'FAAS_API_CLIENT_ID', value: apiClientId }
      { name: 'FAAS_API_CLIENT_SECRET', secureValue: apiClientSecret }
      { name: 'FAAS_CUSTOMER_CLIENT_ID', value: customerIdentityClientId }
      { name: 'FAAS_WAIT_SECONDS', value: string(waitSeconds) }
      { name: 'FAAS_RUN_ID', value: runId }
      { name: 'FAAS_BACKING_APPROVED', value: string(approveDeploymentScriptBackingException) }
      { name: 'FAAS_CONNECTOR_MODE', value: 'proof' }
      { name: 'FAAS_FIREWALL_TYPE', value: firewallType }
      { name: 'FAAS_ADMIN_ALLOWED_SOURCES', value: string(adminAllowedSources) }
      { name: 'FAAS_VALIDATE_CUSTOMER_SCOPE', value: string(validateCustomerScope) }
      { name: 'FAAS_CUSTOMER_TENANT_ID', value: customerTenantId }
      { name: 'FAAS_EXPECTED_CUSTOMER_TENANT_ID', value: expectedCustomerTenantId }
      { name: 'FAAS_EXPECTED_CUSTOMER_SUBSCRIPTION_ID', value: expectedCustomerSubscriptionId }
      { name: 'FAAS_ENROLL_CUSTOMER_SCOPE', value: string(enrollCustomerScope) }
      { name: 'FAAS_CUSTOMER_SUBSCRIPTION_ID', value: customerSubscriptionId }
      { name: 'FAAS_CUSTOMER_RESOURCE_GROUP', value: customerResourceGroup }
      { name: 'FAAS_ENROLLED_CUSTOMER_SCOPE', value: enrolledCustomerResourceGroupId }
    ]
    // HOME is container-local, not the deploymentScripts input/output Azure Files mount.
    scriptContent: 'set -euo pipefail\ncd "$HOME"\npython3 - <<\'FAAS_CONNECTOR_PY\'\n${loadTextContent('../scripts/customer_connector.py')}\nFAAS_CONNECTOR_PY\n'
  }
}
output proofResult object = {
  operationId: proof.properties.outputs.operationId
  status: proof.properties.outputs.status
}
