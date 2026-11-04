@description('Deployment region.')
param location string

@description('Existing, fully provisioned managed virtual hub name.')
param hubName string

@description('Actual ASN read from the provisioned hub.')
param hubAsn int

@description('Actual router peer IPs read from the provisioned hub.')
@minLength(2)
param hubPeers array

@description('Validated CloudGuard configuration from config.json.')
param cloudguard object

@description('New managed resource group; the Marketplace application creates it.')
param managedResourceGroupName string

@description('Gateway SSH public key, forwarded to a vendor secure-string parameter.')
@secure()
param sshPublicKey string

@description('One-time SIC key supplied only at execution.')
@secure()
param sicKey string

@description('Resource ownership tags.')
param tags object

resource hub 'Microsoft.Network/virtualHubs@2025-05-01' existing = {
  name: hubName
}

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-cgvwan-managed-app'
  location: location
  tags: tags
}

resource reader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(hub.id, identity.id, 'reader')
  scope: hub
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'acdd72a7-3385-48ef-bd42-f606fba81ae7')
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource ingress 'Microsoft.Network/publicIPAddresses@2025-05-01' = {
  name: cloudguard.ingressPublicIpName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

resource joinDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, 'cloudguard-ingress-join')
  properties: {
    roleName: 'cgvwan-ingress-join-${uniqueString(resourceGroup().id)}'
    description: 'Allow the managed application identity to attach only its authorized ingress public IP.'
    type: 'CustomRole'
    permissions: [
      {
        actions: ['Microsoft.Network/publicIPAddresses/join/action']
        notActions: []
      }
    ]
    assignableScopes: [resourceGroup().id]
  }
}

resource join 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(ingress.id, identity.id, 'join')
  scope: ingress
  properties: {
    roleDefinitionId: joinDefinition.id
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// Keep this parameter contract aligned with the pinned vendor vwan-managed-app template.
resource application 'Microsoft.Solutions/applications@2021-07-01' = {
  name: cloudguard.applicationName
  location: location
  kind: 'MarketPlace'
  tags: tags
  plan: {
    publisher: 'checkpoint'
    product: cloudguard.planProduct
    name: 'vwan-app'
    version: cloudguard.planVersion
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    managedResourceGroupId: subscriptionResourceId('Microsoft.Resources/resourceGroups', managedResourceGroupName)
    parameters: {
      hubId: { value: hub.id }
      tags: { value: tags }
      imageVersion: { value: cloudguard.imageVersion }
      osVersion: { value: cloudguard.osVersion }
      LicenseType: { value: cloudguard.licenseType }
      scaleUnit: { value: cloudguard.scaleUnit }
      bootstrapScript: { value: '' }
      adminShell: { value: '/bin/bash' }
      sicKey: { value: sicKey }
      sshPublicKey: { value: sshPublicKey }
      MaintenanceModePasswordHash: { value: '' }
      SerialConsolePasswordHash: { value: '' }
      BGP: { value: cloudguard.bgpAsn }
      NVA: { value: cloudguard.nvaName }
      customMetrics: { value: 'yes' }
      location: { value: location }
      hubASN: { value: hubAsn }
      hubPeers: { value: hubPeers }
      publicIPIngress: { value: 'yes' }
      createNewIPIngress: { value: 'no' }
      customLicenseType: { value: '' }
      ipIngressExistingResourceId: { value: ingress.id }
      templateName: { value: 'wan_custom_template' }
    }
  }
  dependsOn: [reader, join]
}

output applicationId string = application.id
output managedResourceGroupId string = subscriptionResourceId('Microsoft.Resources/resourceGroups', managedResourceGroupName)
output ingressPublicIpId string = ingress.id
output readerRoleAssignmentId string = reader.id
output joinRoleAssignmentId string = join.id
output joinRoleDefinitionId string = joinDefinition.id
