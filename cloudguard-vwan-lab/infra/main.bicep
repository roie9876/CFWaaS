targetScope = 'subscription'

@description('Azure region for the provider security deployment.')
param location string

@description('New, dedicated provider resource group.')
param resourceGroupName string

@description('Virtual WAN name.')
param wanName string

@description('Managed virtual hub name.')
param hubName string

@description('Nonoverlapping virtual hub address prefix, at least /23.')
param hubAddressPrefix string

@description('Minimum managed hub routing infrastructure units.')
@minValue(2)
param minRoutingCapacity int = 2

@description('Ownership and cost-allocation tags.')
param tags object

resource providerGroup 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

module hub './modules/hub.bicep' = {
  name: 'provider-hub'
  scope: providerGroup
  params: {
    location: location
    wanName: wanName
    hubName: hubName
    addressPrefix: hubAddressPrefix
    minRoutingCapacity: minRoutingCapacity
    tags: tags
  }
}

output resourceGroupId string = providerGroup.id
output hubId string = hub.outputs.hubId
output wanId string = hub.outputs.wanId
