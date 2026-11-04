using './main.bicep'

var config = loadJsonContent('../config.json')

param location = config.location
param resourceGroupName = config.provider.resourceGroup
param wanName = config.hub.wanName
param hubName = config.hub.name
param hubAddressPrefix = config.hub.addressPrefix
param minRoutingCapacity = config.hub.minRoutingCapacity
param tags = {
  purpose: 'cloudguard-vwan-lab'
  status: 'preparation-only'
}
