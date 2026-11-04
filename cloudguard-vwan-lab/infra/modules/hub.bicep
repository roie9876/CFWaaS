@description('Deployment region.')
param location string

@description('Dedicated customer Virtual WAN name.')
param wanName string

@description('Virtual hub name.')
param hubName string

@description('Virtual hub IPv4 address prefix.')
param addressPrefix string

@description('Minimum managed routing capacity.')
@minValue(2)
param minRoutingCapacity int

@description('Resource ownership tags.')
param tags object

resource wan 'Microsoft.Network/virtualWans@2025-05-01' = {
  name: wanName
  location: location
  tags: tags
  properties: {
    type: 'Standard'
    allowBranchToBranchTraffic: true
    disableVpnEncryption: false
  }
}

resource hub 'Microsoft.Network/virtualHubs@2025-05-01' = {
  name: hubName
  location: location
  tags: tags
  properties: {
    addressPrefix: addressPrefix
    sku: 'Standard'
    virtualWan: {
      id: wan.id
    }
    virtualRouterAutoScaleConfiguration: {
      minCapacity: minRoutingCapacity
    }
  }
}

output hubId string = hub.id
output wanId string = wan.id
