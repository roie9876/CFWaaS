@description('Approved lab region.')
param location string

@description('Dedicated managed-hub prefix.')
param hubPrefix string

@description('Exact run ownership tags.')
param tags object

resource wan 'Microsoft.Network/virtualWans@2025-05-01' = {
  name: 'vwan-ipsec'
  location: location
  tags: tags
  properties: {
    type: 'Standard'
    allowBranchToBranchTraffic: true
  }
}

resource hub 'Microsoft.Network/virtualHubs@2025-05-01' = {
  name: 'vhub-ipsec'
  location: location
  tags: tags
  properties: {
    virtualWan: { id: wan.id }
    addressPrefix: hubPrefix
    sku: 'Standard'
    hubRoutingPreference: 'VpnGateway'
    virtualRouterAutoScaleConfiguration: {
      minCapacity: 2
    }
  }
}

resource gateway 'Microsoft.Network/vpnGateways@2025-05-01' = {
  name: 'vpng-ipsec'
  location: location
  tags: tags
  properties: {
    virtualHub: { id: hub.id }
    vpnGatewayScaleUnit: 1
  }
}

output wanId string = wan.id
output hubId string = hub.id
output gatewayId string = gateway.id
