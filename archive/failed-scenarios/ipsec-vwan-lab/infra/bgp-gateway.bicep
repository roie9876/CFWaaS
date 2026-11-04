@description('Region of the retained customer hub.')
param location string
@description('Retained customer hub name; never redeployed by this template.')
param hubName string
@description('Run and revision ownership tags.')
param tags object

resource hub 'Microsoft.Network/virtualHubs@2025-05-01' existing = {
  name: hubName
}

resource gateway 'Microsoft.Network/vpnGateways@2025-05-01' = {
  name: 'vpng-ipsec-bgp'
  location: location
  tags: tags
  properties: {
    virtualHub: { id: hub.id }
    vpnGatewayScaleUnit: 1
  }
}

output gatewayId string = gateway.id
