param spokeName string
param hubName string
param gatewayTransit bool
resource toSpoke 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2025-05-01' = {
  name: '${hubName}/to-${spokeName}'
  properties: {
    remoteVirtualNetwork: { id: resourceId('Microsoft.Network/virtualNetworks', spokeName) }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: gatewayTransit
    useRemoteGateways: false
  }
}
resource toHub 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2025-05-01' = {
  name: '${spokeName}/to-${hubName}'
  properties: {
    remoteVirtualNetwork: { id: resourceId('Microsoft.Network/virtualNetworks', hubName) }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: gatewayTransit
  }
  dependsOn: [toSpoke]
}
