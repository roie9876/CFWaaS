param location string
param name string
param tags object
param gatewayId string
param remoteEndpoint object
param remotePrefixes array
param enableBgp bool = false
param useExistingLocalGateway bool = false
@secure()
param sharedKey string
resource localGateway 'Microsoft.Network/localNetworkGateways@2025-05-01' = if (!useExistingLocalGateway) {
  name: 'lng-${name}'
  location: location
  tags: tags
  properties: union({
    gatewayIpAddress: remoteEndpoint.publicIp
    localNetworkAddressSpace: { addressPrefixes: remotePrefixes }
  }, enableBgp ? {
    bgpSettings: { asn: remoteEndpoint.asn, bgpPeeringAddress: remoteEndpoint.bgpAddress }
  } : {})
}
resource connection 'Microsoft.Network/connections@2025-05-01' = {
  name: 'conn-${name}'
  location: location
  tags: tags
  properties: {
    connectionType: 'IPsec'
    virtualNetworkGateway1: { id: gatewayId }
    localNetworkGateway2: { id: resourceId('Microsoft.Network/localNetworkGateways', 'lng-${name}') }
    enableBgp: enableBgp
    sharedKey: sharedKey
    connectionProtocol: 'IKEv2'
  }
  dependsOn: [localGateway]
}
