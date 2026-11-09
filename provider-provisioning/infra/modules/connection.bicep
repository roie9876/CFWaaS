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
@description('Lab default: GCMAES128 for both IPsec encryption and integrity (hardware accelerated on Azure VPN gateways; roughly 3x the throughput of encryption None + SHA256 integrity in the E-W performance lab). Both tunnel ends use this module, so overriding it on one connection breaks the tunnel unless the peer connection matches.')
param ipsecPolicies array = [
  {
    ikeEncryption: 'AES256'
    ikeIntegrity: 'SHA256'
    dhGroup: 'DHGroup14'
    ipsecEncryption: 'GCMAES128'
    ipsecIntegrity: 'GCMAES128'
    pfsGroup: 'None'
    saLifeTimeSeconds: 27000
    saDataSizeKilobytes: 102400000
  }
]
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
    ipsecPolicies: ipsecPolicies
  }
  dependsOn: [localGateway]
}
