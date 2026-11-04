param location string
param name string
param subnetId string
param asn int
param tags object
param activeActive bool = false
param defaultSiteId string = ''
@allowed(['VpnGw1AZ', 'VpnGw2AZ', 'VpnGw3AZ', 'VpnGw4AZ', 'VpnGw5AZ'])
param sku string = 'VpnGw1AZ'
resource pip 'Microsoft.Network/publicIPAddresses@2025-05-01' = [for i in range(0, activeActive ? 2 : 1): {
  name: i == 0 ? 'pip-${name}' : 'pip-${name}-secondary'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  zones: ['1', '2', '3']
  properties: { publicIPAllocationMethod: 'Static', publicIPAddressVersion: 'IPv4' }
}]
var gatewayIpConfigurations = [for i in range(0, activeActive ? 2 : 1): {
  name: i == 0 ? 'primary' : 'secondary'
  properties: {
    privateIPAllocationMethod: 'Dynamic'
    subnet: { id: subnetId }
    publicIPAddress: { id: pip[i].id }
  }
}]
resource gateway 'Microsoft.Network/virtualNetworkGateways@2025-05-01' = {
  name: 'gw-${name}'
  location: location
  tags: tags
  properties: union({
    gatewayType: 'Vpn'
    vpnType: 'RouteBased'
    vpnGatewayGeneration: sku == 'VpnGw1AZ' ? 'Generation1' : 'Generation2'
    sku: { name: sku, tier: sku }
    activeActive: activeActive
    enableBgp: true
    bgpSettings: { asn: asn }
    ipConfigurations: gatewayIpConfigurations
  }, empty(defaultSiteId) ? {} : { gatewayDefaultSite: { id: defaultSiteId } })
}
output id string = gateway.id
output endpoint object = {
  publicIp: pip[0].properties.ipAddress
  bgpAddress: split(gateway.properties.bgpSettings.bgpPeeringAddress, ',')[0]
  asn: asn
}
