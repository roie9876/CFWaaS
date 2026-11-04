param location string
param name string
param tags object
param subnetId string
param peerIp string
param createPeer bool = true

resource publicIp 'Microsoft.Network/publicIPAddresses@2025-05-01' = {
  name: 'pip-${name}'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static', publicIPAddressVersion: 'IPv4' }
}
resource routeServer 'Microsoft.Network/virtualHubs@2025-05-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: 'Standard'
    allowBranchToBranchTraffic: true
    hubRoutingPreference: 'ExpressRoute'
    virtualRouterAutoScaleConfiguration: { minCapacity: 2 }
  }
}
resource ipConfiguration 'Microsoft.Network/virtualHubs/ipConfigurations@2025-05-01' = {
  parent: routeServer
  name: 'default'
  properties: {
    subnet: { id: subnetId }
    publicIPAddress: { id: publicIp.id }
  }
}
resource bgpPeer 'Microsoft.Network/virtualHubs/bgpConnections@2025-05-01' = if (createPeer) {
  parent: routeServer
  name: 'nva-primary'
  properties: { peerAsn: 65050, peerIp: peerIp }
  dependsOn: [ipConfiguration]
}
output peerAddresses array = routeServer.properties.virtualRouterIps