param routeServerName string
param peerIp string

resource routeServer 'Microsoft.Network/virtualHubs@2025-05-01' existing = {
  name: routeServerName
}
resource bgpPeer 'Microsoft.Network/virtualHubs/bgpConnections@2025-05-01' = {
  parent: routeServer
  name: 'nva-secondary'
  properties: { peerAsn: 65050, peerIp: peerIp }
}
