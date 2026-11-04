param ingressNetworkName string
param routeTableId string
// Attach after the managed gateway and appliance exist; do not race VNet PUTs.
resource ingress 'Microsoft.Network/virtualNetworks@2025-05-01' existing = {
  name: ingressNetworkName
}
resource subnet 'Microsoft.Network/virtualNetworks/subnets@2025-05-01' = {
  parent: ingress
  name: 'VirtualNetworkApplianceSubnet'
  properties: {
    addressPrefix: '172.18.10.0/24'
    routeTable: { id: routeTableId }
  }
}
