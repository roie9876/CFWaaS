@description('Approved lab region.')
param location string
@description('Network and endpoint definition.')
param node object
@description('Private workload source prefixes.')
param labPrefixes array
@description('Exact run ownership tags.')
param tags object

resource nsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: 'nsg-${node.name}'
  location: location
  tags: tags
  properties: {
    securityRules: concat(node.firewall ? [] : [
      {
        name: 'AllowLabHttp'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefixes: labPrefixes
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '8080'
        }
      }
      {
        name: 'AllowLabIcmp'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Icmp'
          sourceAddressPrefixes: labPrefixes
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ], [
      {
        name: 'DenyOtherInbound'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ])
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: 'vnet-${node.name}'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [node.prefix] }
    subnets: [
      {
        name: 'lab'
        properties: {
          addressPrefix: node.subnetPrefix
          defaultOutboundAccess: false
          networkSecurityGroup: { id: nsg.id }
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2025-05-01' = if (node.firewall) {
  name: 'pip-${node.name}'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2025-05-01' = {
  name: 'nic-${node.name}'
  location: location
  tags: tags
  properties: {
    enableIPForwarding: node.firewall
    ipConfigurations: [
      {
        name: 'primary'
        properties: {
          primary: true
          privateIPAllocationMethod: 'Static'
          privateIPAddress: node.privateIp
          subnet: { id: '${vnet.id}/subnets/lab' }
          publicIPAddress: node.firewall ? { id: publicIp!.id } : null
        }
      }
    ]
  }
}

output resources object = {
  name: node.name
  vnetId: vnet.id
  nicId: nic.id
  nsgId: nsg.id
  publicIpId: node.firewall ? publicIp!.id : ''
}
