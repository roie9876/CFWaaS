@description('Deployment region.')
param location string

@description('Network definition: name, prefix, subnetPrefix, privateIp and firewall Boolean.')
param node object

@description('Lab-only source IPv4 prefixes.')
param labPrefixes array

@description('Ownership tags.')
param tags object

resource nsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: 'nsg-${node.name}'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowLabTraffic'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: node.firewall ? '*' : 'Tcp'
          sourceAddressPrefixes: labPrefixes
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: node.firewall ? '*' : '8080'
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
    ]
  }
}

// AVNM alone populates these tables; the network deployment never adds a UDR.
resource table 'Microsoft.Network/routeTables@2025-05-01' = if (!node.firewall) {
  name: 'rt-${node.name}'
  location: location
  tags: tags
  properties: {
    disableBgpRoutePropagation: true
    routes: []
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: 'vnet-${node.name}'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [node.prefix]
    }
    subnets: [
      {
        name: 'lab'
        properties: {
          addressPrefix: node.subnetPrefix
          defaultOutboundAccess: false
          networkSecurityGroup: {
            id: nsg.id
          }
          routeTable: node.firewall ? null : {
            id: table!.id
          }
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2025-05-01' = if (node.firewall) {
  name: 'pip-${node.name}'
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
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
          subnet: {
            id: '${vnet.id}/subnets/lab'
          }
          publicIPAddress: node.firewall ? {
            id: publicIp!.id
          } : null
        }
      }
    ]
  }
}

output resources object = {
  name: node.name
  vnetId: vnet.id
  subnetId: '${vnet.id}/subnets/lab'
  nicId: nic.id
  routeTableId: node.firewall ? '' : table!.id
  publicIpId: node.firewall ? publicIp!.id : ''
}
