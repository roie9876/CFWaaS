@description('Deployment region.')
param location string

@description('Management NSG name.')
param nsgName string

@description('Management VM private address.')
param privateIp string

@description('Verified single operator public IPv4 /32.')
param operatorCidr string

@description('Discovered CloudGuard gateway management source addresses.')
param gatewaySources array = []

@description('Management VM public /32 for the vendor-required self/hairpin management path.')
param managementSelfSource string = ''

@description('Ownership tags.')
param tags object

resource nsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: nsgName
  location: location
  tags: tags
  properties: {
    securityRules: concat([
      {
        name: 'OperatorManagement'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: operatorCidr
          sourcePortRange: '*'
          destinationAddressPrefix: privateIp
          destinationPortRanges: ['22', '443', '19009']
        }
      }
    ], empty(gatewaySources) ? [] : [
      {
        name: 'CloudGuardManagementAndLogs'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefixes: gatewaySources
          sourcePortRange: '*'
          destinationAddressPrefix: privateIp
          destinationPortRange: '*'
        }
      }
    ], empty(managementSelfSource) ? [] : [
      {
        name: 'ManagementSelfAccess'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: managementSelfSource
          sourcePortRange: '*'
          destinationAddressPrefix: privateIp
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

output nsgId string = nsg.id
