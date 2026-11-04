@description('Provider lab region.')
param location string

@description('Unique run-owned network manager name.')
param managerName string

@description('Two provider firewall network definitions.')
param nodes array

@description('All six lab workload prefixes; host listeners are private only.')
param labPrefixes array

@description('Run ownership tags.')
param tags object

resource manager 'Microsoft.Network/networkManagers@2025-09-01' = {
  name: managerName
  location: location
  tags: tags
  properties: {
    networkManagerScopes: {
      managementGroups: []
      subscriptions: [subscription().id]
    }
    networkManagerScopeAccesses: ['Connectivity', 'Routing']
  }
}

module networks './modules/network.bicep' = [for node in nodes: {
  name: 'network-${node.name}'
  params: {
    location: location
    node: node
    labPrefixes: labPrefixes
    tags: tags
  }
}]

output managerId string = manager.id
output networkResources array = [for (node, index) in nodes: networks[index].outputs.resources]
