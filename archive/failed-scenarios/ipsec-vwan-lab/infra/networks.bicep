@description('Approved lab region.')
param location string

@description('Network definitions owned by this account.')
param nodes array

@description('Private workload source prefixes.')
param labPrefixes array

@description('Exact run ownership tags.')
param tags object

module networks './modules/network.bicep' = [for node in nodes: {
  name: 'network-${node.name}'
  params: {
    location: location
    node: node
    labPrefixes: labPrefixes
    tags: tags
  }
}]

output resources array = [for (node, index) in nodes: networks[index].outputs.resources]
