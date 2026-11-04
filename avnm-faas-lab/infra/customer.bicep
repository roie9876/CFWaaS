@description('Customer workload region.')
param location string

@description('Six private workload network definitions.')
param nodes array

@description('All six lab workload prefixes.')
param labPrefixes array

@description('Run ownership tags.')
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

output networkResources array = [for (node, index) in nodes: networks[index].outputs.resources]
