@description('Deployment region.')
param location string

@description('VM definitions including NIC IDs and nonsecret cloud-init scripts.')
param nodes array

@description('Guest administrator SSH public key; no inbound SSH rule is opened.')
param sshPublicKey string

@description('Pinned Ubuntu Gen2 Marketplace image.')
param image object

@description('Run ownership tags.')
param tags object

module machines './modules/vm.bicep' = [for node in nodes: {
  name: 'compute-${node.name}'
  params: {
    location: location
    node: node
    sshPublicKey: sshPublicKey
    image: image
    tags: tags
  }
}]

output vmIds array = [for (node, index) in nodes: machines[index].outputs.vmId]
