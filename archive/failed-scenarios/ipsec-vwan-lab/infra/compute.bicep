@description('Approved lab region.')
param location string
@description('VM definitions, NICs and cloud-init.')
param nodes array
@description('Ephemeral SSH public provisioning key; no public SSH is allowed.')
param sshPublicKey string
@description('Pinned Ubuntu Gen2 image.')
param image object
@description('Exact run ownership tags.')
param tags object

module vms './modules/vm.bicep' = [for node in nodes: {
  name: 'compute-${node.name}'
  params: {
    location: location
    node: node
    sshPublicKey: sshPublicKey
    image: image
    tags: tags
  }
}]

output vmIds array = [for (node, index) in nodes: {
  name: node.name
  id: vms[index].outputs.vmId
}]
