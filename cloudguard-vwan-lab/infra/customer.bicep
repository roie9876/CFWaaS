targetScope = 'subscription'

@description('Customer workload region.')
param location string

@description('New customer-owned resource group.')
param resourceGroupName string

@description('Spoke definitions: name, addressPrefix, subnetPrefix and privateIp.')
param spokes array

@description('Private workload VM size.')
param vmSize string

@description('SSH-only guest administrator name.')
param adminUsername string

@description('Operator SSH public key, never a private key.')
param sshPublicKey string

@description('Pinned Ubuntu Gen2 image reference.')
param image object

@description('Enable host encryption; registration must be verified before deployment.')
param encryptionAtHost bool = true

@description('Hub prefix for inspected/DNAT traffic and ICMP diagnostics.')
param hubAddressPrefix string

@description('Single operator public IPv4 /32 allowed for the controlled ingress test.')
param operatorCidr string

@description('Resource ownership tags.')
param tags object

resource customerGroup 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: resourceGroupName
  location: location
  tags: tags
}

module workloads './modules/workload.bicep' = [for spoke in spokes: {
  name: 'workload-${spoke.name}'
  scope: customerGroup
  params: {
    location: location
    spoke: spoke
    privatePrefixes: [for item in spokes: item.addressPrefix]
    hubAddressPrefix: hubAddressPrefix
    operatorCidr: operatorCidr
    vmSize: vmSize
    adminUsername: adminUsername
    sshPublicKey: sshPublicKey
    image: image
    encryptionAtHost: encryptionAtHost
    tags: tags
  }
}]

output resourceGroupId string = customerGroup.id
output vnetIds array = [for (spoke, index) in spokes: workloads[index].outputs.vnetId]
output vmIds array = [for (spoke, index) in spokes: workloads[index].outputs.vmId]
