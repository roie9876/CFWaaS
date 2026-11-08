targetScope = 'resourceGroup'

@allowed(['eastus2'])
param location string = 'eastus2'
@minLength(36)
@maxLength(36)
param environmentId string
param sshPublicKey string
param deployWorkloads bool = false
param verifyWorkloads bool = false

var tags = { purpose: 'faas-peering-lab', faasEnvironmentId: environmentId }
var prefixes = ['10.211.0.0/16', '10.212.0.0/16']
var addresses = ['10.211.0.4', '10.212.0.4']
resource routes 'Microsoft.Network/routeTables@2025-05-01' = [for (prefix, i) in prefixes: {
  name: 'rt-peering-workload-${i}'
  location: location
  tags: tags
  properties: {
    disableBgpRoutePropagation: true
    routes: [
      {
        name: 'east-west-through-checkpoint'
        properties: { addressPrefix: prefixes[1 - i], nextHopType: 'VirtualAppliance', nextHopIpAddress: '172.22.20.4' }
      }
      {
        name: 'internet-through-checkpoint'
        properties: { addressPrefix: '0.0.0.0/0', nextHopType: 'VirtualAppliance', nextHopIpAddress: '172.22.20.4' }
      }
    ]
  }
}]
resource nsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: 'nsg-peering-workloads'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'allow-private-lab'
        properties: {
          priority: 100, direction: 'Inbound', access: 'Allow', protocol: '*'
          sourceAddressPrefixes: ['10.211.0.0/16', '10.212.0.0/16', '172.22.0.0/16']
          sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRange: '*'
        }
      }
      {
        name: 'deny-other-inbound'
        properties: {
          priority: 200, direction: 'Inbound', access: 'Deny', protocol: '*'
          sourceAddressPrefix: '*', sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRange: '*'
        }
      }
    ]
  }
}
resource networks 'Microsoft.Network/virtualNetworks@2025-05-01' = [for (prefix, i) in prefixes: {
  name: 'vnet-peering-workload-${i}'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [prefix] }
    subnets: [{
      name: 'workload'
      properties: {
        addressPrefix: i == 0 ? '10.211.0.0/24' : '10.212.0.0/24'
        defaultOutboundAccess: false
        routeTable: { id: routes[i].id }
        networkSecurityGroup: { id: nsg.id }
      }
    }]
  }
}]
module workloads 'modules/vm.bicep' = [for (prefix, i) in prefixes: if (deployWorkloads) {
  name: 'peering-workload-${i}'
  params: {
    location: location
    name: 'peering-workload-${i}'
    tags: tags
    subnetId: '${networks[i].id}/subnets/workload'
    privateIp: addresses[i]
    sshPublicKey: sshPublicKey
    cloudInit: loadTextContent('cloud-init/workload-performance.yaml')
    size: 'Standard_D8s_v6'
    acceleratedNetworking: true
    diskControllerType: 'NVMe'
  }
}]
resource verification 'Microsoft.Compute/virtualMachines/runCommands@2025-04-01' = [for (prefix, i) in prefixes: if (deployWorkloads && verifyWorkloads) {
  name: 'vm-peering-workload-${i}/verify-peering-lab'
  location: location
  tags: tags
  properties: {
    asyncExecution: false
    timeoutInSeconds: 600
    treatFailureAsDeploymentFailure: true
    source: {
      script: replace(replace(loadTextContent('cloud-init/verify-peering.sh'),
        '__REMOTE_IP__', addresses[1 - i]), '__SOURCE_IP__', addresses[i])
    }
  }
  dependsOn: [workloads]
}]
output customerVnetIds array = [for i in range(0, 2): networks[i].id]
output workloadPrivateIps array = addresses
