@description('Deployment region.')
param location string

@description('Spoke definition.')
param spoke object

@description('Protected workload IPv4 prefixes.')
param privatePrefixes array

@description('Integrated hub IPv4 prefix.')
param hubAddressPrefix string

@description('Operator public IPv4 /32 for the controlled ingress path.')
param operatorCidr string

@description('Workload VM size.')
param vmSize string

@description('Guest administrator username.')
param adminUsername string

@description('SSH public key.')
param sshPublicKey string

@description('Pinned Gen2 image reference.')
param image object

@description('Whether host encryption is required.')
param encryptionAtHost bool

@description('Ownership tags.')
param tags object

var prefix = 'cgvwan-${spoke.name}'

resource nsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: 'nsg-${prefix}'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowControlledHttp'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefixes: concat(privatePrefixes, [hubAddressPrefix, operatorCidr])
          sourcePortRange: '*'
          destinationAddressPrefix: spoke.privateIp
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
          sourceAddressPrefixes: concat(privatePrefixes, [hubAddressPrefix])
          sourcePortRange: '*'
          destinationAddressPrefix: spoke.privateIp
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

resource vnet 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: 'vnet-${prefix}'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [spoke.addressPrefix]
    }
    subnets: [
      {
        name: 'snet-workload'
        properties: {
          addressPrefix: spoke.subnetPrefix
          defaultOutboundAccess: false
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2025-05-01' = {
  name: 'nic-${prefix}'
  location: location
  tags: tags
  properties: {
    enableIPForwarding: false
    ipConfigurations: [
      {
        name: 'primary'
        properties: {
          primary: true
          privateIPAllocationMethod: 'Static'
          privateIPAddress: spoke.privateIp
          subnet: {
            id: '${vnet.id}/subnets/snet-workload'
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2025-04-01' = {
  name: 'vm-${prefix}'
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      encryptionAtHost: encryptionAtHost
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
    storageProfile: {
      imageReference: image
      osDisk: {
        name: 'osdisk-${prefix}'
        createOption: 'FromImage'
        deleteOption: 'Delete'
        diskSizeGB: 32
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
    }
    osProfile: {
      computerName: 'vm-${prefix}'
      adminUsername: adminUsername
      // Run Command replaces public SSH as the private workload management path.
      allowExtensionOperations: true
      customData: base64(loadTextContent('workload-cloud-init.yaml'))
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            primary: true
            deleteOption: 'Delete'
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}

output vnetId string = vnet.id
output vmId string = vm.id
