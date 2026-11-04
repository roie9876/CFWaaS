@description('Deployment region.')
param location string

@description('VM name, NIC ID, size and cloud-init.')
param node object

@description('SSH public key.')
param sshPublicKey string

@description('Pinned Gen2 image.')
param image object

@description('Ownership tags.')
param tags object

resource vm 'Microsoft.Compute/virtualMachines@2025-04-01' = {
  name: 'vm-${node.name}'
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: node.size
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
    storageProfile: {
      imageReference: image
      osDisk: {
        name: 'osdisk-${node.name}'
        osType: 'Linux'
        createOption: 'FromImage'
        deleteOption: 'Delete'
        diskSizeGB: 32
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
    }
    osProfile: {
      computerName: 'vm-${node.name}'
      adminUsername: 'labuser'
      allowExtensionOperations: true
      customData: base64(node.cloudInit)
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        ssh: {
          publicKeys: [
            {
              path: '/home/labuser/.ssh/authorized_keys'
              keyData: sshPublicKey
            }
          ]
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: node.nicId
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

output vmId string = vm.id
