@description('Approved lab region.')
param location string
@description('Name, size, NIC and cloud-init.')
param node object
@description('Ephemeral SSH public provisioning key.')
param sshPublicKey string
@description('Pinned Ubuntu Gen2 image.')
param image object
@description('Exact run ownership tags.')
param tags object
@description('Local provisioning account; public SSH remains blocked.')
param adminUsername string = 'labuser'

resource vm 'Microsoft.Compute/virtualMachines@2025-04-01' = {
  name: 'vm-${node.name}'
  location: location
  tags: tags
  properties: {
    hardwareProfile: { vmSize: node.size }
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
        managedDisk: { storageAccountType: 'StandardSSD_LRS' }
      }
    }
    osProfile: {
      computerName: 'vm-${node.name}'
      adminUsername: adminUsername
      allowExtensionOperations: true
      customData: base64(node.cloudInit)
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
          id: node.nicId
          properties: {
            primary: true
            deleteOption: 'Delete'
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: { enabled: true }
    }
  }
}

output vmId string = vm.id
