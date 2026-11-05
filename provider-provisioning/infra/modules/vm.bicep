param location string
param name string
param tags object
param subnetId string
param privateIp string
param sshPublicKey string
param forwarding bool = false
param publicIpId string = ''
param backendPoolId string = ''
param cloudInit string
param size string = 'Standard_B1ms'
param acceleratedNetworking bool = false
@description('Empty keeps the platform default; v6 sizes such as Standard_D8s_v6 accept NVMe only.')
@allowed(['', 'NVMe'])
param diskControllerType string = ''
@allowed(['labuser'])
param adminUsername string = 'labuser'
resource nic 'Microsoft.Network/networkInterfaces@2025-05-01' = {
  name: 'nic-${name}'
  location: location
  tags: tags
  properties: {
    enableIPForwarding: forwarding
    enableAcceleratedNetworking: acceleratedNetworking
    ipConfigurations: [{
      name: 'primary'
      properties: union({
        privateIPAllocationMethod: 'Static'
        privateIPAddress: privateIp
        subnet: { id: subnetId }
      }, empty(publicIpId) ? {} : { publicIPAddress: { id: publicIpId } },
      empty(backendPoolId) ? {} : { loadBalancerBackendAddressPools: [{ id: backendPoolId }] })
    }]
  }
}
resource vm 'Microsoft.Compute/virtualMachines@2025-04-01' = {
  //checkov:skip=CKV_AZURE_50:Tenant-managed security extensions must remain enabled; templates install no arbitrary VM extensions.
  name: 'vm-${name}'
  location: location
  tags: tags
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: size }
    securityProfile: {
      encryptionAtHost: true
      securityType: 'TrustedLaunch'
      uefiSettings: { secureBootEnabled: true, vTpmEnabled: true }
    }
    storageProfile: union(empty(diskControllerType) ? {} : { diskControllerType: diskControllerType }, {
      imageReference: { publisher: 'Canonical', offer: 'ubuntu-24_04-lts', sku: 'server', version: '24.04.202609040' }
      osDisk: {
        name: 'os-${name}'
        createOption: 'FromImage'
        deleteOption: 'Delete'
        managedDisk: { storageAccountType: 'StandardSSD_LRS' }
      }
    })
    osProfile: {
      computerName: take(name, 64)
      adminUsername: adminUsername
      customData: base64(cloudInit)
      allowExtensionOperations: true
      linuxConfiguration: {
        disablePasswordAuthentication: true
        provisionVMAgent: true
        ssh: { publicKeys: [{ path: '/home/${adminUsername}/.ssh/authorized_keys', keyData: sshPublicKey }] }
      }
    }
    networkProfile: { networkInterfaces: [{ id: nic.id, properties: { primary: true, deleteOption: 'Delete' } }] }
    diagnosticsProfile: { bootDiagnostics: { enabled: true } }
  }
}
output id string = vm.id
