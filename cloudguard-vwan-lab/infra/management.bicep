@description('Deployment region.')
param location string

@description('Vendor management-server settings.')
param management object

@description('Verified single operator IPv4 /32; never 0.0.0.0/0.')
param operatorCidr string

@description('Discovered gateway public IPv4 /32 sources; empty until the NVA exists.')
param gatewaySources array = []

@description('SSH public key for the management server.')
param sshPublicKey string

@description('Immutable, official Check Point CloudGuardIaaS commit.')
param vendorCommit string

@description('Ownership tags.')
param tags object

var artifactRoot = 'https://raw.githubusercontent.com/CheckPointSW/CloudGuardIaaS/${vendorCommit}/azure/templates/'

module access './modules/management-access.bicep' = {
  name: 'management-network-access'
  params: {
    location: location
    nsgName: management.nsgName
    privateIp: management.privateIp
    operatorCidr: operatorCidr
    gatewaySources: gatewaySources
    tags: tags
  }
}

resource managementDeployment 'Microsoft.Resources/deployments@2022-09-01' = {
  name: 'checkpoint-management'
  properties: {
    mode: 'Incremental'
    templateLink: {
      uri: '${artifactRoot}marketplace-management/mainTemplate.json'
      contentVersion: '1.0.0.0'
    }
    parameters: {
      location: { value: location }
      cloudGuardVersion: { value: management.version }
      authenticationType: { value: 'sshPublicKey' }
      sshPublicKey: { value: sshPublicKey }
      vmName: { value: management.vmName }
      vmSize: { value: management.vmSize }
      virtualNetworkName: { value: management.virtualNetworkName }
      virtualNetworkAddressPrefix: { value: management.addressPrefix }
      Subnet1Name: { value: 'snet-management' }
      Subnet1Prefix: { value: management.subnetPrefix }
      Subnet1StartAddress: { value: management.privateIp }
      vnetNewOrExisting: { value: 'new' }
      managementGUIClientNetwork: { value: operatorCidr }
      adminShell: { value: '/bin/bash' }
      enableApi: { value: 'gui_clients' }
      diskSizeGB: { value: management.diskSizeGb }
      diskType: { value: 'StandardSSD_LRS' }
      msi: { value: true }
      useBlinkImage: { value: true }
      hyperVGeneration: { value: 'V2' }
      storageAccountDeployMode: { value: 'Managed' }
      deployNewNSG: { value: false }
      ExistingNSG: { value: { id: access.outputs.nsgId } }
      _artifactsLocation: { value: artifactRoot }
      tagsByResource: {
        value: {
          'Microsoft.Compute/virtualMachines': tags
          'Microsoft.Network/virtualNetworks': tags
          'Microsoft.Network/networkInterfaces': tags
          'Microsoft.Network/publicIPAddresses': tags
        }
      }
    }
  }
}

output managementVmId string = resourceId('Microsoft.Compute/virtualMachines', management.vmName)
output managementNsgId string = access.outputs.nsgId
output managementDeploymentId string = managementDeployment.id
