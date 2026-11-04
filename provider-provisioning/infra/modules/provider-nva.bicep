param location string
param name string
param tags object
param subnetId string
param privateIp string
param sshPublicKey string
param publicIpId string
param backendPoolId string
param ingressRouteServerName string
param bgpEnabled bool

resource ingressRouteServer 'Microsoft.Network/virtualHubs@2025-05-01' existing = {
  name: ingressRouteServerName
}
module vm 'vm.bicep' = {
  name: '${name}-vm-deployment'
  params: {
    location: location
    name: name
    tags: tags
    subnetId: subnetId
    privateIp: privateIp
    sshPublicKey: sshPublicKey
    forwarding: true
    publicIpId: publicIpId
    backendPoolId: backendPoolId
    cloudInit: replace(replace(replace(
      loadTextContent('../cloud-init/nva.yaml'),
      '__INGRESS_PEER_1__', ingressRouteServer.properties.virtualRouterIps[0]),
      '__INGRESS_PEER_2__', ingressRouteServer.properties.virtualRouterIps[1]),
      '__BGP_ENABLED__', bgpEnabled ? 'true' : 'false')
  }
}