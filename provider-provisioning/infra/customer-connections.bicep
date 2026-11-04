targetScope = 'resourceGroup'
@allowed(['eastus2', 'eastus', 'northeurope', 'westeurope', 'israelcentral'])
param location string = 'eastus2'
param runId string
param providerManifest object
@secure()
param ingressSharedKey string
@secure()
param deliverySharedKey string
var tags = { purpose: 'provider-provisioning-customer', labRun: runId }
module ingress 'modules/connection.bicep' = {
  name: 'customer-to-provider-ingress'
  params: {
    location: location
    name: 'customer-ingress'
    tags: tags
    gatewayId: resourceId('Microsoft.Network/virtualNetworkGateways', 'gw-customer-ingress')
    remoteEndpoint: providerManifest.providerIngress
    remotePrefixes: ['172.20.0.0/16', '172.22.0.0/16', '10.211.0.0/16', '10.212.0.0/16']
    sharedKey: ingressSharedKey
  }
}
module delivery 'modules/connection.bicep' = {
  name: 'customer-to-provider-delivery'
  params: {
    location: location
    name: 'customer-delivery'
    tags: tags
    gatewayId: resourceId('Microsoft.Network/virtualNetworkGateways', 'gw-customer-delivery')
    remoteEndpoint: providerManifest.providerDelivery
    remotePrefixes: ['${providerManifest.providerDelivery.bgpAddress}/32']
    enableBgp: true
    sharedKey: deliverySharedKey
  }
}
