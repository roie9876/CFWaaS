targetScope = 'resourceGroup'
@allowed(['eastus2'])
param location string = 'eastus2'
@minLength(36)
@maxLength(36)
param environmentId string
param customerIngressPublicIp string
param customerIngressBgpAddress string
@minValue(64512)
@maxValue(65534)
param customerIngressAsn int
param customerDeliveryPublicIp string
param customerDeliveryBgpAddress string
@minValue(64512)
@maxValue(65534)
param customerDeliveryAsn int
// Optional second instance of an active-active customer delivery gateway (four-tunnel BGP ECMP mesh).
param customerDeliverySecondaryPublicIp string = ''
param customerDeliverySecondaryBgpAddress string = ''
@secure()
param ingressSharedKey string
@secure()
param deliverySharedKey string
param sshPublicKey string
@description('Experimental: provision the ingress Route Server concurrently with provider gateways.')
param parallelProviderNetworking bool = false
@description('SKU of both provider VPN gateways (ingress and delivery).')
@allowed(['VpnGw1AZ', 'VpnGw2AZ', 'VpnGw3AZ', 'VpnGw4AZ', 'VpnGw5AZ'])
param providerVpnGatewaySku string = 'VpnGw1AZ'

var tags = { purpose: 'provider-provisioning-dataplane', environmentId: environmentId }
var suffix = take(environmentId, 8)
var vip = '172.22.10.10'
var privatePrefixes = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
resource ingressRoutes 'Microsoft.Network/routeTables@2025-05-01' = {
  name: 'rt-pi-${suffix}'
  location: location
  tags: tags
  properties: {
    disableBgpRoutePropagation: false
    routes: []
  }
}
resource securityRoutes 'Microsoft.Network/routeTables@2025-05-01' = {
  name: 'rt-security-${suffix}'
  location: location
  tags: tags
  properties: {
    disableBgpRoutePropagation: false
    routes: [{ name: 'nva-internet', properties: { addressPrefix: '0.0.0.0/0', nextHopType: 'Internet' } }]
  }
}
resource forwardingNsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: 'nsg-security-${suffix}'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'allow-all-inbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'allow-all-outbound'
        properties: {
          priority: 100
          direction: 'Outbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      {
        name: 'allow-rfc1918-internet-tcp'
        properties: {
          priority: 106
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefixes: privatePrefixes
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRanges: ['22', '53', '80', '443']
        }
      }
      {
        name: 'allow-rfc1918-internet-udp'
        properties: {
          priority: 107
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Udp'
          sourceAddressPrefixes: privatePrefixes
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRanges: ['53', '123', '443']
        }
      }
      {
        name: 'allow-rfc1918-internet-icmp'
        properties: {
          priority: 108
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Icmp'
          sourceAddressPrefixes: privatePrefixes
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRange: '*'
        }
      }
      {
        name: 'allow-rfc1918-east-west'
        properties: {
          priority: 109
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefixes: privatePrefixes
          sourcePortRange: '*'
          destinationAddressPrefixes: privatePrefixes
          destinationPortRange: '*'
        }
      }
    ]
  }
}
var definitions = [
  { name: 'pi', prefix: '172.20.0.0/16', subnet: '172.20.255.0/27', subnetName: 'GatewaySubnet', routes: ingressRoutes.id }
  { name: 'pd', prefix: '172.21.0.0/16', subnet: '172.21.255.0/27', subnetName: 'GatewaySubnet', routes: '' }
  { name: 'security', prefix: '172.22.0.0/16', subnet: '172.22.10.0/24', subnetName: 'firewall', routes: securityRoutes.id }
]
resource networks 'Microsoft.Network/virtualNetworks@2025-05-01' = [for (definition, i) in definitions: {
  name: 'vnet-${definition.name}-${suffix}'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [definition.prefix] }
    subnets: concat([{
      name: definition.subnetName
      properties: union({
        addressPrefix: definition.subnet
      }, empty(definition.routes) ? {} : { routeTable: { id: definition.routes } },
      i == 2 ? { networkSecurityGroup: { id: forwardingNsg.id }, defaultOutboundAccess: true } : {})
    }], i == 0 ? [{
      name: 'RouteServerSubnet'
      properties: { addressPrefix: '172.20.254.0/26' }
    }] : [])
  }
}]
resource deliveryLocalGateway 'Microsoft.Network/localNetworkGateways@2025-05-01' = {
  name: 'lng-pd-${suffix}'
  location: location
  tags: tags
  properties: {
    gatewayIpAddress: customerDeliveryPublicIp
    localNetworkAddressSpace: { addressPrefixes: ['${customerDeliveryBgpAddress}/32'] }
    bgpSettings: { asn: customerDeliveryAsn, bgpPeeringAddress: customerDeliveryBgpAddress }
  }
}
module gateways 'modules/gateway.bicep' = [for i in range(0, 2): {
  name: 'provider-gateway-${i}-${suffix}'
  params: {
    location: location
    name: '${definitions[i].name}-${suffix}'
    subnetId: '${networks[i].id}/subnets/GatewaySubnet'
    asn: i == 0 ? 65515 : 65031
    // Ingress must be active-active for Route Server; delivery is active-active for the BGP ECMP mesh.
    activeActive: true
    defaultSiteId: i == 1 ? deliveryLocalGateway.id : ''
    sku: providerVpnGatewaySku
    tags: tags
  }
}]
module peerings 'modules/peering.bicep' = [for i in range(0, 2): {
  name: 'provider-peering-${i}-${suffix}'
  params: { spokeName: networks[2].name, hubName: networks[i].name, gatewayTransit: i == 1 }
  dependsOn: [gateways, parallelIngressRouteServer]
}]
module ingressRouteServer 'modules/route-server.bicep' = if (!parallelProviderNetworking) {
  name: 'provider-route-server-ingress-${suffix}'
  params: {
    location: location
    name: 'rs-${definitions[0].name}-${suffix}'
    tags: tags
    subnetId: '${networks[0].id}/subnets/RouteServerSubnet'
    peerIp: '172.22.10.4'
  }
  dependsOn: [peerings]
}
module parallelIngressRouteServer 'modules/route-server.bicep' = if (parallelProviderNetworking) {
  name: 'provider-route-server-ingress-parallel-${suffix}'
  params: {
    location: location
    name: 'rs-${definitions[0].name}-${suffix}'
    tags: tags
    subnetId: '${networks[0].id}/subnets/RouteServerSubnet'
    peerIp: '172.22.10.4'
    createPeer: false
  }
}
module parallelIngressPeer 'modules/route-server-peer.bicep' = if (parallelProviderNetworking) {
  name: 'provider-route-server-peer-parallel-${suffix}'
  params: {
    routeServerName: 'rs-${definitions[0].name}-${suffix}'
    peerIp: '172.22.10.4'
  }
  dependsOn: [parallelIngressRouteServer, peerings]
}
resource loadBalancer 'Microsoft.Network/loadBalancers@2025-05-01' = {
  name: 'lb-security-${suffix}'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: {
    frontendIPConfigurations: [{
      name: 'internal'
      properties: {
        privateIPAllocationMethod: 'Static'
        privateIPAddress: vip
        privateIPAddressVersion: 'IPv4'
        subnet: { id: '${networks[2].id}/subnets/firewall' }
      }
    }]
    backendAddressPools: [{ name: 'nvas' }]
    probes: [{
      name: 'health'
      properties: { protocol: 'Http', port: 9999, requestPath: '/', intervalInSeconds: 5, numberOfProbes: 2 }
    }]
    loadBalancingRules: [{
      name: 'ha-ports'
      properties: {
        protocol: 'All'
        frontendPort: 0
        backendPort: 0
        enableFloatingIP: true
        disableOutboundSnat: true
        frontendIPConfiguration: { id: resourceId('Microsoft.Network/loadBalancers/frontendIPConfigurations', 'lb-security-${suffix}', 'internal') }
        backendAddressPool: { id: resourceId('Microsoft.Network/loadBalancers/backendAddressPools', 'lb-security-${suffix}', 'nvas') }
        probe: { id: resourceId('Microsoft.Network/loadBalancers/probes', 'lb-security-${suffix}', 'health') }
      }
    }]
  }
}
// Internal Standard LB disables implicit outbound: each NVA needs explicit update egress.
// The lab NSG allows all traffic, including access to the NVA public IPs.
resource nvaPips 'Microsoft.Network/publicIPAddresses@2025-05-01' = [for i in range(0, 2): {
  name: 'pip-nva-${i}-${suffix}'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static', publicIPAddressVersion: 'IPv4' }
}]
module nvas 'modules/provider-nva.bicep' = [for i in range(0, 2): {
  name: 'provider-nva-${i}-${suffix}'
  params: {
    location: location
    name: 'nva-${i}-${suffix}'
    tags: tags
    subnetId: '${networks[2].id}/subnets/firewall'
    privateIp: i == 0 ? '172.22.10.4' : '172.22.10.5'
    sshPublicKey: sshPublicKey
    publicIpId: nvaPips[i].id
    backendPoolId: '${loadBalancer.id}/backendAddressPools/nvas'
    ingressRouteServerName: 'rs-${definitions[0].name}-${suffix}'
    bgpEnabled: i == 0
  }
  dependsOn: [ingressRouteServer, parallelIngressPeer]
}]
module ingressConnection 'modules/connection.bicep' = {
  name: 'provider-ingress-connection-${suffix}'
  params: {
    location: location
    name: 'pi-${suffix}'
    tags: tags
    gatewayId: gateways[0].outputs.id
    remoteEndpoint: { publicIp: customerIngressPublicIp, bgpAddress: customerIngressBgpAddress, asn: customerIngressAsn }
    remotePrefixes: ['172.18.0.0/16']
    sharedKey: ingressSharedKey
  }
  dependsOn: [ingressRouteServer, parallelIngressPeer]
}
module deliveryConnection 'modules/connection.bicep' = {
  name: 'provider-delivery-connection-${suffix}'
  params: {
    location: location
    name: 'pd-${suffix}'
    tags: tags
    gatewayId: gateways[1].outputs.id
    remoteEndpoint: { publicIp: customerDeliveryPublicIp, bgpAddress: customerDeliveryBgpAddress, asn: customerDeliveryAsn }
    remotePrefixes: ['${customerDeliveryBgpAddress}/32']
    enableBgp: true
    useExistingLocalGateway: true
    sharedKey: deliverySharedKey
  }
}
module deliverySecondaryConnection 'modules/connection.bicep' = if (!empty(customerDeliverySecondaryPublicIp)) {
  name: 'provider-delivery-connection-2-${suffix}'
  params: {
    location: location
    name: 'pd-${suffix}-2'
    tags: tags
    gatewayId: gateways[1].outputs.id
    remoteEndpoint: { publicIp: customerDeliverySecondaryPublicIp, bgpAddress: customerDeliverySecondaryBgpAddress, asn: customerDeliveryAsn }
    remotePrefixes: ['${customerDeliverySecondaryBgpAddress}/32']
    enableBgp: true
    sharedKey: deliverySharedKey
  }
  dependsOn: [deliveryConnection]
}
output connectionManifest object = {
  providerIngress: gateways[0].outputs.endpoint
  providerDelivery: gateways[1].outputs.endpoint
  firewallVip: vip
}
