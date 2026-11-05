targetScope = 'resourceGroup'

@description('Experimental Check Point provider foundation. Not a complete firewall deployment.')
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
@secure()
param ingressSharedKey string
@secure()
param deliverySharedKey string
@maxLength(16)
param adminAllowedSources array = []
@allowed(['single', 'vmss'])
param firewallTopology string = 'single'
@description('SKU of both provider VPN gateways (ingress and delivery).')
@allowed(['VpnGw1AZ', 'VpnGw2AZ', 'VpnGw3AZ', 'VpnGw4AZ', 'VpnGw5AZ'])
param providerVpnGatewaySku string = 'VpnGw1AZ'

var suffix = take(environmentId, 8)
var tags = { purpose: 'provider-provisioning-checkpoint-foundation', environmentId: environmentId }
var firewallPrivateIp = '172.22.10.4'
// The two scale set instances take the first free frontend addresses; the runner verifies them.
var secondaryFirewallPrivateIp = firewallTopology == 'vmss' ? '172.22.10.5' : ''
var securityVnetName = 'vnet-cp-security-${suffix}'
var adminReturnRoutes = [for (source, i) in adminAllowedSources: {
  name: 'approved-admin-${i}'
  properties: { addressPrefix: source, nextHopType: 'Internet' }
}]

resource ingressRoutes 'Microsoft.Network/routeTables@2025-05-01' = {
  name: 'rt-cp-pi-${suffix}'
  location: location
  tags: tags
  properties: { disableBgpRoutePropagation: false, routes: [] }
}
resource securityRoutes 'Microsoft.Network/routeTables@2025-05-01' = {
  name: 'rt-cp-security-${suffix}'
  location: location
  tags: tags
  properties: {
    disableBgpRoutePropagation: false
    routes: concat([{ name: 'firewall-internet', properties: { addressPrefix: '0.0.0.0/0', nextHopType: 'Internet' } }], adminReturnRoutes)
  }
}
resource managementRoutes 'Microsoft.Network/routeTables@2025-05-01' = if (!empty(adminAllowedSources)) {
  name: 'rt-cp-management-${suffix}'
  location: location
  tags: tags
  properties: {
    disableBgpRoutePropagation: false
    routes: [for (source, i) in adminAllowedSources: {
      name: 'approved-admin-${i}'
      properties: { addressPrefix: source, nextHopType: 'Internet' }
    }]
  }
}
resource firewallNsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: 'nsg-cp-firewall-${suffix}'
  location: location
  tags: tags
  properties: empty(adminAllowedSources) ? {
    securityRules: [
      {
        name: 'lab-allow-all-inbound'
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
        name: 'lab-allow-all-outbound'
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
    ]
  } : {}
}
var legacyManagementRules = [
  {
    name: 'allow-provider-management'
    properties: {
      priority: 100
      direction: 'Inbound'
      access: 'Allow'
      protocol: '*'
      sourceAddressPrefixes: ['172.22.10.4/32', '172.22.10.5/32', '172.22.20.4/32', '172.22.30.0/24', '172.22.40.0/23']
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: '*'
    }
  }
  {
    name: 'deny-other-inbound'
    properties: {
      priority: 200
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
resource managementNsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: 'nsg-cp-management-${suffix}'
  location: location
  tags: tags
  properties: empty(adminAllowedSources) ? { securityRules: legacyManagementRules } : {}
}
// Child rules are additive: retries do not replace user-owned NSG rules.
var adminNsgRules = [
  {
    name: 'allow-provider-private'
    properties: {
      priority: 100, direction: 'Inbound', access: 'Allow', protocol: '*'
      sourceAddressPrefixes: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
      sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRange: '*'
    }
  }
  {
    name: 'allow-approved-admin'
    properties: {
      priority: 150, direction: 'Inbound', access: 'Allow', protocol: 'Tcp'
      sourceAddressPrefixes: adminAllowedSources
      sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRanges: ['22', '443']
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
resource firewallAdminRules 'Microsoft.Network/networkSecurityGroups/securityRules@2025-05-01' = [for rule in adminNsgRules: if (!empty(adminAllowedSources)) {
  parent: firewallNsg
  name: rule.name
  properties: rule.properties
}]
resource managementAdminRules 'Microsoft.Network/networkSecurityGroups/securityRules@2025-05-01' = [for (rule, i) in adminNsgRules: if (!empty(adminAllowedSources)) {
  parent: managementNsg
  name: rule.name
  properties: union(rule.properties, i == 0 ? {
    sourceAddressPrefixes: ['172.22.10.4/32', '172.22.10.5/32', '172.22.20.4/32', '172.22.30.0/24', '172.22.40.0/23']
  } : {}, i == 1 ? { destinationPortRanges: ['22', '443', '18190', '19009'] } : {})
}]
// Scale set health probes; without them the internal load balancer drops all inspected traffic.
resource firewallProbeRule 'Microsoft.Network/networkSecurityGroups/securityRules@2025-05-01' = if (!empty(adminAllowedSources) && firewallTopology == 'vmss') {
  parent: firewallNsg
  name: 'allow-azure-load-balancer'
  properties: {
    priority: 120, direction: 'Inbound', access: 'Allow', protocol: '*'
    sourceAddressPrefix: 'AzureLoadBalancer', sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRange: '*'
  }
}
resource automationNsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: 'nsg-cp-automation-${suffix}'
  location: location
  tags: tags
  properties: {
    securityRules: [{
      name: 'deny-inbound'
      properties: {
        priority: 100
        direction: 'Inbound'
        access: 'Deny'
        protocol: '*'
        sourceAddressPrefix: '*'
        sourcePortRange: '*'
        destinationAddressPrefix: '*'
        destinationPortRange: '*'
      }
    }]
  }
}
resource automationPublicIp 'Microsoft.Network/publicIPAddresses@2025-05-01' = {
  name: 'pip-cp-automation-${suffix}'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}
resource automationNat 'Microsoft.Network/natGateways@2025-05-01' = {
  name: 'nat-cp-automation-${suffix}'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: { publicIpAddresses: [{ id: automationPublicIp.id }] }
}

var gatewayNetworks = [
  { name: 'cp-pi', prefix: '172.20.0.0/16', gatewaySubnet: '172.20.255.0/27' }
  { name: 'cp-pd', prefix: '172.21.0.0/16', gatewaySubnet: '172.21.255.0/27' }
]
resource networks 'Microsoft.Network/virtualNetworks@2025-05-01' = [for (definition, i) in gatewayNetworks: {
  name: 'vnet-${definition.name}-${suffix}'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [definition.prefix] }
    subnets: concat([{
      name: 'GatewaySubnet'
      properties: union({ addressPrefix: definition.gatewaySubnet },
        i == 0 ? { routeTable: { id: ingressRoutes.id } } : {})
    }], i == 0 ? [{ name: 'RouteServerSubnet', properties: { addressPrefix: '172.20.254.0/26' } }] : [])
  }
}]
resource securityVnet 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: securityVnetName
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: ['172.22.0.0/16'] }
    subnets: [
      {
        name: 'firewall-frontend'
        properties: {
          addressPrefix: '172.22.10.0/24'
          routeTable: { id: securityRoutes.id }
          networkSecurityGroup: { id: firewallNsg.id }
          defaultOutboundAccess: true
        }
      }
      {
        name: 'firewall-backend'
        properties: {
          addressPrefix: '172.22.20.0/24'
          networkSecurityGroup: { id: firewallNsg.id }
          defaultOutboundAccess: true
        }
      }
      {
        name: 'management'
        properties: union({
          addressPrefix: '172.22.30.0/24'
          networkSecurityGroup: { id: managementNsg.id }
          defaultOutboundAccess: false
        }, empty(adminAllowedSources) ? {} : { routeTable: { id: managementRoutes!.id } })
      }
      {
        name: 'automation'
        properties: {
          addressPrefix: '172.22.40.0/23'
          defaultOutboundAccess: false
          networkSecurityGroup: { id: automationNsg.id }
          natGateway: { id: automationNat.id }
          routeTable: { id: securityRoutes.id }
          delegations: [{
            name: 'container-instances'
            properties: { serviceName: 'Microsoft.ContainerInstance/containerGroups' }
          }]
        }
      }
      {
        name: 'private-endpoints'
        properties: { addressPrefix: '172.22.42.0/24', privateEndpointNetworkPolicies: 'Disabled', defaultOutboundAccess: false }
      }
    ]
  }
}
resource deliveryLocalGateway 'Microsoft.Network/localNetworkGateways@2025-05-01' = {
  name: 'lng-cp-pd-${suffix}'
  location: location
  tags: tags
  properties: {
    gatewayIpAddress: customerDeliveryPublicIp
    localNetworkAddressSpace: { addressPrefixes: ['${customerDeliveryBgpAddress}/32'] }
    bgpSettings: { asn: customerDeliveryAsn, bgpPeeringAddress: customerDeliveryBgpAddress }
  }
}
module gateways 'modules/gateway.bicep' = [for i in range(0, 2): {
  name: 'checkpoint-gateway-${i}-${suffix}'
  params: {
    location: location
    name: '${gatewayNetworks[i].name}-${suffix}'
    subnetId: '${networks[i].id}/subnets/GatewaySubnet'
    asn: i == 0 ? 65515 : 65031
    activeActive: i == 0
    defaultSiteId: i == 1 ? deliveryLocalGateway.id : ''
    sku: providerVpnGatewaySku
    tags: tags
  }
}]
module peerings 'modules/peering.bicep' = [for i in range(0, 2): {
  name: 'checkpoint-peering-${i}-${suffix}'
  params: { spokeName: securityVnet.name, hubName: networks[i].name, gatewayTransit: i == 1 }
  dependsOn: [gateways]
}]
module ingressRouteServer 'modules/route-server.bicep' = {
  name: 'checkpoint-route-server-${suffix}'
  params: {
    location: location
    name: 'rs-cp-pi-${suffix}'
    tags: tags
    subnetId: '${networks[0].id}/subnets/RouteServerSubnet'
    peerIp: firewallPrivateIp
  }
  dependsOn: [peerings]
}
module secondaryRouteServerPeer 'modules/route-server-secondary-peer.bicep' = if (firewallTopology == 'vmss') {
  name: 'checkpoint-route-server-peer2-${suffix}'
  params: { routeServerName: 'rs-cp-pi-${suffix}', peerIp: secondaryFirewallPrivateIp }
  dependsOn: [ingressRouteServer]
}
module ingressConnection 'modules/connection.bicep' = {
  name: 'checkpoint-ingress-connection-${suffix}'
  params: {
    location: location
    name: 'cp-pi-${suffix}'
    tags: tags
    gatewayId: gateways[0].outputs.id
    remoteEndpoint: { publicIp: customerIngressPublicIp, bgpAddress: customerIngressBgpAddress, asn: customerIngressAsn }
    remotePrefixes: ['172.18.0.0/16']
    sharedKey: ingressSharedKey
  }
  dependsOn: [ingressRouteServer]
}
module deliveryConnection 'modules/connection.bicep' = {
  name: 'checkpoint-delivery-connection-${suffix}'
  params: {
    location: location
    name: 'cp-pd-${suffix}'
    tags: tags
    gatewayId: gateways[1].outputs.id
    remoteEndpoint: { publicIp: customerDeliveryPublicIp, bgpAddress: customerDeliveryBgpAddress, asn: customerDeliveryAsn }
    remotePrefixes: ['${customerDeliveryBgpAddress}/32']
    enableBgp: true
    useExistingLocalGateway: true
    sharedKey: deliverySharedKey
  }
}

output connectionManifest object = {
  providerIngress: gateways[0].outputs.endpoint
  providerDelivery: gateways[1].outputs.endpoint
}
output checkpointFoundation object = {
  securityVnetId: securityVnet.id
  securityVnetName: securityVnet.name
  firewallFrontendSubnetId: '${securityVnet.id}/subnets/firewall-frontend'
  firewallBackendSubnetId: '${securityVnet.id}/subnets/firewall-backend'
  managementSubnetId: '${securityVnet.id}/subnets/management'
  automationSubnetId: '${securityVnet.id}/subnets/automation'
  automationNsgId: automationNsg.id
  automationNatGatewayId: automationNat.id
  automationPublicIpId: automationPublicIp.id
  privateEndpointsSubnetId: '${securityVnet.id}/subnets/private-endpoints'
  firewallNsgId: firewallNsg.id
  managementNsgId: managementNsg.id
  firewallFrontendPrivateIp: firewallPrivateIp
  firewallBackendPrivateIp: '172.22.20.4'
  routeServerAsn: 65515
  routeServerPeerAddresses: ingressRouteServer.outputs.peerAddresses
  firewallTopology: firewallTopology
}
