targetScope = 'resourceGroup'
@allowed(['eastus2', 'eastus', 'northeurope', 'westeurope', 'israelcentral'])
param location string = 'eastus2'
param runId string
param sshPublicKey string
@maxLength(16)
param adminAllowedSources array = []
var normalizedAdminSources = [for source in adminAllowedSources: contains(trim(source), '/') ? trim(source) : '${trim(source)}/32']
var adminSources = union(normalizedAdminSources, normalizedAdminSources)
var adminReturnRoutes = [for (source, i) in adminSources: {
  name: 'approved-admin-${i}'
  properties: { addressPrefix: source, nextHopType: 'Internet' }
}]
@description('Customer Routing Appliance bandwidth in Gbps. Only the existing verified 10-Gbps option is exposed.')
@allowed([10])
param routingApplianceBandwidthGbps int = 10
@description('Customer ingress VPN gateway SKU. Defaults to the lowest-priced supported BGP-capable new-deployment SKU.')
@allowed(['VpnGw1AZ', 'VpnGw2AZ', 'VpnGw3AZ', 'VpnGw4AZ', 'VpnGw5AZ'])
param customerIngressVpnGatewaySku string = 'VpnGw1AZ'
@description('Customer delivery VPN gateway SKU. Basic is excluded because delivery requires BGP.')
@allowed(['VpnGw1AZ', 'VpnGw2AZ', 'VpnGw3AZ', 'VpnGw4AZ', 'VpnGw5AZ'])
param customerDeliveryVpnGatewaySku string = 'VpnGw1AZ'
@description('standard: Standard_B1ms test VMs. high-performance: Standard_D8s_v6 with accelerated networking, MTU 9000 and an iperf3 server.')
@allowed(['standard', 'high-performance'])
param workloadVmProfile string = 'standard'
var highPerformance = workloadVmProfile == 'high-performance'
var tags = { purpose: 'provider-provisioning-customer', labRun: runId }
var workloadPrefixes = ['10.211.0.0/16', '10.212.0.0/16']
var ingressWorkloadRoutes = [for (prefix, i) in workloadPrefixes: {
  name: 'workload-${i}-via-ci'
  properties: { addressPrefix: prefix, nextHopType: 'VirtualNetworkGateway' }
}]
resource ingressRoutes 'Microsoft.Network/routeTables@2025-05-01' = {
  name: 'rt-customer-ra-egress'
  location: location
  tags: tags
  properties: {
    disableBgpRoutePropagation: false
    routes: concat(ingressWorkloadRoutes, [{
      name: 'internet-via-ci'
      properties: { addressPrefix: '0.0.0.0/0', nextHopType: 'VirtualNetworkGateway' }
    }])
  }
}
resource ingress 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: 'vnet-customer-ingress'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: ['172.18.0.0/16'] }
    subnets: [
      { name: 'GatewaySubnet', properties: { addressPrefix: '172.18.255.0/27' } }
      {
        name: 'VirtualNetworkApplianceSubnet'
        properties: { addressPrefix: '172.18.10.0/24' }
      }
    ]
  }
}
resource delivery 'Microsoft.Network/virtualNetworks@2025-05-01' = {
  name: 'vnet-customer-delivery'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: ['172.19.0.0/16'] }
    subnets: [{ name: 'GatewaySubnet', properties: { addressPrefix: '172.19.255.0/27' } }]
  }
}
resource appliance 'Microsoft.Network/virtualNetworkAppliances@2026-03-01' = {
  name: 'ra-customer-ingress'
  location: location
  tags: tags
  properties: {
    bandwidthInGbps: routingApplianceBandwidthGbps
    privateIPAddressVersion: 'IPv4'
    subnet: { id: '${ingress.id}/subnets/VirtualNetworkApplianceSubnet' }
  }
  dependsOn: [ci]
}
module applianceRoutes 'modules/customer-ra-routes.bicep' = {
  name: 'customer-ra-route-association'
  params: {
    ingressNetworkName: ingress.name
    routeTableId: ingressRoutes.id
  }
  dependsOn: [appliance, ci]
}
// The service assigns an address. Never assume .4 or synthesize a forwarding address.
var appliancePrimary = filter(appliance.properties.ipConfigurations, configuration => configuration.properties.primary == true)[0].properties.privateIPAddress
resource spokeRoutes 'Microsoft.Network/routeTables@2025-05-01' = [for (prefix, i) in workloadPrefixes: {
  name: 'rt-customer-${i}'
  location: location
  tags: tags
  properties: {
    disableBgpRoutePropagation: false
    routes: concat([
      {
        name: 'other-workload-via-ra'
        properties: {
          addressPrefix: workloadPrefixes[1 - i]
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: appliancePrimary
        }
      }
      {
        name: 'internet-via-ra'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: appliancePrimary
        }
      }
    ], adminReturnRoutes)
  }
}]
var legacyWorkloadRules = [
  {
    name: 'allow-all-inbound'
    properties: {
      priority: 100
      access: 'Allow'
      direction: 'Inbound'
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
      access: 'Allow'
      direction: 'Outbound'
      protocol: '*'
      sourceAddressPrefix: '*'
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: '*'
    }
  }
]
resource nsg 'Microsoft.Network/networkSecurityGroups@2025-05-01' = {
  name: 'nsg-customer-workloads'
  location: location
  tags: tags
  properties: empty(adminSources) ? { securityRules: legacyWorkloadRules } : {}
}
var workloadAdminRules = [
  {
    name: 'allow-private-workloads'
    properties: {
      priority: 100, access: 'Allow', direction: 'Inbound', protocol: '*'
      sourceAddressPrefixes: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
      sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRange: '*'
    }
  }
  {
    name: 'allow-approved-admin-ssh'
    properties: {
      priority: 150, access: 'Allow', direction: 'Inbound', protocol: 'Tcp'
      sourceAddressPrefixes: adminSources
      sourcePortRange: '*', destinationAddressPrefix: '*', destinationPortRange: '22'
    }
  }
]
// No explicit deny: Azure's default DenyAllInBound already blocks other Internet inbound, while the default
// AllowVnetInBound keeps firewall-inspected east-west traffic working if subscription governance strips the
// custom allow rules (observed on customer-24-r2, where a priority-200 deny then blocked all east-west traffic).
resource workloadAdminNsgRules 'Microsoft.Network/networkSecurityGroups/securityRules@2025-05-01' = [for rule in workloadAdminRules: if (!empty(adminSources)) {
  parent: nsg
  name: rule.name
  properties: rule.properties
}]
resource workloadPublicIps 'Microsoft.Network/publicIPAddresses@2025-05-01' = [for (prefix, i) in workloadPrefixes: if (!empty(adminSources)) {
  name: 'pip-customer-workload-${i}'
  location: location
  tags: tags
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}]
resource workloads 'Microsoft.Network/virtualNetworks@2025-05-01' = [for (prefix, i) in workloadPrefixes: {
  name: 'vnet-customer-workload-${i}'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [prefix] }
    subnets: [{
      name: 'workload'
      properties: {
        addressPrefix: i == 0 ? '10.211.0.0/24' : '10.212.0.0/24'
        defaultOutboundAccess: false
        routeTable: { id: spokeRoutes[i].id }
        networkSecurityGroup: { id: nsg.id }
      }
    }]
  }
}]
module ci 'modules/gateway.bicep' = {
  name: 'customer-ingress-gateway'
  params: {
    location: location
    name: 'customer-ingress'
    sku: customerIngressVpnGatewaySku
    subnetId: '${ingress.id}/subnets/GatewaySubnet'
    asn: 65020
    tags: tags
  }
}
module cd 'modules/gateway.bicep' = {
  name: 'customer-delivery-gateway'
  params: {
    location: location
    name: 'customer-delivery'
    sku: customerDeliveryVpnGatewaySku
    subnetId: '${delivery.id}/subnets/GatewaySubnet'
    asn: 65021
    tags: tags
  }
}
module ingressPeerings 'modules/peering.bicep' = [for (prefix, i) in workloadPrefixes: {
  name: 'customer-ingress-peering-${i}'
  params: { spokeName: workloads[i].name, hubName: ingress.name, gatewayTransit: false }
}]
module deliveryPeerings 'modules/peering.bicep' = [for (prefix, i) in workloadPrefixes: {
  name: 'customer-delivery-peering-${i}'
  params: { spokeName: workloads[i].name, hubName: delivery.name, gatewayTransit: true }
  dependsOn: [cd]
}]
module workloadVms 'modules/vm.bicep' = [for (prefix, i) in workloadPrefixes: {
  name: 'customer-workload-vm-${i}'
  params: {
    location: location
    name: 'customer-workload-${i}'
    tags: tags
    subnetId: '${workloads[i].id}/subnets/workload'
    privateIp: i == 0 ? '10.211.0.4' : '10.212.0.4'
    sshPublicKey: sshPublicKey
    publicIpId: empty(adminSources) ? '' : workloadPublicIps[i].id
    size: highPerformance ? 'Standard_D8s_v6' : 'Standard_B1ms'
    acceleratedNetworking: highPerformance
    diskControllerType: highPerformance ? 'NVMe' : ''
    cloudInit: highPerformance ? loadTextContent('cloud-init/workload-performance.yaml') : loadTextContent('cloud-init/workload.yaml')
  }
}]
output customerEndpoints object = {
  customerIngress: ci.outputs.endpoint
  customerDelivery: cd.outputs.endpoint
}
output routingAppliancePrivateIp string = appliancePrimary
