@description('Existing provider virtual hub name.')
param hubName string

@description('Verified integrated Check Point NVA ARM resource ID, not a private IP.')
param nvaId string

resource hub 'Microsoft.Network/virtualHubs@2025-05-01' existing = {
  name: hubName
}

resource intent 'Microsoft.Network/virtualHubs/routingIntent@2025-05-01' = {
  name: 'routing-intent-cgvwan'
  parent: hub
  properties: {
    routingPolicies: [
      {
        name: 'PrivateTrafficPolicy'
        destinations: ['PrivateTraffic']
        nextHop: nvaId
      }
      {
        name: 'InternetTrafficPolicy'
        destinations: ['Internet']
        nextHop: nvaId
      }
    ]
  }
}

output routingIntentId string = intent.id
