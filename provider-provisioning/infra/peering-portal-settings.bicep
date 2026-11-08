targetScope = 'resourceGroup'

@minLength(1)
param managementAppName string
@description('Complete current settings merged with peering-only additions. Keep recovery/parameter files private.')
@secure()
param appSettings object

resource app 'Microsoft.Web/sites@2023-12-01' existing = {
  name: managementAppName
}
resource settings 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: app
  name: 'appsettings'
  properties: appSettings
}
