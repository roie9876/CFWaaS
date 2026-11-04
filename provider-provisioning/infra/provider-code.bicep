targetScope = 'resourceGroup'

param apiAppName string
param workerAppName string
@description('Read-only provider blob SAS for the byte-pinned deployment ZIP. Never output this value.')
@secure()
param packageUri string

resource publish 'Microsoft.Web/sites/extensions@2021-03-01' = [for app in [apiAppName, workerAppName]: {
  name: '${app}/onedeploy'
  properties: {
    packageUri: packageUri
    type: 'zip'
    clean: true
    restart: true
  }
}]
