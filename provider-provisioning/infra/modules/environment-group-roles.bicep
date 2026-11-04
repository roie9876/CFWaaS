targetScope = 'subscription'

@minLength(36)
@maxLength(36)
param provisionerPrincipalId string
@minLength(36)
@maxLength(36)
param deployerPrincipalId string
@description('The provisioner can create or update resource groups and can delegate Contributor to the designated identity at subscription scope.')
@allowed([true])
param approveSubscriptionDelegation bool

var contributorId = 'b24988ac-6180-42a0-ab88-20f7382dd24c'
var roleName = guid(subscription().id, provisionerPrincipalId, 'faas-environment-provisioner')
var condition = '(!(ActionMatches{\'Microsoft.Authorization/roleAssignments/write\'}) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {${contributorId}} AND @Request[Microsoft.Authorization/roleAssignments:PrincipalId] ForAnyOfAnyValues:GuidEquals {${deployerPrincipalId}}))'

resource provisionerRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = if (approveSubscriptionDelegation) {
  name: roleName
  properties: {
    roleName: 'FaaS environment provisioner ${uniqueString(subscription().id, provisionerPrincipalId)}'
    description: 'Creates provider environment groups and delegates Contributor to the designated deployment identity.'
    type: 'CustomRole'
    permissions: [{
      actions: [
        'Microsoft.Resources/subscriptions/resourceGroups/read'
        'Microsoft.Resources/subscriptions/resourceGroups/write'
        'Microsoft.Authorization/roleAssignments/read'
        'Microsoft.Authorization/roleAssignments/write'
      ]
      notActions: []
    }]
    assignableScopes: [subscription().id]
  }
}

resource provisionerAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (approveSubscriptionDelegation) {
  name: guid(subscription().id, provisionerPrincipalId, roleName)
  properties: {
    principalId: provisionerPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: provisionerRole.id
    conditionVersion: '2.0'
    condition: condition
  }
}