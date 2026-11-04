using './main.bicep'

param location = 'israelcentral'
param hubPrefix = '10.253.0.0/23'
param tags = {
  purpose: 'ipsec-vwan-lab'
  labRun: 'preparation-only'
}
