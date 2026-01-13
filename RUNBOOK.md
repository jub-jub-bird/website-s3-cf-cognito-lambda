# Network Hosted Zone StackSet (Console Runbook)

Purpose: Create the public Route 53 hosted zone for a domain in the Network account, driven from the Shared account.

## Accounts
- Shared resources (StackSet admin): 954837761502
- Network (stack instance target): 718311990857

## Template
- `templates/network/hosted-zone-stackset.yaml`

## Console steps (repeatable)
1. Sign into Shared account (954837761502)
2. CloudFormation → StackSets → Create StackSet
3. Permission model: Service-managed
4. Upload template: `templates/network/hosted-zone-stackset.yaml`
5. StackSet name: `network-hosted-zone-mullinsfam-co-uk`
6. Parameters:
   - DomainName: `mullinsfam.co.uk`
   - NetworkAccountId: `718311990857`
7. Create stack instances:
   - Target account: `718311990857`
   - Region: `eu-west-2` (any region is fine)

## Expected outcome
- Hosted zone `mullinsfam.co.uk` exists in Network account Route 53
- Stack outputs include HostedZoneId and NameServers
