## Deployment order (must follow)

### Phase 1: DNS ownership (Network account)
1. Deploy the hosted zone StackSet **from the Shared resources account (XXXXXXXXXXXX)** into the **Network account (XXXXXXXXXXXX)**.
   - Template: `templates/network/hosted-zone-stackset.yaml`
   - Parameter: `DomainName` (e.g. `example.com`)