## Naming convention (StackSets)

Domain slug rule: lowercase domain with dots replaced by hyphens.  
Example: `mullinsfam.co.uk` → `mullinsfam-co-uk`

StackSet names:
- Network hosted zone: `net-hz-<domain-slug>`
- Workload CloudFront ACM cert (us-east-1, per env): `wl-acm-cf-<domain-slug>-<env>`
- Network ACM DNS validation record (per env): `net-acm-validate-<domain-slug>-<env>`  
  where `<env>` is `prod` or `staging`

---

## Deployment order (must follow)

### Phase 1: DNS ownership (Network account)
1. Deploy the hosted zone StackSet **from the Shared resources account (954837761502)** into the **Network account (718311990857)**.
   - Template: `templates/network/hosted-zone-stackset.yaml`
   - Parameter: `DomainName` (e.g. `mullinsfam.co.uk`)

---

## Phase 2: CloudFront ACM certs + DNS validation (cross-account)

This project uses cross-account DNS validation for CloudFront ACM certificates.

### Ownership
- Route 53 hosted zones live in the **Network account**
- CloudFront distributions and their ACM certificates live in **workload accounts**
- CloudFront ACM certificates are always created in **us-east-1**

### Deployment steps (per domain)
1. Deploy workload ACM cert StackSets (us-east-1):
   - `wl-acm-cf-<domain-slug>-prod` → targets prod workload account
   - `wl-acm-cf-<domain-slug>-staging` → targets staging workload account
2. Deploy Network validation StackSets:
   - `net-acm-validate-<domain-slug>-prod`
   - `net-acm-validate-<domain-slug>-staging`

Each Network validation StackSet:
- Targets the Network account (718311990857)
- Is operated from the Shared account (954837761502)
- Creates the required ACM DNS validation CNAME records for **one environment only**

### Validation behaviour
- ACM issues **one CNAME per domain name** on the certificate (e.g. apex and `www`)
- Apex and `www` validate independently and may complete at different times
- This is expected behaviour
- No cross-account IAM roles are used for DNS writes

### Important rule
Do **not** reuse a single validation StackSet for both prod and staging.  
Parameter overrides can replace existing DNS records.

Always use **separate validation StackSets per environment**.
