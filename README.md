## Naming convention (StackSets)

Domain slug rule: lowercase domain with dots replaced by hyphens.
Example: `mullinsfam.co.uk` → `mullinsfam-co-uk`

StackSet names:
- Network hosted zone: `net-hz-<domain-slug>`
- Workload CloudFront ACM cert (us-east-1): `wl-acm-cf-<domain-slug>`
- Network ACM DNS validation record (per env): `net-acm-validate-<domain-slug>-<env>` where env is `prod` or `staging`

## Deployment order (must follow)

### Phase 1: DNS ownership (Network account)
1. Deploy the hosted zone StackSet **from the Shared resources account (XXXXXXXXXXXX)** into the **Network account (XXXXXXXXXXXX)**.
   - Template: `templates/network/hosted-zone-stackset.yaml`
   - Parameter: `DomainName` (e.g. `example.com`)
	 
## DNS + CloudFront certificate validation flow (cross-account)

This project uses cross-account DNS validation for CloudFront ACM certificates.

### Ownership
- Route 53 hosted zones live in the **Network account**
- CloudFront distributions and their ACM certificates live in **workload accounts**
- CloudFront ACM certificates are always created in **us-east-1**

### Validation pattern (per domain / environment)
1. A workload StackSet requests an ACM certificate (DNS validation).
   - Certificate remains `Pending validation`.
2. ACM provides **one CNAME per domain name** (e.g. apex and www).
3. A Network StackSet creates the required CNAME records in the hosted zone.
   - One stack instance may create multiple validation records.
4. ACM automatically validates and the certificate transitions to `Issued`.

### Important notes
- Apex and `www` validate independently and may complete at different times.
- This is expected behaviour.
- No cross-account IAM roles are used for DNS writes.