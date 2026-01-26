# AWS Website Pattern (Pulumi)

A reusable infrastructure template for deploying a secure static website on AWS using **S3**, **CloudFront**, **Cognito**, and **Lambda**, managed with **Pulumi**.

This repo is intended to be cloned and adapted when provisioning a new website (e.g. `example.com`) using a consistent, multi-account AWS pattern.

---

## What This Is

This project defines a standard pattern for:

- Hosting a static website in S3  
- Serving it via CloudFront  
- Using Cognito for authentication  
- Using Lambda for authorization / request handling  
- Managing everything as code with Pulumi  

It is designed to support multiple isolated environments (staging and production) and shared organisational infrastructure.

---

## Account Model

The template assumes an AWS Organization with four accounts:

- **Provisioning account**  
  Runs the Pulumi CLI and deploys all infrastructure.

- **Shared network account**  
  Holds shared resources such as VPCs, Route 53 hosted zones, and ACM certificates.

- **Staging account**  
  Hosts the staging website and supporting services.

- **Production account**  
  Hosts the production website and supporting services.

Each website environment is fully isolated in its own AWS account.

---

## How It’s Used

Typical workflow for a new site:

1. Clone this repo  
2. Update domain-specific configuration (e.g. `example.com`)  
3. Create Pulumi stacks for:
   - shared network  
   - staging  
   - production  
4. Run Pulumi from the provisioning account (Windows PowerShell)  
5. Validate staging  
6. Promote to production  

---

## Tooling

- **Infrastructure as Code:** Pulumi  
- **Cloud Provider:** AWS  
- **CLI Environment:** Windows PowerShell  

---

## Scope

This README is intentionally high-level.

Detailed operational steps, configuration reference, and troubleshooting notes will live in a separate **runbook** (or expanded README) as this pattern matures.

---

## Status

Early-stage template / evolving pattern.  
Structure and conventions may change as new sites are onboarded.

---

## License

MIT
