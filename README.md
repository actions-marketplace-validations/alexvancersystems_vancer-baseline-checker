# 🛡️ Vancer Baseline Checker

A lightweight, production-grade GitHub Action designed to act as an automated security gating mechanism for your Infrastructure as Code (IaC). 

`vancer-baseline-checker` statically analyzes touched Terraform and OpenTofu files on every Pull Request, detects security drift against baseline standards, leaves detailed inline feedback, and blocks non-compliant infrastructure from merging into production.

---

## Key Features

- **Automated S3 Security Checks:** Identifies missing `aws_s3_bucket_public_access_block` configuration and flags public ACLs (`public-read`, `public-read-write`).
- **Network Ingress Audit:** Flags unrestricted incoming traffic (`0.0.0.0/0`) on sensitive infrastructure ports (SSH `22`, RDP `3389`, PostgreSQL `5432`, MySQL `3306`, MongoDB `27017`).
- **Encryption at Rest Verification:** Ensures KMS / customer-managed encryption is explicitly active on EBS volumes, RDS instances, and S3 buckets.
- **IAM Over-Privilege Protection:** Catches risky `"Action": "*"` and `"Resource": "*"` wildcard policies before deployment.
- **Rich PR Feedback:** Automatically posts a clear Markdown comment with violation tables, affected line numbers, and actionable remediations.
- **Fail-Safe Gate:** Exits with code `1` on critical violations to natively block non-compliant PR merges.

---

## Quick Start

Add `.github/workflows/vancer-checker.yml` to your repository:

```yaml
name: Vancer Baseline Security Gate

on:
  pull_request:
    branches: [ main, master ]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run Vancer Baseline Checker
        uses: alexvancersystems/vancer-baseline-checker@v1.0.0

Enterprise Ready
vancer-baseline-checker is an open-source companion tool to Vancer Baseline One — the commercial, enterprise-hardened AWS & Terraform infrastructure baseline designed for rapid startup onboarding, SOC 2, and GDPR compliance.

License
Distributed under the MIT License. See LICENSE for more information.
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          fail_on_violation: true
