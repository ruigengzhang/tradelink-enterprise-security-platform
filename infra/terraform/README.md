# AWS IaC extension — not deployed

This is a **plan-only, optional** AWS infrastructure template for private CloudTrail log archival storage. It is not used by the local Flask lab and no live AWS API is called by the automated tests.

- A globally unique S3 bucket name is required.
- Versioning, SSE-S3 and block-public-access are enabled.
- This is **not an active CloudTrail integration**; no trail is deployed.
- Do not commit Terraform state files or credentials.

Preflight (Terraform installed):
```bash
terraform init -backend=false
terraform validate
```

Do not run apply until you understand billing, AWS permissions and resource ownership. Destroy any test resources after use.
