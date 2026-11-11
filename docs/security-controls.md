# Security standard and risk register

| Control | Status | Evidence | Gap |
|---|---|---|---|
| Tenant authorization | Implemented in API | Order API test | Add dedicated RBAC policy engine |
| Password hashing | Implemented | PBKDF2-HMAC-SHA256 | Production identity provider, MFA |
| Session revocation | Implemented | Approval/revocation test | Enforce credential rotation post-compromise |
| SOC approval boundary | Implemented | Analyst vs admin roles | Organization-wide separation of duties |
| Audit logging | Implemented locally | SQLite event store | Immutable external forwarding and retention |
| Detection-as-code | Implemented | 8 code rules | Native SIEM rules, real-time ingestion |
| AWS infrastructure | Template only | Terraform S3 example | Actually provision and audit resources |
| AI agent security | Synthetic signal only | Scenario fixture | Real Keycloak identity and agent integration |
| CI checks | Configured | GitHub Actions workflow | Validate actual runs and add SAST/DAST metrics |
| Incident reporting | Documentation + cases | Runbook/sample report | Evidence preservation chain of custody |

## Risk ownership

In a real organization, assign each risk an accountable owner, severity, due date, exception process and verification evidence. This lab includes only demonstration data and does not claim compliance certification.

## Cost safety

Local Python/SQLite is essentially free. Docker may consume local CPU/RAM. The optional AWS Terraform example creates S3 resources only if manually applied; usage may incur cost. No AWS credential, cloud token or secret should be added to GitHub.
