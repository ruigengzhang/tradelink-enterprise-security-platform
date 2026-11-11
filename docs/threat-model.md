# TradeLink threat model (STRIDE-inspired)

## Assets and actors

- **Customers:** US buyers and overseas suppliers.
- **Security principals:** business users, SOC analysts and a security administrator.
- **Assets:** order ownership, product catalog, authentication sessions, audit events and incident evidence.
- **External inputs:** HTTP JSON bodies, usernames, product search strings and source IP data.
- **Trust boundaries:** browser/client → API; API → SQLite; business API → SOC API; analyst → admin approval; synthetic cloud/agent fixture → detection.

## Attack paths and controls

| Threat | Possible impact | Control and evidence |
|---|---|---|
| Broken object-level authorization (BOLA/IDOR) | Cross-tenant order disclosure | Tenant included in every order query, foreign orders respond 404; integration test |
| SQL injection | Tenant-bypass, data exposure | SQLite parameter placeholders; search escapes literal wildcards |
| Credential guessing | Account takeover | Auth failure audit + threshold alert; **not** a complete rate limiter |
| Token theft | Unauthorized access | Opaque 256-bit token, hash stored, 1h expiry, explicit revocation; TLS needed outside local lab |
| Abuse of bulk export | Customer contact disclosure | Export-count monitoring; no real export data in lab |
| SOC privilege abuse | Unapproved containment | Analyst requests; separate admin approval; atomic revocation in DB |
| Cloud IAM drift | Privilege increase | Synthetic log rule only; needs CloudTrail and AWS integration |
| Agent tool misuse | Unauthorized account update | Synthetic denied-event rule only; needs real Keycloak/agent integration |
| Audit tampering | Loss of investigation evidence | Current SQLite events are **not immutable**; future append-only remote log sink |
| Denial of service | API unavailability | Request size cap; no gateway rate limiting in this MVP |

## Remaining risk

Shared seeded demo password and unsecured local HTTP are explicitly lab-only. Application startup and SQLite are not a deployment hardening recipe. No real log integrity, HA, data retention, secrets service, cloud perimeter or automatic kill-switch is present.

## Validation

Use `pytest -q` and the case approval/revocation scenario. Open issues for gaps before publishing any “production-grade” claims.
