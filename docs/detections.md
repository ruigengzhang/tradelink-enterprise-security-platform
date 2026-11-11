# Detection-as-Code catalog

All eight detections are implemented in `src/tradelink/detection.py`, operate on SQLite audit events and return IDs of the original evidence. They are **not native Splunk/Elastic/Sentinel rules**.

| ID | Severity | Condition | False-positive discussion |
|---|---|---|---|
| TL-101 | High | 5+ authentication failures from same user/IP within 10 min | Password manager retries |
| TL-102 | Medium | A successful login from an IP absent from prior successful sessions | VPN, hotel Wi-Fi |
| TL-103 | High | 2+ foreign-tenant order access attempts rejected | Stale URL, client bug |
| TL-104 | Critical | A synthetic export involving >=500 records | Authorized bulk report |
| TL-105 | Critical | Role set to admin with approved=false in audit payload | Broken approval metadata |
| TL-106 | Medium | 2+ denied product write attempts by same principal | Mistaken UI permission |
| TL-107 | High | Synthetic cloud IAM policy change with approved=false | Approved emergency change |
| TL-108 | Medium | Synthetic AI agent tool denied event | Legitimate guardrail block |

Detection ID != incident certainty. An order read returning HTTP 404 proves the boundary held for that request; it does not establish successful access. A synthetic export count cannot establish external transmission. TL-107 and TL-108 only prove the log records were recognized.

## Workflow and gaps

1. Read raw audit event and cross-reference evidence IDs.
2. Determine entity, affected tenant, activity outcome and preceding baseline.
3. Record true positive / false positive / inconclusive disposition.
4. Request containment with a reason; have a separate admin review it.
5. Verify session revocation, document scope and any remaining uncertainty.

The CLI runs detections on demand; no worker currently processes events continuously. Use integration tests to quantify behavior, but don't claim a measured false-positive rate from this limited fixture.
