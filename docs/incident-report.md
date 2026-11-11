# Sample incident report — TL-IR-005

**Status:** Exercise illustration; not a real breach.

**System:** TradeLink fictional B2B marketplace.
**Detection:** TL-101/TL-102/TL-103/TL-104.
**Classification:** Suspicious supplier account activity; synthetic test.

## Summary

The scenario generates failed authentication attempts, successful access from an unfamiliar lab IP, rejected cross-tenant order requests and a simulated 1,500-record export. The combination is higher priority than any one signal. Because each cross-tenant request returned 404, those attempts **did not demonstrate successful tenant disclosure**. A logged export count is not proof of data egress.

## Evidence

Inspect `GET /api/security/events` filtered by event type and match alert `evidence` IDs. Capture the username, source IP, timestamp, HTTP decision and business tenant. No customer data, secret or token is needed in an incident report.

## Impact

No actual customer impact. This is an isolated test with artificial records. A real-world assessment would require endpoint/network telemetry, application export details and token lineage.

## Triage

1. Correlate TL-101, TL-102 and TL-103 for a shared principal.
2. Validate account ownership, expected IP changes and authorized business activity.
3. Request analyst-approved containment when warranted.
4. Have a separate security administrator approve the action.
5. Verify session invalidation and preserve audit evidence.

## Root cause / learning

The lab intentionally generates a compromise-shaped sequence. Do not claim a real root cause from generated signals. The exercise validates authorization controls, alert logic and the case-to-response workflow.

## Follow-up

Add MFA, adaptive login throttling, source reputation enrichment, immutable audit storage, EDR/cloud correlation and measured detection latency.
