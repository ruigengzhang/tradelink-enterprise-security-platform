# SOC analyst runbook

## Prepare

```bash
tradelink-enterprise seed
tradelink-enterprise demo
tradelink-enterprise serve
```

Open a second terminal for curl. Login as `soc-analyst` and capture the access token in a shell variable (do not commit or print the token).

```bash
BASE=http://127.0.0.1:5000
ANALYST=$(curl -fsS "$BASE/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"soc-analyst","password":"TradeLink-Demo-Only!"}' | python -c 'import json,sys;print(json.load(sys.stdin)["access_token"])')
curl -fsS "$BASE/api/security/alerts" -H "Authorization: Bearer $ANALYST"
curl -fsS "$BASE/api/security/cases" -H "Authorization: Bearer $ANALYST"
```

## Investigate

1. Examine `GET /api/security/events` and choose an alert by rule ID.
2. Cross-reference alert `evidence` with audit event IDs.
3. Determine whether each request was allowed or denied.
4. Decide a disposition: `true_positive`, `false_positive` or `inconclusive`.
5. Set case status and notes:

```bash
curl -fsS -X PATCH "$BASE/api/security/cases/1" \
  -H "Authorization: Bearer $ANALYST" -H 'Content-Type: application/json' \
  -d '{"status":"investigating","disposition":"inconclusive","notes":"Review auth and tenant boundary evidence"}'
```

## Human-approved containment

Choose a case with actor `pacific-supplier`, then request session revocation:

```bash
curl -fsS -X POST "$BASE/api/security/responses" \
  -H "Authorization: Bearer $ANALYST" -H 'Content-Type: application/json' \
  -d '{"case_id":1,"target_user":"pacific-supplier","reason":"Review confirmed suspicious account activity"}'
```

**Replace case_id with a matching actual case ID returned above.** The response gives a request ID.

Login as `security-admin` (not the requester), then approve or reject the response:

```bash
curl -fsS -X POST "$BASE/api/security/responses/1/review" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"decision":"approve"}'
```

The approval atomically revokes all current sessions of the target demo user; it does not disable the account or change cloud IAM. A new login may still be possible, so a production runbook must add password reset/rotation and investigation. No actions occur without approval.

```bash
unset ANALYST ADMIN
```

## Analyst quality checklist

- Confirm the detection evidence and affected tenant.
- Distinguish failed attacks from actual compromise.
- Review business impact before containment.
- Keep analyst/admin separation of duties.
- Document evidence, action, verification and unresolved questions.
