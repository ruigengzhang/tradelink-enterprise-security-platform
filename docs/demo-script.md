# Five-minute demonstration script

1. **Context (30s):** Two tenant workspaces: Pacific and Atlantic. Show the architecture and trust boundaries.
2. **Authorization (45s):** Login Pacific buyer; read order 1001; request Atlantic order 2002 and show HTTP 404.
3. **Adversary sequence (60s):** Run `tradelink-enterprise demo`. Explain which actions were real Flask requests versus synthetic cloud/AI event fixtures.
4. **Detection (60s):** Run `tradelink-enterprise detect` and show evidence-linked alerts. Re-run to show idempotence.
5. **Response (60s):** View cases; analyst requests revocation of supplier sessions; different admin approves; verify old token now returns 401.
6. **Limitations and next phase (45s):** Current audit store is SQLite, not an external SIEM; cloud and AI scenarios are synthetic; plan to add streaming, hosted infrastructure, and real identity integration.

Good interview prompts: Why does a 404 matter? Why is an export event not proof of external exfiltration? How would this detector handle VPN false positives? What checks would you add before automatic containment?
