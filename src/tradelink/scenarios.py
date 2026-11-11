"""Three isolated, deterministic-style lab scenarios. No external targets are contacted."""
from .app import create_app
from .cli import DEMO_PASSWORD
from .store import connect, log
from .detection import detect


def exercise(db_path):
    app = create_app({"DATABASE": db_path, "TESTING": True})
    client = app.test_client()

    def login(user, ip="198.51.100.10"):
        result = client.post("/api/auth/login", json={"username": user, "password": DEMO_PASSWORD},
                             environ_base={"REMOTE_ADDR": ip})
        assert result.status_code == 200, result.json
        return result.json["access_token"]

    def auth(token):
        return {"Authorization": "Bearer " + token}

    # Scenario A: first successful supplier session, then password guessing and unfamiliar successful login.
    login("pacific-supplier")
    for _ in range(6):
        r = client.post("/api/auth/login", json={"username": "pacific-supplier", "password": "wrong"},
                        environ_base={"REMOTE_ADDR": "203.0.113.77"})
        assert r.status_code == 401
    compromised = login("pacific-supplier", "203.0.113.77")
    for _ in range(3):
        r = client.get("/api/orders/2002", headers=auth(compromised),
                       environ_base={"REMOTE_ADDR": "203.0.113.77"})
        assert r.status_code == 404
    assert client.post("/api/exports", headers=auth(compromised),
                       json={"record_count": 1500}).status_code == 200

    # Scenario B: synthetic cloud audit signal; no actual AWS access or API call occurs.
    with connect(db_path) as db:
        log(db, "cloud.iam_policy_change", "demo-cloud-worker", "infra", "192.0.2.44",
            "success", {"approved": False, "risk": "wildcard_permissions", "synthetic": True})
        # Scenario C: intentionally blocked AI agent tool request; NOT a successful privilege change.
        log(db, "agent.tool_denied", "north-invoice-agent", "north", "192.0.2.45",
            "denied", {"tool": "change_bank_account", "reason": "scope_denied", "synthetic": True})
        new = detect(db)
        alerts = [dict(x) for x in db.execute(
            "SELECT rule_id,severity,actor,evidence_json FROM alerts ORDER BY rule_id"
        )]
    return {"scenario_count": 3, "new_alerts": new, "alerts": alerts,
            "notice": "Cloud and AI signals are synthetic fixtures; web/API scenario uses Flask test client."}
