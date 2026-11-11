import json
from tradelink.cli import seed
from tradelink.detection import detect
from tradelink.scenarios import exercise
from tradelink.store import connect
from conftest import login


def test_multi_tenant_order_boundary(lab):
    client, _ = lab
    header = login(client, "pacific-buyer")
    assert client.get("/api/orders/1001", headers=header).status_code == 200
    assert client.get("/api/orders/2002", headers=header).status_code == 404
    assert client.post("/api/orders", headers=header,
                       json={"product_id": 202, "quantity": 1}).status_code == 404


def test_role_enforcement_and_audit(lab):
    client, db = lab
    header = login(client, "pacific-buyer")
    for _ in range(2):
        assert client.post("/api/products", json={"name": "demo", "price_cents": 100},
                           headers=header).status_code == 403
    with connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM events WHERE kind='product.write_denied'").fetchone()["n"] == 2
        assert detect(conn) == 1


def test_login_bad_password_and_logout(lab):
    client, _ = lab
    assert client.post("/api/auth/login", json={"username": "pacific-buyer", "password": "bad"}).status_code == 401
    header = login(client, "pacific-buyer")
    assert client.get("/api/orders", headers=header).status_code == 200
    assert client.post("/api/auth/logout", headers=header).status_code == 200
    assert client.get("/api/orders", headers=header).status_code == 401


def test_security_api_requires_analyst(lab):
    client, _ = lab
    buyer = login(client, "pacific-buyer")
    assert client.get("/api/security/events", headers=buyer).status_code == 403
    assert client.post("/api/security/detect", headers=buyer).status_code == 403
    analyst = login(client, "soc-analyst")
    assert client.get("/api/security/events", headers=analyst).status_code == 200


def test_three_scenarios_create_evidence(lab):
    _, db = lab
    result = exercise(db)
    ids = {a["rule_id"] for a in result["alerts"]}
    assert result["scenario_count"] == 3
    assert {"TL-101", "TL-102", "TL-103", "TL-104", "TL-107", "TL-108"} <= ids
    with connect(db) as conn:
        assert detect(conn) == 0  # Duplicate suppression / idempotence.


def test_response_approval_revokes_sessions(lab):
    client, db = lab
    supplier = login(client, "pacific-supplier")
    analyst = login(client, "soc-analyst")
    admin = login(client, "security-admin")
    with connect(db) as conn:
        from tradelink.store import log
        log(conn, "data.export", "pacific-supplier", "pacific", "127.0.0.1",
            "success", {"record_count": 1000, "synthetic": True})
    assert client.post("/api/security/detect", headers=analyst).json["new_alerts"] == 1
    case_id = client.get("/api/security/cases", headers=analyst).json["cases"][0]["id"]
    response = client.post("/api/security/responses", headers=analyst,
                           json={"case_id": case_id, "target_user": "pacific-supplier",
                                 "reason": "Confirmed synthetic bulk export"})
    assert response.status_code == 201
    request_id = response.json["request_id"]
    assert client.get("/api/orders", headers=supplier).status_code == 200
    decision = client.post(f"/api/security/responses/{request_id}/review", headers=admin,
                           json={"decision": "approve"})
    assert decision.json["status"] == "executed"
    assert client.get("/api/orders", headers=supplier).status_code == 401


def test_no_secret_in_audit_log(lab):
    client, db = lab
    header = login(client, "pacific-buyer")
    assert client.get("/api/orders", headers=header).status_code == 200
    with connect(db) as conn:
        events = [dict(row) for row in conn.execute("SELECT * FROM events")]
    text = json.dumps(events)
    assert "TradeLink-Demo-Only!" not in text
    assert header["Authorization"].split(" ", 1)[1] not in text


def test_approval_is_not_repeatable(lab):
    client, db = lab
    analyst = login(client, "soc-analyst")
    admin = login(client, "security-admin")
    with connect(db) as conn:
        from tradelink.store import log
        log(conn, "data.export", "pacific-supplier", "pacific", "127.0.0.1",
            "success", {"record_count": 1000})
    client.post("/api/security/detect", headers=analyst)
    case_id = client.get("/api/security/cases", headers=analyst).json["cases"][0]["id"]
    response = client.post("/api/security/responses", headers=analyst,
                           json={"case_id": case_id, "target_user": "pacific-supplier", "reason": "Investigate export"})
    request_id = response.json["request_id"]
    first = client.post(f"/api/security/responses/{request_id}/review",
                        headers=admin, json={"decision": "reject"})
    assert first.status_code == 200
    repeat = client.post(f"/api/security/responses/{request_id}/review",
                         headers=admin, json={"decision": "approve"})
    assert repeat.status_code == 409
