import json
from tradelink.evidence import export
from tradelink.store import connect, log
from tradelink.worker import run_once


def test_continuous_worker_is_idempotent(lab):
    _, path = lab
    with connect(path) as db:
        log(db, "data.export", "pacific-supplier", "pacific", "127.0.0.1",
            "success", {"record_count": 1400, "synthetic": True})
    assert run_once(path) == 1
    assert run_once(path) == 0


def test_export_is_structured_and_does_not_include_tokens(lab, tmp_path):
    client, path = lab
    result = client.post("/api/auth/login", json={
        "username": "pacific-buyer", "password": "TradeLink-Demo-Only!"
    })
    token = result.json["access_token"]
    target = tmp_path / "evidence.jsonl"
    assert export(path, target) == 1
    data = json.loads(target.read_text().strip())
    assert data["kind"] == "auth.success"
    assert token not in target.read_text()
    assert "meta_json" not in data
