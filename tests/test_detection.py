from tradelink.detection import detect
from tradelink.store import connect, log


def test_empty_log_no_alert(lab):
    _, path = lab
    with connect(path) as db:
        assert detect(db) == 0


def test_five_failed_login_threshold(lab):
    _, path = lab
    with connect(path) as db:
        for _ in range(4):
            log(db, "auth.failure", "supplier", "pacific", "203.0.113.77", "failure")
        assert detect(db) == 0
        log(db, "auth.failure", "supplier", "pacific", "203.0.113.77", "failure")
        assert detect(db) == 1


def test_denied_orders_are_not_successful_disclosure(lab):
    _, path = lab
    with connect(path) as db:
        for _ in range(2):
            log(db, "order.cross_tenant_denied", "supplier", "pacific", "203.0.113.77", "denied")
        assert detect(db) == 1
        result = db.execute("SELECT rule_id FROM alerts").fetchone()
        assert result["rule_id"] == "TL-103"
