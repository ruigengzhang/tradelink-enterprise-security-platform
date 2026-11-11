"""TradeLink marketplace and analyst console API.

Local educational service. JWTs aren't used: session tokens are opaque, hashed at rest.
All business reads apply server-side tenant boundaries, and only synthetic data is seeded.
"""
import json
import os
from pathlib import Path

from flask import Flask, g, jsonify, request

from .auth import hash_token, identity, issue_session, require_auth, verify_password
from .detection import detect
from .store import connect, initialize, log, now


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.environ.get("TRADELINK_DB", str(Path.cwd() / "instance" / "tradelink.sqlite3")),
        MAX_CONTENT_LENGTH=64 * 1024,
        JSON_SORT_KEYS=True,
    )
    if test_config:
        app.config.update(test_config)
    initialize(app.config["DATABASE"])

    def db():
        return connect(app.config["DATABASE"])

    def ip():
        # Deliberately ignore X-Forwarded-For unless a trusted reverse proxy is configured.
        return request.remote_addr or "unknown"

    @app.after_request
    def security_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response

    @app.get("/health")
    def health():
        return jsonify(status="ok", lab="tradelink-enterprise")

    @app.post("/api/auth/login")
    def login():
        data = request.get_json(silent=True) or {}
        username = data.get("username", "")
        password = data.get("password", "")
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify(error="invalid_credentials"), 401
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            valid = bool(user and not user["disabled"] and verify_password(password, user["password_hash"]))
            if not valid:
                log(conn, "auth.failure", username[:128], user["tenant_id"] if user else "unknown",
                    ip(), "failure")
                return jsonify(error="invalid_credentials"), 401
            token = issue_session(conn, user["id"])
            log(conn, "auth.success", user["username"], user["tenant_id"], ip(), "success")
            return jsonify(access_token=token, expires_in=3600, role=user["role"])

    @app.post("/api/auth/logout")
    @require_auth()
    def logout():
        raw = request.headers["Authorization"][7:]
        with db() as conn:
            conn.execute("UPDATE sessions SET revoked=1 WHERE token_hash=?", (hash_token(raw),))
            log(conn, "auth.logout", g.principal["username"], g.principal["tenant_id"], ip(), "success")
        return jsonify(status="revoked")

    @app.get("/api/products")
    @require_auth()
    def products():
        q = request.args.get("q", "")[:100]
        with db() as conn:
            rows = conn.execute(
                "SELECT id,name,price_cents FROM products WHERE tenant_id=? AND name LIKE ? LIMIT 100",
                (g.principal["tenant_id"], "%" + q.replace("%", r"\%").replace("_", r"\_") + "%"),
            ).fetchall() if not q else conn.execute(
                "SELECT id,name,price_cents FROM products WHERE tenant_id=? AND name LIKE ? ESCAPE '\\' LIMIT 100",
                (g.principal["tenant_id"], "%" + q.replace("%", r"\%").replace("_", r"\_") + "%"),
            ).fetchall()
        return jsonify(products=[dict(r) for r in rows])

    @app.post("/api/products")
    @require_auth()
    def add_product():
        actor = g.principal
        if actor["role"] != "supplier":
            with db() as conn:
                log(conn, "product.write_denied", actor["username"], actor["tenant_id"], ip(), "denied")
            return jsonify(error="forbidden"), 403
        data = request.get_json(silent=True) or {}
        name, price = data.get("name"), data.get("price_cents")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 100 or type(price) is not int or price <= 0:
            return jsonify(error="invalid_product"), 400
        with db() as conn:
            cur = conn.execute("INSERT INTO products(tenant_id,name,price_cents) VALUES(?,?,?)",
                               (actor["tenant_id"], name.strip(), price))
            log(conn, "product.create", actor["username"], actor["tenant_id"], ip(), "success",
                {"product_id": cur.lastrowid})
            return jsonify(id=cur.lastrowid), 201

    @app.get("/api/orders/<int:order_id>")
    @require_auth()
    def order_details(order_id):
        actor = g.principal
        with db() as conn:
            row = conn.execute("SELECT * FROM orders WHERE id=? AND tenant_id=?",
                               (order_id, actor["tenant_id"])).fetchone()
            if not row:
                foreign = conn.execute("SELECT tenant_id FROM orders WHERE id=?", (order_id,)).fetchone()
                if foreign:
                    log(conn, "order.cross_tenant_denied", actor["username"], actor["tenant_id"], ip(),
                        "denied", {"order_id": order_id})
                return jsonify(error="not_found"), 404
            log(conn, "order.read", actor["username"], actor["tenant_id"], ip(), "success",
                {"order_id": order_id})
            return jsonify(order=dict(row))

    @app.get("/api/orders")
    @require_auth()
    def list_orders():
        with db() as conn:
            rows = conn.execute("SELECT * FROM orders WHERE tenant_id=? ORDER BY id LIMIT 100",
                                (g.principal["tenant_id"],)).fetchall()
        return jsonify(orders=[dict(row) for row in rows])

    @app.post("/api/orders")
    @require_auth("buyer")
    def create_order():
        data = request.get_json(silent=True) or {}
        product_id, qty = data.get("product_id"), data.get("quantity")
        if type(product_id) is not int or type(qty) is not int or not 1 <= qty <= 100:
            return jsonify(error="invalid_order"), 400
        with db() as conn:
            product = conn.execute("SELECT id FROM products WHERE id=? AND tenant_id=?",
                                   (product_id, g.principal["tenant_id"])).fetchone()
            if not product:
                return jsonify(error="product_not_found"), 404
            cur = conn.execute("INSERT INTO orders(tenant_id,product_id,quantity) VALUES(?,?,?)",
                               (g.principal["tenant_id"], product_id, qty))
            log(conn, "order.create", g.principal["username"], g.principal["tenant_id"], ip(),
                "success", {"order_id": cur.lastrowid})
            return jsonify(id=cur.lastrowid), 201

    @app.post("/api/exports")
    @require_auth("supplier", "admin")
    def export():
        data = request.get_json(silent=True) or {}
        count = data.get("record_count", 0)
        if type(count) is not int or not 0 <= count <= 5000:
            return jsonify(error="invalid_record_count"), 400
        # Educational simulation: NO customer records or file are returned.
        with db() as conn:
            log(conn, "data.export", g.principal["username"], g.principal["tenant_id"],
                ip(), "success", {"record_count": count, "synthetic": True})
        return jsonify(status="simulated", record_count=count)

    @app.get("/api/security/events")
    @require_auth("analyst", "admin")
    def get_events():
        kind = request.args.get("kind", "")[:100]
        with db() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE (?='' OR kind=?) ORDER BY id DESC LIMIT 200",
                (kind, kind),
            ).fetchall()
        return jsonify(events=[{**dict(row), "meta": json.loads(row["meta_json"])} for row in rows])

    @app.post("/api/security/detect")
    @require_auth("analyst", "admin")
    def run_detections():
        with db() as conn:
            count = detect(conn)
            log(conn, "security.detect", g.principal["username"], g.principal["tenant_id"],
                ip(), "success", {"new_alerts": count})
        return jsonify(new_alerts=count)

    @app.get("/api/security/alerts")
    @require_auth("analyst", "admin")
    def list_alerts():
        with db() as conn:
            rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 200").fetchall()
        return jsonify(alerts=[{**dict(r), "evidence": json.loads(r["evidence_json"])} for r in rows])

    @app.get("/api/security/cases")
    @require_auth("analyst", "admin")
    def list_cases():
        with db() as conn:
            rows = conn.execute(
                """SELECT c.*,a.rule_id,a.title,a.severity,a.actor FROM cases c
                   JOIN alerts a ON a.id=c.alert_id ORDER BY c.id DESC LIMIT 200"""
            ).fetchall()
        return jsonify(cases=[dict(r) for r in rows])

    @app.patch("/api/security/cases/<int:case_id>")
    @require_auth("analyst", "admin")
    def update_case(case_id):
        data = request.get_json(silent=True) or {}
        status = data.get("status")
        disposition = data.get("disposition")
        notes = data.get("notes", "")
        if status not in ("open", "investigating", "resolved") or disposition not in (
            "unreviewed", "true_positive", "false_positive", "inconclusive"
        ) or not isinstance(notes, str) or len(notes) > 2000:
            return jsonify(error="invalid_case_update"), 400
        with db() as conn:
            result = conn.execute(
                "UPDATE cases SET status=?,disposition=?,notes=? WHERE id=?",
                (status, disposition, notes, case_id),
            )
            if result.rowcount == 0:
                return jsonify(error="not_found"), 404
            log(conn, "security.case_update", g.principal["username"], g.principal["tenant_id"],
                ip(), "success", {"case_id": case_id, "status": status})
        return jsonify(status=status, disposition=disposition)

    @app.post("/api/security/responses")
    @require_auth("analyst", "admin")
    def request_response():
        data = request.get_json(silent=True) or {}
        case_id = data.get("case_id")
        target = data.get("target_user")
        reason = data.get("reason", "")
        if type(case_id) is not int or not isinstance(target, str) or not isinstance(reason, str) or not 5 <= len(reason) <= 500:
            return jsonify(error="invalid_request"), 400
        with db() as conn:
            case = conn.execute(
                """SELECT c.id,a.actor FROM cases c JOIN alerts a ON a.id=c.alert_id WHERE c.id=?""",
                (case_id,),
            ).fetchone()
            user = conn.execute("SELECT username,role FROM users WHERE username=?", (target,)).fetchone()
            if not case or not user or case["actor"] != target or user["role"] in ("admin", "analyst"):
                return jsonify(error="invalid_target_or_case"), 400
            cur = conn.execute(
                """INSERT INTO response_requests(case_id,target_user,action,reason,requested_by)
                   VALUES(?,?,'revoke_sessions',?,?)""",
                (case_id, target, reason, g.principal["username"]),
            )
            log(conn, "security.response_requested", g.principal["username"],
                g.principal["tenant_id"], ip(), "success", {"request_id": cur.lastrowid})
        return jsonify(request_id=cur.lastrowid, status="pending"), 201

    @app.get("/api/security/responses")
    @require_auth("analyst", "admin")
    def responses():
        with db() as conn:
            rows = conn.execute("SELECT * FROM response_requests ORDER BY id DESC LIMIT 100").fetchall()
        return jsonify(responses=[dict(r) for r in rows])

    @app.post("/api/security/responses/<int:response_id>/review")
    @require_auth("admin")
    def review_response(response_id):
        data = request.get_json(silent=True) or {}
        decision = data.get("decision")
        if decision not in ("approve", "reject"):
            return jsonify(error="invalid_decision"), 400
        with db() as conn:
            item = conn.execute("SELECT * FROM response_requests WHERE id=?", (response_id,)).fetchone()
            if not item:
                return jsonify(error="not_found"), 404
            if item["status"] != "pending":
                return jsonify(error="already_reviewed"), 409
            if item["requested_by"] == g.principal["username"]:
                return jsonify(error="separation_of_duties"), 403
            if decision == "approve":
                # Transaction commits response state and session revocation atomically.
                conn.execute(
                    "UPDATE sessions SET revoked=1 WHERE user_id=(SELECT id FROM users WHERE username=?)",
                    (item["target_user"],),
                )
                new_status = "executed"
            else:
                new_status = "rejected"
            conn.execute(
                "UPDATE response_requests SET status=?,reviewed_by=?,executed_at=? WHERE id=?",
                (new_status, g.principal["username"], now() if decision == "approve" else None, response_id),
            )
            log(conn, "security.response_review", g.principal["username"], g.principal["tenant_id"],
                ip(), "success", {"request_id": response_id, "decision": decision})
        return jsonify(status=new_status)

    return app
