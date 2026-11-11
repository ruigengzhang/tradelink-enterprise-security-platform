"""Detection-as-code. All rules cite stored event IDs; no live network attacks."""
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta

from .store import now


RULES = {
    "TL-101": ("high", "Repeated failed sign-ins"),
    "TL-102": ("medium", "New successful login IP"),
    "TL-103": ("high", "Cross-tenant order access attempts"),
    "TL-104": ("critical", "Sensitive bulk export"),
    "TL-105": ("critical", "Unapproved privilege escalation"),
    "TL-106": ("medium", "Blocked unauthorized product modification"),
    "TL-107": ("high", "Unapproved cloud IAM policy change"),
    "TL-108": ("medium", "AI agent unauthorized tool attempt"),
}


def detect(db):
    rows = db.execute("SELECT * FROM events ORDER BY ts,id").fetchall()
    failures = defaultdict(list)
    seen_ip = defaultdict(set)
    cross_tenant = defaultdict(list)
    unauthorized_write = defaultdict(list)
    findings = []
    for e in rows:
        meta = json.loads(e["meta_json"])
        actor = e["actor"]
        ip = e["source_ip"]
        kind = e["kind"]
        if kind == "auth.failure":
            failures[(actor, ip)].append(e)
        elif kind == "auth.success":
            if seen_ip[actor] and ip not in seen_ip[actor]:
                findings.append(("TL-102", actor, [e["id"]]))
            seen_ip[actor].add(ip)
        elif kind == "order.cross_tenant_denied":
            cross_tenant[actor].append(e["id"])
        elif kind == "data.export" and meta.get("record_count", 0) >= 500 and e["outcome"] == "success":
            findings.append(("TL-104", actor, [e["id"]]))
        elif kind == "iam.role_change" and meta.get("approved") is False and meta.get("new_role") == "admin":
            findings.append(("TL-105", actor, [e["id"]]))
        elif kind == "cloud.iam_policy_change" and meta.get("approved") is False:
            findings.append(("TL-107", actor, [e["id"]]))
        elif kind == "agent.tool_denied" and meta.get("tool"):
            findings.append(("TL-108", actor, [e["id"]]))
        elif kind == "product.write_denied":
            unauthorized_write[actor].append(e["id"])

    for (actor, ip), seq in failures.items():
        for i, event in enumerate(seq):
            start = datetime.fromisoformat(event["ts"])
            matching = [x["id"] for x in seq[i:]
                        if datetime.fromisoformat(x["ts"]) - start <= timedelta(minutes=10)]
            if len(matching) >= 5:
                findings.append(("TL-101", actor, matching))
                break
    for actor, ids in cross_tenant.items():
        if len(ids) >= 2:
            findings.append(("TL-103", actor, ids))
    for actor, ids in unauthorized_write.items():
        if len(ids) >= 2:
            findings.append(("TL-106", actor, ids))

    created = 0
    for rule, actor, evidence in findings:
        severity, title = RULES[rule]
        ids = sorted(set(evidence))
        fingerprint = hashlib.sha256((rule + ":" + actor + ":" + ",".join(map(str, ids))).encode()).hexdigest()
        cur = db.execute(
            """INSERT OR IGNORE INTO alerts(rule_id,actor,severity,title,evidence_json,created_at,fingerprint)
               VALUES(?,?,?,?,?,?,?)""",
            (rule, actor, severity, title, json.dumps(ids), now(), fingerprint),
        )
        if cur.rowcount:
            db.execute("INSERT INTO cases(alert_id) VALUES(?)", (cur.lastrowid,))
            created += 1
    return created
