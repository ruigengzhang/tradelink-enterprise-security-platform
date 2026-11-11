"""SQLite storage with bounded, parameterized queries and schema initialization."""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('buyer','supplier','analyst','admin')),
 tenant_id TEXT NOT NULL, disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, name TEXT NOT NULL, price_cents INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL, product_id INTEGER NOT NULL,
 quantity INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'created'
);
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, kind TEXT NOT NULL,
 actor TEXT NOT NULL, tenant_id TEXT NOT NULL, source_ip TEXT NOT NULL,
 outcome TEXT NOT NULL, meta_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_actor ON events(actor);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, rule_id TEXT NOT NULL, actor TEXT NOT NULL,
 severity TEXT NOT NULL, title TEXT NOT NULL, evidence_json TEXT NOT NULL,
 created_at TEXT NOT NULL, fingerprint TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS cases (
 id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER NOT NULL UNIQUE REFERENCES alerts(id),
 status TEXT NOT NULL DEFAULT 'open', disposition TEXT NOT NULL DEFAULT 'unreviewed',
 notes TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS response_requests (
 id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL REFERENCES cases(id),
 target_user TEXT NOT NULL, action TEXT NOT NULL CHECK(action='revoke_sessions'),
 reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 requested_by TEXT NOT NULL, reviewed_by TEXT, executed_at TEXT
);
"""


def connect(path):
    db = sqlite3.connect(str(path), timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def initialize(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with connect(path) as db:
        db.executescript(SCHEMA)


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(db, kind, actor, tenant, ip, outcome, meta=None):
    """Audit evidence must not include bearer tokens, passwords or customer records."""
    db.execute(
        "INSERT INTO events(ts,kind,actor,tenant_id,source_ip,outcome,meta_json) VALUES(?,?,?,?,?,?,?)",
        (now(), kind, actor, tenant, ip, outcome, json.dumps(meta or {}, sort_keys=True)),
    )
