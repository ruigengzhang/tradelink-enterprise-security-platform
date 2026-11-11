"""Credential hashing, opaque short-lived sessions, strict identity lookup."""
import hashlib
import hmac
import os
import secrets
import time
from functools import wraps

from flask import current_app, g, jsonify, request

from .store import connect


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260000)
    return salt.hex() + ":" + digest.hex()


def verify_password(password, encoded):
    try:
        salt_hex, expected = encoded.split(":", 1)
        actual = password_hash(password, bytes.fromhex(salt_hex)).split(":", 1)[1]
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def issue_session(db, user_id):
    token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
        (hash_token(token), user_id, int(time.time()) + 3600),
    )
    return token


def identity():
    token = request.headers.get("Authorization", "")
    if not token.startswith("Bearer ") or len(token) > 256:
        return None
    raw = token[7:]
    if not raw:
        return None
    with connect(current_app.config["DATABASE"]) as db:
        return db.execute(
            """SELECT u.id,u.username,u.role,u.tenant_id FROM users u JOIN sessions s ON s.user_id=u.id
               WHERE s.token_hash=? AND s.revoked=0 AND s.expires_at>? AND u.disabled=0""",
            (hash_token(raw), int(time.time())),
        ).fetchone()


def require_auth(*roles):
    def decorate(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            g.principal = identity()
            if g.principal is None:
                return jsonify(error="authentication_required"), 401
            if roles and g.principal["role"] not in roles:
                return jsonify(error="forbidden"), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorate
