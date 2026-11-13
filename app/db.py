"""SQLite access. Parameterized queries only, everywhere in the app.

Each request runs in ONE write transaction on app.db (BEGIN IMMEDIATE on first
use). That serializes requests, so checks like "is the account locked?" or
"was this 2FA code already used?" can't be raced by parallel requests. The
transaction commits just before the response is sent, and rolls back on any
error, so a change is never kept when its audit entry couldn't be written.
"""
import os
import sqlite3
from pathlib import Path

from flask import current_app, g

_HERE = Path(__file__).parent


def _connect(path: str) -> sqlite3.Connection:
    # isolation_level=None: we issue BEGIN/COMMIT ourselves.
    conn = sqlite3.connect(path, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def _path(name: str) -> str:
    return os.path.join(current_app.config["DATA_DIR"], name)


def get_db() -> sqlite3.Connection:
    if "_db" not in g:
        conn = _connect(_path("app.db"))
        conn.execute("BEGIN IMMEDIATE")
        g._db = conn
    return g._db


def get_audit_db() -> sqlite3.Connection:
    if "_audit_db" not in g:
        g._audit_db = _connect(_path("audit.db"))
    return g._audit_db


def finish(commit: bool) -> None:
    """Commit (or roll back) the request's app.db transaction."""
    conn = g.get("_db")
    if conn is not None and conn.in_transaction:
        conn.execute("COMMIT" if commit else "ROLLBACK")


def _commit_before_response(response):
    # Runs before the response leaves the server. 5xx = something failed: roll back.
    finish(commit=response.status_code < 500)
    return response


def _close(exc=None):
    conn = g.pop("_db", None)
    if conn is not None:
        if conn.in_transaction:
            conn.execute("ROLLBACK" if exc is not None else "COMMIT")
        conn.close()
    audit_conn = g.pop("_audit_db", None)
    if audit_conn is not None:
        audit_conn.close()


def init_app(app):
    data_dir = app.config["DATA_DIR"]
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    for db_name, schema in (("app.db", "schema.sql"), ("audit.db", "audit_schema.sql")):
        path = os.path.join(data_dir, db_name)
        conn = _connect(path)
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript((_HERE / schema).read_text())
        finally:
            conn.close()
        os.chmod(path, 0o600)
    # Registered first => runs LAST among after_request hooks (Flask runs them in reverse).
    app.after_request(_commit_before_response)
    app.teardown_appcontext(_close)
