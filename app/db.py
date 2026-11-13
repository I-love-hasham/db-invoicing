"""SQLite access. Parameterized queries only, everywhere in the app."""
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from flask import current_app, g

_HERE = Path(__file__).parent


def _connect(path: str) -> sqlite3.Connection:
    # isolation_level=None: autocommit; multi-step writes use transaction().
    conn = sqlite3.connect(path, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def _path(name: str) -> str:
    return os.path.join(current_app.config["DATA_DIR"], name)


def get_db() -> sqlite3.Connection:
    if "_db" not in g:
        g._db = _connect(_path("app.db"))
    return g._db


def get_audit_db() -> sqlite3.Connection:
    if "_audit_db" not in g:
        g._audit_db = _connect(_path("audit.db"))
    return g._audit_db


@contextmanager
def transaction(conn: sqlite3.Connection):
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def _close(_exc=None):
    for key in ("_db", "_audit_db"):
        conn = g.pop(key, None)
        if conn is not None:
            conn.close()


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
    app.teardown_appcontext(_close)
