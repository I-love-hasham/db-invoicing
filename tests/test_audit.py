import sqlite3

import pytest

from app import audit
from app.db import get_audit_db


def test_chain_verifies_and_redacts(app):
    with app.test_request_context("/"):
        from flask import g
        g.ip, g.ua, g.user = "1.2.3.4", "pytest", None
        audit.log("thing", "system", details={"password": "hunter2", "api_key": "sk-x", "after": {"rate": 77.18}})
        audit.log("thing2", "system")
        ok, n, _ = audit.verify_chain()
        assert ok and n == 2
        details = get_audit_db().execute("SELECT details FROM audit_log WHERE id = 1").fetchone()[0]
        assert "hunter2" not in details and "sk-x" not in details and "77.18" in details


def test_database_blocks_edit_and_delete(app):
    with app.test_request_context("/"):
        from flask import g
        g.ip, g.ua, g.user = "1.2.3.4", "pytest", None
        audit.log("thing", "system")
        conn = get_audit_db()
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE audit_log SET action = 'x'")
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM audit_log")


def test_tampering_is_detected(app):
    with app.test_request_context("/"):
        from flask import g
        g.ip, g.ua, g.user = "1.2.3.4", "pytest", None
        for i in range(3):
            audit.log(f"a{i}", "system")
        conn = get_audit_db()
        # an attacker with file access drops the trigger and edits a row
        conn.execute("DROP TRIGGER audit_log_no_update")
        conn.execute("UPDATE audit_log SET action = 'innocent' WHERE id = 2")
        ok, _, msg = audit.verify_chain()
        assert not ok and "#2" in msg


def test_truncation_is_detected(app):
    with app.test_request_context("/"):
        from flask import g
        g.ip, g.ua, g.user = "1.2.3.4", "pytest", None
        for i in range(3):
            audit.log(f"a{i}", "system")
        conn = get_audit_db()
        conn.execute("DROP TRIGGER audit_log_no_delete")
        conn.execute("DELETE FROM audit_log WHERE id = 3")
        ok, _, msg = audit.verify_chain()
        assert not ok and "missing" in msg
