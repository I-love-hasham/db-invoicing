"""Regression tests for the independent security review findings."""
import os
import re
import shutil
import threading

from app import audit
from app.db import get_audit_db, get_db
from conftest import PASSWORD, csrf, current_code, do_login, do_setup


def _parallel(fn, n):
    results = [None] * n
    barrier = threading.Barrier(n)

    def run(i):
        barrier.wait()
        results[i] = fn(i)
    threads = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def _password_stage_client(app):
    c = app.test_client()
    token = csrf(c, "/login")
    r = c.post("/login", data={"csrf_token": token, "username": "david", "password": PASSWORD})
    assert r.headers["Location"].endswith("/login/2fa")
    return c, csrf(c, "/login/2fa")


def _signed_out(client):
    client.post("/logout", data={"csrf_token": csrf(client, "/")})


def test_F1_parallel_wrong_passwords_still_lock_at_five(client, app, clock):
    do_setup(client, app, clock)
    _signed_out(client)

    def attempt(_):
        c = app.test_client()
        token = csrf(c, "/login")
        return c.post("/login", data={"csrf_token": token, "username": "david",
                                      "password": "wrong-password-xyz"}).status_code
    _parallel(attempt, 16)
    with app.app_context():
        u = get_db().execute("SELECT failed_count, locked_until FROM users").fetchone()
        tries = get_audit_db().execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'login_password_failed'").fetchone()[0]
    assert u["locked_until"] is not None
    assert tries <= 5          # never more than 5 real password checks


def test_F2_one_totp_code_gives_one_session(client, app, clock):
    do_setup(client, app, clock)
    _signed_out(client)
    staged = [_password_stage_client(app) for _ in range(4)]
    code = current_code(client, app, clock)
    results = _parallel(lambda i: staged[i][0].post(
        "/login/2fa", data={"csrf_token": staged[i][1], "code": code}).status_code, 4)
    assert results.count(302) == 1


def test_F3_one_backup_code_gives_one_session(client, app, clock):
    codes = do_setup(client, app, clock)
    _signed_out(client)
    staged = [_password_stage_client(app) for _ in range(4)]
    results = _parallel(lambda i: staged[i][0].post(
        "/login/2fa", data={"csrf_token": staged[i][1], "code": codes[0]}).status_code, 4)
    assert results.count(302) == 1


def test_F4_reauth_redirect_tricks_are_blocked(client, app, clock):
    do_setup(client, app, clock)
    for bad in ("/\t/evil.example", "/\\evil.example", "//evil.example", "/x\r\nSet-Cookie: a=b",
                "https://evil.example", "/%2F/evil.example"):
        clock.advance()
        token = csrf(client, "/reauth")
        r = client.post("/reauth", data={"csrf_token": token, "next": bad,
                                         "code": current_code(client, app, clock)})
        assert r.status_code == 302 and r.headers["Location"] == "/", bad


def test_F5_password_typed_as_username_is_not_logged(client, app, clock):
    do_setup(client, app, clock)
    _signed_out(client)
    secretish = "MyS3cret-Passw0rd!"
    token = csrf(client, "/login")
    client.post("/login", data={"csrf_token": token, "username": secretish, "password": "x"})
    with app.app_context():
        dump = " ".join(str(tuple(r)) for r in get_audit_db().execute("SELECT * FROM audit_log"))
    assert secretish not in dump


def test_F6_change_is_rolled_back_if_audit_write_fails(client, app, clock, monkeypatch):
    app.config["PROPAGATE_EXCEPTIONS"] = False   # behave like production: return a 500 page
    do_setup(client, app, clock)
    with app.app_context():
        before = get_db().execute("SELECT password_hash FROM users").fetchone()[0]
    token = csrf(client, "/settings/password")
    real_log = audit.log

    def failing_log(action, *a, **kw):
        if action == "password_changed":
            raise OSError("disk full")
        return real_log(action, *a, **kw)
    monkeypatch.setattr(audit, "log", failing_log)
    new = "Another-Long-Passphrase-42"
    r = client.post("/settings/password", data={"csrf_token": token, "current_password": PASSWORD,
                                                "new_password": new, "new_password_confirm": new})
    assert r.status_code == 500
    with app.app_context():
        after = get_db().execute("SELECT password_hash FROM users").fetchone()[0]
    assert after == before        # password NOT changed


def test_F8_deleted_audit_db_is_detected(client, app, clock):
    do_setup(client, app, clock)
    data = app.config["DATA_DIR"]
    for suffix in ("", "-wal", "-shm"):
        p = os.path.join(data, "audit.db" + suffix)
        if os.path.exists(p):
            os.remove(p)
    from app.db import _connect
    from pathlib import Path
    conn = _connect(os.path.join(data, "audit.db"))
    conn.executescript((Path(app.root_path) / "audit_schema.sql").read_text())
    conn.close()
    with app.app_context():
        ok, _, msg = audit.verify_chain()
    assert not ok


def test_F8_restored_older_copy_is_detected(client, app, clock):
    do_setup(client, app, clock)
    data = app.config["DATA_DIR"]
    with app.app_context():
        get_audit_db().execute("PRAGMA wal_checkpoint(TRUNCATE)")
    shutil.copy(os.path.join(data, "audit.db"), "/tmp/_old_audit.db")
    _signed_out(client)
    do_login(client, app, clock)       # more entries written after the copy
    with app.app_context():
        get_audit_db().execute("PRAGMA wal_checkpoint(TRUNCATE)")
    for suffix in ("-wal", "-shm"):
        p = os.path.join(data, "audit.db" + suffix)
        if os.path.exists(p):
            os.remove(p)
    shutil.copy("/tmp/_old_audit.db", os.path.join(data, "audit.db"))
    with app.app_context():
        ok, _, msg = audit.verify_chain()
    assert not ok and "older copy" in msg


def test_F9_locked_and_wrong_password_look_the_same(client, app, clock):
    do_setup(client, app, clock)
    _signed_out(client)
    token = csrf(client, "/login")
    unknown = client.post("/login", data={"csrf_token": token, "username": "nobody", "password": "x" * 12})
    for _ in range(5):
        do_login(client, app, clock, password="wrong-password-123")
    token = csrf(client, "/login")
    locked = client.post("/login", data={"csrf_token": token, "username": "david", "password": PASSWORD})
    strip = lambda r: re.sub(r'value="[^"]*"', "", r.get_data(as_text=True))
    assert unknown.status_code == locked.status_code == 401
    assert strip(unknown) == strip(locked)


def test_F10_unknown_username_spraying_raises_alert(client, app, clock):
    do_setup(client, app, clock)
    _signed_out(client)
    for i in range(3):
        token = csrf(client, "/login")
        client.post("/login", data={"csrf_token": token, "username": f"user{i}", "password": "x" * 12})
    with app.app_context():
        kinds = [r[0] for r in get_db().execute("SELECT kind FROM security_alerts")]
    assert "ip_failed_logins" in kinds


def test_F13_signed_out_csrf_spam_is_capped(client, app):
    for _ in range(40):
        client.post("/login", data={"csrf_token": "bogus"})
    with app.app_context():
        n = get_audit_db().execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'csrf_rejected'").fetchone()[0]
    assert n <= 20


def test_F14_reloading_authenticator_page_keeps_same_secret(client, app, clock):
    do_setup(client, app, clock)
    first = re.search(r'<div class="secret">([A-Z2-7]+)</div>', client.get("/settings/authenticator").get_data(as_text=True)).group(1)
    second = re.search(r'<div class="secret">([A-Z2-7]+)</div>', client.get("/settings/authenticator").get_data(as_text=True)).group(1)
    assert first == second


# ---------------------------------------------------------------- second review round

def test_NA_pages_load_while_another_writer_holds_the_lock(client, app, clock):
    import sqlite3
    import time
    do_setup(client, app, clock)
    blocker = sqlite3.connect(os.path.join(app.config["DATA_DIR"], "app.db"), isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")           # simulate a slow writer
    try:
        t0 = time.time()
        assert client.get("/").status_code == 200
        assert client.get("/audit/").status_code == 200
        assert time.time() - t0 < 2              # reads don't queue behind writers
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()


def test_NB_no_phantom_audit_entry_when_page_render_fails(client, app, clock, monkeypatch):
    app.config["PROPAGATE_EXCEPTIONS"] = False
    do_setup(client, app, clock)
    token = csrf(client, "/settings/password")
    import app.views.settings_views as sv
    real = sv.render_template

    def boom(name, **kw):
        if name == "settings/done.html":
            raise RuntimeError("template broke")
        return real(name, **kw)
    monkeypatch.setattr(sv, "render_template", boom)
    new = "Another-Long-Passphrase-42"
    client.post("/settings/password", data={"csrf_token": token, "current_password": PASSWORD,
                                            "new_password": new, "new_password_confirm": new})
    with app.app_context():
        logged = get_audit_db().execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'password_changed'").fetchone()[0]
        alert = get_db().execute("SELECT COUNT(*) FROM security_alerts WHERE kind = 'password_changed'").fetchone()[0]
        from werkzeug.security import check_password_hash
        changed = check_password_hash(get_db().execute("SELECT password_hash FROM users").fetchone()[0], new)
    assert changed and logged == 1 and alert == 1   # audit log matches what really happened


def test_NC_removing_checkpoint_is_detected(client, app, clock):
    do_setup(client, app, clock)
    with app.app_context():
        get_db().execute("DELETE FROM app_state WHERE key = 'audit_checkpoint'")
        ok, _, msg = audit.verify_chain()
    assert not ok and "checkpoint" in msg


def test_NC_checkpoint_read_first_no_false_alarm(client, app, clock):
    do_setup(client, app, clock)

    def write(_):
        c = app.test_client()
        for _ in range(5):
            token = csrf(c, "/login")
            c.post("/login", data={"csrf_token": token, "username": "nobody", "password": "x" * 12})

    def verify(_):
        with app.app_context():
            return all(audit.verify_chain()[0] for _ in range(10))
    results = _parallel(lambda i: write(i) if i < 2 else verify(i), 3)
    assert results[2] is True


def test_ND_locked_account_still_runs_password_hash(client, app, clock, monkeypatch):
    do_setup(client, app, clock)
    _signed_out(client)
    for _ in range(5):
        do_login(client, app, clock, password="wrong-password-123")
    from app import auth
    calls = []
    real = auth.check_password
    monkeypatch.setattr(auth, "check_password", lambda u, p: calls.append(1) or real(u, p))
    token = csrf(client, "/login")
    client.post("/login", data={"csrf_token": token, "username": "david", "password": PASSWORD})
    assert calls       # same scrypt work as an unknown user, so timing doesn't reveal the lock


def test_NE_floods_dont_fill_audit_log(client, app, clock):
    do_setup(client, app, clock)
    _signed_out(client)
    for _ in range(5):
        do_login(client, app, clock, password="wrong-password-123")   # lock the account
    for _ in range(60):
        token = csrf(client, "/login")
        client.post("/login", data={"csrf_token": token, "username": "david", "password": "y" * 12})
    with app.app_context():
        n = get_audit_db().execute(
            "SELECT COUNT(*) FROM audit_log WHERE action IN ('login_blocked_locked', 'login_throttled')"
        ).fetchone()[0]
    assert n <= 2


def test_NF_password_like_username_not_logged(client, app, clock):
    do_setup(client, app, clock)
    _signed_out(client)
    token = csrf(client, "/login")
    client.post("/login", data={"csrf_token": token, "username": "Correct.Horse-Battery9", "password": "x" * 12})
    with app.app_context():
        dump = " ".join(str(tuple(r)) for r in get_audit_db().execute("SELECT * FROM audit_log"))
    assert "Correct.Horse-Battery9" not in dump
