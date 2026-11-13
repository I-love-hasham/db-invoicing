from app.db import get_audit_db, get_db
from conftest import PASSWORD, SETUP_TOKEN, csrf, current_code, do_login, do_setup


def actions(app):
    with app.app_context():
        return [r["action"] for r in get_audit_db().execute("SELECT action FROM audit_log ORDER BY id")]


def test_everything_requires_login(client):
    for path in ("/", "/audit/", "/settings/", "/security-status", "/audit/export.csv"):
        r = client.get(path)
        assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert client.get("/healthz").status_code == 200


def test_first_visit_goes_to_setup(client):
    assert client.get("/login").headers["Location"].endswith("/setup")


def test_setup_needs_token(client, app, clock):
    token = csrf(client, "/setup")
    r = client.post("/setup", data={"csrf_token": token, "setup_token": "wrong", "username": "david",
                                    "password": PASSWORD, "password_confirm": PASSWORD})
    assert r.status_code == 403
    assert "setup_token_invalid" in actions(app)


def test_setup_then_login_with_totp(client, app, clock):
    do_setup(client, app, clock)
    assert client.get("/setup").status_code == 404           # setup closes once done
    client.post("/logout", data={"csrf_token": csrf(client, "/")})
    r = do_login(client, app, clock)
    assert r.status_code == 302 and r.headers["Location"].endswith("/")
    assert client.get("/").status_code == 200
    a = actions(app)
    assert "2fa_enrolled" in a and "login_success" in a and "logout" in a


def test_password_alone_is_not_enough(client, app, clock):
    do_setup(client, app, clock)
    client.post("/logout", data={"csrf_token": csrf(client, "/")})
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf_token": token, "username": "david", "password": PASSWORD})
    assert r.headers["Location"].endswith("/login/2fa")
    assert client.get("/").status_code == 302                 # dashboard still blocked


def test_totp_code_cannot_be_reused(client, app, clock):
    do_setup(client, app, clock)
    client.post("/logout", data={"csrf_token": csrf(client, "/")})
    code = current_code(client, app, clock)
    assert do_login(client, app, clock, code=code).status_code == 302
    clock.t -= 30  # same 30-second window
    client.post("/logout", data={"csrf_token": csrf(client, "/")})
    r = do_login(client, app, clock, code=code)
    assert r.status_code == 401


def test_backup_code_login_is_single_use_and_alerts(client, app, clock):
    codes = do_setup(client, app, clock)
    client.post("/logout", data={"csrf_token": csrf(client, "/")})
    assert do_login(client, app, clock, code=codes[0]).status_code == 302
    client.post("/logout", data={"csrf_token": csrf(client, "/")})
    assert do_login(client, app, clock, code=codes[0]).status_code == 401
    with app.app_context():
        kinds = [r["kind"] for r in get_db().execute("SELECT kind FROM security_alerts")]
    assert "backup_code_used" in kinds


def test_lockout_after_five_failures(client, app, clock):
    do_setup(client, app, clock)
    client.post("/logout", data={"csrf_token": csrf(client, "/")})
    for _ in range(5):
        r = do_login(client, app, clock, password="wrong-password-123")
    assert r.status_code == 401 and b"locked" in r.data
    r = do_login(client, app, clock)                           # right password, still locked
    assert r.status_code == 401 and client.get("/").status_code == 302
    with app.app_context():
        kinds = [r["kind"] for r in get_db().execute("SELECT kind FROM security_alerts")]
    assert "failed_logins" in kinds and "lockout" in kinds
    clock.advance(0)
    import time as _t
    with app.app_context():                                    # simulate 15 minutes passing
        get_db().execute("UPDATE users SET locked_until = ?", (_t.time() - 1,))
    assert do_login(client, app, clock).status_code == 302


def test_csrf_required(client, app, clock):
    do_setup(client, app, clock)
    r = client.post("/logout", data={})
    assert r.status_code == 400
    r = client.post("/logout", data={"csrf_token": csrf(client, "/")}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 400
    assert "csrf_rejected" in actions(app)


def test_sensitive_settings_reask_2fa(client, app, clock):
    do_setup(client, app, clock)
    client.post("/logout", data={"csrf_token": csrf(client, "/")})
    do_login(client, app, clock)
    with app.app_context():
        get_db().execute("UPDATE sessions SET reauth_at = reauth_at - 600")
    r = client.get("/settings/password")
    assert "/reauth" in r.headers["Location"]
    token = csrf(client, "/reauth?next=/settings/password")
    r = client.post("/reauth", data={"csrf_token": token, "next": "/settings/password",
                                     "code": current_code(client, app, clock)})
    assert r.headers["Location"].endswith("/settings/password")
    new = "Another-Long-Passphrase-42"
    token = csrf(client, "/settings/password")
    r = client.post("/settings/password", data={"csrf_token": token, "current_password": PASSWORD,
                                                "new_password": new, "new_password_confirm": new})
    assert r.status_code == 200
    assert "password_changed" in actions(app)


def test_reauth_rejects_open_redirect(client, app, clock):
    do_setup(client, app, clock)
    token = csrf(client, "/reauth")
    r = client.post("/reauth", data={"csrf_token": token, "next": "//evil.example/",
                                     "code": current_code(client, app, clock)})
    assert r.headers["Location"] == "/"


def test_security_headers(client):
    r = client.get("/login")
    h = r.headers
    assert "default-src 'none'" in h["Content-Security-Policy"]
    assert h["X-Frame-Options"] == "DENY" and h["Cache-Control"] == "no-store"


def test_audit_chain_ok_after_flow_and_csv_export(client, app, clock):
    do_setup(client, app, clock)
    r = client.get("/audit/export.csv")
    assert r.status_code == 200 and r.mimetype == "text/csv"
    assert client.get("/audit/?category=auth&q=login").status_code == 200
    page = client.get("/security-status").get_data(as_text=True)
    assert "entries verified" in page


def test_move_authenticator_and_new_backup_codes(client, app, clock):
    import re
    from app import totp
    do_setup(client, app, clock)
    html = client.get("/settings/authenticator").get_data(as_text=True)
    new_secret = re.search(r'<div class="secret">([A-Z2-7]+)</div>', html).group(1)
    token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    r = client.post("/settings/authenticator",
                    data={"csrf_token": token, "code": totp.code_at(new_secret, totp.current_step())})
    assert r.status_code == 200 and b"Authenticator updated" in r.data
    token = csrf(client, "/settings/backup-codes")
    r = client.post("/settings/backup-codes", data={"csrf_token": token})
    assert r.status_code == 200 and len(re.findall(r"<div>[a-z2-9]{5}-[a-z2-9]{5}</div>", r.get_data(as_text=True))) == 10
    a = actions(app)
    assert "authenticator_changed" in a and "backup_codes_regenerated" in a
    with app.app_context():
        kinds = {r["kind"] for r in get_db().execute("SELECT kind FROM security_alerts")}
    assert "2fa_changed" in kinds
    # alert banner shows and can be acknowledged
    page = client.get("/").get_data(as_text=True)
    assert "Security alert" in page
    alert_id = re.search(r'/alerts/(\d+)/ack', page).group(1)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    assert client.post(f"/alerts/{alert_id}/ack", data={"csrf_token": token}).status_code == 302
    assert "alert_acknowledged" in actions(app)


def test_no_secrets_in_audit_log(client, app, clock):
    codes = do_setup(client, app, clock)
    with app.app_context():
        dump = " ".join(str(tuple(r)) for r in get_audit_db().execute("SELECT * FROM audit_log"))
    assert PASSWORD not in dump and SETUP_TOKEN not in dump
    assert not any(c in dump for c in codes)
