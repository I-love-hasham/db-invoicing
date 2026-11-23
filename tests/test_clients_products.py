import re

from app import forms
from app.db import get_audit_db, get_db
from conftest import csrf, do_setup


def _audit(app, action):
    with app.app_context():
        return get_audit_db().execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,)).fetchall()


def _add_product(client, name="Regular Hours", rate="77.18", desc="IT services", unit="hour"):
    token = csrf(client, "/products/new")
    return client.post("/products/new", data={"csrf_token": token, "name": name, "description": desc,
                                              "unit": unit, "default_rate": rate})


def _add_client(client, name="OKG Tech", **extra):
    token = csrf(client, "/clients/new")
    data = {"csrf_token": token, "name": name, "address": "4a Medical Park Drive\nPomona, NY 10970",
            "email": "hr@okgtech.com", "payment_terms_days": "15", "notes": ""}
    data.update(extra)
    return client.post("/clients/new", data=data)


def test_money_parsing():
    f = lambda v, req=True: forms.money({"x": v}, "x", "Rate", required=req)
    assert f("77.18") == 7718 and f("$77.18") == 7718 and f("1,250") == 125000 and f("0.5") == 50
    assert f("", req=False) is None
    for bad in ("77.181", "-5", "abc", "1e3", "٧٧", "99999999", "77,18", "0,500", "1,2,3"):
        try:
            f(bad)
            assert False, bad
        except forms.FormError:
            pass
    assert forms.format_money(334344) == "$3,343.44" and forms.format_money(5) == "$0.05"


def test_pages_need_login(client):
    for path in ("/clients/", "/clients/new", "/products/", "/products/new"):
        assert client.get(path).status_code == 302


def test_create_client_product_and_rate(client, app, clock):
    do_setup(client, app, clock)
    assert _add_product(client).status_code == 302
    r = _add_client(client)
    assert r.status_code == 302
    cid = int(re.search(r"/clients/(\d+)", r.headers["Location"]).group(1))
    page = client.get(f"/clients/{cid}").get_data(as_text=True)
    assert "OKG Tech" in page and "$77.18" in page

    # client's own rate overrides the default
    pid = 1
    token = csrf(client, f"/clients/{cid}")
    client.post(f"/clients/{cid}/rates", data={"csrf_token": token, f"rate_{pid}": "80"})
    with app.app_context():
        assert get_db().execute("SELECT rate_cents FROM client_rates").fetchone()[0] == 8000
    entry = _audit(app, "client_rate_changed")[-1]
    assert entry["client_id"] == cid and '"$80.00"' in entry["details"] and '"—"' in entry["details"]

    # blank removes the override
    token = csrf(client, f"/clients/{cid}")
    client.post(f"/clients/{cid}/rates", data={"csrf_token": token, f"rate_{pid}": ""})
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM client_rates").fetchone()[0] == 0


def test_edit_logs_before_and_after(client, app, clock):
    do_setup(client, app, clock)
    _add_client(client)
    token = csrf(client, "/clients/1")
    client.post("/clients/1", data={"csrf_token": token, "name": "OKG Tech", "address": "4a Medical Park Drive",
                                    "email": "billing@okgtech.com", "payment_terms_days": "30", "notes": ""})
    d = _audit(app, "client_edited")[-1]["details"]
    assert "hr@okgtech.com" in d and "billing@okgtech.com" in d and '"payment_terms_days": 15' in d
    assert "Medical" in d     # address changed too


def test_validation_and_duplicates(client, app, clock):
    do_setup(client, app, clock)
    assert _add_client(client, email="not-an-email").status_code == 400
    assert _add_client(client, payment_terms_days="999").status_code == 400
    assert _add_client(client, name="").status_code == 400
    assert _add_client(client, name="Bad\x00Name").status_code == 400
    assert _add_client(client).status_code == 302
    assert _add_client(client, name="okg tech").status_code == 400     # case-insensitive duplicate
    assert _add_product(client, rate="12.345").status_code == 400
    assert _add_product(client, unit="decade").status_code == 400


def test_names_are_escaped_not_executed(client, app, clock):
    do_setup(client, app, clock)
    _add_client(client, name='<script>alert(1)</script>')
    html = client.get("/clients/").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_archive_client_alerts_and_keeps_record(client, app, clock):
    do_setup(client, app, clock)
    _add_client(client)
    token = csrf(client, "/clients/1")
    client.post("/clients/1/archive", data={"csrf_token": token})
    with app.app_context():
        row = get_db().execute("SELECT archived_at FROM clients WHERE id = 1").fetchone()
        kinds = [r[0] for r in get_db().execute("SELECT kind FROM security_alerts")]
    assert row["archived_at"] and "client_archived" in kinds
    assert 'href="/clients/1"' not in client.get("/clients/").get_data(as_text=True)
    assert 'href="/clients/1"' in client.get("/clients/?archived=1").get_data(as_text=True)
    # archived clients can't be edited
    token = csrf(client, "/clients/1")
    r = client.post("/clients/1", data={"csrf_token": token, "name": "X", "payment_terms_days": "15"})
    assert r.status_code == 400
    token = csrf(client, "/clients/1")
    client.post("/clients/1/restore", data={"csrf_token": token})
    assert _audit(app, "client_restored")


def test_audit_filter_by_client(client, app, clock):
    do_setup(client, app, clock)
    _add_client(client)
    _add_client(client, name="ClemenTech")
    page = client.get("/audit/?client=2").get_data(as_text=True)
    assert "client:2" in page and "client:1" not in page
    assert client.get("/audit/export.csv?client=1").status_code == 200


def test_product_edit_archive_restore(client, app, clock):
    do_setup(client, app, clock)
    _add_product(client)
    token = csrf(client, "/products/1")
    client.post("/products/1", data={"csrf_token": token, "name": "Regular Hours", "description": "IT services",
                                     "unit": "hour", "default_rate": "79.00"})
    d = _audit(app, "product_edited")[-1]["details"]
    assert "$77.18" in d and "$79.00" in d
    token = csrf(client, "/products/")
    client.post("/products/1/archive", data={"csrf_token": token})
    token = csrf(client, "/products/")
    client.post("/products/1/restore", data={"csrf_token": token})
    assert _audit(app, "product_archived") and _audit(app, "product_restored")


def test_audit_chain_still_verifies(client, app, clock):
    do_setup(client, app, clock)
    _add_product(client)
    _add_client(client)
    assert "entries verified" in client.get("/security-status").get_data(as_text=True)


# ---------------------------------------------------------------- review findings

def test_upgrade_from_previous_version_keeps_audit_chain_valid(tmp_path):
    """An audit.db created before client_id existed must upgrade and still verify."""
    import sqlite3
    from cryptography.fernet import Fernet
    from app import audit, create_app
    cfg = {"SECRET_KEY": "s" * 48, "AUDIT_HMAC_KEY": "a" * 48, "ENCRYPTION_KEY": Fernet.generate_key().decode(),
           "SETUP_TOKEN": "t" * 30, "DATA_DIR": str(tmp_path / "data"), "COOKIE_SECURE": False,
           "TRUST_PROXY_HEADERS": False, "APP_TIMEZONE": "UTC", "BUILD_DATE": "t",
           "SECURITY_DIR": str(tmp_path), "TESTING": True}
    old = create_app(cfg)
    with old.test_request_context("/"):
        from flask import g
        g.ip, g.ua, g.user = "1.1.1.1", "t", None
        audit.log("old_entry_1", "system")
        audit.log("old_entry_2", "system")
    # turn it into the previous version's file: no client_id column
    conn = sqlite3.connect(tmp_path / "data" / "audit.db")
    conn.execute("DROP INDEX idx_audit_client")
    conn.execute("ALTER TABLE audit_log DROP COLUMN client_id")
    conn.commit()
    conn.close()

    new = create_app(cfg)          # must start, and migrate
    with new.test_request_context("/"):
        from flask import g
        g.ip, g.ua, g.user = "1.1.1.1", "t", None
        audit.log("new_entry", "clients", client_id=7)
        ok, n, msg = audit.verify_chain()
    assert ok and n == 3, msg


def test_comma_as_decimal_is_rejected_not_multiplied(client, app, clock):
    do_setup(client, app, clock)
    assert _add_product(client, rate="77,18").status_code == 400
    assert _add_product(client, rate="1,250.00").status_code == 302


def test_client_notes_text_never_logged(client, app, clock):
    do_setup(client, app, clock)
    _add_client(client, notes="Server admin password: Hunter2-Example")
    token = csrf(client, "/clients/1")
    client.post("/clients/1", data={"csrf_token": token, "name": "OKG Tech", "address": "", "email": "",
                                    "payment_terms_days": "15", "notes": "new secret Hunter3"})
    with app.app_context():
        dump = " ".join(str(tuple(r)) for r in get_audit_db().execute("SELECT * FROM audit_log"))
    assert "Hunter2" not in dump and "Hunter3" not in dump and "characters]" in dump
    assert "Hunter2" not in client.get("/audit/export.csv").get_data(as_text=True)


def test_archived_product_rate_is_read_only(client, app, clock):
    do_setup(client, app, clock)
    _add_product(client)
    _add_client(client)
    token = csrf(client, "/clients/1")
    client.post("/clients/1/rates", data={"csrf_token": token, "rate_1": "80"})
    token = csrf(client, "/products/")
    client.post("/products/1/archive", data={"csrf_token": token})
    token = csrf(client, "/clients/1")
    client.post("/clients/1/rates", data={"csrf_token": token, "rate_1": "5"})
    with app.app_context():
        assert get_db().execute("SELECT rate_cents FROM client_rates").fetchone()[0] == 8000


def test_invisible_and_reversing_characters_rejected(client, app, clock):
    do_setup(client, app, clock)
    assert _add_client(client, name="OKG​ Tech").status_code == 400
    assert _add_client(client, name="‮heT GKO").status_code == 400
    assert _add_client(client, name="Café Services").status_code == 302


def test_billing_email_change_raises_alert(client, app, clock):
    do_setup(client, app, clock)
    _add_client(client)
    token = csrf(client, "/clients/1")
    client.post("/clients/1", data={"csrf_token": token, "name": "OKG Tech", "address": "",
                                    "email": "attacker@evil.example", "payment_terms_days": "15", "notes": ""})
    with app.app_context():
        msgs = [r[0] for r in get_db().execute("SELECT message FROM security_alerts WHERE kind = 'client_email_changed'")]
    assert msgs and "attacker@evil.example" in msgs[0] and "hr@okgtech.com" in msgs[0]
