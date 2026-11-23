import sqlite3

from app.db import get_audit_db, get_db
from conftest import csrf, do_setup
from test_invoices import _create, _seed, _time


def _invoice(client, app, clock):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)          # #1205, $154.36, dated 2026-11-12, due 2026-11-27


def _audit(app, action):
    with app.app_context():
        return get_audit_db().execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,)).fetchall()


def _set_due(app, due):
    with app.app_context():
        get_db().execute("UPDATE invoices SET due_date = ?", (due,))


def test_mark_paid_and_undo(client, app, clock):
    _invoice(client, app, clock)
    t = csrf(client, "/invoices/1")
    r = client.post("/invoices/1/paid", data={"csrf_token": t, "paid_date": "2026-11-20", "method": "zelle"})
    assert r.status_code == 302
    with app.app_context():
        inv = get_db().execute("SELECT * FROM invoices").fetchone()
    assert inv["status"] == "paid" and inv["paid_at"] == "2026-11-20" and inv["paid_method"] == "zelle"
    d = _audit(app, "invoice_marked_paid")[-1]["details"]
    assert "Zelle" in d and "2026-11-20" in d and "$154.36" in d
    page = client.get("/invoices/1").get_data(as_text=True)
    assert "Paid 2026-11-20 by Zelle" in page
    # edit is blocked once paid
    assert client.post("/invoices/1/edit", data={"csrf_token": t, "invoice_date": "2026-11-12",
                                                 "notes": ""}).status_code == 400
    # undo needs a reason and raises an alert
    assert client.post("/invoices/1/unpaid", data={"csrf_token": t, "reason": ""}).status_code == 400
    client.post("/invoices/1/unpaid", data={"csrf_token": t, "reason": "check bounced"})
    with app.app_context():
        assert get_db().execute("SELECT status FROM invoices").fetchone()[0] == "unpaid"
        assert "payment_undone" in [r[0] for r in get_db().execute("SELECT kind FROM security_alerts")]


def test_paid_validation(client, app, clock):
    _invoice(client, app, clock)
    t = csrf(client, "/invoices/1")
    for data in ({"paid_date": "2099-01-01", "method": "zelle"},      # future
                 {"paid_date": "2020-01-01", "method": "zelle"},      # long before invoice
                 {"paid_date": "2026-11-20", "method": "bitcoin"},    # unknown method
                 {"paid_date": "nope", "method": "check"}):
        assert client.post("/invoices/1/paid", data={"csrf_token": t, **data}).status_code == 400
    with app.app_context():
        assert get_db().execute("SELECT status FROM invoices").fetchone()[0] == "unpaid"


def test_void_or_paid_cannot_be_marked_paid_again(client, app, clock):
    _invoice(client, app, clock)
    t = csrf(client, "/invoices/1")
    client.post("/invoices/1/void", data={"csrf_token": t, "reason": "x", "confirm": "yes"})
    client.post("/invoices/1/paid", data={"csrf_token": t, "paid_date": "2026-11-20", "method": "check"})
    with app.app_context():
        assert get_db().execute("SELECT status FROM invoices").fetchone()[0] == "void"


def test_dashboard_totals(client, app, clock):
    _invoice(client, app, clock)
    _time(client, "2026-11-20", "1")
    _create(client, frm="2026-11-15", to="2026-11-21", inv_date="2026-11-22")     # #1206, $77.18
    with app.app_context():
        get_db().execute("UPDATE invoices SET due_date = '2000-01-01' WHERE number = 1205")   # overdue
        get_db().execute("UPDATE invoices SET due_date = '2999-01-01' WHERE number = 1206")   # not due
    page = client.get("/").get_data(as_text=True)
    assert "$231.54" in page and "$154.36" in page and "$77.18" in page


def test_follow_ups_appear_at_7_and_14_days_and_are_logged_once(client, app, clock):
    from datetime import date, timedelta
    _invoice(client, app, clock)
    today = date.today()
    _set_due(app, (today - timedelta(days=3)).isoformat())
    assert "Reminders ready" not in client.get("/").get_data(as_text=True)
    _set_due(app, (today - timedelta(days=8)).isoformat())
    page = client.get("/").get_data(as_text=True)
    assert "Review 7-day reminder" in page
    client.get("/")
    assert len(_audit(app, "followup_drafted")) == 1           # drafted once, not on every load
    r = client.get("/invoices/1/follow-up/7").get_data(as_text=True)
    assert "friendly reminder" in r and "hr@okgtech.com" in r and "$154.36" in r and "David" in r
    _set_due(app, (today - timedelta(days=15)).isoformat())
    assert "Review 14-day reminder" in client.get("/").get_data(as_text=True)
    assert "two weeks past" in client.get("/invoices/1/follow-up/14").get_data(as_text=True)
    assert client.get("/invoices/1/follow-up/30").status_code == 404
    # paid invoices drop off
    t = csrf(client, "/invoices/1")
    client.post("/invoices/1/paid", data={"csrf_token": t, "paid_date": today.isoformat(), "method": "check"})
    assert "Reminders ready" not in client.get("/").get_data(as_text=True)


def test_paid_pdf_says_paid(client, app, clock):
    _invoice(client, app, clock)
    with app.app_context():
        old = get_db().execute("SELECT pdf_sha256 FROM invoices").fetchone()[0]
    t = csrf(client, "/invoices/1")
    client.post("/invoices/1/paid", data={"csrf_token": t, "paid_date": "2026-11-20", "method": "check"})
    with app.app_context():
        assert get_db().execute("SELECT pdf_sha256 FROM invoices").fetchone()[0] != old
    assert client.get("/invoices/1/pdf").status_code == 200


def test_upgrade_adds_paid_method_column(tmp_path):
    """An app.db made before paid_method existed gets the column on start."""
    from cryptography.fernet import Fernet
    from app import create_app
    cfg = {"SECRET_KEY": "s" * 48, "AUDIT_HMAC_KEY": "a" * 48, "ENCRYPTION_KEY": Fernet.generate_key().decode(),
           "SETUP_TOKEN": "t" * 30, "DATA_DIR": str(tmp_path / "data"), "COOKIE_SECURE": False,
           "TRUST_PROXY_HEADERS": False, "APP_TIMEZONE": "UTC", "BUILD_DATE": "t",
           "SECURITY_DIR": str(tmp_path), "TESTING": True}
    create_app(cfg)
    conn = sqlite3.connect(tmp_path / "data" / "app.db")
    conn.execute("ALTER TABLE invoices DROP COLUMN paid_method")
    conn.commit()
    conn.close()
    create_app(cfg)
    conn = sqlite3.connect(tmp_path / "data" / "app.db")
    assert "paid_method" in [r[1] for r in conn.execute("PRAGMA table_info(invoices)")]
