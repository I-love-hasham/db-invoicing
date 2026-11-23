import base64
import datetime as dt
import json
import os
import re
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from app import graph
from app.db import get_audit_db, get_db
from conftest import csrf, do_setup
from test_invoices import _create, _seed, _time

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _make_cert(path, mode=0o600):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "db-invoicing")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=365)).sign(key, hashes.SHA256()))
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()) + cert.public_bytes(serialization.Encoding.PEM)
    with open(path, "wb") as fh:
        fh.write(pem)
    os.chmod(path, mode)
    return key, cert


class FakeMicrosoft:
    """Stands in for login.microsoftonline.com + graph.microsoft.com."""
    def __init__(self):
        self.calls = []
        self.send_status = 202
        self.lock = threading.Lock()

    def __call__(self, url, body, headers):
        with self.lock:
            self.calls.append((url, body, headers))
        if "oauth2/v2.0/token" in url:
            return 200, json.dumps({"access_token": "fake-token", "expires_in": 3600}).encode()
        if url.endswith("/sendMail"):
            return self.send_status, (b"" if self.send_status == 202 else b'{"error":{"code":"ErrorAccessDenied"}}')
        return 404, b"{}"

    def sends(self):
        return [json.loads(b)["message"] for u, b, h in self.calls if u.endswith("/sendMail")]


@pytest.fixture
def ms(app, tmp_path, monkeypatch):
    path = tmp_path / "m365.pem"
    _make_cert(path)
    app.config.update(M365_TENANT_ID=TENANT, M365_CLIENT_ID=CLIENT_ID, M365_SENDER="billing@dbit.example",
                      M365_CERT_PATH=str(path))
    graph._token["value"] = None
    fake = FakeMicrosoft()
    monkeypatch.setattr(graph, "_post", fake)
    return fake


def _set_copy(client, address="david@dbit.example", mode="cc", enabled=True):
    t = csrf(client, "/settings/email/copy")
    data = {"csrf_token": t, "address": address, "mode": mode}
    if enabled:
        data["enabled"] = "1"
    return client.post("/settings/email/copy", data=data)


def _audit(app, action):
    with app.app_context():
        return get_audit_db().execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,)).fetchall()


def _send_form(client, path):
    html = client.get(path).get_data(as_text=True)
    return {"csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', html).group(1),
            "send_token": re.search(r'name="send_token" value="([^"]+)"', html).group(1),
            "body": re.search(r'<textarea id="body" name="body"[^>]*>(.*?)</textarea>', html, re.S).group(1)}


# ---------------------------------------------------------------- the Microsoft sign-in itself

def test_client_assertion_matches_microsoft_spec(tmp_path):
    key, cert = _make_cert(tmp_path / "c.pem")
    jwt = graph.client_assertion(TENANT, CLIENT_ID, key, cert, now=1_800_000_000)
    h, c, s = jwt.split(".")
    pad = lambda x: x + "=" * (-len(x) % 4)
    header = json.loads(base64.urlsafe_b64decode(pad(h)))
    claims = json.loads(base64.urlsafe_b64decode(pad(c)))
    assert header["alg"] == "PS256" and header["typ"] == "JWT"
    der = cert.public_bytes(serialization.Encoding.DER)
    d = hashes.Hash(hashes.SHA256()); d.update(der)
    assert base64.urlsafe_b64decode(pad(header["x5t#S256"])) == d.finalize()
    assert claims["aud"] == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    assert claims["iss"] == claims["sub"] == CLIENT_ID and claims["exp"] - claims["nbf"] == 300
    key.public_key().verify(base64.urlsafe_b64decode(pad(s)), f"{h}.{c}".encode(),
                            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())


def test_only_microsoft_hosts_allowed():
    for url in ("https://evil.example/token", "http://graph.microsoft.com/v1.0/x",
                "https://graph.microsoft.com.evil.example/x"):
        with pytest.raises(graph.GraphError):
            graph._post(url, b"", {})


def test_world_readable_certificate_refused(app, tmp_path):
    path = tmp_path / "loose.pem"
    _make_cert(path, mode=0o644)
    app.config.update(M365_TENANT_ID=TENANT, M365_CLIENT_ID=CLIENT_ID, M365_SENDER="billing@x.example",
                      M365_CERT_PATH=str(path))
    with app.app_context():
        st = graph.status()
    assert not st["configured"] and "chmod 600" in st["cert_problem"]


def test_not_configured_means_no_send(client, app, clock):
    do_setup(client, app, clock)
    page = client.get("/settings/email").get_data(as_text=True)
    assert "Not set up yet" in page and "M365_TENANT_ID" in page


# ---------------------------------------------------------------- copy setting

def test_copy_setting_needs_2fa_audits_and_alerts(client, app, clock, ms):
    do_setup(client, app, clock)
    with app.app_context():
        get_db().execute("UPDATE sessions SET reauth_at = reauth_at - 600")
    assert "/reauth" in client.get("/settings/email/copy").headers["Location"]
    with app.app_context():
        get_db().execute("UPDATE sessions SET reauth_at = reauth_at + 600")
    _set_copy(client, "david@dbit.example")
    _set_copy(client, "other@dbit.example", mode="bcc")
    d = _audit(app, "email_copy_changed")[-1]["details"]
    assert "david@dbit.example" in d and "other@dbit.example" in d
    with app.app_context():
        assert "email_copy_changed" in [r[0] for r in get_db().execute("SELECT kind FROM security_alerts")]
    # the OLD address was warned directly
    assert any(m["toRecipients"][0]["emailAddress"]["address"] == "david@dbit.example" for m in ms.sends())


# ---------------------------------------------------------------- invoice email

def test_send_invoice_with_preview_copy_and_audit(client, app, clock, ms):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    _set_copy(client)
    ms.calls.clear()
    page = client.get("/invoices/1/send").get_data(as_text=True)
    assert "hr@okgtech.com" in page and "Invoice #1205 – DB IT Consulting – 10/29/26 to 11/06/26" in page
    assert "CC:</strong> david@dbit.example" in page
    form = _send_form(client, "/invoices/1/send")
    r = client.post("/invoices/1/send", data=form)
    assert r.status_code == 302
    (msg,) = ms.sends()
    assert msg["toRecipients"][0]["emailAddress"]["address"] == "hr@okgtech.com"
    assert msg["ccRecipients"][0]["emailAddress"]["address"] == "david@dbit.example"
    att = msg["attachments"][0]
    assert att["name"] == "Invoice-1205.pdf" and base64.b64decode(att["contentBytes"])[:5] == b"%PDF-"
    assert all("/users/billing@dbit.example/sendMail" in u for u, b, h in ms.calls if "graph" in u)
    entry = _audit(app, "invoice_emailed")[-1]
    assert "hr@okgtech.com" in entry["details"] and "david@dbit.example" in entry["details"]
    assert "Please find attached" not in entry["details"]          # message text never logged
    assert _audit(app, "graph_sendmail")
    with app.app_context():
        dump = " ".join(str(tuple(r)) for r in get_audit_db().execute("SELECT * FROM audit_log"))
    assert "fake-token" not in dump                                  # tokens never logged
    assert "sent" in client.get("/invoices/1").get_data(as_text=True)


def test_double_click_sends_once(client, app, clock, ms):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    form = _send_form(client, "/invoices/1/send")
    assert client.post("/invoices/1/send", data=form).status_code == 302
    r = client.post("/invoices/1/send", data=form)
    assert r.status_code == 400 and "already sent" in r.get_data(as_text=True)
    assert len(ms.sends()) == 1


def test_graph_failure_is_shown_and_logged(client, app, clock, ms):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    ms.send_status = 403
    r = client.post("/invoices/1/send", data=_send_form(client, "/invoices/1/send"))
    assert r.status_code == 400 and "ErrorAccessDenied" in r.get_data(as_text=True)
    assert _audit(app, "invoice_email_failed")
    with app.app_context():
        assert get_db().execute("SELECT status FROM email_log").fetchone()[0] == "failed"


def test_tampered_pdf_is_not_sent(client, app, clock, ms):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    with app.app_context():
        rel = get_db().execute("SELECT pdf_path FROM invoices").fetchone()[0]
    with open(os.path.join(app.config["DATA_DIR"], rel), "ab") as fh:
        fh.write(b"x")
    r = client.post("/invoices/1/send", data=_send_form(client, "/invoices/1/send"))
    assert r.status_code == 400 and ms.sends() == []


def test_void_invoice_cannot_be_sent(client, app, clock, ms):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    form = _send_form(client, "/invoices/1/send")
    t = csrf(client, "/invoices/1")
    client.post("/invoices/1/void", data={"csrf_token": t, "reason": "x", "confirm": "yes"})
    assert client.post("/invoices/1/send", data=form).status_code == 400
    assert ms.sends() == []


# ---------------------------------------------------------------- reminders

def test_follow_up_send_marks_sent_and_refuses_when_paid(client, app, clock, ms):
    from datetime import date, timedelta
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    with app.app_context():
        get_db().execute("UPDATE invoices SET due_date = ?", ((date.today() - timedelta(days=8)).isoformat(),))
    client.get("/")
    form = _send_form(client, "/invoices/1/follow-up/7")
    assert client.post("/invoices/1/follow-up/7/send", data=form).status_code == 302
    (msg,) = ms.sends()
    assert msg["subject"].startswith("Reminder: Invoice #1205")
    with app.app_context():
        assert get_db().execute("SELECT sent_at FROM follow_ups").fetchone()[0]
    assert "Review 7-day reminder" not in client.get("/").get_data(as_text=True)
    # a second, stale form can't send it again
    form["send_token"] = "another-token"
    assert client.post("/invoices/1/follow-up/7/send", data=form).status_code == 400
    assert len(ms.sends()) == 1


# ---------------------------------------------------------------- security alerts by email

def _new_alert(app, msg="test alert"):
    with app.test_request_context("/"):
        from flask import g
        g.ip, g.ua, g.user = "1.1.1.1", "t", None
        from app import audit
        from app.db import atomic
        with atomic():
            audit.raise_alert("test", msg)


def test_alerts_are_emailed_once(client, app, clock, ms):
    do_setup(client, app, clock)
    _set_copy(client)
    ms.calls.clear()
    _new_alert(app)
    client.get("/")                     # flush runs after each request
    alert_mails = [m for m in ms.sends() if m["subject"].startswith("[Invoicing app] Security alert (")]
    assert alert_mails and alert_mails[0]["toRecipients"][0]["emailAddress"]["address"] == "david@dbit.example"
    n = len(ms.sends())
    client.get("/")
    assert len(ms.sends()) == n         # not sent twice
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM security_alerts WHERE emailed_at IS NULL").fetchone()[0] == 0


def test_alert_email_failure_retries_then_gives_up(client, app, clock, ms):
    do_setup(client, app, clock)
    _set_copy(client)
    ms.send_status = 500
    _new_alert(app)
    for _ in range(6):
        client.get("/")
    with app.app_context():
        row = get_db().execute("SELECT emailed_at, email_attempts FROM security_alerts ORDER BY id DESC").fetchone()
    assert row["emailed_at"] == "failed" and row["email_attempts"] == 5


def test_test_email(client, app, clock, ms):
    do_setup(client, app, clock)
    _set_copy(client)
    ms.calls.clear()
    html = client.get("/settings/email").get_data(as_text=True)
    assert "Ready" in html
    form = {"csrf_token": re.search(r'name="csrf_token" value="([^"]+)"', html).group(1),
            "send_token": re.search(r'name="send_token" value="([^"]+)"', html).group(1)}
    r = client.post("/settings/email/test", data=form)
    assert r.status_code == 200 and "Test email sent" in r.get_data(as_text=True)
    assert any(m["subject"] == "Test email from your invoicing app" for m in ms.sends())
