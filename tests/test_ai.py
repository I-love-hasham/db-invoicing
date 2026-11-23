import json
import re

import pytest

from app import ai, outbound
from app.db import get_audit_db, get_db
from conftest import csrf, do_setup
from test_invoices import _seed, _time

KEY = "sk-ant-api03-" + "A1b2C3d4E5f6G7h8I9j0" * 3


class FakeClaude:
    def __init__(self, reply="Replaced failing drive on the file server and verified backups."):
        self.reply, self.status, self.calls = reply, 200, []

    def __call__(self, url, body, headers, allowed_hosts, timeout=20):
        self.calls.append((url, json.loads(body), headers, allowed_hosts))
        if self.status != 200:
            return self.status, b'{"type":"error","error":{"type":"authentication_error"}}'
        return 200, json.dumps({"content": [{"type": "thinking", "thinking": "", "signature": "x"},
                                            {"type": "text", "text": self.reply}],
                                "usage": {"input_tokens": 90, "output_tokens": 20}}).encode()


@pytest.fixture
def claude(monkeypatch):
    fake = FakeClaude()
    monkeypatch.setattr(outbound, "post", fake)
    return fake


def _save_key(client, key=KEY):
    t = csrf(client, "/settings/ai/key")
    return client.post("/settings/ai/key", data={"csrf_token": t, "api_key": key})


def _entry(client, notes):
    t = csrf(client, "/time/new")
    client.post("/time/new", data={"csrf_token": t, "client_id": "1", "product_id": "1",
                                   "work_date": "2026-11-02", "hours": "2", "notes": notes})


def _audit_dump(app):
    with app.app_context():
        return " ".join(str(tuple(r)) for r in get_audit_db().execute("SELECT * FROM audit_log"))


@pytest.mark.parametrize("text", [
    "reset admin pw to Winter2026!", "Password: hunter22", "new wifi passphrase is CorrectHorse9",
    "api key = abcd1234efgh", "token: eyJhbGciOi", "card 4111 1111 1111 1111 for licenses",
    "-----BEGIN PRIVATE KEY----- abc", "set secret AbCdEfGhIjKlMnOpQrStUvWx1234",
])
def test_secrets_are_caught(text):
    assert ai.sensitive_reason(text)


@pytest.mark.parametrize("text", [
    "Reset John's password and enabled MFA", "replaced switch in server room",
    "invoice 1205 for 43.32 hours", "called 845-263-5628 re printer", "patched DC01 and FS02",
])
def test_normal_notes_pass(text):
    assert ai.sensitive_reason(text) is None


def test_key_needs_2fa_is_encrypted_audited_and_alerts(client, app, clock):
    do_setup(client, app, clock)
    with app.app_context():
        get_db().execute("UPDATE sessions SET reauth_at = reauth_at - 600")
    assert "/reauth" in client.get("/settings/ai/key").headers["Location"]
    with app.app_context():
        get_db().execute("UPDATE sessions SET reauth_at = reauth_at + 600")
    assert _save_key(client, "not-a-key").status_code == 400
    assert _save_key(client).status_code == 200
    with app.app_context():
        stored = dict(get_db().execute("SELECT key, value FROM app_settings WHERE key LIKE 'ai.%'").fetchall())
        kinds = [r[0] for r in get_db().execute("SELECT kind FROM security_alerts")]
    assert KEY not in stored["ai.key_enc"] and stored["ai.key_last4"] == KEY[-4:]
    assert "ai_key_changed" in kinds
    assert KEY not in _audit_dump(app)
    assert "…" + KEY[-4:] in client.get("/settings/ai").get_data(as_text=True)


def test_cleanup_suggests_but_saves_nothing(client, app, clock, claude):
    do_setup(client, app, clock)
    _seed(client)
    _save_key(client)
    _entry(client, "swapped bad hdd on fs, checked bkups ok")
    t = csrf(client, "/time/1")
    r = client.post("/time/1/ai", data={"csrf_token": t, "notes": "swapped bad hdd on fs, checked bkups ok"})
    page = r.get_data(as_text=True)
    assert r.status_code == 200 and "Replaced failing drive" in page and "AI suggestion" in page
    with app.app_context():
        assert get_db().execute("SELECT notes FROM time_entries").fetchone()[0] == "swapped bad hdd on fs, checked bkups ok"
    (url, body, headers, hosts), = claude.calls
    assert url == "https://api.anthropic.com/v1/messages" and hosts == {"api.anthropic.com"}
    assert body["model"] == "claude-haiku-5-5" and headers["x-api-key"] == KEY
    sent = json.dumps(body)
    assert "OKG" not in sent and "77.18" not in sent          # only the notes go out
    dump = _audit_dump(app)
    assert "claude_api" in dump and "bkups" not in dump and "Replaced failing" not in dump and KEY not in dump


def test_secret_in_notes_is_never_sent(client, app, clock, claude):
    do_setup(client, app, clock)
    _seed(client)
    _save_key(client)
    _entry(client, "reset admin pw to Winter2026!")
    t = csrf(client, "/time/1")
    r = client.post("/time/1/ai", data={"csrf_token": t, "notes": "reset admin pw to Winter2026!"})
    assert r.status_code == 400 and "Not sent" in r.get_data(as_text=True) and claude.calls == []


def test_off_without_key(client, app, clock, claude):
    do_setup(client, app, clock)
    _seed(client)
    _entry(client, "did stuff")
    t = csrf(client, "/time/1")
    r = client.post("/time/1/ai", data={"csrf_token": t, "notes": "did stuff"})
    assert r.status_code == 400 and "set up yet" in r.get_data(as_text=True) and claude.calls == []


def test_daily_limit(client, app, clock, claude, monkeypatch):
    monkeypatch.setattr(ai, "DAILY_LIMIT", 2)
    do_setup(client, app, clock)
    _seed(client)
    _save_key(client)
    _entry(client, "did stuff")
    codes = []
    for _ in range(3):
        t = csrf(client, "/time/1")
        codes.append(client.post("/time/1/ai", data={"csrf_token": t, "notes": "did stuff"}).status_code)
    assert codes == [200, 200, 400] and len(claude.calls) == 2


def test_api_error_is_reported_and_logged(client, app, clock, claude):
    do_setup(client, app, clock)
    _seed(client)
    _save_key(client)
    _entry(client, "did stuff")
    claude.status = 401
    t = csrf(client, "/time/1")
    r = client.post("/time/1/ai", data={"csrf_token": t, "notes": "did stuff"})
    assert r.status_code == 400 and "authentication_error" in r.get_data(as_text=True)
    with app.app_context():
        row = get_audit_db().execute("SELECT outcome FROM audit_log WHERE action = 'claude_api'").fetchone()
    assert row[0] == "failure"


def test_reply_is_escaped_and_cleaned(client, app, clock, claude):
    claude.reply = "<script>alert(1)</script>‮evil"
    do_setup(client, app, clock)
    _seed(client)
    _save_key(client)
    _entry(client, "did stuff")
    t = csrf(client, "/time/1")
    page = client.post("/time/1/ai", data={"csrf_token": t, "notes": "did stuff"}).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page and "‮" not in page


def test_invoice_work_summary(client, app, clock, claude):
    claude.reply = "- Replaced failing drive\n- Verified backups"
    do_setup(client, app, clock)
    _seed(client)
    _save_key(client)
    _entry(client, "swapped hdd")
    html = client.get("/invoices/new?client_id=1&period_from=2026-10-29&period_to=2026-11-06"
                      "&invoice_date=2026-11-12").get_data(as_text=True)
    form = dict(re.findall(r'<input type="hidden" name="([a-z_]+)" value="([^"]*)"', html))
    r = client.post("/invoices/new/summary", data=form)
    page = r.get_data(as_text=True)
    assert r.status_code == 200 and "- Replaced failing drive" in page and "AI summary" in page
    sent = json.dumps(claude.calls[0][1])
    assert "2026-11-02: swapped hdd" in sent and "OKG" not in sent
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM invoices").fetchone()[0] == 0   # nothing created
