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
        self.reply, self.status, self.calls, self.stop = reply, 200, [], "end_turn"

    def __call__(self, url, body, headers, allowed_hosts, timeout=20):
        self.calls.append((url, json.loads(body), headers, allowed_hosts))
        if self.status != 200:
            return self.status, b'{"type":"error","error":{"type":"authentication_error"}}'
        return 200, json.dumps({"content": [{"type": "thinking", "thinking": "", "signature": "x"},
                                            {"type": "text", "text": self.reply}], "stop_reason": self.stop,
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


BAD = ['pw Winter2026!','PIN 4821','creds admin/Passw0rd','login admin / Summer2026!','user jsmith temp pass Welcome1',
'new password Spring2026# for jsmith','passwd Tr0ub4dor&3','local admin Hunter2!! set on DC01','wifi key Guest2026!',
'WPA2 key: Fr0ntDesk','vpn psk 8f3Kq9','recovery key 123456-234567-345678-456789-567890-678901-789012-890123',
'MFA code 482913','product key NPPR9-FWDCX-D2C8J-H872K-2YT43','AKIAIOSFODNN7EXAMPLE','routing 021000021 acct 123456789',
'reset admin pw to Winter2026!','Password: hunter22','set it to Winter2026! for the user','card 4111 1111 1111 1111',
'new wifi passphrase is CorrectHorse9','api key = abcd1234efgh','token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0',
'pw is 1234','password=Summer25','wifi password: guest2026','gave user temp pw Welcome2026','otp 551203',
'2FA code 019283','account 000123456789 for ACH','set local admin password to Adm1n!2026','creds: svc_backup / Bkp#2026']
GOOD = ['Reset password to default for the front desk user',"User's password was reset and MFA re-registered",
'Troubleshot password was expired issue','pin to taskbar for all users','token is expired, re-authenticated Outlook',
"Reset John's password and enabled MFA",'replaced switch in server room','invoice 1205 for 43.32 hours',
'called 845-263-5628 re printer','patched DC01 and FS02','installed Office365 on win11 laptop for user jsmith',
'error code 1603 on MSI install','admin console on SRV-01 updated','created user account for new hire',
'key fob reprogrammed','login issues with VPN, reset the client','registry key HKLM\\Software fixed',
'user sarah locked out, unlocked account','set wifi to 5GHz band','renewed SSL cert for owa','configured 802.1x on switch',
'password policy updated to 14 characters','enabled self-service password reset','wifi key rotated per policy',
'admin rights removed from user','recovery partition rebuilt on laptop','set up user mailbox for Sarah Cohen',
'pin pad replaced at front desk','user reported login loop in Teams','reset MFA for user, re-enrolled phone',
'upgraded admin pc to Windows 11 24H2','moved user to OU=Staff','password expiry set to 90 days']


# Second set: written by the independent reviewer to try to beat the detector.
BAD2 = [
 'new pw "Autumn2026" for front desk',            # quoted
 "temp password 'Bluebird7' given to user",
 'pass is Bluebird7',
 'pwd->Bluebird7',
 'admin | Bluebird7! | router',
 'creds: admin, Bluebird7!',
 'user: jsmith\npass: Bluebird7',                  # two-line
 'password same as before: Bluebird7',
 'password: Ｂluebird７',                         # fullwidth look-alikes
 'TeamViewer ID 1 234 567 890 pw 8hq2kd',
 'AnyDesk 123 456 789 / Unattended123',
 'router admin/admin123 at 192.168.1.1',
 'QuickBooks login sarah@okg.com Qb2026books',
 'bank login jsmith Chase!2026',
 'door code 4471',
 'alarm code 0923#',
 'gate code is 1979',
 'M365 recovery codes 4821-9932 1283-4410 5521-7710',
 'seed phrase: abandon ability able about above absent absorb abstract absurd abuse access accident',
 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 root@srv',
 'Server=sql01;Database=acct;User Id=sa;Password=Sq1Server!;',
 'connection string uses User=app;Pwd=Abc12345',
 'mongodb://admin:S3cretPw@db01:27017',
 'https://admin:Hunter2pw@nas.local/',
 'local admin acct: .\\localadmin  Winter26',
 'enable secret Cisco123 on core switch',
 'snmp community string Pr1vate',
 'Wi-Fi: OKG-Guest / Welcome2OKG',
 'SSID OKG-Staff  key=Pomona10970!',
 'set BIOS supervisor pw to bios2026',
 'gave him the code 739204 from authenticator',
 'iDRAC root calvin',                                  # default Dell creds (no keyword)
 'PIN changed to 5582 for copier',
 'safe combo 12-34-56',
 'Duo bypass code 948201',
 'LAPS password for PC-12 was Xk3$pq9Lm',
 'vault unlock key 9F8A-77BC-1D2E-3F40',
 'login: admin\npassword: P@ssw0rd',
 'P@ssw0rd',                                            # bare
 'Summer2026',                                          # bare common pattern
]
GOOD2 = [
 'Reset password for 3 users after phishing test', 'Password manager rollout: installed Keeper on 5 PCs',
 'Explained password complexity rules to staff', 'pw reset for jsmith, done', 'key card reader at door replaced',
 'set up new SSID for guest network', 'updated router firmware to 1.2.3.4', 'checked admin audit log in Entra',
 'login page loads slowly in Edge, cleared cache', 'enabled BitLocker on 4 laptops, keys escrowed to Entra',
 'printed recovery codes for the safe (not stored here)', 'token signing cert renewed in ADFS',
 'MFA prompts fixed for 2 users', 'replaced PIN pad battery', 'TeamViewer removed from all PCs',
 'AnyDesk blocked at firewall', 'QuickBooks Desktop 2024 R5 update installed', 'Chase bank website not loading — DNS issue',
 'door code panel rewired', 'alarm panel battery swapped', 'SQL Server 2019 CU25 applied on SQL01',
 'connection string updated in web.config to new server name', 'SSH enabled on switch, keys only',
 'seeded new SharePoint site with templates', 'gave user admin rights for install, removed after',
 'Win11 23H2 to 24H2 upgrade on PC-07', 'moved 120GB mailbox to archive', 'WiFi 6E AP installed in conf room 2',
 'Okta to Entra SSO migration call, 1.5h', 'Patched CVE-2026-1234 on firewall', 'reviewed Secure Score, now 78%',
 'user forgot password again, reset via SSPR', 'cleared stuck print jobs on HP M404n', 'created password reset ticket #4471',
 'set recovery email for CEO mailbox', 'vlan 20 created for VoIP phones', 'Office 365 E3 licenses reassigned (3)',
 'replaced DIMM in ESXi host 2 (32GB DDR4-3200)', 'firmware 2.41.0 on UniFi APs', 'renamed admin account to it-admin',
]


@pytest.mark.parametrize("text", BAD + BAD2)
def test_secrets_are_caught(text):
    assert ai.sensitive_reason(text), text


@pytest.mark.parametrize("text", GOOD + GOOD2)
def test_normal_notes_pass(text):
    assert ai.sensitive_reason(text) is None, (text, ai.sensitive_reason(text))


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
    assert "swapped hdd" in sent and "2026-11-02" not in sent and "OKG" not in sent
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM invoices").fetchone()[0] == 0   # nothing created


def test_cut_off_reply_is_not_offered(client, app, clock, claude):
    claude.stop = "max_tokens"
    do_setup(client, app, clock)
    _seed(client)
    _save_key(client)
    _entry(client, "did stuff")
    t = csrf(client, "/time/1")
    r = client.post("/time/1/ai", data={"csrf_token": t, "notes": "did stuff"})
    assert r.status_code == 400 and "didn" in r.get_data(as_text=True)
    assert claude.calls[0][1]["thinking"] == {"type": "disabled"}


def test_blocked_message_shows_what_triggered_it(client, app, clock, claude):
    do_setup(client, app, clock)
    _seed(client)
    _save_key(client)
    _entry(client, "set wifi key Guest2026! on AP")
    t = csrf(client, "/time/1")
    page = client.post("/time/1/ai", data={"csrf_token": t, "notes": "set wifi key Guest2026! on AP"}).get_data(as_text=True)
    assert "wifi Gu•" in page and "Guest2026!" not in page.split("<textarea")[0] and claude.calls == []


def test_unsaved_form_changes_are_kept(client, app, clock, claude):
    do_setup(client, app, clock)
    _seed(client)
    _save_key(client)
    _entry(client, "did stuff")
    t = csrf(client, "/time/1")
    page = client.post("/time/1/ai", data={"csrf_token": t, "notes": "did stuff", "hours": "3.25",
                                           "work_date": "2026-11-04"}).get_data(as_text=True)
    assert 'value="3.25"' in page and 'value="2026-11-04"' in page


@pytest.mark.parametrize("url", ["https://:pw@api.anthropic.com/x", "https://api.anthropic.com:abc/x",
                                 "https://x@api.anthropic.com/x", "https://api.anthropic.com:443/x",
                                 "https://api.anthropic.com./x", "http://api.anthropic.com/x",
                                 "https://api.anthropic.com.evil.com/x"])
def test_outbound_blocks_odd_urls(url):
    with pytest.raises(outbound.OutboundError):
        outbound.post(url, b"", {}, {"api.anthropic.com"})
