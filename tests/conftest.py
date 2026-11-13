import re

import pytest
from cryptography.fernet import Fernet

from app import create_app, totp

SETUP_TOKEN = "test-setup-token-0123456789abcdef"
PASSWORD = "Correct-Horse-Battery-9"


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t

    def advance(self, seconds=30):
        self.t += seconds


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(totp, "_now", c)
    return c


@pytest.fixture
def app(tmp_path):
    return create_app({
        "SECRET_KEY": "s" * 48,
        "AUDIT_HMAC_KEY": "a" * 48,
        "ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "SETUP_TOKEN": SETUP_TOKEN,
        "DATA_DIR": str(tmp_path / "data"),
        "COOKIE_SECURE": False,
        "TRUST_PROXY_HEADERS": False,
        "APP_TIMEZONE": "America/New_York",
        "BUILD_DATE": "test",
        "SECURITY_DIR": str(tmp_path / "security"),
        "TESTING": True,
    })


@pytest.fixture
def client(app):
    return app.test_client()


def csrf(client, path):
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, f"no csrf token on {path}"
    return m.group(1)


def current_code(client, app, clock):
    """Current TOTP for the single user, read from the DB like the phone would."""
    from app import crypto
    from app.db import get_db
    with app.app_context():
        row = get_db().execute("SELECT totp_secret_enc FROM users").fetchone()
        secret = crypto.decrypt(row["totp_secret_enc"])
    return totp.code_at(secret, int(clock() // totp.PERIOD))


def do_setup(client, app, clock, username="david"):
    token = csrf(client, "/setup")
    r = client.post("/setup", data={"csrf_token": token, "setup_token": SETUP_TOKEN, "username": username,
                                    "password": PASSWORD, "password_confirm": PASSWORD})
    assert r.status_code == 302 and r.headers["Location"].endswith("/setup/2fa")
    token = csrf(client, "/setup/2fa")
    r = client.post("/setup/2fa", data={"csrf_token": token, "code": current_code(client, app, clock)})
    assert r.status_code == 200
    codes = re.findall(r"<div>([a-z2-9]{5}-[a-z2-9]{5})</div>", r.get_data(as_text=True))
    assert len(codes) == 10
    clock.advance()
    return codes


def do_login(client, app, clock, username="david", password=PASSWORD, code=None):
    token = csrf(client, "/login")
    r = client.post("/login", data={"csrf_token": token, "username": username, "password": password})
    if r.status_code != 302:
        return r
    token = csrf(client, "/login/2fa")
    r = client.post("/login/2fa", data={"csrf_token": token,
                                        "code": code or current_code(client, app, clock)})
    clock.advance()
    return r
