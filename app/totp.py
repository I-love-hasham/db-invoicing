"""TOTP (RFC 6238) for Microsoft / Google Authenticator.

Small and self-contained so it can be checked line by line; it is verified
against the official RFC 6238 test vectors in tests/test_totp.py.
"""
import base64
import hashlib
import hmac
import re
import secrets
import struct
import time
from urllib.parse import quote

PERIOD = 30
DIGITS = 6
ISSUER = "DB IT Invoicing"
_CODE_RE = re.compile(r"[0-9]{%d}" % DIGITS)


def _now() -> float:  # separate function so tests can control the clock
    return time.time()


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret_b32: str) -> bytes:
    s = secret_b32.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret_b32: str, step: int, digits: int = DIGITS, key: bytes | None = None) -> str:
    key = key if key is not None else _key(secret_b32)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def current_step() -> int:
    return int(_now() // PERIOD)


def verify(secret_b32: str, code: str, last_step: int, window: int = 1) -> int | None:
    """Return the matched time step, or None.

    Accepts the current step +/- `window` (clock drift) but never a step at or
    before `last_step`, so a code can't be used twice.
    """
    # ASCII 0-9 only: str.isdigit() would also accept e.g. Arabic-Indic digits
    if not (isinstance(code, str) and _CODE_RE.fullmatch(code)):
        return None
    now = current_step()
    matched = None
    for step in range(now - window, now + window + 1):
        # compare every candidate (no early exit) to keep timing uniform
        if hmac.compare_digest(code_at(secret_b32, step), code) and step > last_step:
            matched = step
    return matched


def provisioning_uri(secret_b32: str, username: str) -> str:
    label = quote(f"{ISSUER}:{username}")
    return (
        f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(ISSUER)}"
        f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"
    )


def qr_data_uri(uri: str) -> str | None:
    """SVG QR code as a data: URI, or None if segno isn't installed."""
    try:
        import segno
    except ImportError:
        return None
    return segno.make_qr(uri, error="m").svg_data_uri(scale=5, dark="#1e3d2f")
