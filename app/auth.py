"""Passwords, 2FA, lockouts and server-side sessions."""
import functools
import hashlib
import re
import secrets
import time

from flask import current_app, g, redirect, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import audit, crypto, totp
from .db import get_db

LOCK_THRESHOLD = 5          # failed attempts before lockout
LOCK_SECONDS = 15 * 60
ALERT_THRESHOLD = 3         # failed attempts that raise an alert
IP_MAX_FAILURES = 20        # per IP, per window, regardless of account
IP_WINDOW = 15 * 60
IDLE_TIMEOUT = 30 * 60
ABSOLUTE_TIMEOUT = 12 * 60 * 60
PASSWORD_STAGE_TIMEOUT = 5 * 60   # time allowed to enter the 2FA code after the password
ENROLL_STAGE_TIMEOUT = 30 * 60
REAUTH_WINDOW = 5 * 60            # sensitive changes need 2FA within this window
BACKUP_CODE_COUNT = 10
_BACKUP_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o/1/l/i
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")

# Used when the username doesn't exist so response time doesn't reveal that.
_DUMMY_HASH = generate_password_hash("timing-equalizer-not-a-real-password", method="scrypt")


# ---------------------------------------------------------------- passwords

def hash_password(password: str) -> str:
    return generate_password_hash(password, method="scrypt")


def check_password(user, password: str) -> bool:
    stored = user["password_hash"] if user else _DUMMY_HASH
    ok = check_password_hash(stored, password or "")
    return bool(user) and ok


def password_problem(password: str, username: str) -> str | None:
    if not password or len(password) < 12:
        return "Password must be at least 12 characters."
    if len(password) > 128:
        return "Password must be 128 characters or fewer."
    if password.lower() == (username or "").lower():
        return "Password can't be the same as the username."
    if len(set(password)) < 5:
        return "Password is too simple."
    return None


# ---------------------------------------------------------------- lockout / throttling

def ip_throttled(ip: str) -> bool:
    row = get_db().execute(
        "SELECT COUNT(*) AS n FROM login_failures WHERE ip = ? AND ts > ?",
        (ip, time.time() - IP_WINDOW),
    ).fetchone()
    return row["n"] >= IP_MAX_FAILURES


def is_locked(user) -> bool:
    return bool(user and user["locked_until"] and user["locked_until"] > time.time())


def register_failure(user, reason: str, attempted_username: str | None = None) -> bool:
    """Record a failed password / 2FA / setup attempt. Returns True if the account is now locked."""
    db = get_db()
    now = time.time()
    db.execute("INSERT INTO login_failures (ip, ts) VALUES (?, ?)", (g.ip, now))
    db.execute("DELETE FROM login_failures WHERE ts < ?", (now - 86400,))
    name = user["username"] if user else loggable_username(attempted_username)
    audit.log(reason, "auth", outcome="failure", username=name,
              details={"unknown_username": True} if not user else None)
    ip_failures = db.execute("SELECT COUNT(*) AS n FROM login_failures WHERE ip = ? AND ts > ?",
                             (g.ip, now - IP_WINDOW)).fetchone()["n"]
    if ip_failures == IP_MAX_FAILURES:
        audit.raise_alert("ip_throttled", f"{ip_failures} failed sign-in attempts from {g.ip} in 15 minutes. "
                                          "That address is now blocked from signing in for a while.")
    if not user:
        if ip_failures == ALERT_THRESHOLD:
            audit.raise_alert("failed_logins", f"{ip_failures} failed sign-in attempts from {g.ip} "
                                               "(unknown username or bad setup token).")
        return False
    count = user["failed_count"] + 1
    if count >= LOCK_THRESHOLD:
        db.execute("UPDATE users SET failed_count = 0, locked_until = ? WHERE id = ?",
                   (now + LOCK_SECONDS, user["id"]))
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
        audit.log("account_locked", "auth", outcome="failure", username=name,
                  details={"minutes": LOCK_SECONDS // 60, "failed_attempts": count})
        audit.raise_alert("lockout", f"Account '{name}' was locked for 15 minutes after "
                                     f"{count} failed sign-in attempts (last from {g.ip}).")
        return True
    db.execute("UPDATE users SET failed_count = ? WHERE id = ?", (count, user["id"]))
    if count == ALERT_THRESHOLD:
        audit.raise_alert("failed_logins", f"{count} failed sign-in attempts in a row for "
                                           f"'{name}' (last from {g.ip}).")
    return False


def reset_failures(user_id: int) -> None:
    get_db().execute("UPDATE users SET failed_count = 0, locked_until = NULL WHERE id = ?", (user_id,))


# ---------------------------------------------------------------- 2FA

def user_totp_secret(user) -> str:
    return crypto.decrypt(user["totp_secret_enc"])


def check_totp(user, code: str, secret: str | None = None) -> bool:
    """Verify a TOTP code and record its step so it can't be reused."""
    step = totp.verify(secret or user_totp_secret(user), code, user["totp_last_step"])
    if step is None:
        return False
    # Conditional update: only one request can ever claim a given time step.
    cur = get_db().execute("UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?",
                           (step, user["id"], step))
    return cur.rowcount == 1


def _normalize_backup(code: str) -> str:
    return re.sub(r"[\s-]", "", (code or "").lower())


def generate_backup_codes(user_id: int) -> list[str]:
    """Replace all backup codes; returns the plain codes to show once."""
    codes = []
    db = get_db()
    db.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
    for _ in range(BACKUP_CODE_COUNT):
        raw = "".join(secrets.choice(_BACKUP_ALPHABET) for _ in range(10))
        db.execute("INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)",
                   (user_id, generate_password_hash(raw, method="scrypt")))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def use_backup_code(user, code: str) -> bool:
    norm = _normalize_backup(code)
    if len(norm) != 10:
        return False
    db = get_db()
    for row in db.execute("SELECT id, code_hash FROM backup_codes WHERE user_id = ? AND used_at IS NULL",
                          (user["id"],)).fetchall():
        if check_password_hash(row["code_hash"], norm):
            cur = db.execute("UPDATE backup_codes SET used_at = ? WHERE id = ? AND used_at IS NULL",
                             (audit.utcnow_iso(), row["id"]))
            return cur.rowcount == 1
    return False


def backup_codes_left(user_id: int) -> int:
    return get_db().execute("SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = ? AND used_at IS NULL",
                            (user_id,)).fetchone()["n"]


def verify_second_factor(user, code: str) -> str | None:
    """Returns 'totp' or 'backup_code' on success, None on failure."""
    code = (code or "").strip().replace(" ", "")
    if code.isdigit() and len(code) == totp.DIGITS:
        return "totp" if check_totp(user, code) else None
    if use_backup_code(user, code):
        return "backup_code"
    return None


# ---------------------------------------------------------------- sessions

def cookie_name() -> str:
    # __Host- prefix: browser only accepts it over HTTPS, path=/, no domain.
    return "__Host-dbinv" if current_app.config["COOKIE_SECURE"] else "dbinv"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(user_id: int, stage: str) -> None:
    """Create a fresh session (new token = no session fixation) and queue the cookie."""
    db = get_db()
    old = g.get("session")
    if old:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (old["token_hash"],))
    token = secrets.token_urlsafe(32)
    now = time.time()
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, stage, created_at, last_seen, reauth_at, ip,"
        " user_agent, csrf_token) VALUES (?,?,?,?,?,?,?,?,?)",
        (_hash_token(token), user_id, stage, now, now, now if stage == "full" else None,
         g.ip, g.ua, secrets.token_urlsafe(32)),
    )
    g.set_cookie_token = token
    g.clear_cookie = False


def end_session() -> None:
    if g.get("session"):
        get_db().execute("DELETE FROM sessions WHERE token_hash = ?", (g.session["token_hash"],))
    g.session = None
    g.user = None
    g.clear_cookie = True
    g.set_cookie_token = None


def load_session() -> None:
    token = request.cookies.get(cookie_name())
    if not token:
        return
    if len(token) > 128:
        g.clear_cookie = True
        return
    db = get_db()
    row = db.execute(
        "SELECT s.*, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (_hash_token(token),),
    ).fetchone()
    if row is None:
        g.clear_cookie = True
        return
    now = time.time()
    reason = None
    if now - row["created_at"] > ABSOLUTE_TIMEOUT:
        reason = "absolute_timeout"
    elif now - row["last_seen"] > IDLE_TIMEOUT:
        reason = "idle_timeout"
    elif row["stage"] == "password" and now - row["created_at"] > PASSWORD_STAGE_TIMEOUT:
        reason = "2fa_not_completed"
    elif row["stage"] == "enroll" and now - row["created_at"] > ENROLL_STAGE_TIMEOUT:
        reason = "setup_not_completed"
    if reason:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
        audit.log("session_expired", "auth", username=row["username"], details={"reason": reason})
        g.clear_cookie = True
        return
    if now - row["last_seen"] > 60:
        db.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (now, row["token_hash"]))
    g.session = dict(row)
    g.user = {"id": row["user_id"], "username": row["username"]}


def get_user(user_id: int):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def has_fresh_2fa() -> bool:
    s = g.get("session")
    return bool(s and s["stage"] == "full" and s["reauth_at"] and time.time() - s["reauth_at"] <= REAUTH_WINDOW)


def mark_reauth() -> None:
    now = time.time()
    get_db().execute("UPDATE sessions SET reauth_at = ? WHERE token_hash = ?", (now, g.session["token_hash"]))
    g.session["reauth_at"] = now


def fresh_2fa_required(view):
    """Sensitive pages: settings, keys, connected accounts. Re-asks for 2FA."""
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not has_fresh_2fa():
            return redirect(url_for("auth.reauth", next=request.path))
        return view(*args, **kwargs)
    return wrapper


_SAFE_PATH = re.compile(r"^/[A-Za-z0-9_\-./]*$")


def safe_next(target: str | None, default: str) -> str:
    """Only plain local paths like /settings/password; anything else goes to the default."""
    if target and _SAFE_PATH.match(target) and not target.startswith("//") and len(target) <= 200:
        return target
    return default


def loggable_username(name: str | None) -> str | None:
    """Never log free text from the username box: it might be a mistyped password."""
    if name is None:
        return None
    return name if USERNAME_RE.match(name) else "[not a valid username]"


# ---------------------------------------------------------------- devices

def check_known_device(user_id: int, username: str) -> None:
    """Alert on sign-in from an IP address or browser not seen before."""
    db = get_db()
    ua_hash = hashlib.sha256((g.ua or "").encode()).hexdigest()[:32]
    now = audit.utcnow_iso()
    has_any = db.execute("SELECT 1 FROM known_devices WHERE user_id = ? LIMIT 1", (user_id,)).fetchone()
    ip_known = db.execute("SELECT 1 FROM known_devices WHERE user_id = ? AND ip = ? LIMIT 1",
                          (user_id, g.ip)).fetchone()
    ua_known = db.execute("SELECT 1 FROM known_devices WHERE user_id = ? AND ua_hash = ? LIMIT 1",
                          (user_id, ua_hash)).fetchone()
    db.execute(
        "INSERT INTO known_devices (user_id, ip, ua_hash, first_seen, last_seen) VALUES (?,?,?,?,?)"
        " ON CONFLICT(user_id, ip, ua_hash) DO UPDATE SET last_seen = excluded.last_seen",
        (user_id, g.ip, ua_hash, now, now),
    )
    if has_any and not (ip_known and ua_known):
        what = []
        if not ip_known:
            what.append(f"new IP address {g.ip}")
        if not ua_known:
            what.append("new device/browser")
        audit.raise_alert("new_device", f"Sign-in to '{username}' from " + " and ".join(what)
                          + f" ({(g.ua or 'unknown browser')[:120]}).")
