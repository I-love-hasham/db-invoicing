"""Passwords, 2FA, lockouts and server-side sessions."""
import functools
import hashlib
import re
import secrets
import time

from flask import current_app, g, redirect, request, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from . import audit, crypto, totp
from .db import atomic, get_db

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
#
# Every password / 2FA / setup-token check is bracketed by begin_attempt() and
# end_attempt(). begin_attempt() *reserves* the attempt atomically (counts it
# toward the account and the IP) BEFORE the slow check runs, so parallel
# requests can never get more than 5 guesses in. A successful check gives the
# reservation back.

class Attempt:
    def __init__(self, status: str, count: int = 0, row_id: int | None = None):
        self.status = status      # "ok", "locked" or "throttled"
        self.count = count        # this attempt's number toward the account lockout
        self.row_id = row_id      # its row in login_failures (per-IP counter)

    @property
    def blocked(self) -> bool:
        return self.status != "ok"


def _ip_failures(now: float) -> int:
    return get_db().execute("SELECT COUNT(*) AS n FROM login_failures WHERE ip = ? AND ts > ?",
                            (g.ip, now - IP_WINDOW)).fetchone()["n"]


def begin_attempt(user) -> Attempt:
    now = time.time()
    with atomic() as db:
        if _ip_failures(now) >= IP_MAX_FAILURES:
            return Attempt("throttled")
        row_id = db.execute("INSERT INTO login_failures (ip, ts) VALUES (?, ?)", (g.ip, now)).lastrowid
        db.execute("DELETE FROM login_failures WHERE ts < ?", (now - 86400,))
        if user is None:
            return Attempt("ok", 0, row_id)
        row = db.execute("SELECT failed_count, locked_until FROM users WHERE id = ?", (user["id"],)).fetchone()
        if row["locked_until"] and row["locked_until"] > now:
            return Attempt("locked", 0, row_id)   # still counts toward the IP limit
        if row["failed_count"] >= LOCK_THRESHOLD:
            # 5 attempts reserved but never closed (e.g. a crashed request): turn it into
            # a normal 15-minute lock so it always expires, and alert.
            _lock(user, row["failed_count"], now)
            return Attempt("locked", 0, row_id)
        count = db.execute("UPDATE users SET failed_count = failed_count + 1 WHERE id = ? RETURNING failed_count",
                           (user["id"],)).fetchone()["failed_count"]
        return Attempt("ok", count, row_id)


def end_attempt(attempt: Attempt, user, success: bool, reason: str | None = None) -> bool:
    """Close a reserved attempt. Returns True if the account is now locked."""
    with atomic() as db:
        if success:
            db.execute("DELETE FROM login_failures WHERE id = ?", (attempt.row_id,))
            if user is not None:
                db.execute("UPDATE users SET failed_count = MAX(failed_count - 1, 0) WHERE id = ?", (user["id"],))
            return False
        name = user["username"] if user is not None else "[unknown]"
        audit.log(reason, "auth", outcome="failure", username=name,
                  details={"unknown_username": True} if user is None else None)
        _ip_alerts()
        if user is None:
            return False
        if attempt.count >= LOCK_THRESHOLD:
            _lock(user, attempt.count, time.time())
            return True
        if attempt.count == ALERT_THRESHOLD:
            audit.raise_alert("failed_logins", f"{attempt.count} failed sign-in attempts in a row for "
                                               f"'{name}' (last from {g.ip}).")
        return False


def _lock(user, failed: int, now: float) -> None:
    db = get_db()
    db.execute("UPDATE users SET failed_count = 0, locked_until = ? WHERE id = ?", (now + LOCK_SECONDS, user["id"]))
    db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
    audit.log("account_locked", "auth", outcome="failure", username=user["username"],
              details={"minutes": LOCK_SECONDS // 60, "failed_attempts": failed})
    audit.raise_alert("lockout", f"Account '{user['username']}' was locked for 15 minutes after "
                                 f"{failed} failed sign-in attempts (last from {g.ip}).")


def run_check(attempt: Attempt, user, reason: str, check):
    """Run a password/2FA check; if it crashes, the reserved attempt is closed
    as a failure instead of leaking."""
    try:
        return check()
    except Exception:
        try:
            end_attempt(attempt, user, False, reason + "_error")
        except Exception:
            pass
        raise


def _ip_alerts() -> None:
    n = _ip_failures(time.time())
    if n >= IP_MAX_FAILURES:
        alert_once("ip_throttled", f"{n} failed attempts from {g.ip} in 15 minutes. That address "
                                   "is blocked from signing in for a while.")
    elif n >= ALERT_THRESHOLD:
        alert_once("ip_failed_logins", f"{n} failed sign-in attempts from {g.ip} in 15 minutes.")


def blocked_attempt(attempt: Attempt, user, password: str | None = None) -> None:
    """Locked or throttled: same work and same answer as a wrong password."""
    if password is not None:
        check_password(None, password)   # equal timing: always run one scrypt check
    action = "login_blocked_locked" if attempt.status == "locked" else "login_throttled"
    log_rate_limited(action, "auth", outcome="failure",
                     username=user["username"] if user is not None else "[unknown]")
    _ip_alerts()


def reset_failures(user_id: int) -> None:
    get_db().execute("UPDATE users SET failed_count = 0, locked_until = NULL WHERE id = ?", (user_id,))


def _window_state(key: str, now: float):
    row = get_db().execute("SELECT value FROM app_state WHERE key = ?", (key,)).fetchone()
    if row is None:
        return None, 0
    start, _, suppressed = row["value"].partition("|")
    try:
        return float(start), int(suppressed or 0)
    except ValueError:
        return None, 0


def log_rate_limited(action: str, category: str, **kwargs) -> None:
    """At most one audit entry per action per IP per 15 minutes; the next one
    reports how many were skipped. Keeps floods from filling the disk."""
    now = time.time()
    key = f"rl:{action}:{g.ip}"
    with atomic() as db:
        start, suppressed = _window_state(key, now)
        if start is not None and now - start < IP_WINDOW:
            db.execute("UPDATE app_state SET value = ? WHERE key = ?", (f"{start}|{suppressed + 1}", key))
            return
        details = dict(kwargs.pop("details", None) or {})
        if suppressed:
            details["repeats_not_logged_in_last_window"] = suppressed
        audit.log(action, category, details=details or None, **kwargs)
        db.execute("INSERT INTO app_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET"
                   " value = excluded.value", (key, f"{now}|0"))
    sweep_rate_limits()


def sweep_rate_limits() -> None:
    """Write a summary for finished windows that skipped entries, then prune old keys.
    Runs on every rate-limited event and whenever the dashboard loads."""
    now = time.time()
    cutoff_sql = "CAST(substr(value, 1, instr(value || '|', '|') - 1) AS REAL)"
    pending = get_db().execute(   # lock-free check first: usually there's nothing to do
        f"SELECT EXISTS (SELECT 1 FROM app_state WHERE key LIKE 'rl:%' AND value NOT LIKE '%|0'"
        f" AND {cutoff_sql} <= ?) OR EXISTS (SELECT 1 FROM app_state WHERE (key LIKE 'rl:%'"
        f" OR key LIKE 'alert:%') AND {cutoff_sql} < ?)", (now - IP_WINDOW, now - 86400)).fetchone()[0]
    if not pending:
        return
    with atomic() as db:
        for row in db.execute("SELECT key, value FROM app_state WHERE key LIKE 'rl:%'").fetchall():
            start, _, suppressed = row["value"].partition("|")
            try:
                start_f, n = float(start), int(suppressed or 0)
            except ValueError:
                continue
            if n and now - start_f >= IP_WINDOW:
                _, action, ip = row["key"].split(":", 2)
                audit.log(action + "_summary", "security", outcome="failure",
                          details={"ip": ip, "repeats_not_logged": n, "window_minutes": IP_WINDOW // 60})
                db.execute("UPDATE app_state SET value = ? WHERE key = ?", (f"{start_f}|0", row["key"]))
        db.execute("DELETE FROM app_state WHERE (key LIKE 'rl:%' OR key LIKE 'alert:%')"
                   " AND CAST(substr(value, 1, instr(value || '|', '|') - 1) AS REAL) < ?", (now - 86400,))


def alert_once(kind: str, message: str) -> None:
    """Raise an alert for this IP at most once per 15 minutes."""
    now = time.time()
    key = f"alert:{kind}:{g.ip}"
    with atomic() as db:
        start, _ = _window_state(key, now)
        if start is not None and now - start < IP_WINDOW:
            return
        audit.raise_alert(kind, message)
        db.execute("INSERT INTO app_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET"
                   " value = excluded.value", (key, f"{now}|0"))
        db.execute("DELETE FROM app_state WHERE key LIKE 'alert:%'"
                   " AND CAST(substr(value, 1, instr(value || '|', '|') - 1) AS REAL) < ?", (now - 86400,))


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
    if re.fullmatch(r"[0-9]{%d}" % totp.DIGITS, code):
        return "totp" if check_totp(user, code) else None
    if re.fullmatch(r"[A-Za-z0-9-]{10,11}", code) and use_backup_code(user, code):
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
        with atomic():
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
