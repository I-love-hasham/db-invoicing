"""Append-only, tamper-evident audit log and security alerts.

Each entry's hash = HMAC-SHA256(AUDIT_HMAC_KEY, previous_hash | entry). Changing,
removing or reordering any entry breaks the chain, and without the key (kept
only in .env) a rewritten chain can't be made to verify. A signed "head"
record catches entries being cut off the end. SQLite triggers also block
UPDATE and DELETE, and the app has no code path that edits or deletes entries.
"""
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone

from flask import current_app, g, has_request_context

from .db import get_audit_db, get_db

GENESIS = "0" * 64
FIELDS = ("ts", "username", "ip", "user_agent", "category", "action", "target", "outcome", "details")
CATEGORIES = ("auth", "settings", "security", "audit", "system", "error")

# Any detail key that looks like it could hold a secret is replaced before writing.
_SENSITIVE_KEY = re.compile(
    r"pass|secret|token|key|code|otp|cookie|session|bank|card|routing|account_number", re.I
)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def redact(value, _depth: int = 0):
    if _depth > 6:
        return "[truncated]"
    if isinstance(value, dict):
        return {
            str(k): ("[redacted]" if _SENSITIVE_KEY.search(str(k)) else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v, _depth + 1) for v in value[:100]]
    if isinstance(value, str):
        return value[:2000]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:2000]


def _mac(message: str) -> str:
    key = current_app.config["AUDIT_HMAC_KEY"].encode()
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def _payload(entry: dict) -> str:
    return json.dumps([entry[f] for f in FIELDS], ensure_ascii=False, separators=(",", ":"))


def _head_mac(count: int, last_hash: str) -> str:
    return _mac(f"head|{count}|{last_hash}")


def log(action: str, category: str, outcome: str = "success", target: str | None = None,
        details: dict | None = None, username: str | None = None) -> None:
    """Write one audit entry. Raises on failure (fail closed)."""
    if category not in CATEGORIES:
        raise ValueError(f"unknown audit category {category!r}")
    if username is None and has_request_context() and g.get("user"):
        username = g.user["username"]
    entry = {
        "ts": utcnow_iso(),
        "username": username,
        "ip": g.get("ip") if has_request_context() else None,
        "user_agent": g.get("ua") if has_request_context() else None,
        "category": category,
        "action": action,
        "target": target,
        "outcome": outcome,
        "details": json.dumps(redact(details or {}), ensure_ascii=False, sort_keys=True),
    }
    conn = get_audit_db()
    conn.execute("BEGIN IMMEDIATE")  # serializes writers so the chain never forks
    try:
        head = conn.execute("SELECT entry_count, last_hash FROM audit_head WHERE id = 1").fetchone()
        prev = head["last_hash"] if head else GENESIS
        count = (head["entry_count"] if head else 0) + 1
        entry_hash = _mac(prev + "|" + _payload(entry))
        conn.execute(
            "INSERT INTO audit_log (ts, username, ip, user_agent, category, action, target,"
            " outcome, details, prev_hash, entry_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (*[entry[f] for f in FIELDS], prev, entry_hash),
        )
        conn.execute(
            "INSERT INTO audit_head (id, entry_count, last_hash, mac) VALUES (1, ?, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET entry_count = excluded.entry_count,"
            " last_hash = excluded.last_hash, mac = excluded.mac",
            (count, entry_hash, _head_mac(count, entry_hash)),
        )
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    _save_checkpoint(count, entry_hash)


def _save_checkpoint(count: int, entry_hash: str) -> None:
    """Remember the newest entry in app.db (commits with the request)."""
    value = f"{count}|{entry_hash}|{_mac(f'checkpoint|{count}|{entry_hash}')}"
    get_db().execute(
        "INSERT INTO app_state (key, value) VALUES ('audit_checkpoint', ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value"
        " WHERE CAST(substr(app_state.value, 1, instr(app_state.value, '|') - 1) AS INTEGER) < ?",
        (value, count),
    )


def _read_checkpoint():
    row = get_db().execute("SELECT value FROM app_state WHERE key = 'audit_checkpoint'").fetchone()
    has_users = get_db().execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
    return (row["value"] if row else None), has_users


def _check_checkpoint(checkpoint: tuple, entries: list) -> str | None:
    """Problem text if the log is shorter than, or doesn't contain, the highest entry ever written."""
    value, has_users = checkpoint
    if value is None:
        # Account creation is always audited (with a checkpoint) in the same transaction,
        # so accounts without a checkpoint means the checkpoint was removed.
        if has_users:
            return "The audit checkpoint is missing — audit data was deleted or replaced."
        return None
    row = {"value": value}
    try:
        count_s, entry_hash, mac = row["value"].split("|")
        count = int(count_s)
    except ValueError:
        return "The audit checkpoint is unreadable."
    if not hmac.compare_digest(mac, _mac(f"checkpoint|{count}|{entry_hash}")):
        return "The audit checkpoint was altered."
    if len(entries) < count:
        return (f"The audit log has {len(entries)} entries but {count} were written — "
                "it was deleted, cut short, or restored from an older copy.")
    if entries[count - 1] != entry_hash:
        return f"Audit entry #{count} doesn't match what was originally written."
    return None


def verify_chain() -> tuple[bool, int, str]:
    """Walk the whole chain. Returns (ok, entries_checked, message)."""
    checkpoint = _read_checkpoint()   # read FIRST: entries written after it are fine
    conn = get_audit_db()
    prev = GENESIS
    count = 0
    hashes = []
    for row in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        count += 1
        hashes.append(row["entry_hash"])
        entry = {f: row[f] for f in FIELDS}
        if row["prev_hash"] != prev:
            return False, count, f"Entry #{row['id']} does not link to the entry before it."
        if not hmac.compare_digest(row["entry_hash"], _mac(prev + "|" + _payload(entry))):
            return False, count, f"Entry #{row['id']} was altered."
        prev = row["entry_hash"]
    problem = _check_checkpoint(checkpoint, hashes)
    if problem:
        return False, count, problem
    head = conn.execute("SELECT * FROM audit_head WHERE id = 1").fetchone()
    if head is None:
        if count == 0:
            return True, 0, "Audit log is empty."
        return False, count, "Audit head record is missing."
    if not hmac.compare_digest(head["mac"], _head_mac(head["entry_count"], head["last_hash"])):
        return False, count, "Audit head record was altered."
    if head["entry_count"] != count or head["last_hash"] != prev:
        return False, count, "Entries are missing from the end of the audit log."
    return True, count, f"All {count} entries verified."


# ---------------------------------------------------------------- alerts

def raise_alert(kind: str, message: str) -> None:
    """Red dashboard banner until acknowledged. Email from billing@ is added
    with the Microsoft Graph step (emailed_at stays empty until then)."""
    get_db().execute(
        "INSERT INTO security_alerts (ts, kind, message) VALUES (?, ?, ?)",
        (utcnow_iso(), kind, message),
    )
    log("alert_raised", "security", details={"kind": kind, "message": message})


def open_alerts():
    return get_db().execute(
        "SELECT * FROM security_alerts WHERE acknowledged_at IS NULL ORDER BY id DESC"
    ).fetchall()
