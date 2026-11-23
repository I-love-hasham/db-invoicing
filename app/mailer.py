"""Everything the app emails: invoices, reminders, test messages and security alerts.

Rules (from the spec):
- invoices and reminders go out only after David previews them and clicks Send;
- every outgoing email gets the Settings → Email copy address (CC or BCC) when it's on;
- every send is in the audit log (recipients, subject, time — never the message text);
- one Send click = at most one email (unique send token, claimed under the lock).
"""
import math
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone


from . import audit, graph
from .db import atomic, get_db

COPY_DEFAULTS = {"address": "", "mode": "cc", "enabled": "1"}
MAX_ALERT_ATTEMPTS = 5


class SendRefused(Exception):
    """A send that must not happen (already sent, invoice no longer eligible...)."""


# ---------------------------------------------------------------- email copy setting

def copy_settings() -> dict:
    rows = get_db().execute("SELECT key, value FROM app_settings WHERE key LIKE 'email_copy.%'").fetchall()
    stored = {r["key"].removeprefix("email_copy."): r["value"] for r in rows}
    s = {k: stored.get(k, v) for k, v in COPY_DEFAULTS.items()}
    s["enabled"] = s["enabled"] == "1"
    return s


def save_copy_settings(address: str, mode: str, enabled: bool) -> None:
    db = get_db()
    for k, v in (("address", address), ("mode", mode), ("enabled", "1" if enabled else "0")):
        db.execute("INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET"
                   " value = excluded.value", (f"email_copy.{k}", v))


def copy_recipients() -> tuple[list[str], list[str]]:
    s = copy_settings()
    if not (s["enabled"] and s["address"]):
        return [], []
    return ([s["address"]], []) if s["mode"] == "cc" else ([], [s["address"]])


_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32}$")


def new_send_token() -> str:
    return secrets.token_urlsafe(24)     # 32 characters


# ---------------------------------------------------------------- sending with a paper trail

def send(kind: str, send_token: str, to: list[str], subject: str, body: str, *,
         invoice=None, follow_up_id: int | None = None, attachments=None, add_copy: bool = True,
         recheck=None) -> None:
    """Claim the send token, send through Graph, record the result. Raises SendRefused or graph.GraphError.

    `recheck(db)` runs under the lock right before the claim; it raises SendRefused if the
    email must not go out any more (e.g. the invoice was paid a moment ago)."""
    if not _TOKEN_RE.match(send_token or ""):
        raise SendRefused("This form is out of date. Reload the page and try again.")
    cc, bcc = copy_recipients() if add_copy else ([], [])
    now = audit.utcnow_iso()
    client_id = invoice["client_id"] if invoice is not None else None
    target = f"invoice:{invoice['number']}" if invoice is not None else None
    with atomic() as db:
        if recheck is not None:
            recheck(db)
        if follow_up_id is not None and db.execute(
                "SELECT 1 FROM email_log WHERE follow_up_id = ? AND status IN ('sending', 'sent')",
                (follow_up_id,)).fetchone():
            raise SendRefused("This reminder was already sent (or is being sent right now).")
        if kind == "invoice" and db.execute(
                "SELECT 1 FROM email_log WHERE invoice_id = ? AND kind = 'invoice' AND status = 'sending'",
                (invoice["id"],)).fetchone():
            raise SendRefused("This invoice is being sent right now. Check the history in a moment.")
        if db.execute("SELECT 1 FROM email_log WHERE send_token = ?", (send_token,)).fetchone():
            raise SendRefused("This email was already sent (the Send button was clicked twice).")
        log_id = db.execute(
            "INSERT INTO email_log (kind, invoice_id, follow_up_id, to_addr, cc_addr, bcc_addr, subject, send_token,"
            " status, created_at) VALUES (?,?,?,?,?,?,?,?, 'sending', ?)",
            (kind, invoice["id"] if invoice is not None else None, follow_up_id, ", ".join(to), ", ".join(cc),
             ", ".join(bcc), subject, send_token, now)).lastrowid
    try:
        graph.send_mail(to, subject, body, cc=cc, bcc=bcc, attachments=attachments)   # network: no lock held
    except graph.GraphError as e:
        with atomic() as db:
            db.execute("UPDATE email_log SET status = 'failed', error = ? WHERE id = ?", (str(e)[:300], log_id))
            audit.log("graph_sendmail", "outside", outcome="failure", target=target, client_id=client_id,
                      details={"kind": kind, "error": str(e)[:300]})
            audit.log(f"{kind}_email_failed", "email", outcome="failure", target=target, client_id=client_id,
                      details={"to": to, "cc": cc, "bcc": bcc, "subject": subject})
        raise
    sent = audit.utcnow_iso()
    with atomic() as db:
        db.execute("UPDATE email_log SET status = 'sent', sent_at = ? WHERE id = ?", (sent, log_id))
        if follow_up_id is not None:
            db.execute("UPDATE follow_ups SET sent_at = ? WHERE id = ? AND sent_at IS NULL", (sent, follow_up_id))
        audit.log("graph_sendmail", "outside", target=target, client_id=client_id, details={"kind": kind})
        audit.log(f"{kind}_emailed", "email", target=target, client_id=client_id,
                  details={"to": to, "cc": cc, "bcc": bcc, "subject": subject, "sent_at": sent,
                           "attachments": [name for name, _ in (attachments or [])]})


def history(invoice_id: int):
    return get_db().execute("SELECT * FROM email_log WHERE invoice_id = ? ORDER BY id DESC", (invoice_id,)).fetchall()


# ---------------------------------------------------------------- security alerts by email
#
# Alerts are emailed by a background thread (one per worker process), never inside a
# page request: a slow or down Microsoft can't slow the app, and visitors can't make
# the app call out by loading pages. Claims expire, so a crash never strands an alert.

CLAIM_TTL = 600          # seconds before a stuck 'sending' claim is retried
FLUSH_EVERY = 60         # seconds between background flushes


def _alert_email(to: str, rows) -> None:
    lines = [f"- {r['ts'][:16].replace('T', ' ')} UTC — {r['message']}" for r in rows]
    body = ("Security alerts from your DB IT Consulting invoicing app:\n\n" + "\n".join(lines) +
            "\n\nSign in to the app to review and acknowledge them. If you didn't expect this, "
            "check the audit log right away.")
    graph.send_mail([to], f"[Invoicing app] Security alert ({len(rows)})", body)


def _mark_email_configured(db) -> None:
    """The first time email works, old alerts (>24 h) are marked skipped once — not on every flush."""
    if db.execute("SELECT 1 FROM app_settings WHERE key = 'email.configured_at'").fetchone():
        return
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    db.execute("UPDATE security_alerts SET emailed_at = 'skipped' WHERE emailed_at IS NULL AND ts < ?", (cutoff,))
    db.execute("INSERT INTO app_settings (key, value) VALUES ('email.configured_at', ?)", (audit.utcnow_iso(),))


def flush_alerts() -> None:
    """Email security alerts that haven't gone out yet. Safe to run from several workers."""
    if not graph.configured():
        return
    to = copy_settings()["address"]
    if not to:
        return
    now = time.time()
    claim = f"sending:{now:.0f}:{secrets.token_hex(6)}"
    with atomic() as db:
        _mark_email_configured(db)
        # release claims older than CLAIM_TTL (the worker that took them died)
        for r in db.execute("SELECT id, emailed_at FROM security_alerts WHERE emailed_at LIKE 'sending:%'").fetchall():
            try:
                taken = float(r["emailed_at"].split(":")[1])
            except (IndexError, ValueError):
                taken = 0
            if not math.isfinite(taken):
                taken = 0
            if now - taken > CLAIM_TTL:
                db.execute("UPDATE security_alerts SET emailed_at = NULL WHERE id = ?", (r["id"],))
        db.execute("UPDATE security_alerts SET emailed_at = ? WHERE id IN (SELECT id FROM security_alerts"
                   " WHERE emailed_at IS NULL ORDER BY id LIMIT 20)", (claim,))
        rows = db.execute("SELECT * FROM security_alerts WHERE emailed_at = ? ORDER BY id", (claim,)).fetchall()
    if not rows:
        return
    try:
        _alert_email(to, rows)
    except graph.GraphError as e:
        with atomic() as db:
            db.execute("UPDATE security_alerts SET email_attempts = email_attempts + 1,"
                       " emailed_at = CASE WHEN email_attempts + 1 >= ? THEN 'failed' ELSE NULL END"
                       " WHERE emailed_at = ?", (MAX_ALERT_ATTEMPTS, claim))
            audit.log("graph_sendmail", "outside", outcome="failure",
                      details={"kind": "alert", "alerts": len(rows), "error": str(e)[:300]})
        return
    sent = audit.utcnow_iso()
    with atomic() as db:
        db.execute("UPDATE security_alerts SET emailed_at = ? WHERE emailed_at = ?", (sent, claim))
        audit.log("graph_sendmail", "outside", details={"kind": "alert", "alerts": len(rows)})
        audit.log("alert_emailed", "email", details={"to": [to], "alerts": len(rows)})


def unemailed_alert_count() -> int:
    """Alerts that could not be emailed (failed) or were skipped — shown on the dashboard."""
    return get_db().execute("SELECT COUNT(*) AS n FROM security_alerts WHERE emailed_at IN ('failed', 'skipped')"
                            " AND acknowledged_at IS NULL").fetchone()["n"]


def send_direct_alert(to: str, message: str) -> None:
    """One-off alert to a specific address (used to warn the OLD address when the copy
    address is changed). Best effort: failures are audited, not raised."""
    if not (graph.configured() and to):
        return
    try:
        graph.send_mail([to], "[Invoicing app] Security alert", message +
                        "\n\nIf you didn't make this change, sign in and check the audit log right away.")
        audit.log("graph_sendmail", "outside", details={"kind": "alert_old_address"})
    except graph.GraphError as e:
        audit.log("graph_sendmail", "outside", outcome="failure",
                  details={"kind": "alert_old_address", "error": str(e)[:300]})


_worker = {"pid": None}
_worker_lock = threading.Lock()


def _loop(app) -> None:
    while True:
        time.sleep(FLUSH_EVERY)
        try:
            with app.app_context():
                flush_alerts()
        except Exception:
            app.logger.exception("alert email flush failed")


def init_app(app):
    if app.config.get("TESTING"):
        return          # tests call flush_alerts() directly

    @app.before_request
    def _start_worker():
        # one background thread per worker process (gunicorn forks after preloading)
        if _worker["pid"] != os.getpid():
            with _worker_lock:
                if _worker["pid"] != os.getpid():
                    threading.Thread(target=_loop, args=(app,), daemon=True, name="alert-mailer").start()
                    _worker["pid"] = os.getpid()
