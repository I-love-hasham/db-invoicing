"""Payment status, dashboard totals and 7/14-day reminder drafts."""
from datetime import date, timedelta

from . import audit, forms, invoicing
from .db import atomic, get_db

METHODS = {"check": "Check", "zelle": "Zelle", "transfer": "Bank transfer", "other": "Other"}
FOLLOW_UP_STAGES = (7, 14)


def summary(today: str) -> dict:
    """Outstanding (not yet due), overdue, total owed — unpaid invoices only."""
    rows = get_db().execute("SELECT due_date, total_cents FROM invoices WHERE status = 'unpaid'").fetchall()
    overdue = [r for r in rows if r["due_date"] < today]
    current = [r for r in rows if r["due_date"] >= today]
    return {
        "outstanding_cents": sum(r["total_cents"] for r in current), "outstanding_count": len(current),
        "overdue_cents": sum(r["total_cents"] for r in overdue), "overdue_count": len(overdue),
        "owed_cents": sum(r["total_cents"] for r in rows), "owed_count": len(rows),
    }


def follow_up_text(inv, stage: int, signature: str) -> dict:
    """The pre-written reminder (David previews it; nothing is sent automatically)."""
    vm = invoicing.view_model(inv, [], "9999-12-31")
    biz, client = vm["business"]["name"], vm["client"]["name"]
    total = forms.format_money(inv["total_cents"])
    subject = f"Reminder: Invoice #{inv['number']} – {biz} – due {vm['due_date']}"
    if stage == 7:
        body = (f"Hi {client},\n\n"
                f"I hope all is well. This is a friendly reminder that invoice #{inv['number']} for {total}, "
                f"dated {vm['invoice_date']}, was due on {vm['due_date']}. I've attached a copy for convenience.\n\n"
                "If payment is already on its way, thank you, and please disregard this note.\n\n"
                f"Thank you,\n{signature}\n{biz}")
    else:
        body = (f"Hi {client},\n\n"
                f"I'm following up on invoice #{inv['number']} for {total}, dated {vm['invoice_date']}, which is now "
                f"two weeks past its due date of {vm['due_date']}. A copy is attached.\n\n"
                "Could you let me know when payment will be sent? If there's a question about the invoice, "
                "I'm happy to go over it.\n\n"
                f"Thank you,\n{signature}\n{biz}")
    return {"subject": subject, "body": body, "to": vm["client"]["email"]}


def due_follow_ups(today: str) -> list[dict]:
    """Unpaid invoices that have reached 7 or 14 days past due and whose reminder isn't sent yet.
    The first time a reminder becomes due, its draft is recorded in the audit log."""
    db = get_db()
    out = []
    for inv in db.execute("SELECT * FROM invoices WHERE status = 'unpaid' AND due_date < ? ORDER BY due_date",
                          (today,)).fetchall():
        days_late = (date.fromisoformat(today) - date.fromisoformat(inv["due_date"])).days
        reached = [s for s in FOLLOW_UP_STAGES if days_late >= s]
        if not reached:
            continue
        stage = reached[-1]           # the most recent stage reached
        row = db.execute("SELECT * FROM follow_ups WHERE invoice_id = ? AND stage = ?", (inv["id"], stage)).fetchone()
        if row is None:
            with atomic() as wdb:
                row = wdb.execute("SELECT * FROM follow_ups WHERE invoice_id = ? AND stage = ?",
                                  (inv["id"], stage)).fetchone()
                if row is None:
                    wdb.execute("INSERT INTO follow_ups (invoice_id, stage, drafted_at) VALUES (?, ?, ?)",
                                (inv["id"], stage, audit.utcnow_iso()))
                    audit.log("followup_drafted", "invoices", target=f"invoice:{inv['number']}",
                              client_id=inv["client_id"], details={"stage_days": stage, "days_late": days_late})
                    row = wdb.execute("SELECT * FROM follow_ups WHERE invoice_id = ? AND stage = ?",
                                      (inv["id"], stage)).fetchone()
        if row["sent_at"] is None:
            out.append({"invoice": inv, "stage": stage, "days_late": days_late, "follow_up": row})
    return out


def latest_paid_date(today: str) -> str:
    return today


def valid_paid_date(form, invoice_date: str, today: str) -> str:
    value = forms.date_value(form, "paid_date", "Date paid", latest=today)
    earliest = (date.fromisoformat(invoice_date) - timedelta(days=60)).isoformat()
    if value < earliest:
        raise forms.FormError("paid_date", "That's long before the invoice date — check the date.")
    return value
