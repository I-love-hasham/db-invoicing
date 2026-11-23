"""Building invoices from time entries. All money math goes through billing.py."""
import hashlib
import json
from datetime import date, timedelta

from . import billing
from .db import get_db

FIRST_NUMBER = 1205   # continues from the last invoice made before this app (#1204)


class InvoiceProblem(ValueError):
    pass


def us_date(iso: str) -> str:
    """2026-11-06 -> 11/06/26 (the spec's line-item format)."""
    d = date.fromisoformat(iso)
    return d.strftime("%m/%d/%y")


def billable_entries(client_id: int, period_from: str, period_to: str):
    """Finished, not-deleted, not-yet-invoiced time for this client in the period."""
    return get_db().execute(
        "SELECT t.*, p.name AS product_name, p.description AS product_description, p.archived_at AS product_archived"
        " FROM time_entries t JOIN products p ON p.id = t.product_id"
        " WHERE t.client_id = ? AND t.work_date >= ? AND t.work_date <= ? AND t.deleted_at IS NULL"
        " AND t.invoice_id IS NULL AND t.duration_seconds IS NOT NULL ORDER BY t.work_date, t.id",
        (client_id, period_from, period_to),
    ).fetchall()


def running_timer_in_period(client_id: int, period_from: str, period_to: str) -> bool:
    return get_db().execute(
        "SELECT 1 FROM time_entries WHERE client_id = ? AND work_date BETWEEN ? AND ? AND deleted_at IS NULL"
        " AND duration_seconds IS NULL", (client_id, period_from, period_to)).fetchone() is not None


def rate_for(client_id: int, product_id: int) -> int | None:
    row = get_db().execute(
        "SELECT COALESCE((SELECT rate_cents FROM client_rates WHERE client_id = ? AND product_id = ?),"
        " (SELECT default_rate_cents FROM products WHERE id = ?)) AS rate", (client_id, product_id, product_id),
    ).fetchone()
    return row["rate"]


def fingerprint(entries, lines) -> str:
    """Identifies exactly what a preview showed: which entries, and every line's rate and amount.
    If anything differs at Create time, David is sent back to a fresh preview."""
    raw = ",".join(f"{e['id']}:{e['duration_seconds']}:{e['product_id']}" for e in entries)
    raw += "|" + ",".join(f"{l['description']}:{l['seconds']}:{l['rate_cents']}:{l['amount_cents']}" for l in lines)
    return hashlib.sha256(raw.encode()).hexdigest()


def build_lines(client_id: int, entries, period_from: str, period_to: str) -> list[dict]:
    """One line per product: 'Regular Hours, IT services, 10/29/26 – 11/06/26', hours x rate."""
    by_product: dict[int, dict] = {}
    for e in entries:
        p = by_product.setdefault(e["product_id"], {
            "product_id": e["product_id"], "name": e["product_name"],
            "product_description": e["product_description"], "seconds": 0,
        })
        p["seconds"] += e["duration_seconds"]
    lines = []
    for sort, p in enumerate(sorted(by_product.values(), key=lambda x: x["name"].lower())):
        rate = rate_for(client_id, p["product_id"])
        if rate is None:
            raise InvoiceProblem(f"'{p['name']}' has no rate for this client. Set one on the client's page first.")
        parts = [p["name"]] + ([p["product_description"]] if p["product_description"] else [])
        parts.append(f"{us_date(period_from)} – {us_date(period_to)}")
        lines.append({
            "sort": sort, "product_id": p["product_id"], "description": ", ".join(parts),
            "seconds": p["seconds"], "hours": str(billing.billable_hours(p["seconds"])),
            "rate_cents": rate, "amount_cents": billing.line_amount_cents(p["seconds"], rate),
        })
    return lines


def next_number() -> int:
    row = get_db().execute("SELECT MAX(number) AS n FROM invoices").fetchone()
    return max(row["n"] or 0, FIRST_NUMBER - 1) + 1


def due_date(invoice_date: str, terms_days: int) -> str:
    return (date.fromisoformat(invoice_date) + timedelta(days=terms_days)).isoformat()


def client_snapshot(client) -> str:
    return json.dumps({"name": client["name"], "address": client["address"], "email": client["email"],
                       "payment_terms_days": client["payment_terms_days"]}, ensure_ascii=False)


def load(invoice_id: int):
    db = get_db()
    inv = db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if inv is None:
        return None, None
    lines = db.execute("SELECT * FROM invoice_lines WHERE invoice_id = ? ORDER BY sort", (invoice_id,)).fetchall()
    return inv, lines


def view_model(inv, lines, today: str) -> dict:
    """Everything the HTML page and the PDF show, computed in one place."""
    client = json.loads(inv["client_snapshot"])
    business = json.loads(inv["business_snapshot"])
    status = inv["status"]
    shown_status = {"unpaid": "Unpaid", "paid": "Paid", "void": "Void"}[status]
    if status == "unpaid" and inv["due_date"] < today:
        shown_status = "Overdue"
    return {
        "number": inv["number"], "status": status, "shown_status": shown_status,
        "invoice_date": us_date(inv["invoice_date"]), "due_date": us_date(inv["due_date"]),
        "period": f"{us_date(inv['period_from'])} – {us_date(inv['period_to'])}",
        "client": client, "business": business, "notes": inv["notes"],
        "lines": [dict(line) for line in lines],
        "subtotal_cents": inv["subtotal_cents"], "total_cents": inv["total_cents"],
        "terms": f"Net {client['payment_terms_days']}",
    }
