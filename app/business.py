"""Business details printed on invoices (Settings → Business details)."""
from .db import get_db

DEFAULTS = {
    "name": "DB IT Consulting",
    "address": "3 Crestview Terrace\nMonsey, NY 10952",
    "phone": "845-263-5628",
    "email": "",
    "footer": "Thank you for your business.",
    "signature": "David",
}
FIELDS = tuple(DEFAULTS)


def get_details() -> dict:
    rows = get_db().execute("SELECT key, value FROM app_settings WHERE key LIKE 'business.%'").fetchall()
    stored = {r["key"].removeprefix("business."): r["value"] for r in rows}
    return {k: stored.get(k, DEFAULTS[k]) for k in FIELDS}


def save_details(values: dict) -> None:
    db = get_db()
    for k in FIELDS:
        db.execute("INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET"
                   " value = excluded.value", (f"business.{k}", values[k]))
