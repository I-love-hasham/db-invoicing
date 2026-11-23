"""Timer and time entries. Entries are soft-deleted, and locked once invoiced."""
import sqlite3
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from flask import Blueprint, abort, current_app, redirect, render_template, request, url_for

from .. import audit, forms
from ..db import atomic, get_db

bp = Blueprint("time", __name__, url_prefix="/time")

MAX_TIMER_SECONDS = 86400
NOTES_MAX = 2000


# ---------------------------------------------------------------- helpers

def _tz():
    try:
        return ZoneInfo(current_app.config["APP_TIMEZONE"])
    except Exception:
        return timezone.utc


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(iso: str) -> datetime:
    return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def _today() -> str:
    return _now_utc().astimezone(_tz()).date().isoformat()


def _latest_work_date() -> str:
    return (date.fromisoformat(_today()) + timedelta(days=1)).isoformat()


MIN_TIMER_SECONDS = 60


def _check_active(db, client_id: int, product_id: int) -> None:
    """Re-check under the write lock that neither was archived a moment ago."""
    row = db.execute("SELECT (SELECT archived_at FROM clients WHERE id = ?) AS ca,"
                     " (SELECT archived_at FROM products WHERE id = ?) AS pa", (client_id, product_id)).fetchone()
    if row["ca"] is not None or row["pa"] is not None:
        abort(400, "That client or product was just archived.")


def _notes_meta(notes: str) -> str:
    """Notes may contain anything a tech types (even a password): log only their length."""
    return f"[{len(notes)} characters]" if notes else "[empty]"


def _active_choices():
    db = get_db()
    clients = db.execute("SELECT id, name FROM clients WHERE archived_at IS NULL ORDER BY name").fetchall()
    products = db.execute("SELECT id, name, unit FROM products WHERE archived_at IS NULL ORDER BY name").fetchall()
    return clients, products


def _pick(form, clients, products):
    """Validate the client/product dropdowns against ACTIVE records only."""
    try:
        cid = int(form.get("client_id", ""))
        pid = int(form.get("product_id", ""))
    except ValueError:
        raise forms.FormError("client_id", "Choose a client and a product.")
    client = next((c for c in clients if c["id"] == cid), None)
    product = next((p for p in products if p["id"] == pid), None)
    if client is None or product is None:
        raise forms.FormError("client_id", "Choose an active client and product.")
    return client, product


def running_timer():
    return get_db().execute(
        "SELECT t.*, c.name AS client_name, p.name AS product_name FROM time_entries t"
        " JOIN clients c ON c.id = t.client_id JOIN products p ON p.id = t.product_id"
        " WHERE t.source = 'timer' AND t.duration_seconds IS NULL AND t.deleted_at IS NULL"
    ).fetchone()


def _get_entry(entry_id: int):
    row = get_db().execute(
        "SELECT t.*, c.name AS client_name, p.name AS product_name FROM time_entries t"
        " JOIN clients c ON c.id = t.client_id JOIN products p ON p.id = t.product_id WHERE t.id = ?",
        (entry_id,),
    ).fetchone()
    if row is None or row["deleted_at"]:
        abort(404)
    return row


def _editable_or_400(entry):
    if entry["invoice_id"] is not None:
        abort(400, "This entry is on an invoice and can't be changed.")
    if entry["duration_seconds"] is None:
        abort(400, "Stop the timer first.")


def elapsed(entry) -> str:
    seconds = int((_now_utc() - _parse(entry["started_at"])).total_seconds())
    return f"{seconds // 3600}h {seconds % 3600 // 60:02d}m"


# ---------------------------------------------------------------- list + timer

@bp.route("/")
def index():
    return _render_index()


def _render_index(error: str | None = None, status: int = 200, typed_notes: str | None = None):
    args = request.args
    today = date.fromisoformat(_today())
    week_start = today - timedelta(days=today.weekday())
    try:
        date_from = forms.date_value(args, "from", "From") if args.get("from") else week_start.isoformat()
        date_to = forms.date_value(args, "to", "To") if args.get("to") else today.isoformat()
    except forms.FormError:
        date_from, date_to = week_start.isoformat(), today.isoformat()
    client_filter = args.get("client", "")
    where = ["t.deleted_at IS NULL", "t.work_date >= ?", "t.work_date <= ?"]
    params: list = [date_from, date_to]
    if client_filter.isascii() and client_filter.isdigit():
        where.append("t.client_id = ?")
        params.append(int(client_filter))
    else:
        client_filter = ""
    db = get_db()
    entries = db.execute(
        "SELECT t.*, c.name AS client_name, p.name AS product_name FROM time_entries t"
        " JOIN clients c ON c.id = t.client_id JOIN products p ON p.id = t.product_id"
        f" WHERE {' AND '.join(where)} ORDER BY t.work_date DESC, t.id DESC", params,
    ).fetchall()
    total = sum(e["duration_seconds"] or 0 for e in entries)
    clients, products = _active_choices()
    all_clients = db.execute("SELECT id, name FROM clients ORDER BY name").fetchall()
    timer = running_timer()
    return render_template(
        "time/index.html", entries=entries, total=total, clients=clients, products=products,
        all_clients=all_clients, timer=timer, elapsed=elapsed(timer) if timer else None,
        f={"from": date_from, "to": date_to, "client": client_filter}, error=error,
        typed_notes=typed_notes,
    ), status


@bp.route("/start", methods=["POST"])
def start():
    clients, products = _active_choices()
    try:
        client, product = _pick(request.form, clients, products)
        notes = forms.text(request.form, "notes", "Notes", NOTES_MAX, multiline=True)
    except forms.FormError as e:
        return _index_with_error(e.message)
    now = _now_utc()
    try:
        with atomic() as db:
            _check_active(db, client["id"], product["id"])
            cur = db.execute(
                "INSERT INTO time_entries (client_id, product_id, work_date, started_at, notes, source,"
                " created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'timer', ?, ?)",
                (client["id"], product["id"], now.astimezone(_tz()).date().isoformat(), _iso(now), notes,
                 _iso(now), _iso(now)),
            )
            audit.log("timer_started", "time", target=f"time:{cur.lastrowid}", client_id=client["id"],
                      details={"client": client["name"], "product": product["name"], "notes": _notes_meta(notes)})
    except sqlite3.IntegrityError:
        return _index_with_error("A timer is already running. Stop it first.")
    return redirect(url_for("time.index"))


@bp.route("/timer/notes", methods=["POST"])
def save_timer_notes():
    return _finish_or_save(stop=False)


@bp.route("/stop", methods=["POST"])
def stop():
    return _finish_or_save(stop=True)


def _finish_or_save(stop: bool):
    try:
        notes = forms.text(request.form, "notes", "Notes", NOTES_MAX, multiline=True)
    except forms.FormError as e:
        return _index_with_error(e.message)
    now = _now_utc()
    with atomic() as db:
        timer = running_timer()          # read under the lock
        if timer is None:
            return redirect(url_for("time.index"))
        if request.form.get("version") != timer["updated_at"]:
            # notes were saved from another tab/device since this page loaded
            return _render_index(error="These notes were also changed somewhere else. Below is the text you "
                                       "typed — check it, then Save or Stop again.",
                                 status=400, typed_notes=notes)
        if not stop:
            if notes != timer["notes"]:
                db.execute("UPDATE time_entries SET notes = ?, updated_at = ? WHERE id = ?",
                           (notes, _iso(now), timer["id"]))
                audit.log("timer_notes_saved", "time", target=f"time:{timer['id']}", client_id=timer["client_id"],
                          details={"notes": _notes_meta(notes)})
            return redirect(url_for("time.index"))
        seconds = int((now - _parse(timer["started_at"])).total_seconds())
        if seconds < MIN_TIMER_SECONDS:
            db.execute("UPDATE time_entries SET deleted_at = ?, updated_at = ? WHERE id = ?",
                       (_iso(now), _iso(now), timer["id"]))
            audit.log("timer_discarded", "time", target=f"time:{timer['id']}", client_id=timer["client_id"],
                      details={"reason": "under 1 minute", "seconds": seconds})
            return redirect(url_for("time.index", short=1))
        capped = seconds > MAX_TIMER_SECONDS
        seconds = max(0, min(seconds, MAX_TIMER_SECONDS))
        db.execute("UPDATE time_entries SET ended_at = ?, duration_seconds = ?, notes = ?, updated_at = ?"
                   " WHERE id = ?", (_iso(now), seconds, notes, _iso(now), timer["id"]))
        audit.log("timer_stopped", "time", target=f"time:{timer['id']}", client_id=timer["client_id"],
                  details={"hours": forms.format_hours(seconds), "capped_at_24h": capped,
                           "notes": _notes_meta(notes)})
    if capped:
        return redirect(url_for("time.edit", entry_id=timer["id"], capped=1))
    return redirect(url_for("time.index"))


def _index_with_error(message: str):
    return _render_index(error=message, status=400)


# ---------------------------------------------------------------- manual entries

@bp.route("/new", methods=["GET", "POST"])
def new():
    clients, products = _active_choices()
    if request.method == "GET":
        return render_template("time/form.html", entry={"work_date": _today()}, clients=clients,
                               products=products, is_new=True)
    try:
        client, product = _pick(request.form, clients, products)
        work_date = forms.date_value(request.form, "work_date", "Date", latest=_latest_work_date())
        seconds = forms.hours(request.form, "hours", "Hours")
        notes = forms.text(request.form, "notes", "Notes", NOTES_MAX, multiline=True)
    except forms.FormError as e:
        return render_template("time/form.html", entry=request.form, clients=clients, products=products,
                               is_new=True, error=e.message), 400
    now = _iso(_now_utc())
    with atomic() as db:
        _check_active(db, client["id"], product["id"])
        cur = db.execute(
            "INSERT INTO time_entries (client_id, product_id, work_date, duration_seconds, notes, source,"
            " created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'manual', ?, ?)",
            (client["id"], product["id"], work_date, seconds, notes, now, now),
        )
        audit.log("time_entry_added", "time", target=f"time:{cur.lastrowid}", client_id=client["id"],
                  details={"after": {"client": client["name"], "product": product["name"], "date": work_date,
                                     "hours": forms.format_hours(seconds), "notes": _notes_meta(notes)}})
    return redirect(url_for("time.index", **{"from": min(work_date, _today()), "to": max(work_date, _today())}))


@bp.route("/<int:entry_id>", methods=["GET", "POST"])
def edit(entry_id: int):
    entry = _get_entry(entry_id)
    clients, products = _active_choices()
    # an entry's own (possibly archived) client/product stays selectable
    if all(c["id"] != entry["client_id"] for c in clients):
        clients = [*clients, {"id": entry["client_id"], "name": entry["client_name"] + " (archived)"}]
    if all(p["id"] != entry["product_id"] for p in products):
        products = [*products, {"id": entry["product_id"], "name": entry["product_name"] + " (archived)", "unit": ""}]
    values = {**dict(entry), "hours": forms.format_hours(entry["duration_seconds"])}
    if request.method == "GET":
        return render_template("time/form.html", entry=values, clients=clients, products=products, is_new=False,
                               locked=entry["invoice_id"] is not None, running=entry["duration_seconds"] is None,
                               capped=request.args.get("capped"))
    _editable_or_400(entry)
    try:
        client, product = _pick(request.form, clients, products)
        work_date = forms.date_value(request.form, "work_date", "Date", latest=_latest_work_date())
        hours_text = (request.form.get("hours") or "").strip()
        notes = forms.text(request.form, "notes", "Notes", NOTES_MAX, multiline=True)
        seconds = None if hours_text == values["hours"] else forms.hours(request.form, "hours", "Hours")
    except forms.FormError as e:
        return render_template("time/form.html", entry={**values, **request.form.to_dict()}, clients=clients,
                               products=products, is_new=False, error=e.message), 400
    with atomic() as db:
        current = _get_entry(entry_id)            # re-read under the lock
        _editable_or_400(current)
        if seconds is None:                       # hours left as shown: keep the exact stored seconds
            seconds = current["duration_seconds"]
        if client["id"] != current["client_id"] or product["id"] != current["product_id"]:
            _check_active(db, client["id"], product["id"])
        before = {"client": current["client_name"], "product": current["product_name"], "date": current["work_date"],
                  "hours": forms.format_hours(current["duration_seconds"]), "notes": current["notes"]}
        after = {"client": client["name"].removesuffix(" (archived)"),
                 "product": product["name"].removesuffix(" (archived)"), "date": work_date,
                 "hours": forms.format_hours(seconds), "notes": notes}
        changed = [k for k in after if before[k] != after[k]]
        if seconds != current["duration_seconds"] and "hours" not in changed:
            # same 2-decimal display, different exact time: still a change, logged in seconds
            changed.append("hours")
            before["hours"] = f"{before['hours']} ({current['duration_seconds']} s)"
            after["hours"] = f"{after['hours']} ({seconds} s)"
        if changed:
            db.execute("UPDATE time_entries SET client_id = ?, product_id = ?, work_date = ?, duration_seconds = ?,"
                       " notes = ?, updated_at = ? WHERE id = ?",
                       (client["id"], product["id"], work_date, seconds, notes, _iso(_now_utc()), entry_id))
            safe = lambda d: {k: (_notes_meta(d[k]) if k == "notes" else d[k]) for k in changed}
            audit.log("time_entry_edited", "time", target=f"time:{entry_id}", client_id=client["id"],
                      details={"before": safe(before), "after": safe(after),
                               **({"previous_client_id": current["client_id"]}
                                  if current["client_id"] != client["id"] else {})})
    return redirect(url_for("time.index"))


@bp.route("/<int:entry_id>/delete", methods=["POST"])
def delete(entry_id: int):
    with atomic() as db:
        entry = _get_entry(entry_id)
        if entry["invoice_id"] is not None:
            abort(400, "This entry is on an invoice and can't be deleted.")
        db.execute("UPDATE time_entries SET deleted_at = ?, updated_at = ? WHERE id = ?",
                   (_iso(_now_utc()), _iso(_now_utc()), entry_id))
        audit.log("time_entry_deleted", "time", target=f"time:{entry_id}", client_id=entry["client_id"],
                  details={"before": {"client": entry["client_name"], "product": entry["product_name"],
                                      "date": entry["work_date"],
                                      "hours": forms.format_hours(entry["duration_seconds"]),
                                      "was_running_timer": entry["duration_seconds"] is None}})
    return redirect(url_for("time.index"))


@bp.route("/<int:entry_id>/ai", methods=["POST"])
def ai_cleanup(entry_id: int):
    """Suggest cleaner notes. Nothing is saved: the suggestion fills the form for review."""
    from .. import ai
    entry = _get_entry(entry_id)
    clients, products = _active_choices()
    if all(c["id"] != entry["client_id"] for c in clients):
        clients = [*clients, {"id": entry["client_id"], "name": entry["client_name"] + " (archived)"}]
    if all(p["id"] != entry["product_id"] for p in products):
        products = [*products, {"id": entry["product_id"], "name": entry["product_name"] + " (archived)", "unit": ""}]
    values = {**dict(entry), "hours": forms.format_hours(entry["duration_seconds"])}
    _editable_or_400(entry)
    # keep any unsaved changes on the form (date, hours, client, product) — only notes get the suggestion
    for k in ("client_id", "product_id", "work_date", "hours"):
        if request.form.get(k):
            values[k] = request.form[k]
    notes = (request.form.get("notes") or entry["notes"]).strip()
    try:
        suggestion = ai.clean_up(notes, "entry", target=f"time:{entry_id}", client_id=entry["client_id"])
    except ai.AIError as e:
        return render_template("time/form.html", entry={**values, "notes": notes}, clients=clients, products=products,
                               is_new=False, error=str(e)), 400
    return render_template("time/form.html", entry={**values, "notes": suggestion}, clients=clients,
                           products=products, is_new=False, ai_original=notes)
