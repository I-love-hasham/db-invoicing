"""Clients and their own rates. Clients are archived, never deleted."""
import sqlite3

from flask import Blueprint, abort, g, redirect, render_template, request, url_for

from .. import audit, forms
from ..db import atomic, get_db

bp = Blueprint("clients", __name__, url_prefix="/clients")

FIELDS = ("name", "address", "email", "payment_terms_days", "notes")


def _read_form(form) -> dict:
    return {
        "name": forms.text(form, "name", "Client name", 100, required=True),
        "address": forms.text(form, "address", "Address", 500, multiline=True),
        "email": forms.email(form, "email", "Billing email"),
        "payment_terms_days": forms.integer(form, "payment_terms_days", "Payment terms", 0, 120),
        "notes": forms.text(form, "notes", "Notes", 2000, multiline=True),
    }


def changes(before: dict, after: dict) -> dict:
    """Only the fields that changed, as {'before': {...}, 'after': {...}}."""
    keys = [k for k in after if before.get(k) != after[k]]
    return {"before": {k: before.get(k) for k in keys}, "after": {k: after[k] for k in keys}}


def get_client(client_id: int):
    row = get_db().execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if row is None:
        abort(404)
    return row


def rate_rows(client_id: int):
    """Every product with this client's own rate (if set) and the rate that will be billed."""
    return get_db().execute(
        "SELECT p.id, p.name, p.unit, p.default_rate_cents, p.archived_at, r.rate_cents AS client_rate_cents,"
        " COALESCE(r.rate_cents, p.default_rate_cents) AS effective_cents"
        " FROM products p LEFT JOIN client_rates r ON r.product_id = p.id AND r.client_id = ?"
        " WHERE p.archived_at IS NULL OR r.rate_cents IS NOT NULL ORDER BY p.name",
        (client_id,),
    ).fetchall()


@bp.route("/")
def index():
    show_archived = request.args.get("archived") == "1"
    rows = get_db().execute(
        "SELECT * FROM clients WHERE (archived_at IS NULL) = ? ORDER BY name",
        (0 if show_archived else 1,),
    ).fetchall()
    return render_template("clients/list.html", clients=rows, show_archived=show_archived)


@bp.route("/new", methods=["GET", "POST"])
def new():
    if request.method == "GET":
        return render_template("clients/form.html", client={"payment_terms_days": 15}, is_new=True)
    try:
        data = _read_form(request.form)
    except forms.FormError as e:
        return render_template("clients/form.html", client=request.form, is_new=True, error=e.message), 400
    now = audit.utcnow_iso()
    try:
        with atomic() as db:
            cur = db.execute(
                "INSERT INTO clients (name, address, email, payment_terms_days, notes, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (*[data[f] for f in FIELDS], now, now),
            )
            audit.log("client_created", "clients", target=f"client:{cur.lastrowid}", client_id=cur.lastrowid,
                      details={"after": data})
    except sqlite3.IntegrityError:
        return render_template("clients/form.html", client=request.form, is_new=True,
                               error="A client with that name already exists."), 400
    return redirect(url_for("clients.detail", client_id=cur.lastrowid))


@bp.route("/<int:client_id>", methods=["GET", "POST"])
def detail(client_id: int):
    client = get_client(client_id)
    if request.method == "GET":
        return render_template("clients/detail.html", client=client, rates=rate_rows(client_id))
    if client["archived_at"]:
        abort(400)
    try:
        data = _read_form(request.form)
    except forms.FormError as e:
        return render_template("clients/detail.html", client={**dict(client), **request.form.to_dict()},
                               rates=rate_rows(client_id), error=e.message), 400
    diff = changes({f: client[f] for f in FIELDS}, data)
    if diff["after"]:
        try:
            with atomic() as db:
                db.execute(
                    "UPDATE clients SET name = ?, address = ?, email = ?, payment_terms_days = ?, notes = ?,"
                    " updated_at = ? WHERE id = ?",
                    (*[data[f] for f in FIELDS], audit.utcnow_iso(), client_id),
                )
                audit.log("client_edited", "clients", target=f"client:{client_id}", client_id=client_id,
                          details=diff)
        except sqlite3.IntegrityError:
            return render_template("clients/detail.html", client={**dict(client), **request.form.to_dict()},
                                   rates=rate_rows(client_id),
                                   error="A client with that name already exists."), 400
    return redirect(url_for("clients.detail", client_id=client_id, saved=1))


@bp.route("/<int:client_id>/rates", methods=["POST"])
def rates(client_id: int):
    client = get_client(client_id)
    if client["archived_at"]:
        abort(400)
    current = {r["id"]: r for r in rate_rows(client_id)}
    updates = {}
    try:
        for product_id, row in current.items():
            field = f"rate_{product_id}"
            if field not in request.form:
                continue
            new = forms.money(request.form, field, f"Rate for {row['name']}", required=False)
            if new != row["client_rate_cents"]:
                updates[product_id] = (row, new)
    except forms.FormError as e:
        return render_template("clients/detail.html", client=client, rates=rate_rows(client_id),
                               error=e.message), 400
    now = audit.utcnow_iso()
    with atomic() as db:
        for product_id, (row, new) in updates.items():
            if new is None:
                db.execute("DELETE FROM client_rates WHERE client_id = ? AND product_id = ?", (client_id, product_id))
            else:
                db.execute(
                    "INSERT INTO client_rates (client_id, product_id, rate_cents, updated_at) VALUES (?, ?, ?, ?)"
                    " ON CONFLICT(client_id, product_id) DO UPDATE SET rate_cents = excluded.rate_cents,"
                    " updated_at = excluded.updated_at",
                    (client_id, product_id, new, now),
                )
            audit.log("client_rate_changed", "clients", target=f"client:{client_id}", client_id=client_id,
                      details={"product": row["name"],
                               "before": {"rate": forms.format_money(row["client_rate_cents"])},
                               "after": {"rate": forms.format_money(new)}})
    return redirect(url_for("clients.detail", client_id=client_id, saved=1) + "#rates")


@bp.route("/<int:client_id>/archive", methods=["POST"])
def archive(client_id: int):
    client = get_client(client_id)
    if client["archived_at"]:
        return redirect(url_for("clients.detail", client_id=client_id))
    with atomic() as db:
        db.execute("UPDATE clients SET archived_at = ?, updated_at = ? WHERE id = ?",
                   (audit.utcnow_iso(), audit.utcnow_iso(), client_id))
        audit.log("client_archived", "clients", target=f"client:{client_id}", client_id=client_id,
                  details={"name": client["name"]})
        audit.raise_alert("client_archived", f"Client '{client['name']}' was archived by "
                                             f"{g.user['username']} from {g.ip}.")
    return redirect(url_for("clients.index"))


@bp.route("/<int:client_id>/restore", methods=["POST"])
def restore(client_id: int):
    client = get_client(client_id)
    if not client["archived_at"]:
        return redirect(url_for("clients.detail", client_id=client_id))
    with atomic() as db:
        db.execute("UPDATE clients SET archived_at = NULL, updated_at = ? WHERE id = ?",
                   (audit.utcnow_iso(), client_id))
        audit.log("client_restored", "clients", target=f"client:{client_id}", client_id=client_id,
                  details={"name": client["name"]})
    return redirect(url_for("clients.detail", client_id=client_id))
