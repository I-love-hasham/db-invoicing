"""Products / services (Regular Hours, PTO, On-site...). Archived, never deleted."""
import sqlite3

from flask import Blueprint, abort, redirect, render_template, request, url_for

from .. import audit, forms
from ..db import atomic, get_db
from .clients_views import changes

bp = Blueprint("products", __name__, url_prefix="/products")

FIELDS = ("name", "description", "unit", "default_rate_cents")
UNITS = ("hour", "each")


def _read_form(form) -> dict:
    return {
        "name": forms.text(form, "name", "Name", 80, required=True),
        "description": forms.text(form, "description", "Invoice description", 200),
        "unit": forms.choice(form, "unit", "Unit", UNITS),
        "default_rate_cents": forms.money(form, "default_rate", "Default rate", required=False),
    }


def _for_log(data: dict) -> dict:
    out = dict(data)
    out["default_rate"] = forms.format_money(out.pop("default_rate_cents"))
    return out


def get_product(product_id: int):
    row = get_db().execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if row is None:
        abort(404)
    return row


@bp.route("/")
def index():
    rows = get_db().execute("SELECT * FROM products ORDER BY archived_at IS NOT NULL, name").fetchall()
    return render_template("products/list.html", products=rows)


@bp.route("/new", methods=["GET", "POST"])
def new():
    if request.method == "GET":
        return render_template("products/form.html", product={"unit": "hour"}, is_new=True)
    try:
        data = _read_form(request.form)
    except forms.FormError as e:
        return render_template("products/form.html", product=request.form, is_new=True, error=e.message), 400
    now = audit.utcnow_iso()
    try:
        with atomic() as db:
            cur = db.execute(
                "INSERT INTO products (name, description, unit, default_rate_cents, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?)", (*[data[f] for f in FIELDS], now, now))
            audit.log("product_created", "products", target=f"product:{cur.lastrowid}",
                      details={"after": _for_log(data)})
    except sqlite3.IntegrityError:
        return render_template("products/form.html", product=request.form, is_new=True,
                               error="A product with that name already exists."), 400
    return redirect(url_for("products.index"))


@bp.route("/<int:product_id>", methods=["GET", "POST"])
def edit(product_id: int):
    product = get_product(product_id)
    form_values = {**dict(product), "default_rate": forms.cents_to_input(product["default_rate_cents"])}
    if request.method == "GET":
        return render_template("products/form.html", product=form_values, is_new=False)
    if product["archived_at"]:
        abort(400)
    try:
        data = _read_form(request.form)
    except forms.FormError as e:
        return render_template("products/form.html", product={**form_values, **request.form.to_dict()},
                               is_new=False, error=e.message), 400
    before = _for_log({f: product[f] for f in FIELDS})
    diff = changes(before, _for_log(data))
    if diff["after"]:
        try:
            with atomic() as db:
                db.execute("UPDATE products SET name = ?, description = ?, unit = ?, default_rate_cents = ?,"
                           " updated_at = ? WHERE id = ?", (*[data[f] for f in FIELDS], audit.utcnow_iso(), product_id))
                audit.log("product_edited", "products", target=f"product:{product_id}", details=diff)
        except sqlite3.IntegrityError:
            return render_template("products/form.html", product={**form_values, **request.form.to_dict()},
                                   is_new=False, error="A product with that name already exists."), 400
    return redirect(url_for("products.index"))


@bp.route("/<int:product_id>/archive", methods=["POST"])
def archive(product_id: int):
    product = get_product(product_id)
    if not product["archived_at"]:
        with atomic() as db:
            db.execute("UPDATE products SET archived_at = ?, updated_at = ? WHERE id = ?",
                       (audit.utcnow_iso(), audit.utcnow_iso(), product_id))
            audit.log("product_archived", "products", target=f"product:{product_id}",
                      details={"name": product["name"]})
    return redirect(url_for("products.index"))


@bp.route("/<int:product_id>/restore", methods=["POST"])
def restore(product_id: int):
    product = get_product(product_id)
    if product["archived_at"]:
        with atomic() as db:
            db.execute("UPDATE products SET archived_at = NULL, updated_at = ? WHERE id = ?",
                       (audit.utcnow_iso(), product_id))
            audit.log("product_restored", "products", target=f"product:{product_id}",
                      details={"name": product["name"]})
    return redirect(url_for("products.index"))
