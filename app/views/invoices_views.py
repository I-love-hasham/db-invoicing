"""Invoices: preview -> create (auto-numbered) -> PDF; edit notes/date; void (never delete)."""
import hashlib
import json
import os
from datetime import date

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, send_file, url_for

from .. import audit, business, forms, invoicing, mailer, pdf
from ..db import atomic, get_db
from .time_views import _today

bp = Blueprint("invoices", __name__, url_prefix="/invoices")
NOTES_MAX = 2000


def _active_clients():
    return get_db().execute("SELECT * FROM clients WHERE archived_at IS NULL ORDER BY name").fetchall()


def _get(invoice_id: int):
    inv, lines = invoicing.load(invoice_id)
    if inv is None:
        abort(404)
    return inv, lines


def _read_period(values):
    """client, from, to, invoice date from a form or query string (validated)."""
    clients = _active_clients()
    try:
        cid = int(values.get("client_id", ""))
    except ValueError:
        raise forms.FormError("client_id", "Choose a client.")
    client = next((c for c in clients if c["id"] == cid), None)
    if client is None:
        raise forms.FormError("client_id", "Choose an active client.")
    period_from = forms.date_value(values, "period_from", "From")
    period_to = forms.date_value(values, "period_to", "To")
    if period_from > period_to:
        raise forms.FormError("period_to", "'To' must be on or after 'From'.")
    invoice_date = forms.date_value(values, "invoice_date", "Invoice date")
    return client, period_from, period_to, invoice_date


def _write_pdf(invoice_id: int, action: str) -> None:
    """(Re)generate the PDF and record its fingerprint. Everything happens under the
    write lock, so two clicks can't interleave: the recorded hash is always the file kept."""
    data_dir = current_app.config["DATA_DIR"]
    with atomic() as db:
        inv, lines = invoicing.load(invoice_id)
        vm = invoicing.view_model(inv, lines, _today())
        client_name = json.loads(inv["client_snapshot"])["name"]
        staged = pdf.stage(data_dir, client_name, inv["invoice_date"][:4], inv["number"], pdf.render(vm))
        old = inv["pdf_path"]
        try:
            # record + audit first; the file only replaces the old one once those succeeded
            db.execute("UPDATE invoices SET pdf_path = ?, pdf_sha256 = ? WHERE id = ?",
                       (staged["rel"], staged["sha256"], invoice_id))
            details = {"file": staged["rel"], "sha256": staged["sha256"]}
            if old and old != staged["rel"]:
                details["removed_old_file"] = old
            audit.log(action, "invoices", target=f"invoice:{inv['number']}", client_id=inv["client_id"],
                      details=details)
            pdf.publish(staged)
        except BaseException:
            pdf.discard(staged)
            raise
    if old and old != staged["rel"]:
        # e.g. invoice date moved to another year: remove the stale copy, after the commit
        pdf.remove(data_dir, old)


# ---------------------------------------------------------------- list

@bp.route("/")
def index():
    rows = get_db().execute(
        "SELECT i.*, json_extract(i.client_snapshot, '$.name') AS client_name FROM invoices i"
        " ORDER BY i.number DESC").fetchall()
    today = _today()
    shown = [{**dict(r), "shown_status": invoicing.view_model(r, [], today)["shown_status"]} for r in rows]
    return render_template("invoices/list.html", invoices=shown)


# ---------------------------------------------------------------- create

@bp.route("/new", methods=["GET"])
def new():
    clients = _active_clients()
    args = request.args
    defaults = {"invoice_date": _today(), "client_id": args.get("client_id", ""),
                "period_from": args.get("period_from", ""), "period_to": args.get("period_to", "")}
    if not args.get("client_id"):
        return render_template("invoices/new.html", clients=clients, f=defaults, preview=None)
    try:
        client, period_from, period_to, invoice_date = _read_period({**defaults, **args.to_dict()})
        entries = invoicing.billable_entries(client["id"], period_from, period_to)
        if not entries:
            raise forms.FormError("period_from", "No uninvoiced time for this client in that period.")
        lines = invoicing.build_lines(client["id"], entries, period_from, period_to)
    except (forms.FormError, invoicing.InvoiceProblem) as e:
        return render_template("invoices/new.html", clients=clients, f={**defaults, **args.to_dict()},
                               preview=None, error=str(e) if isinstance(e, invoicing.InvoiceProblem) else e.message), 400
    return render_template("invoices/new.html", clients=clients, f={**defaults, **args.to_dict()},
                           preview=_build_preview(client, entries, lines, period_from, period_to, invoice_date))


def _build_preview(client, entries, lines, period_from, period_to, invoice_date) -> dict:
    return {
        "client": client, "entries": entries, "lines": lines,
        "total_cents": sum(l["amount_cents"] for l in lines),
        "fingerprint": invoicing.fingerprint(entries, lines),
        "running_timer": invoicing.running_timer_in_period(client["id"], period_from, period_to),
        "next_number": invoicing.next_number(),
        "due_date": invoicing.due_date(invoice_date, client["payment_terms_days"]),
    }


@bp.route("/new/summary", methods=["POST"])
def ai_summary():
    """Suggest invoice notes (a short work summary) from the period's time-entry notes."""
    from .. import ai
    clients = _active_clients()
    f = request.form.to_dict()
    try:
        client, period_from, period_to, invoice_date = _read_period(request.form)
        entries = invoicing.billable_entries(client["id"], period_from, period_to)
        if not entries:
            raise forms.FormError("period_from", "No uninvoiced time for this client in that period.")
        lines = invoicing.build_lines(client["id"], entries, period_from, period_to)
    except (forms.FormError, invoicing.InvoiceProblem) as e:
        return render_template("invoices/new.html", clients=clients, f=f, preview=None,
                               error=str(e) if isinstance(e, invoicing.InvoiceProblem) else e.message), 400
    preview = _build_preview(client, entries, lines, period_from, period_to, invoice_date)
    raw = "\n".join(f"{e['work_date']}: {e['notes']}" for e in entries if e["notes"].strip())
    try:
        suggestion = ai.clean_up(raw, "summary", client_id=client["id"])
    except ai.AIError as e:
        return render_template("invoices/new.html", clients=clients, f=f, preview=preview, error=str(e)), 400
    return render_template("invoices/new.html", clients=clients, f=f, preview=preview, suggested_notes=suggestion)


@bp.route("/new", methods=["POST"])
def create():
    try:
        client, period_from, period_to, invoice_date = _read_period(request.form)
        notes = forms.text(request.form, "notes", "Notes", NOTES_MAX, multiline=True)
    except forms.FormError as e:
        return render_template("invoices/new.html", clients=_active_clients(), f=request.form.to_dict(),
                               preview=None, error=e.message), 400
    back = url_for("invoices.new", client_id=client["id"], period_from=period_from, period_to=period_to,
                   invoice_date=invoice_date)
    now = audit.utcnow_iso()
    try:
        with atomic() as db:
            entries = invoicing.billable_entries(client["id"], period_from, period_to)   # under the lock
            lines = invoicing.build_lines(client["id"], entries, period_from, period_to) if entries else []
            if not entries or invoicing.fingerprint(entries, lines) != request.form.get("fingerprint"):
                # time or rates changed since the preview: show the new preview instead of guessing
                return redirect(back + "&changed=1")
            total = sum(l["amount_cents"] for l in lines)
            number = invoicing.next_number()
            cur = db.execute(
                "INSERT INTO invoices (number, client_id, invoice_date, due_date, period_from, period_to,"
                " subtotal_cents, total_cents, notes, client_snapshot, business_snapshot, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (number, client["id"], invoice_date, invoicing.due_date(invoice_date, client["payment_terms_days"]),
                 period_from, period_to, total, total, notes, invoicing.client_snapshot(client),
                 json.dumps(business.get_details(), ensure_ascii=False), now, now),
            )
            invoice_id = cur.lastrowid
            for l in lines:
                db.execute("INSERT INTO invoice_lines (invoice_id, sort, product_id, description, seconds, hours,"
                           " rate_cents, amount_cents) VALUES (?,?,?,?,?,?,?,?)",
                           (invoice_id, l["sort"], l["product_id"], l["description"], l["seconds"], l["hours"],
                            l["rate_cents"], l["amount_cents"]))
            ids = [e["id"] for e in entries]
            marked = db.execute(
                f"UPDATE time_entries SET invoice_id = ? WHERE id IN ({','.join('?' * len(ids))})"
                " AND invoice_id IS NULL AND deleted_at IS NULL", (invoice_id, *ids)).rowcount
            if marked != len(ids):
                raise RuntimeError("time entries changed while creating the invoice")
            audit.log("invoice_created", "invoices", target=f"invoice:{number}", client_id=client["id"],
                      details={"after": {"number": number, "client": client["name"], "invoice_date": invoice_date,
                                         "period": f"{period_from} to {period_to}", "entries": len(ids),
                                         "lines": [{"description": l["description"], "hours": l["hours"],
                                                    "rate": forms.format_money(l["rate_cents"]),
                                                    "amount": forms.format_money(l["amount_cents"])} for l in lines],
                                         "total": forms.format_money(total),
                                         "notes": f"[{len(notes)} characters]" if notes else "[empty]"}})
    except invoicing.InvoiceProblem as e:
        return render_template("invoices/new.html", clients=_active_clients(), f=request.form.to_dict(),
                               preview=None, error=str(e)), 400
    try:
        _write_pdf(invoice_id, "invoice_pdf_generated")
    except Exception as exc:   # the invoice is saved; the PDF can be generated from its page
        current_app.logger.error("PDF generation failed: %s", type(exc).__name__)
        audit.log("invoice_pdf_failed", "error", outcome="failure", target=f"invoice:{invoice_id}",
                  client_id=client["id"], details={"exception": type(exc).__name__})
    return redirect(url_for("invoices.detail", invoice_id=invoice_id))


# ---------------------------------------------------------------- view / pdf

@bp.route("/<int:invoice_id>")
def detail(invoice_id: int):
    inv, lines = _get(invoice_id)
    vm = invoicing.view_model(inv, lines, _today())
    entries = get_db().execute(
        "SELECT t.*, p.name AS product_name FROM time_entries t JOIN products p ON p.id = t.product_id"
        " WHERE t.invoice_id = ? ORDER BY t.work_date, t.id", (invoice_id,)).fetchall()
    return render_template("invoices/detail.html", inv=inv, vm=vm, entries=entries, today=_today(),
                           emails=mailer.history(invoice_id))


@bp.route("/<int:invoice_id>/pdf")
def download_pdf(invoice_id: int):
    inv, _ = _get(invoice_id)
    if not inv["pdf_path"]:
        abort(404)
    base = os.path.realpath(current_app.config["DATA_DIR"])
    full = os.path.realpath(os.path.join(base, inv["pdf_path"]))
    if not full.startswith(base + os.sep) or not os.path.isfile(full):
        abort(404)
    with open(full, "rb") as fh:
        data = fh.read()
    if hashlib.sha256(data).hexdigest() != inv["pdf_sha256"]:
        # the file on disk isn't the one the app wrote
        audit.log("invoice_pdf_mismatch", "security", outcome="failure", target=f"invoice:{inv['number']}",
                  client_id=inv["client_id"])
        audit.raise_alert("invoice_pdf_changed", f"The PDF file for invoice #{inv['number']} was changed on disk "
                                                 "outside the app. Regenerate it from the invoice page.")
        abort(409)
    import io
    return send_file(io.BytesIO(data), mimetype="application/pdf", as_attachment=True,
                     download_name=f"Invoice-{inv['number']}.pdf")


@bp.route("/<int:invoice_id>/pdf", methods=["POST"])
def regenerate_pdf(invoice_id: int):
    _get(invoice_id)
    _write_pdf(invoice_id, "invoice_pdf_regenerated")
    return redirect(url_for("invoices.detail", invoice_id=invoice_id))


# ---------------------------------------------------------------- edit / void

@bp.route("/<int:invoice_id>/edit", methods=["GET", "POST"])
def edit(invoice_id: int):
    inv, _ = _get(invoice_id)
    if inv["status"] != "unpaid":
        abort(400, "Only unpaid invoices can be edited.")
    if request.method == "GET":
        return render_template("invoices/edit.html", inv=inv)
    try:
        invoice_date = forms.date_value(request.form, "invoice_date", "Invoice date")
        notes = forms.text(request.form, "notes", "Notes", NOTES_MAX, multiline=True)
    except forms.FormError as e:
        return render_template("invoices/edit.html", inv={**dict(inv), **request.form.to_dict()},
                               error=e.message), 400
    with atomic() as db:
        current, _ = _get(invoice_id)                       # re-read under the lock
        if current["status"] != "unpaid":
            abort(400)
        terms = json.loads(current["client_snapshot"])["payment_terms_days"]
        new_due = invoicing.due_date(invoice_date, terms)
        changed = {}
        if invoice_date != current["invoice_date"]:
            changed["invoice_date"] = (current["invoice_date"], invoice_date)
            changed["due_date"] = (current["due_date"], new_due)
        if notes != current["notes"]:
            changed["notes"] = (f"[{len(current['notes'])} characters]", f"[{len(notes)} characters]")
        if not changed:
            return redirect(url_for("invoices.detail", invoice_id=invoice_id))
        db.execute("UPDATE invoices SET invoice_date = ?, due_date = ?, notes = ?, updated_at = ? WHERE id = ?",
                   (invoice_date, new_due, notes, audit.utcnow_iso(), invoice_id))
        audit.log("invoice_edited", "invoices", target=f"invoice:{current['number']}", client_id=current["client_id"],
                  details={"before": {k: v[0] for k, v in changed.items()},
                           "after": {k: v[1] for k, v in changed.items()}})
    _write_pdf(invoice_id, "invoice_pdf_regenerated")
    return redirect(url_for("invoices.detail", invoice_id=invoice_id))


@bp.route("/<int:invoice_id>/void", methods=["POST"])
def void(invoice_id: int):
    try:
        reason = forms.text(request.form, "reason", "Reason", 300, required=True)
        if request.form.get("confirm") != "yes":
            raise forms.FormError("confirm", "Tick the box to confirm.")
    except forms.FormError as e:
        inv, lines = _get(invoice_id)
        return render_template("invoices/detail.html", inv=inv, vm=invoicing.view_model(inv, lines, _today()),
                               entries=[], error=e.message), 400
    with atomic() as db:
        inv, _ = _get(invoice_id)
        if inv["status"] != "unpaid":
            # a paid invoice can't be voided (its time would become billable again);
            # change it back to unpaid first — that needs a reason and raises an alert
            return redirect(url_for("invoices.detail", invoice_id=invoice_id))
        released = db.execute("UPDATE time_entries SET invoice_id = NULL WHERE invoice_id = ?", (invoice_id,)).rowcount
        now = audit.utcnow_iso()
        db.execute("UPDATE invoices SET status = 'void', void_reason = ?, voided_at = ?, updated_at = ? WHERE id = ?",
                   (reason, now, now, invoice_id))
        audit.log("invoice_voided", "invoices", target=f"invoice:{inv['number']}", client_id=inv["client_id"],
                  details={"before": {"status": inv["status"]}, "after": {"status": "void"}, "reason": reason,
                           "time_entries_released": released, "total": forms.format_money(inv["total_cents"])})
        audit.raise_alert("invoice_voided", f"Invoice #{inv['number']} ({forms.format_money(inv['total_cents'])}) "
                                            f"was voided by {g.user['username']} from {g.ip}. Reason: {reason}")
    _write_pdf(invoice_id, "invoice_pdf_regenerated")
    return redirect(url_for("invoices.detail", invoice_id=invoice_id))


# ---------------------------------------------------------------- payments

@bp.route("/<int:invoice_id>/paid", methods=["POST"])
def mark_paid(invoice_id: int):
    from .. import payments
    today = _today()
    inv, lines = _get(invoice_id)
    try:
        paid_date = payments.valid_paid_date(request.form, inv["invoice_date"], today)
        method = forms.choice(request.form, "method", "Payment method", tuple(payments.METHODS))
    except forms.FormError as e:
        return render_template("invoices/detail.html", inv=inv, vm=invoicing.view_model(inv, lines, today),
                               entries=[], error=e.message), 400
    with atomic() as db:
        current, _ = _get(invoice_id)                 # re-read under the lock
        if current["status"] != "unpaid":
            return redirect(url_for("invoices.detail", invoice_id=invoice_id))
        db.execute("UPDATE invoices SET status = 'paid', paid_at = ?, paid_method = ?, updated_at = ? WHERE id = ?",
                   (paid_date, method, audit.utcnow_iso(), invoice_id))
        audit.log("invoice_marked_paid", "invoices", target=f"invoice:{current['number']}",
                  client_id=current["client_id"],
                  details={"before": {"status": "unpaid"},
                           "after": {"status": "paid", "paid_date": paid_date, "method": payments.METHODS[method]},
                           "total": forms.format_money(current["total_cents"])})
    _write_pdf(invoice_id, "invoice_pdf_regenerated")
    return redirect(url_for("invoices.detail", invoice_id=invoice_id))


@bp.route("/<int:invoice_id>/unpaid", methods=["POST"])
def undo_paid(invoice_id: int):
    """Correct a payment recorded by mistake. Needs a reason and raises an alert."""
    try:
        reason = forms.text(request.form, "reason", "Reason", 300, required=True)
    except forms.FormError as e:
        inv, lines = _get(invoice_id)
        return render_template("invoices/detail.html", inv=inv, vm=invoicing.view_model(inv, lines, _today()),
                               entries=[], error=e.message), 400
    with atomic() as db:
        current, _ = _get(invoice_id)
        if current["status"] != "paid":
            return redirect(url_for("invoices.detail", invoice_id=invoice_id))
        db.execute("UPDATE invoices SET status = 'unpaid', paid_at = NULL, paid_method = NULL, updated_at = ?"
                   " WHERE id = ?", (audit.utcnow_iso(), invoice_id))
        audit.log("invoice_payment_undone", "invoices", target=f"invoice:{current['number']}",
                  client_id=current["client_id"],
                  details={"before": {"status": "paid", "paid_date": current["paid_at"],
                                      "method": current["paid_method"]},
                           "after": {"status": "unpaid"}, "reason": reason})
        audit.raise_alert("payment_undone", f"Invoice #{current['number']} was changed from Paid back to Unpaid by "
                                            f"{g.user['username']} from {g.ip}. Reason: {reason}")
    _write_pdf(invoice_id, "invoice_pdf_regenerated")
    return redirect(url_for("invoices.detail", invoice_id=invoice_id))


@bp.route("/<int:invoice_id>/follow-up/<int:stage>")
def follow_up(invoice_id: int, stage: int):
    from .. import business, payments
    if stage not in payments.FOLLOW_UP_STAGES:
        abort(404)
    inv, _ = _get(invoice_id)
    if inv["status"] != "unpaid":
        abort(404)       # paid or void: no reminder (the future Send re-checks this under the lock)
    row = get_db().execute("SELECT * FROM follow_ups WHERE invoice_id = ? AND stage = ?",
                           (invoice_id, stage)).fetchone()
    if row is None:
        abort(404)
    from .. import graph
    msg = payments.follow_up_text(inv, stage, business.get_details()["signature"])
    msg["to"] = _current_client_email(inv)
    return render_template("invoices/follow_up.html", inv=inv, stage=stage, msg=msg, follow_up=row,
                           email_ready=graph.configured(), send_token=mailer.new_send_token())


# ---------------------------------------------------------------- email (preview -> Send)

def _invoice_email_defaults(inv) -> dict:
    vm = invoicing.view_model(inv, [], _today())
    biz = vm["business"]
    sig = business.get_details()["signature"]
    subject = (f"Invoice #{inv['number']} – {biz['name']} – {invoicing.us_date(inv['period_from'])} to "
               f"{invoicing.us_date(inv['period_to'])}")
    if inv["status"] == "paid":
        body = (f"Hi {vm['client']['name']},\n\n"
                f"Attached for your records is invoice #{inv['number']} for {forms.format_money(inv['total_cents'])}, "
                f"marked paid on {invoicing.us_date(inv['paid_at'])}. Thank you for your payment.\n\n"
                f"{sig}\n{biz['name']}")
    else:
        body = (f"Hi {vm['client']['name']},\n\n"
                f"Please find attached invoice #{inv['number']} for {forms.format_money(inv['total_cents'])} for IT "
                f"services from {vm['period'].replace(' – ', ' to ')}. Payment is due by {vm['due_date']} "
                f"({vm['terms']}).\n\n"
                f"Thank you,\n{sig}\n{biz['name']}")
    return {"subject": subject, "body": body}


def _current_client_email(inv) -> str:
    row = get_db().execute("SELECT email FROM clients WHERE id = ?", (inv["client_id"],)).fetchone()
    return row["email"] if row else ""


def _verified_pdf(inv) -> bytes:
    """The invoice PDF, but only if it's exactly the file the app wrote."""
    if not inv["pdf_path"]:
        raise mailer.SendRefused("Generate the PDF first.")
    base = os.path.realpath(current_app.config["DATA_DIR"])
    full = os.path.realpath(os.path.join(base, inv["pdf_path"]))
    if not full.startswith(base + os.sep) or not os.path.isfile(full):
        raise mailer.SendRefused("The PDF file is missing. Regenerate it first.")
    with open(full, "rb") as fh:
        data = fh.read()
    if hashlib.sha256(data).hexdigest() != inv["pdf_sha256"]:
        raise mailer.SendRefused("The PDF was changed outside the app. Regenerate it before sending.")
    return data


@bp.route("/<int:invoice_id>/send", methods=["GET", "POST"])
def send_invoice(invoice_id: int):
    from .. import graph
    inv, _ = _get(invoice_id)
    to = _current_client_email(inv)
    cc, bcc = mailer.copy_recipients()
    defaults = _invoice_email_defaults(inv)
    history = mailer.history(invoice_id)
    already_sent = any(h["kind"] == "invoice" and h["status"] == "sent" for h in history)
    ctx = {"inv": inv, "to": to, "cc": cc, "bcc": bcc, "subject": defaults["subject"],
           "email_ready": graph.configured(), "history": history, "already_sent": already_sent}
    if request.method == "GET":
        if inv["status"] == "void":
            abort(400)
        return render_template("invoices/send.html", body=defaults["body"], send_token=mailer.new_send_token(), **ctx)
    try:
        body = forms.text(request.form, "body", "Message", 5000, required=True, multiline=True)
        if not to:
            raise forms.FormError("to", "This client has no billing email. Add one on the client's page.")
        if already_sent and request.form.get("resend") != "yes":
            raise forms.FormError("resend", "This invoice was already emailed. Tick the box to send it again.")
    except forms.FormError as e:
        return render_template("invoices/send.html", body=request.form.get("body", ""),
                               send_token=request.form.get("send_token", ""), error=e.message, **ctx), 400

    shown_status = request.form.get("shown_status", "")    # status when the preview was opened

    def recheck(db):
        current = db.execute("SELECT status FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
        if current["status"] == "void":
            raise mailer.SendRefused("This invoice was voided.")
        if current["status"] != shown_status:
            raise mailer.SendRefused("This invoice changed (paid/unpaid) since this page was opened. Reload and "
                                     "check the message before sending.")
    try:
        pdf_bytes = _verified_pdf(inv)
        mailer.send("invoice", request.form.get("send_token", ""), [to], defaults["subject"], body, invoice=inv,
                    attachments=[(f"Invoice-{inv['number']}.pdf", pdf_bytes)], recheck=recheck)
    except (mailer.SendRefused, graph.GraphError) as e:
        return render_template("invoices/send.html", body=body, send_token=mailer.new_send_token(),
                               error=str(e), **ctx), 400
    return redirect(url_for("invoices.detail", invoice_id=invoice_id, sent=1))


@bp.route("/<int:invoice_id>/follow-up/<int:stage>/send", methods=["POST"])
def send_follow_up(invoice_id: int, stage: int):
    from .. import graph, payments
    inv, _ = _get(invoice_id)
    fu = get_db().execute("SELECT * FROM follow_ups WHERE invoice_id = ? AND stage = ?", (invoice_id, stage)).fetchone()
    if fu is None or stage not in payments.FOLLOW_UP_STAGES:
        abort(404)
    to = _current_client_email(inv)
    msg = payments.follow_up_text(inv, stage, business.get_details()["signature"])
    try:
        body = forms.text(request.form, "body", "Message", 5000, required=True, multiline=True)
        if not to:
            raise forms.FormError("to", "This client has no billing email. Add one on the client's page.")
    except forms.FormError as e:
        return render_template("invoices/follow_up.html", inv=inv, stage=stage,
                               msg={**msg, "to": to, "body": request.form.get("body", msg["body"])}, follow_up=fu,
                               email_ready=graph.configured(), send_token=mailer.new_send_token(),
                               error=e.message), 400

    def recheck(db):
        cur = db.execute("SELECT i.status, f.sent_at FROM invoices i JOIN follow_ups f ON f.invoice_id = i.id"
                         " WHERE f.id = ?", (fu["id"],)).fetchone()
        if cur["status"] != "unpaid":
            raise mailer.SendRefused("This invoice isn't unpaid any more — no reminder needed.")
        if cur["sent_at"]:
            raise mailer.SendRefused("This reminder was already sent.")
    try:
        mailer.send("follow_up", request.form.get("send_token", ""), [to], msg["subject"], body, invoice=inv,
                    follow_up_id=fu["id"], attachments=[(f"Invoice-{inv['number']}.pdf", _verified_pdf(inv))],
                    recheck=recheck)
    except (mailer.SendRefused, graph.GraphError) as e:
        return render_template("invoices/follow_up.html", inv=inv, stage=stage, msg={**msg, "to": to, "body": body},
                               follow_up=fu, email_ready=graph.configured(), send_token=mailer.new_send_token(),
                               error=str(e)), 400
    return redirect(url_for("main.dashboard", reminder_sent=1))
