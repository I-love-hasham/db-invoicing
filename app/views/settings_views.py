"""Account security settings. Every change needs a fresh 2FA check and raises an alert."""
from flask import Blueprint, g, redirect, render_template, request, url_for

from .. import audit, auth, crypto, totp
from ..db import atomic, get_db

bp = Blueprint("settings", __name__, url_prefix="/settings")


@bp.route("/")
def index():
    return render_template("settings/index.html", backups_left=auth.backup_codes_left(g.user["id"]))


@bp.route("/password", methods=["GET", "POST"])
@auth.fresh_2fa_required
def password():
    if request.method == "GET":
        return render_template("settings/password.html")
    user = auth.get_user(g.user["id"])
    attempt = auth.begin_attempt(user)
    if attempt.blocked:
        auth.blocked_attempt(attempt, user)
        with atomic():
            auth.end_session()
        return redirect(url_for("auth.login"))
    current = request.form.get("current_password", "")
    if not auth.run_check(attempt, user, "password_change_wrong_current",
                          lambda: auth.check_password(user, current)):
        if auth.end_attempt(attempt, user, False, "password_change_wrong_current"):
            with atomic():
                auth.end_session()
            return redirect(url_for("auth.login"))
        return render_template("settings/password.html", error="Current password is incorrect."), 400
    auth.end_attempt(attempt, user, True)
    new = request.form.get("new_password", "")
    problem = auth.password_problem(new, user["username"])
    if not problem and new != request.form.get("new_password_confirm", ""):
        problem = "New passwords don't match."
    if problem:
        return render_template("settings/password.html", error=problem), 400
    new_hash = auth.hash_password(new)   # slow: before taking the lock
    now = audit.utcnow_iso()
    with atomic() as db:
        db.execute("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?",
                   (new_hash, now, user["id"]))
        # sign out every other session
        db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?",
                   (user["id"], g.session["token_hash"]))
        audit.log("password_changed", "settings", target=f"user:{user['username']}",
                  details={"before": {"changed_at": user["password_changed_at"]}, "after": {"changed_at": now},
                           "other_sessions_signed_out": True})
        audit.raise_alert("password_changed", f"The password for '{user['username']}' was changed from {g.ip}.")
        auth.start_session(user["id"], "full")  # new session token after a credential change
    return render_template("settings/done.html", message="Password changed. Other sessions were signed out.")


@bp.route("/backup-codes", methods=["GET", "POST"])
@auth.fresh_2fa_required
def backup_codes():
    if request.method == "GET":
        return render_template("settings/backup_codes_confirm.html",
                               backups_left=auth.backup_codes_left(g.user["id"]))
    with atomic():
        before = auth.backup_codes_left(g.user["id"])
        codes = auth.generate_backup_codes(g.user["id"])
        audit.log("backup_codes_regenerated", "settings",
                  details={"before": {"unused": before}, "after": {"unused": len(codes)}})
        audit.raise_alert("2fa_changed", f"New 2FA backup codes were generated for '{g.user['username']}' "
                                         f"from {g.ip}. The old codes no longer work.")
    return render_template("backup_codes.html", codes=codes, first_time=False)


@bp.route("/authenticator", methods=["GET", "POST"])
@auth.fresh_2fa_required
def authenticator():
    """Move 2FA to a new phone: scan a new secret, confirm a code, then the old one stops working."""
    db = get_db()
    token_hash = g.session["token_hash"]
    if not g.session.get("pending_totp_enc"):
        if request.method == "POST":
            return redirect(url_for("settings.authenticator"))
        # Create the new secret once; reloading the page shows the same one.
        secret = totp.new_secret()
        db.execute("UPDATE sessions SET pending_totp_enc = ? WHERE token_hash = ?",
                   (crypto.encrypt(secret), token_hash))
        return render_template("settings/authenticator.html", secret=secret,
                               qr=totp.qr_data_uri(totp.provisioning_uri(secret, g.user["username"])))

    secret = crypto.decrypt(g.session["pending_totp_enc"])
    if request.method == "GET":
        return render_template("settings/authenticator.html", secret=secret,
                               qr=totp.qr_data_uri(totp.provisioning_uri(secret, g.user["username"])))
    step = totp.verify(secret, request.form.get("code", "").strip(), last_step=0)
    if step is None:
        audit.log("authenticator_change_failed", "settings", outcome="failure")
        return render_template("settings/authenticator.html", secret=secret,
                               qr=totp.qr_data_uri(totp.provisioning_uri(secret, g.user["username"])),
                               error="That code didn't match the new secret."), 400
    with atomic():
        db.execute("UPDATE users SET totp_secret_enc = ?, totp_last_step = ? WHERE id = ?",
                   (crypto.encrypt(secret), step, g.user["id"]))
        db.execute("UPDATE sessions SET pending_totp_enc = NULL WHERE token_hash = ?", (token_hash,))
        db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (g.user["id"], token_hash))
        audit.log("authenticator_changed", "settings",
                  details={"before": {"authenticator": "previous device"},
                           "after": {"authenticator": "new device"}, "other_sessions_signed_out": True})
        audit.raise_alert("2fa_changed", f"The authenticator app for '{g.user['username']}' was moved to a "
                                         f"new device from {g.ip}.")
    return render_template("settings/done.html",
                           message="Authenticator updated. Codes from the old phone no longer work.")


@bp.route("/business", methods=["GET", "POST"])
@auth.fresh_2fa_required
def business_details():
    """Name, address, phone, email and footer printed on new invoices."""
    from .. import business, forms
    current = business.get_details()
    if request.method == "GET":
        return render_template("settings/business.html", b=current)
    try:
        values = {
            "name": forms.text(request.form, "name", "Business name", 100, required=True),
            "address": forms.text(request.form, "address", "Address", 300, multiline=True),
            "phone": forms.text(request.form, "phone", "Phone", 40),
            "email": forms.email(request.form, "email", "Email"),
            "footer": forms.text(request.form, "footer", "Invoice footer", 140),
            "signature": forms.text(request.form, "signature", "Name to sign emails with", 60, required=True),
        }
    except forms.FormError as e:
        return render_template("settings/business.html", b={**current, **request.form.to_dict()},
                               error=e.message), 400
    with atomic():
        before = business.get_details()
        changed = [k for k in values if values[k] != before[k]]
        if changed:
            business.save_details(values)
            audit.log("business_details_changed", "settings",
                      details={"before": {k: before[k] for k in changed}, "after": {k: values[k] for k in changed}})
            audit.raise_alert("business_details_changed",
                              f"The business details printed on invoices were changed ({', '.join(changed)}) "
                              f"by {g.user['username']} from {g.ip}.")
    return render_template("settings/done.html",
                           message="Business details saved. They appear on invoices created from now on.")


# ---------------------------------------------------------------- email (Microsoft 365)

@bp.route("/email")
def email():
    from .. import graph, mailer
    return render_template("settings/email.html", status=graph.status(), copy=mailer.copy_settings(),
                           send_token=mailer.new_send_token())


@bp.route("/email/copy", methods=["GET", "POST"])
@auth.fresh_2fa_required
def email_copy():
    """The address that gets a copy of every outgoing email (and the security alerts)."""
    from .. import forms, mailer
    current = mailer.copy_settings()
    if request.method == "GET":
        return render_template("settings/email_copy.html", copy=current)
    try:
        address = forms.email(request.form, "address", "Copy address", required=True)
        mode = forms.choice(request.form, "mode", "Copy type", ("cc", "bcc"))
        enabled = request.form.get("enabled") == "1"
    except forms.FormError as e:
        return render_template("settings/email_copy.html", copy={**current, **request.form.to_dict()},
                               error=e.message), 400
    after = {"address": address, "mode": mode, "enabled": enabled}
    with atomic():
        before = mailer.copy_settings()
        changed = [k for k in after if after[k] != before[k]]
        if changed:
            mailer.save_copy_settings(address, mode, enabled)
            audit.log("email_copy_changed", "settings",
                      details={"before": {k: before[k] for k in changed}, "after": {k: after[k] for k in changed}})
            audit.raise_alert("email_copy_changed",
                              f"The email copy / alert address setting was changed ({', '.join(changed)}) by "
                              f"{g.user['username']} from {g.ip}. Address is now '{address}', "
                              f"{mode.upper()}, {'on' if enabled else 'off'}.")
    if changed and before["address"] and before["address"] != address:
        # warn the OLD address too, in case someone else redirected the alerts
        mailer.send_direct_alert(before["address"], f"The alert/copy address for your invoicing app was changed "
                                                    f"from {before['address']} to {address} from {g.ip}.")
    return render_template("settings/done.html", message="Email copy setting saved.")


@bp.route("/email/test", methods=["POST"])
def email_test():
    from .. import graph, mailer
    to = mailer.copy_settings()["address"]
    if not to:
        return render_template("settings/email.html", status=graph.status(), copy=mailer.copy_settings(),
                               send_token=mailer.new_send_token(),
                               error="Set the email copy address first — the test goes there."), 400
    try:
        mailer.send("test", request.form.get("send_token", ""), [to], "Test email from your invoicing app",
                    "This is a test from your DB IT Consulting invoicing app. Email sending works.",
                    add_copy=False)
    except (mailer.SendRefused, graph.GraphError) as e:
        return render_template("settings/email.html", status=graph.status(), copy=mailer.copy_settings(),
                               send_token=mailer.new_send_token(), error=str(e)), 400
    return render_template("settings/done.html", message=f"Test email sent to {to}. Check your inbox.")


# ---------------------------------------------------------------- AI note cleanup (Claude API)

@bp.route("/ai")
def ai_settings():
    from .. import ai
    return render_template("settings/ai.html", status=ai.key_status())


@bp.route("/ai/key", methods=["GET", "POST"])
@auth.fresh_2fa_required
def ai_key():
    from .. import ai
    status = ai.key_status()
    if request.method == "GET":
        return render_template("settings/ai_key.html", status=status)
    remove = request.form.get("remove") == "yes"
    key = (request.form.get("api_key") or "").strip()
    if not remove and not ai.valid_key_format(key):
        return render_template("settings/ai_key.html", status=status,
                               error="That doesn't look like a Claude API key (it starts with sk-ant-)."), 400
    with atomic():
        before = ai.key_status()
        ai.save_key(None if remove else key)
        after_desc = "removed" if remove else f"…{key[-4:]}"
        before_desc = f"…{before['last4']}" if before["configured"] else "none"
        audit.log("ai_key_changed", "settings", details={"before": {"key": before_desc}, "after": {"key": after_desc}})
        audit.raise_alert("ai_key_changed", f"The Claude API key was {'removed' if remove else 'changed'} "
                                            f"by {g.user['username']} from {g.ip}.")
    return render_template("settings/done.html",
                           message="API key removed." if remove else "API key saved (encrypted). AI cleanup is on.")
