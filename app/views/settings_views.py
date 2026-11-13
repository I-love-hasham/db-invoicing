"""Account security settings. Every change needs a fresh 2FA check and raises an alert."""
from flask import Blueprint, g, redirect, render_template, request, url_for

from .. import audit, auth, crypto, totp
from ..db import get_db

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
    if not auth.check_password(user, request.form.get("current_password", "")):
        auth.register_failure(user, "password_change_wrong_current")
        return render_template("settings/password.html", error="Current password is incorrect."), 400
    new = request.form.get("new_password", "")
    problem = auth.password_problem(new, user["username"])
    if not problem and new != request.form.get("new_password_confirm", ""):
        problem = "New passwords don't match."
    if problem:
        return render_template("settings/password.html", error=problem), 400
    db = get_db()
    now = audit.utcnow_iso()
    db.execute("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?",
               (auth.hash_password(new), now, user["id"]))
    # sign out every other session
    db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (user["id"], g.session["token_hash"]))
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
    if request.method == "GET" or not g.session.get("pending_totp_enc"):
        secret = totp.new_secret()
        db.execute("UPDATE sessions SET pending_totp_enc = ? WHERE token_hash = ?",
                   (crypto.encrypt(secret), token_hash))
        return render_template("settings/authenticator.html", secret=secret,
                               qr=totp.qr_data_uri(totp.provisioning_uri(secret, g.user["username"])))

    secret = crypto.decrypt(g.session["pending_totp_enc"])
    step = totp.verify(secret, request.form.get("code", "").strip(), last_step=0)
    if step is None:
        audit.log("authenticator_change_failed", "settings", outcome="failure")
        return render_template("settings/authenticator.html", secret=secret,
                               qr=totp.qr_data_uri(totp.provisioning_uri(secret, g.user["username"])),
                               error="That code didn't match the new secret."), 400
    db.execute("UPDATE users SET totp_secret_enc = ?, totp_last_step = ? WHERE id = ?",
               (crypto.encrypt(secret), step, g.user["id"]))
    db.execute("UPDATE sessions SET pending_totp_enc = NULL WHERE token_hash = ?", (token_hash,))
    db.execute("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", (g.user["id"], token_hash))
    audit.log("authenticator_changed", "settings",
              details={"before": {"authenticator": "previous device"}, "after": {"authenticator": "new device"},
                       "other_sessions_signed_out": True})
    audit.raise_alert("2fa_changed", f"The authenticator app for '{g.user['username']}' was moved to a "
                                     f"new device from {g.ip}.")
    return render_template("settings/done.html",
                           message="Authenticator updated. Codes from the old phone no longer work.")
