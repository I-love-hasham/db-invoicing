"""First-time setup, sign-in with 2FA, re-authentication and sign-out."""
import hmac

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from .. import audit, auth, crypto, totp
from ..db import get_db

bp = Blueprint("auth", __name__)

GENERIC_FAIL = "Invalid username or password."
LOCKED_MSG = "Too many failed attempts. The account is locked for 15 minutes."
THROTTLED_MSG = "Too many failed attempts from your network. Try again later."


def _enrolled_user_exists() -> bool:
    return get_db().execute("SELECT 1 FROM users WHERE totp_enabled = 1 LIMIT 1").fetchone() is not None


# ---------------------------------------------------------------- setup

@bp.route("/setup", methods=["GET", "POST"])
def setup():
    if _enrolled_user_exists():
        abort(404)
    if request.method == "GET":
        return render_template("setup.html")

    if auth.ip_throttled(g.ip):
        audit.log("setup_throttled", "auth", outcome="failure")
        return render_template("setup.html", error=THROTTLED_MSG), 429

    form = request.form
    username = form.get("username", "").strip()
    password = form.get("password", "")
    if not hmac.compare_digest(form.get("setup_token", "").encode(),
                               current_app.config["SETUP_TOKEN"].encode()):
        auth.register_failure(None, "setup_token_invalid", attempted_username=username[:64])
        return render_template("setup.html", error="Setup token is incorrect.", username=username), 403
    if not auth.USERNAME_RE.match(username):
        return render_template("setup.html", error="Username: 3–32 letters, numbers, . _ or -.",
                               username=username), 400
    problem = auth.password_problem(password, username)
    if not problem and password != form.get("password_confirm", ""):
        problem = "Passwords don't match."
    if problem:
        return render_template("setup.html", error=problem, username=username), 400

    db = get_db()
    now = audit.utcnow_iso()
    # An abandoned, never-finished setup is replaced (needs the setup token again).
    db.execute("DELETE FROM users WHERE totp_enabled = 0")
    cur = db.execute(
        "INSERT INTO users (username, password_hash, totp_secret_enc, created_at, password_changed_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (username, auth.hash_password(password), crypto.encrypt(totp.new_secret()), now, now),
    )
    g.user = {"id": cur.lastrowid, "username": username}
    audit.log("user_created", "auth", target=f"user:{username}")
    auth.start_session(cur.lastrowid, "enroll")
    return redirect(url_for("auth.setup_2fa"))


@bp.route("/setup/2fa", methods=["GET", "POST"])
def setup_2fa():
    if g.session is None or g.session["stage"] != "enroll":
        return redirect(url_for("auth.login"))
    user = auth.get_user(g.user["id"])
    secret = auth.user_totp_secret(user)
    uri = totp.provisioning_uri(secret, user["username"])
    ctx = {"secret": secret, "qr": totp.qr_data_uri(uri)}

    if request.method == "GET":
        return render_template("setup_2fa.html", **ctx)

    if not auth.check_totp(user, request.form.get("code", "").strip()):
        audit.log("2fa_enroll_failed", "auth", outcome="failure")
        return render_template("setup_2fa.html", error="That code didn't match. Check the time on "
                                                       "your phone and try the next code.", **ctx), 400
    get_db().execute("UPDATE users SET totp_enabled = 1 WHERE id = ?", (user["id"],))
    codes = auth.generate_backup_codes(user["id"])
    audit.log("2fa_enrolled", "auth", details={"method": "totp", "backups_issued": len(codes)})
    auth.check_known_device(user["id"], user["username"])  # records this device as the baseline
    auth.start_session(user["id"], "full")
    audit.log("login_success", "auth", details={"via": "initial_setup"})
    return render_template("backup_codes.html", codes=codes, first_time=True)


# ---------------------------------------------------------------- sign in

@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.session and g.session["stage"] == "full":
        return redirect(url_for("main.dashboard"))
    if not _enrolled_user_exists():
        return redirect(url_for("auth.setup"))
    if request.method == "GET":
        return render_template("login.html")

    if auth.ip_throttled(g.ip):
        audit.log("login_throttled", "auth", outcome="failure")
        return render_template("login.html", error=THROTTLED_MSG), 429

    username = request.form.get("username", "").strip()[:64]
    password = request.form.get("password", "")
    user = get_db().execute("SELECT * FROM users WHERE username = ? AND totp_enabled = 1",
                            (username,)).fetchone()
    if auth.is_locked(user):
        audit.log("login_blocked_locked", "auth", outcome="failure", username=user["username"])
        return render_template("login.html", error=LOCKED_MSG, username=username), 403
    if not auth.check_password(user, password):
        locked = auth.register_failure(user, "login_password_failed", attempted_username=username)
        return render_template("login.html", error=LOCKED_MSG if locked else GENERIC_FAIL,
                               username=username), 401

    g.user = {"id": user["id"], "username": user["username"]}
    audit.log("login_password_ok", "auth")
    auth.start_session(user["id"], "password")
    return redirect(url_for("auth.login_2fa"))


@bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    if g.session is None or g.session["stage"] != "password":
        return redirect(url_for("auth.login"))
    if request.method == "GET":
        return render_template("login_2fa.html")

    user = auth.get_user(g.user["id"])
    if auth.is_locked(user):
        auth.end_session()
        return render_template("login.html", error=LOCKED_MSG), 403

    method = auth.verify_second_factor(user, request.form.get("code", ""))
    if method is None:
        locked = auth.register_failure(user, "2fa_failed")
        if locked:
            auth.end_session()
            return render_template("login.html", error=LOCKED_MSG), 403
        return render_template("login_2fa.html", error="That code didn't work."), 401

    auth.reset_failures(user["id"])
    auth.start_session(user["id"], "full")
    left = auth.backup_codes_left(user["id"])
    audit.log("login_success", "auth", details={"second_factor": method})
    if method == "backup_code":
        audit.raise_alert("backup_code_used", f"A backup code was used to sign in to '{user['username']}' "
                                              f"from {g.ip}. {left} backup codes left.")
    auth.check_known_device(user["id"], user["username"])
    return redirect(url_for("main.dashboard"))


# ---------------------------------------------------------------- re-auth / sign out

@bp.route("/reauth", methods=["GET", "POST"])
def reauth():
    nxt = auth.safe_next(request.values.get("next"), url_for("main.dashboard"))
    if request.method == "GET":
        return render_template("reauth.html", next=nxt)
    user = auth.get_user(g.user["id"])
    method = auth.verify_second_factor(user, request.form.get("code", ""))
    if method is None:
        locked = auth.register_failure(user, "2fa_reauth_failed")
        if locked:
            auth.end_session()
            return redirect(url_for("auth.login"))
        return render_template("reauth.html", next=nxt, error="That code didn't work."), 401
    auth.reset_failures(user["id"])
    auth.mark_reauth()
    audit.log("2fa_reauth_ok", "auth", details={"second_factor": method})
    if method == "backup_code":
        audit.raise_alert("backup_code_used", f"A backup code was used to confirm a sensitive change "
                                              f"from {g.ip}. {auth.backup_codes_left(user['id'])} left.")
    return redirect(nxt)


@bp.route("/logout", methods=["POST"])
def logout():
    if g.session:
        audit.log("logout", "auth")
    auth.end_session()
    return redirect(url_for("auth.login"))
