"""First-time setup, sign-in with 2FA, re-authentication and sign-out."""
import hmac

from flask import Blueprint, abort, current_app, g, redirect, render_template, request, url_for

from .. import audit, auth, crypto, totp
from ..db import atomic, get_db

bp = Blueprint("auth", __name__)

# One message for wrong password AND locked account, so the page doesn't reveal
# which usernames exist. The real reason is in the audit log (and an alert).
GENERIC_FAIL = ("Sign-in failed. Check your username and password. After 5 failed "
                "attempts the account is locked for 15 minutes.")
THROTTLED_MSG = "Too many failed attempts from your network. Try again later."


def _enrolled_user_exists() -> bool:
    return get_db().execute("SELECT 1 FROM users WHERE totp_enabled = 1 LIMIT 1").fetchone() is not None


def _blocked_response(attempt, template="login.html"):
    if attempt.status == "throttled":
        return render_template(template, error=THROTTLED_MSG), 429
    return render_template(template, error=GENERIC_FAIL), 401


# ---------------------------------------------------------------- setup

@bp.route("/setup", methods=["GET", "POST"])
def setup():
    if _enrolled_user_exists():
        abort(404)
    if request.method == "GET":
        return render_template("setup.html")

    form = request.form
    username = form.get("username", "").strip()
    attempt = auth.begin_attempt(None)
    if attempt.blocked:
        auth.blocked_attempt(attempt, None)
        return render_template("setup.html", error=THROTTLED_MSG), 429
    if not hmac.compare_digest(form.get("setup_token", "").encode(),
                               current_app.config["SETUP_TOKEN"].encode()):
        auth.end_attempt(attempt, None, False, "setup_token_invalid")
        return render_template("setup.html", error="Setup token is incorrect."), 403
    auth.end_attempt(attempt, None, True)

    password = form.get("password", "")
    if not auth.USERNAME_RE.match(username):
        return render_template("setup.html", error="Username: 3–32 letters, numbers, . _ or -.",
                               username=username), 400
    problem = auth.password_problem(password, username)
    if not problem and password != form.get("password_confirm", ""):
        problem = "Passwords don't match."
    if problem:
        return render_template("setup.html", error=problem, username=username), 400

    password_hash = auth.hash_password(password)   # slow: done before taking the lock
    now = audit.utcnow_iso()
    with atomic() as db:
        if _enrolled_user_exists():
            abort(404)
        # An abandoned, never-finished setup is replaced (needs the setup token again).
        db.execute("DELETE FROM users WHERE totp_enabled = 0")
        cur = db.execute(
            "INSERT INTO users (username, password_hash, totp_secret_enc, created_at, password_changed_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (username, password_hash, crypto.encrypt(totp.new_secret()), now, now),
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
    ctx = {"secret": secret, "qr": totp.qr_data_uri(totp.provisioning_uri(secret, user["username"]))}
    if request.method == "GET":
        return render_template("setup_2fa.html", **ctx)

    with atomic() as db:
        if not auth.check_totp(user, request.form.get("code", "").strip()):
            audit.log("2fa_enroll_failed", "auth", outcome="failure")
            ok = False
        else:
            ok = True
            db.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?", (user["id"],))
            codes = auth.generate_backup_codes(user["id"])
            audit.log("2fa_enrolled", "auth", details={"method": "totp", "backups_issued": len(codes)})
            auth.check_known_device(user["id"], user["username"])  # this device becomes the baseline
            auth.start_session(user["id"], "full")
            audit.log("login_success", "auth", details={"via": "initial_setup"})
    if not ok:
        return render_template("setup_2fa.html", error="That code didn't match. Check the time on "
                                                       "your phone and try the next code.", **ctx), 400
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

    username = request.form.get("username", "").strip()[:64]
    password = request.form.get("password", "")
    user = get_db().execute("SELECT * FROM users WHERE username = ? AND totp_enabled = 1",
                            (username,)).fetchone()
    attempt = auth.begin_attempt(user)
    if attempt.blocked:
        auth.blocked_attempt(attempt, user, password)
        return _blocked_response(attempt)
    if not auth.check_password(user, password):      # slow check, no lock held
        auth.end_attempt(attempt, user, False, "login_password_failed")
        return render_template("login.html", error=GENERIC_FAIL), 401

    with atomic():
        auth.end_attempt(attempt, user, True)   # password alone doesn't clear earlier failures
        g.user = {"id": user["id"], "username": user["username"]}
        audit.log("login_password_ok", "auth")
        auth.start_session(user["id"], "password")
    return redirect(url_for("auth.login_2fa"))


def _second_factor(user, code: str, fail_reason: str):
    """Shared by sign-in and re-auth. Returns (method, response_if_failed)."""
    attempt = auth.begin_attempt(user)
    if attempt.blocked:
        auth.blocked_attempt(attempt, user)
        with atomic():
            auth.end_session()
        return None, _blocked_response(attempt)
    method = auth.verify_second_factor(user, code)   # backup-code checks are slow: no lock held
    if method is None:
        if auth.end_attempt(attempt, user, False, fail_reason):
            with atomic():
                auth.end_session()
            return None, (render_template("login.html", error=GENERIC_FAIL), 401)
        return None, None
    with atomic():
        auth.end_attempt(attempt, user, True)
        auth.reset_failures(user["id"])
    return method, None


@bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    if g.session is None or g.session["stage"] != "password":
        return redirect(url_for("auth.login"))
    if request.method == "GET":
        return render_template("login_2fa.html")

    user = auth.get_user(g.user["id"])
    method, failed = _second_factor(user, request.form.get("code", ""), "2fa_failed")
    if failed:
        return failed
    if method is None:
        return render_template("login_2fa.html", error="That code didn't work."), 401

    with atomic():
        auth.start_session(user["id"], "full")
        audit.log("login_success", "auth", details={"second_factor": method})
        if method == "backup_code":
            audit.raise_alert("backup_code_used",
                              f"A backup code was used to sign in to '{user['username']}' from {g.ip}. "
                              f"{auth.backup_codes_left(user['id'])} backup codes left.")
        auth.check_known_device(user["id"], user["username"])
    return redirect(url_for("main.dashboard"))


# ---------------------------------------------------------------- re-auth / sign out

@bp.route("/reauth", methods=["GET", "POST"])
def reauth():
    nxt = auth.safe_next(request.values.get("next"), url_for("main.dashboard"))
    if request.method == "GET":
        return render_template("reauth.html", next=nxt)
    user = auth.get_user(g.user["id"])
    method, failed = _second_factor(user, request.form.get("code", ""), "2fa_reauth_failed")
    if failed:
        return redirect(url_for("auth.login"))
    if method is None:
        return render_template("reauth.html", next=nxt, error="That code didn't work."), 401
    with atomic():
        auth.mark_reauth()
        audit.log("2fa_reauth_ok", "auth", details={"second_factor": method})
        if method == "backup_code":
            audit.raise_alert("backup_code_used", f"A backup code was used to confirm a sensitive change "
                                                  f"from {g.ip}. {auth.backup_codes_left(user['id'])} left.")
    return redirect(nxt)


@bp.route("/logout", methods=["POST"])
def logout():
    with atomic():
        if g.session:
            audit.log("logout", "auth")
        auth.end_session()
    return redirect(url_for("auth.login"))
