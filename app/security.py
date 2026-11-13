"""Request guard: client IP, session loading, CSRF, default-deny access, security headers."""
import hmac
import ipaddress
import secrets
import time
from urllib.parse import urlsplit

from flask import abort, current_app, g, redirect, request, url_for
from itsdangerous import BadSignature, URLSafeSerializer

from . import audit, auth
from .db import get_db

# Everything not listed here requires a fully signed-in session (password + 2FA).
PUBLIC_ENDPOINTS = {"auth.login", "auth.setup", "main.healthz", "static"}
PASSWORD_STAGE_ENDPOINTS = {"auth.login_2fa", "auth.logout"}
ENROLL_STAGE_ENDPOINTS = {"auth.setup_2fa", "auth.logout"}
PRE_CSRF_COOKIE = "dbinv_csrf"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def client_ip() -> str:
    if current_app.config["TRUST_PROXY_HEADERS"]:
        value = request.headers.get("CF-Connecting-IP", "").strip()
        if value:
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                pass
    return request.remote_addr or "unknown"


def _pre_serializer() -> URLSafeSerializer:
    return URLSafeSerializer(current_app.config["SECRET_KEY"], salt="pre-login-csrf")


def _load_csrf_token() -> None:
    if g.session:
        g.csrf_token = g.session["csrf_token"]
        return
    raw = request.cookies.get(PRE_CSRF_COOKIE)
    if raw:
        try:
            g.csrf_token = _pre_serializer().loads(raw)
            return
        except BadSignature:
            pass
    g.csrf_token = secrets.token_urlsafe(32)
    g.new_pre_csrf = g.csrf_token


def _csrf_ok() -> bool:
    origin = request.headers.get("Origin")
    if origin is not None:
        if origin == "null" or urlsplit(origin).netloc != request.host:
            return False
    sent = request.form.get("csrf_token", "")
    return bool(sent) and hmac.compare_digest(sent, g.csrf_token)


def _before_request():
    g.ip = client_ip()
    g.ua = (request.user_agent.string or "")[:300]
    g.user = None
    g.session = None
    g.set_cookie_token = None
    g.clear_cookie = False
    g.new_pre_csrf = None
    endpoint = request.endpoint
    if endpoint in ("main.healthz", "static"):
        return None

    auth.load_session()
    _load_csrf_token()

    if request.method not in SAFE_METHODS and not _csrf_ok():
        # Signed-out senders can't flood the audit log: they count toward the
        # per-IP limit, and once throttled their rejections aren't logged.
        if g.session:
            audit.log("csrf_rejected", "security", outcome="failure", target=request.path)
        else:
            get_db().execute("INSERT INTO login_failures (ip, ts) VALUES (?, ?)", (g.ip, time.time()))
            auth.log_rate_limited("csrf_rejected", "security", outcome="failure", target=request.path)
        abort(400)

    if endpoint is None or endpoint in PUBLIC_ENDPOINTS:
        return None
    stage = g.session["stage"] if g.session else None
    if stage == "full":
        return None
    if stage == "password" and endpoint in PASSWORD_STAGE_ENDPOINTS:
        return None
    if stage == "enroll" and endpoint in ENROLL_STAGE_ENDPOINTS:
        return None
    return redirect(url_for("auth.login"))


def _after_request(response):
    secure = current_app.config["COOKIE_SECURE"]
    if g.get("set_cookie_token"):
        response.set_cookie(auth.cookie_name(), g.set_cookie_token, httponly=True, secure=secure,
                            samesite="Lax", path="/")
    elif g.get("clear_cookie"):
        response.delete_cookie(auth.cookie_name(), path="/", secure=secure, httponly=True, samesite="Lax")
    if g.get("new_pre_csrf"):
        response.set_cookie(PRE_CSRF_COOKIE, _pre_serializer().dumps(g.new_pre_csrf), httponly=True,
                            secure=secure, samesite="Strict", path="/", max_age=3600)

    h = response.headers
    h["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    )
    h["X-Frame-Options"] = "DENY"
    h["X-Content-Type-Options"] = "nosniff"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    if secure:
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.endpoint != "static":
        h["Cache-Control"] = "no-store"
    return response


def init_app(app):
    app.before_request(_before_request)
    app.after_request(_after_request)
    app.jinja_env.globals["csrf_token"] = lambda: g.get("csrf_token", "")
