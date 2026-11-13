"""DB IT Consulting time tracking & invoicing app."""
import logging
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Flask, g, render_template, request

from . import audit, db, security
from .config import load_config

log = logging.getLogger(__name__)

ERROR_TEXT = {
    400: "That request couldn't be processed. Reload the page and try again.",
    403: "You don't have access to that.",
    404: "Page not found.",
    405: "That action isn't allowed here.",
    413: "That upload is too large.",
    429: "Too many requests. Wait a moment and try again.",
    500: "Something went wrong. The error was recorded in the audit log.",
}


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(test_config if test_config is not None else load_config())
    app.config.update(
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
        # Flask's own cookie session is not used; sessions are server-side (see auth.py).
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=app.config["COOKIE_SECURE"],
        SESSION_COOKIE_SAMESITE="Lax",
    )

    db.init_app(app)
    security.init_app(app)

    try:
        tz = ZoneInfo(app.config["APP_TIMEZONE"])
    except (ZoneInfoNotFoundError, ValueError):
        tz = timezone.utc

    @app.template_filter("localtime")
    def localtime(iso: str | None) -> str:
        if not iso:
            return ""
        try:
            dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        except ValueError:
            return iso
        return dt.astimezone(tz).strftime("%m/%d/%y %I:%M:%S %p")

    @app.context_processor
    def inject_alerts():
        if g.get("user") and g.get("session") and g.session["stage"] == "full":
            return {"open_alerts": audit.open_alerts()}
        return {"open_alerts": []}

    from .views import audit_views, auth_views, main_views, settings_views
    for module in (auth_views, main_views, settings_views, audit_views):
        app.register_blueprint(module.bp)

    def _error(exc):
        code = getattr(exc, "code", 500) or 500
        return render_template("error.html", code=code, message=ERROR_TEXT.get(code, "Error.")), code

    for code in (400, 403, 404, 405, 413, 429):
        app.register_error_handler(code, _error)

    @app.errorhandler(500)
    def _server_error(exc):
        original = getattr(exc, "original_exception", exc)
        log.error("unhandled error: %s", type(original).__name__)
        try:
            # metadata only: exception type and path, never request data
            audit.log("server_error", "error", outcome="failure",
                      target=getattr(g, "path", None),
                      details={"exception": type(original).__name__})
        except Exception:  # never let audit failure mask the original error page
            log.exception("could not write error to audit log")
        return render_template("error.html", code=500, message=ERROR_TEXT[500]), 500

    @app.before_request
    def _remember_path():
        g.path = request.path

    return app
