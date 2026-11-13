"""Dashboard, security alerts, Security Status page and health check."""
import json
import os
import platform
from pathlib import Path

from flask import Blueprint, abort, current_app, g, redirect, render_template, url_for

from .. import audit, auth
from ..db import atomic, get_db

bp = Blueprint("main", __name__)
VERSION_FILE = Path(__file__).resolve().parents[2] / "VERSION"


def app_version() -> str:
    try:
        return VERSION_FILE.read_text().strip()
    except OSError:
        return "unknown"


def vulnerability_report() -> dict:
    """Reads the pip-audit report produced when the Docker image was built."""
    sec_dir = current_app.config["SECURITY_DIR"]
    report = {"scanned": False, "scanned_at": None, "vulns": []}
    try:
        with open(os.path.join(sec_dir, "pip-audit.json")) as fh:
            data = json.load(fh)
        report["scanned"] = True
    except (OSError, ValueError):
        return report
    try:
        report["scanned_at"] = Path(sec_dir, "scanned_at").read_text().strip()
    except OSError:
        pass
    for dep in data.get("dependencies", []):
        for v in dep.get("vulns", []):
            report["vulns"].append({
                "package": dep.get("name"), "version": dep.get("version"), "id": v.get("id"),
                "fix": ", ".join(v.get("fix_versions") or []) or "no fix yet",
            })
    return report


@bp.route("/healthz")
def healthz():
    return "ok", 200, {"Content-Type": "text/plain"}


@bp.route("/")
def dashboard():
    auth.sweep_rate_limits()
    vulns = vulnerability_report()
    chain_ok, _, _ = audit.verify_chain()
    return render_template(
        "dashboard.html",
        vulns=vulns,
        chain_ok=chain_ok,
        backups_left=auth.backup_codes_left(g.user["id"]),
        version=app_version(),
    )


@bp.route("/alerts/<int:alert_id>/ack", methods=["POST"])
def ack_alert(alert_id: int):
    with atomic() as db:
        row = db.execute("SELECT * FROM security_alerts WHERE id = ? AND acknowledged_at IS NULL",
                         (alert_id,)).fetchone()
        if row is None:
            abort(404)
        db.execute("UPDATE security_alerts SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ?",
                   (audit.utcnow_iso(), g.user["username"], alert_id))
        audit.log("alert_acknowledged", "security", target=f"alert:{alert_id}",
                  details={"kind": row["kind"], "message": row["message"]})
    return redirect(url_for("main.dashboard"))


@bp.route("/security-status")
def security_status():
    chain_ok, entries, chain_msg = audit.verify_chain()
    return render_template(
        "security_status.html",
        version=app_version(),
        build_date=current_app.config["BUILD_DATE"],
        python_version=platform.python_version(),
        vulns=vulnerability_report(),
        chain_ok=chain_ok,
        chain_entries=entries,
        chain_msg=chain_msg,
    )
