"""Audit log viewer with filters and CSV export (read-only)."""
import csv
import io
import re
from datetime import date, timedelta

from flask import Blueprint, Response, render_template, request

from .. import audit
from ..db import get_audit_db

bp = Blueprint("audit", __name__, url_prefix="/audit")
PAGE_SIZE = 100
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _filters():
    args = request.args
    f = {
        "date_from": args.get("date_from", "").strip(),
        "date_to": args.get("date_to", "").strip(),
        "category": args.get("category", "").strip(),
        "outcome": args.get("outcome", "").strip(),
        "q": args.get("q", "").strip()[:100],
    }
    where, params = [], []
    for key, op in (("date_from", ">="), ("date_to", "<")):
        value = f[key]
        if value and _DATE.match(value):
            try:
                d = date.fromisoformat(value)
            except ValueError:
                f[key] = ""
                continue
            if key == "date_to":
                d += timedelta(days=1)  # inclusive end date
            where.append(f"ts {op} ?")
            params.append(d.isoformat())
        else:
            f[key] = ""
    if f["category"] in audit.CATEGORIES:
        where.append("category = ?")
        params.append(f["category"])
    else:
        f["category"] = ""
    if f["outcome"] in ("success", "failure"):
        where.append("outcome = ?")
        params.append(f["outcome"])
    else:
        f["outcome"] = ""
    if f["q"]:
        like = f"%{_like_escape(f['q'])}%"
        where.append("(action LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\' OR details LIKE ? ESCAPE '\\'"
                     " OR username LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\')")
        params.extend([like] * 5)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    return f, clause, params


@bp.route("/")
def index():
    f, clause, params = _filters()
    try:
        page = max(1, int(request.args.get("page", "1")))
    except ValueError:
        page = 1
    conn = get_audit_db()
    total = conn.execute(f"SELECT COUNT(*) AS n FROM audit_log{clause}", params).fetchone()["n"]
    rows = conn.execute(f"SELECT * FROM audit_log{clause} ORDER BY id DESC LIMIT ? OFFSET ?",
                        [*params, PAGE_SIZE, (page - 1) * PAGE_SIZE]).fetchall()
    return render_template("audit.html", rows=rows, f=f, page=page, total=total,
                           pages=max(1, -(-total // PAGE_SIZE)), categories=audit.CATEGORIES)


def _csv_safe(value) -> str:
    """Stop spreadsheet formula injection when the CSV is opened in Excel."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@bp.route("/export.csv")
def export_csv():
    f, clause, params = _filters()
    rows = get_audit_db().execute(f"SELECT * FROM audit_log{clause} ORDER BY id", params).fetchall()
    out = io.StringIO()
    writer = csv.writer(out)
    cols = ["id", "ts", "username", "ip", "user_agent", "category", "action", "target", "outcome",
            "details", "entry_hash"]
    writer.writerow(cols)
    for r in rows:
        writer.writerow([_csv_safe(r[c]) for c in cols])
    audit.log("audit_exported", "audit", details={"filters": f, "rows": len(rows)})
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=audit-log.csv"})
