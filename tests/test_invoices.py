import json
import os
import re

from app.db import get_audit_db, get_db
from conftest import csrf, do_setup


def _seed(client):
    t = csrf(client, "/products/new")
    client.post("/products/new", data={"csrf_token": t, "name": "Regular Hours", "description": "IT services",
                                       "unit": "hour", "default_rate": ""})
    t = csrf(client, "/clients/new")
    client.post("/clients/new", data={"csrf_token": t, "name": "OKG Tech",
                                      "address": "4a Medical Park Drive\nPomona, NY 10970",
                                      "email": "hr@okgtech.com", "payment_terms_days": "15", "notes": ""})
    t = csrf(client, "/clients/1")
    client.post("/clients/1/rates", data={"csrf_token": t, "rate_1": "77.18"})


def _time(client, day, hours, client_id="1"):
    t = csrf(client, "/time/new")
    r = client.post("/time/new", data={"csrf_token": t, "client_id": client_id, "product_id": "1",
                                       "work_date": day, "hours": hours, "notes": "work"})
    assert r.status_code == 302


def _preview(client, frm="2026-10-29", to="2026-11-06", inv_date="2026-11-12"):
    return client.get(f"/invoices/new?client_id=1&period_from={frm}&period_to={to}&invoice_date={inv_date}")


def _create(client, notes="", **kw):
    html = _preview(client, **kw).get_data(as_text=True)
    form = dict(re.findall(r'<input type="hidden" name="([a-z_]+)" value="([^"]*)"', html))
    form["notes"] = notes
    return client.post("/invoices/new", data=form)


def _audit(app, action):
    with app.app_context():
        return get_audit_db().execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,)).fetchall()


def _spec_week(client):
    # 43.32 hours, like the spec's invoice #1204
    for day, h in [("2026-10-29", "8.5"), ("2026-10-30", "9"), ("2026-11-02", "8:45"),
                   ("2026-11-03", "8.32"), ("2026-11-06", "8:45")]:
        _time(client, day, h)


def test_invoice_matches_spec_example(client, app, clock):
    do_setup(client, app, clock)
    _seed(client)
    _spec_week(client)
    page = _preview(client).get_data(as_text=True)
    assert "Regular Hours, IT services, 10/29/26 – 11/06/26" in page
    assert "43.32" in page and "$3,343.44" in page and "#1205" in page
    r = _create(client)
    assert r.status_code == 302
    with app.app_context():
        inv = get_db().execute("SELECT * FROM invoices").fetchone()
        assert inv["number"] == 1205 and inv["total_cents"] == 334344 and inv["due_date"] == "2026-11-27"
        assert get_db().execute("SELECT COUNT(*) FROM time_entries WHERE invoice_id = ?", (inv["id"],)).fetchone()[0] == 5
        path = os.path.join(app.config["DATA_DIR"], inv["pdf_path"])
    assert inv["pdf_path"] == "Invoices/OKG Tech/2026/Invoice-1205.pdf" and os.path.isfile(path)
    pdf = client.get("/invoices/1/pdf")
    assert pdf.status_code == 200 and pdf.data[:5] == b"%PDF-"
    assert _audit(app, "invoice_created") and _audit(app, "invoice_pdf_generated")


def test_numbers_continue_and_time_not_billed_twice(client, app, clock):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    assert "No uninvoiced time" in _preview(client).get_data(as_text=True)   # already billed
    _time(client, "2026-11-20", "3")
    _create(client, frm="2026-11-15", to="2026-11-21", inv_date="2026-11-22")
    with app.app_context():
        assert [r[0] for r in get_db().execute("SELECT number FROM invoices ORDER BY id")] == [1205, 1206]


def test_changed_time_after_preview_is_not_silently_billed(client, app, clock):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    html = _preview(client).get_data(as_text=True)
    form = dict(re.findall(r'<input type="hidden" name="([a-z_]+)" value="([^"]*)"', html))
    _time(client, "2026-11-03", "5")          # added after the preview
    r = client.post("/invoices/new", data={**form, "notes": ""})
    assert "changed=1" in r.headers["Location"]
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM invoices").fetchone()[0] == 0


def test_missing_rate_blocks_invoice(client, app, clock):
    do_setup(client, app, clock)
    _seed(client)
    t = csrf(client, "/clients/1")
    client.post("/clients/1/rates", data={"csrf_token": t, "rate_1": ""})   # remove rate; no default
    _time(client, "2026-11-02", "2")
    r = _preview(client)
    assert r.status_code == 400 and "no rate" in r.get_data(as_text=True)


def test_invoice_is_a_snapshot(client, app, clock):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    t = csrf(client, "/clients/1")
    client.post("/clients/1", data={"csrf_token": t, "name": "OKG Technologies", "address": "elsewhere",
                                    "email": "new@okgtech.com", "payment_terms_days": "30", "notes": ""})
    client.post("/clients/1/rates", data={"csrf_token": csrf(client, "/clients/1"), "rate_1": "99"})
    page = client.get("/invoices/1").get_data(as_text=True)
    assert "OKG Tech" in page and "$154.36" in page and "OKG Technologies" not in page


def test_edit_regenerates_pdf_and_audits(client, app, clock):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    with app.app_context():
        old_hash = get_db().execute("SELECT pdf_sha256 FROM invoices").fetchone()[0]
    t = csrf(client, "/invoices/1/edit")
    client.post("/invoices/1/edit", data={"csrf_token": t, "invoice_date": "2026-11-15", "notes": "Thanks!"})
    with app.app_context():
        inv = get_db().execute("SELECT * FROM invoices").fetchone()
    assert inv["due_date"] == "2026-11-30" and inv["pdf_sha256"] != old_hash
    d = _audit(app, "invoice_edited")[-1]["details"]
    assert "2026-11-12" in d and "2026-11-15" in d and "Thanks" not in d


def test_void_keeps_record_releases_time_and_alerts(client, app, clock):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    t = csrf(client, "/invoices/1")
    assert client.post("/invoices/1/void", data={"csrf_token": t, "reason": "wrong period"}).status_code == 400
    client.post("/invoices/1/void", data={"csrf_token": t, "reason": "wrong period", "confirm": "yes"})
    with app.app_context():
        inv = get_db().execute("SELECT * FROM invoices").fetchone()
        free = get_db().execute("SELECT COUNT(*) FROM time_entries WHERE invoice_id IS NULL").fetchone()[0]
        kinds = [r[0] for r in get_db().execute("SELECT kind FROM security_alerts")]
    assert inv["status"] == "void" and free == 1 and "invoice_voided" in kinds
    assert client.post("/invoices/1/edit", data={"csrf_token": t, "invoice_date": "2026-11-15",
                                                 "notes": ""}).status_code == 400
    r = _create(client)                      # the released time can be billed again, as #1206
    with app.app_context():
        assert get_db().execute("SELECT MAX(number) FROM invoices").fetchone()[0] == 1206


def test_tampered_pdf_is_detected(client, app, clock):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    with app.app_context():
        rel = get_db().execute("SELECT pdf_path FROM invoices").fetchone()[0]
    with open(os.path.join(app.config["DATA_DIR"], rel), "ab") as fh:
        fh.write(b"tampered")
    assert client.get("/invoices/1/pdf").status_code == 409
    with app.app_context():
        assert "invoice_pdf_changed" in [r[0] for r in get_db().execute("SELECT kind FROM security_alerts")]


def test_odd_client_names_make_safe_paths(client, app, clock):
    from app import pdf
    assert pdf.safe_folder_name("../../etc") == "etc" and pdf.safe_folder_name("..") == "client"
    assert pdf.safe_folder_name("Smith & Sons, LLC") == "Smith _ Sons_ LLC"
    assert "/" not in pdf.safe_folder_name("a/b\\c")


def test_pdf_renders_unusual_text():
    from app import pdf
    vm = {"number": 1205, "status": "void", "shown_status": "Void", "invoice_date": "11/12/26",
          "due_date": "11/27/26", "period": "10/29/26 – 11/06/26", "terms": "Net 15",
          "client": {"name": "Café Ünïcode 😀 שלום", "address": "line1\nline2", "email": "a@b.co",
                     "payment_terms_days": 15},
          "business": {"name": "DB IT Consulting", "address": "3 Crestview Terrace\nMonsey, NY 10952",
                       "phone": "845-263-5628", "email": "", "footer": "Thanks"},
          "notes": "x" * 3000, "lines": [{"description": "Regular Hours, IT services, 10/29/26 – 11/06/26",
                                          "hours": "43.32", "rate_cents": 7718, "amount_cents": 334344}],
          "subtotal_cents": 334344, "total_cents": 334344}
    data = pdf.render(vm)
    assert data.startswith(b"%PDF-") and pdf.render(vm) == data      # deterministic


def test_business_details_need_fresh_2fa_and_are_audited(client, app, clock):
    do_setup(client, app, clock)
    with app.app_context():
        get_db().execute("UPDATE sessions SET reauth_at = reauth_at - 600")
    assert "/reauth" in client.get("/settings/business").headers["Location"]
    with app.app_context():
        get_db().execute("UPDATE sessions SET reauth_at = reauth_at + 600")
    t = csrf(client, "/settings/business")
    client.post("/settings/business", data={"csrf_token": t, "name": "DB IT Consulting", "address": "x",
                                            "phone": "845-263-5628", "email": "billing@dbit.example", "footer": "Thanks",
                                            "signature": "David"})
    d = _audit(app, "business_details_changed")[-1]["details"]
    assert "billing@dbit.example" in d


def test_pages_need_login(client):
    for p in ("/invoices/", "/invoices/new", "/invoices/1", "/invoices/1/pdf"):
        assert client.get(p).status_code == 302


# ---------------------------------------------------------------- review findings

def test_rate_change_after_preview_sends_back_to_preview(client, app, clock):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    html = _preview(client).get_data(as_text=True)
    form = dict(re.findall(r'<input type="hidden" name="([a-z_]+)" value="([^"]*)"', html))
    client.post("/clients/1/rates", data={"csrf_token": csrf(client, "/clients/1"), "rate_1": "99.99"})
    r = client.post("/invoices/new", data={**form, "notes": ""})
    assert "changed=1" in r.headers["Location"]
    with app.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM invoices").fetchone()[0] == 0


def test_parallel_pdf_writes_stay_consistent(client, app, clock):
    import threading
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    cookie = client.get_cookie("dbinv").value
    clients = []
    for _ in range(4):
        c = app.test_client()
        c.set_cookie("dbinv", cookie)
        clients.append((c, csrf(c, "/invoices/1")))
    barrier = threading.Barrier(4)
    codes = []

    def go(c, t):
        barrier.wait()
        codes.append(c.post("/invoices/1/pdf", data={"csrf_token": t}).status_code)
    ts = [threading.Thread(target=go, args=x) for x in clients]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert codes == [302] * 4
    assert client.get("/invoices/1/pdf").status_code == 200        # no false tamper alert
    folder = os.path.join(app.config["DATA_DIR"], "Invoices", "OKG Tech", "2026")
    assert sorted(os.listdir(folder)) == ["Invoice-1205.pdf"]       # no leftover temp files


def test_moving_invoice_to_another_year_removes_old_pdf(client, app, clock):
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    t = csrf(client, "/invoices/1/edit")
    client.post("/invoices/1/edit", data={"csrf_token": t, "invoice_date": "2027-01-02", "notes": ""})
    base = os.path.join(app.config["DATA_DIR"], "Invoices", "OKG Tech")
    assert not os.path.exists(os.path.join(base, "2026", "Invoice-1205.pdf"))
    assert os.path.exists(os.path.join(base, "2027", "Invoice-1205.pdf"))
    assert client.get("/invoices/1/pdf").status_code == 200


def test_audit_failure_during_pdf_leaves_old_file_intact(client, app, clock, monkeypatch):
    app.config["PROPAGATE_EXCEPTIONS"] = False
    do_setup(client, app, clock)
    _seed(client)
    _time(client, "2026-11-02", "2")
    _create(client)
    from app import audit
    real = audit.log

    def failing(action, *a, **kw):
        if action == "invoice_pdf_regenerated":
            raise OSError("disk full")
        return real(action, *a, **kw)
    monkeypatch.setattr(audit, "log", failing)
    t = csrf(client, "/invoices/1")
    assert client.post("/invoices/1/pdf", data={"csrf_token": t}).status_code == 500
    monkeypatch.setattr(audit, "log", real)
    assert client.get("/invoices/1/pdf").status_code == 200      # old file + old hash still match
    folder = os.path.join(app.config["DATA_DIR"], "Invoices", "OKG Tech", "2026")
    assert sorted(os.listdir(folder)) == ["Invoice-1205.pdf"]


def test_pdf_remove_only_touches_invoice_pdfs(app):
    from app import pdf
    data = app.config["DATA_DIR"]
    pdf.remove(data, "app.db")
    pdf.remove(data, "../etc/passwd")
    assert os.path.exists(os.path.join(data, "app.db"))
