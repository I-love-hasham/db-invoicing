import re
import threading
from datetime import datetime, timedelta, timezone

from app.db import get_audit_db, get_db
from conftest import csrf, do_setup


def _seed(client, app):
    t = csrf(client, "/products/new")
    client.post("/products/new", data={"csrf_token": t, "name": "Regular Hours", "description": "IT services",
                                       "unit": "hour", "default_rate": "77.18"})
    t = csrf(client, "/clients/new")
    client.post("/clients/new", data={"csrf_token": t, "name": "OKG Tech", "address": "", "email": "",
                                      "payment_terms_days": "15", "notes": ""})


def _audit(app, action):
    with app.app_context():
        return get_audit_db().execute("SELECT * FROM audit_log WHERE action = ? ORDER BY id", (action,)).fetchall()


def _entries(app):
    with app.app_context():
        return get_db().execute("SELECT * FROM time_entries ORDER BY id").fetchall()


def _start(client, notes=""):
    t = csrf(client, "/time/")
    return client.post("/time/start", data={"csrf_token": t, "client_id": "1", "product_id": "1", "notes": notes})


def _backdate_timer(app, hours):
    start = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    with app.app_context():
        get_db().execute("UPDATE time_entries SET started_at = ? WHERE duration_seconds IS NULL", (start,))


def test_requires_login(client):
    for path in ("/time/", "/time/new"):
        assert client.get(path).status_code == 302


def test_timer_start_notes_stop(client, app, clock):
    do_setup(client, app, clock)
    _seed(client, app)
    assert _start(client, "checking backups").status_code == 302
    page = client.get("/time/").get_data(as_text=True)
    assert "Timer running" in page and "checking backups" in page
    assert "Timer running" in client.get("/").get_data(as_text=True)
    t = csrf(client, "/time/")
    client.post("/time/timer/notes", data={"csrf_token": t, "notes": "checked backups, patched DC01"})
    _backdate_timer(app, 2.5)
    t = csrf(client, "/time/")
    client.post("/time/stop", data={"csrf_token": t, "notes": "checked backups, patched DC01"})
    e = _entries(app)[0]
    assert 2.5 * 3600 - 5 <= e["duration_seconds"] <= 2.5 * 3600 + 5 and e["ended_at"]
    assert "2.50" in client.get("/time/").get_data(as_text=True)
    assert _audit(app, "timer_started") and _audit(app, "timer_notes_saved") and _audit(app, "timer_stopped")


def test_only_one_timer_even_in_parallel(client, app, clock):
    do_setup(client, app, clock)
    _seed(client, app)
    clients = [app.test_client() for _ in range(4)]
    for c in clients:
        c.set_cookie("dbinv", client.get_cookie("dbinv").value)
    tokens = [csrf(c, "/time/") for c in clients]
    barrier = threading.Barrier(4)
    codes = [None] * 4

    def go(i):
        barrier.wait()
        codes[i] = clients[i].post("/time/start", data={"csrf_token": tokens[i], "client_id": "1",
                                                        "product_id": "1", "notes": ""}).status_code
    threads = [threading.Thread(target=go, args=(i,)) for i in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(_entries(app)) == 1 and codes.count(302) == 1


def test_forgotten_timer_capped_at_24h(client, app, clock):
    do_setup(client, app, clock)
    _seed(client, app)
    _start(client)
    _backdate_timer(app, 30)
    t = csrf(client, "/time/")
    r = client.post("/time/stop", data={"csrf_token": t, "notes": ""})
    assert "capped=1" in r.headers["Location"]
    assert _entries(app)[0]["duration_seconds"] == 86400


def test_manual_add_edit_delete_with_audit(client, app, clock):
    do_setup(client, app, clock)
    _seed(client, app)
    t = csrf(client, "/time/new")
    r = client.post("/time/new", data={"csrf_token": t, "client_id": "1", "product_id": "1",
                                       "work_date": "2026-11-02", "hours": "7:30", "notes": "on-site, server swap"})
    assert r.status_code == 302 and _entries(app)[0]["duration_seconds"] == 27000
    t = csrf(client, "/time/1")
    client.post("/time/1", data={"csrf_token": t, "client_id": "1", "product_id": "1",
                                 "work_date": "2026-11-03", "hours": "8", "notes": "on-site, server swap"})
    d = _audit(app, "time_entry_edited")[-1]
    assert '"7.50"' in d["details"] and '"8.00"' in d["details"] and "2026-11-02" in d["details"]
    assert d["client_id"] == 1
    t = csrf(client, "/time/1")
    client.post("/time/1/delete", data={"csrf_token": t})
    assert _entries(app)[0]["deleted_at"]                      # kept, just hidden
    assert "server swap" not in client.get("/time/?from=2026-11-01&to=2026-11-30").get_data(as_text=True)
    assert _audit(app, "time_entry_deleted")


def test_notes_text_never_in_audit_log(client, app, clock):
    do_setup(client, app, clock)
    _seed(client, app)
    _start(client, "reset admin pw to Winter2026!")
    t = csrf(client, "/time/")
    client.post("/time/stop", data={"csrf_token": t, "notes": "reset admin pw to Winter2026!"})
    with app.app_context():
        dump = " ".join(str(tuple(r)) for r in get_audit_db().execute("SELECT * FROM audit_log"))
    assert "Winter2026" not in dump


def test_validation(client, app, clock):
    do_setup(client, app, clock)
    _seed(client, app)
    t = csrf(client, "/time/new")
    base = {"csrf_token": t, "client_id": "1", "product_id": "1", "work_date": "2026-11-02", "notes": ""}
    for hours in ("0", "25", "abc", "7,5", "٧", "7:75"):
        assert client.post("/time/new", data={**base, "hours": hours}).status_code == 400, hours
    assert client.post("/time/new", data={**base, "hours": "1", "work_date": "2026-13-40"}).status_code == 400
    assert client.post("/time/new", data={**base, "hours": "1", "client_id": "999"}).status_code == 400
    assert client.post("/time/new", data={**base, "hours": "1", "client_id": "x"}).status_code == 400
    assert _entries(app) == []


def test_archived_client_cannot_get_new_time(client, app, clock):
    do_setup(client, app, clock)
    _seed(client, app)
    t = csrf(client, "/clients/1")
    client.post("/clients/1/archive", data={"csrf_token": t})
    assert _start(client).status_code == 400
    assert _entries(app) == []


def test_invoiced_entries_are_locked(client, app, clock):
    do_setup(client, app, clock)
    _seed(client, app)
    t = csrf(client, "/time/new")
    client.post("/time/new", data={"csrf_token": t, "client_id": "1", "product_id": "1",
                                   "work_date": "2026-11-02", "hours": "2", "notes": ""})
    with app.app_context():
        get_db().execute("UPDATE time_entries SET invoice_id = 1205")
    t = csrf(client, "/time/")
    r = client.post("/time/1", data={"csrf_token": t, "client_id": "1", "product_id": "1",
                                     "work_date": "2026-11-02", "hours": "9", "notes": ""})
    assert r.status_code == 400
    assert client.post("/time/1/delete", data={"csrf_token": t}).status_code == 400
    assert _entries(app)[0]["duration_seconds"] == 7200


def test_running_timer_cannot_be_edited(client, app, clock):
    do_setup(client, app, clock)
    _seed(client, app)
    _start(client)
    t = csrf(client, "/time/")
    r = client.post("/time/1", data={"csrf_token": t, "client_id": "1", "product_id": "1",
                                     "work_date": "2026-11-02", "hours": "9", "notes": ""})
    assert r.status_code == 400


def test_total_hours_and_client_filter(client, app, clock):
    do_setup(client, app, clock)
    _seed(client, app)
    for hrs in ("2.5", "1.25"):
        t = csrf(client, "/time/new")
        client.post("/time/new", data={"csrf_token": t, "client_id": "1", "product_id": "1",
                                       "work_date": "2026-11-05", "hours": hrs, "notes": ""})
    page = client.get("/time/?from=2026-11-01&to=2026-11-30&client=1").get_data(as_text=True)
    assert "Total: 3.75 hours" in page
