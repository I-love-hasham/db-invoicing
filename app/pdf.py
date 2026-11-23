"""Invoice PDF, "Forest + Gold" design (spec): forest-green header bar and table
header, gold accents and Total Due box. Drawn directly on a canvas — no markup
is parsed, so text from the database can't inject anything into the PDF."""
import hashlib
import io
import os
import re
import tempfile

from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import simpleSplit
from reportlab.pdfgen import canvas

from .forms import format_money

FOREST = (0x1E / 255, 0x3D / 255, 0x2F / 255)
GOLD = (0xB8 / 255, 0x89 / 255, 0x2E / 255)
INK = (0.12, 0.14, 0.13)
MUTED = (0.37, 0.42, 0.39)
LINE = (0.85, 0.87, 0.86)
PAGE_W, PAGE_H = letter
MARGIN = 48


def _safe(text: str) -> str:
    """Built-in PDF fonts cover Windows-1252 only; anything else becomes '?'."""
    return (text or "").encode("cp1252", "replace").decode("cp1252")


def _lines(text: str, font: str, size: float, width: float) -> list[str]:
    out = []
    for para in _safe(text).split("\n"):
        out.extend(simpleSplit(para, font, size, width) or [""])
    return out


def render(vm: dict) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter, invariant=1)   # invariant: same input -> same bytes
    biz, client = vm["business"], vm["client"]
    c.setTitle(_safe(f"Invoice {vm['number']} - {biz['name']}"))
    c.setAuthor(_safe(biz["name"]))

    # header bar
    bar_h = 92
    c.setFillColorRGB(*FOREST)
    c.rect(0, PAGE_H - bar_h, PAGE_W, bar_h, stroke=0, fill=1)
    c.setFillColorRGB(*GOLD)
    c.rect(0, PAGE_H - bar_h - 4, PAGE_W, 4, stroke=0, fill=1)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(MARGIN, PAGE_H - 44, _safe(biz["name"]))
    c.setFont("Helvetica", 9)
    contact = "  ·  ".join(x for x in [biz["address"].replace("\n", ", "), biz["phone"], biz["email"]] if x)
    c.drawString(MARGIN, PAGE_H - 62, _safe(contact)[:130])
    c.setFont("Helvetica-Bold", 22)
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 44, f"INVOICE #{vm['number']}")
    if vm["status"] in ("paid", "void"):     # an invoice sent to a client doesn't say "unpaid"
        c.setFillColorRGB(*GOLD)
        c.setFont("Helvetica-Bold", 10)
        c.drawRightString(PAGE_W - MARGIN, PAGE_H - 62, vm["shown_status"].upper())

    # billed to (left) / dates (right)
    y = PAGE_H - bar_h - 34
    c.setFillColorRGB(*GOLD)
    c.setFont("Helvetica-Bold", 9)
    c.drawString(MARGIN, y, "BILLED TO")
    c.setFillColorRGB(*INK)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(MARGIN, y - 16, _safe(client["name"])[:60])
    c.setFont("Helvetica", 10)
    yy = y - 31
    for ln in _lines(client["address"], "Helvetica", 10, 250)[:5] + ([_safe(client["email"])] if client["email"] else []):
        c.drawString(MARGIN, yy, ln)
        yy -= 13

    right_x = PAGE_W - MARGIN
    rows = [("Invoice date", vm["invoice_date"]), ("Due date", vm["due_date"]),
            ("Terms", vm["terms"]), ("Service period", vm["period"])]
    ry = y
    for label, value in rows:
        c.setFillColorRGB(*MUTED)
        c.setFont("Helvetica", 9)
        c.drawRightString(right_x - 110, ry, label)
        c.setFillColorRGB(*INK)
        c.setFont("Helvetica-Bold", 10)
        c.drawRightString(right_x, ry, _safe(value))
        ry -= 16

    # line items
    y = min(yy, ry) - 24
    cols = [MARGIN, PAGE_W - MARGIN - 230, PAGE_W - MARGIN - 150, PAGE_W - MARGIN]
    c.setFillColorRGB(*FOREST)
    c.rect(MARGIN, y - 6, PAGE_W - 2 * MARGIN, 22, stroke=0, fill=1)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 9.5)
    c.drawString(cols[0] + 8, y + 1, "DESCRIPTION")
    c.drawRightString(cols[1] + 40, y + 1, "HOURS")
    c.drawRightString(cols[2] + 70, y + 1, "RATE")
    c.drawRightString(cols[3] - 8, y + 1, "AMOUNT")
    y -= 26
    c.setFont("Helvetica", 10)
    for line in vm["lines"]:
        desc = _lines(line["description"], "Helvetica", 10, cols[1] - cols[0] - 40)
        c.setFillColorRGB(*INK)
        for i, d in enumerate(desc[:3]):
            c.drawString(cols[0] + 8, y - i * 12, d)
        c.drawRightString(cols[1] + 40, y, line["hours"])
        c.drawRightString(cols[2] + 70, y, format_money(line["rate_cents"]))
        c.drawRightString(cols[3] - 8, y, format_money(line["amount_cents"]))
        y -= 12 * max(1, min(3, len(desc))) + 8
        c.setStrokeColorRGB(*LINE)
        c.line(MARGIN, y + 4, PAGE_W - MARGIN, y + 4)
        y -= 6

    # subtotal + total due box
    y -= 6
    c.setFillColorRGB(*MUTED)
    c.setFont("Helvetica", 10)
    c.drawRightString(cols[2] + 70, y, "Subtotal")
    c.setFillColorRGB(*INK)
    c.drawRightString(cols[3] - 8, y, format_money(vm["subtotal_cents"]))
    y -= 40
    box_w, box_h = 230, 40
    c.setFillColorRGB(*GOLD)
    c.roundRect(PAGE_W - MARGIN - box_w, y - 8, box_w, box_h, 6, stroke=0, fill=1)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(PAGE_W - MARGIN - box_w + 14, y + 7, "TOTAL DUE")
    c.setFont("Helvetica-Bold", 16)
    c.drawRightString(PAGE_W - MARGIN - 14, y + 6, format_money(vm["total_cents"]))

    # notes
    y -= 40
    if vm["notes"]:
        c.setFillColorRGB(*GOLD)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(MARGIN, y, "NOTES")
        c.setFillColorRGB(*INK)
        c.setFont("Helvetica", 10)
        for ln in _lines(vm["notes"], "Helvetica", 10, PAGE_W - 2 * MARGIN)[:12]:
            y -= 13
            c.drawString(MARGIN, y, ln)

    # void stamp
    if vm["status"] == "void":
        c.saveState()
        c.setFillColorRGB(0.64, 0.09, 0.10, 0.25)
        c.setFont("Helvetica-Bold", 110)
        c.translate(PAGE_W / 2, PAGE_H / 2)
        c.rotate(30)
        c.drawCentredString(0, 0, "VOID")
        c.restoreState()

    # footer
    c.setStrokeColorRGB(*GOLD)
    c.line(MARGIN, 52, PAGE_W - MARGIN, 52)
    c.setFillColorRGB(*MUTED)
    c.setFont("Helvetica", 9)
    c.drawCentredString(PAGE_W / 2, 38, _safe(biz.get("footer") or "")[:140])

    c.showPage()
    c.save()
    return buf.getvalue()


def safe_folder_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9 ._-]", "_", name).strip(" ._") or "client"
    return cleaned[:60]


def _target(data_dir: str, client_name: str, year: str, number: int) -> tuple[str, str, str]:
    rel = os.path.join("Invoices", safe_folder_name(client_name), year, f"Invoice-{number}.pdf")
    base = os.path.realpath(data_dir)
    full = os.path.realpath(os.path.join(base, rel))
    if not full.startswith(os.path.join(base, "Invoices") + os.sep):
        raise ValueError("invoice path escapes the invoices folder")
    return rel, full, base


def stage(data_dir: str, client_name: str, year: str, number: int, pdf_bytes: bytes) -> dict:
    """Write the PDF to a unique temp file next to its final place. Nothing is replaced yet."""
    rel, full, _ = _target(data_dir, client_name, year, number)
    os.makedirs(os.path.dirname(full), mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(full), prefix=".tmp-", suffix=".pdf")   # unique, 0600
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(pdf_bytes)
            fh.flush()
            os.fsync(fh.fileno())
    except BaseException:
        discard({"tmp": tmp})
        raise
    return {"rel": rel, "full": full, "tmp": tmp, "sha256": hashlib.sha256(pdf_bytes).hexdigest()}


def publish(staged: dict) -> None:
    os.replace(staged["tmp"], staged["full"])   # atomic: never a half-written PDF


def discard(staged: dict) -> None:
    if os.path.exists(staged["tmp"]):
        os.remove(staged["tmp"])


def save(data_dir: str, client_name: str, year: str, number: int, pdf_bytes: bytes) -> tuple[str, str]:
    staged = stage(data_dir, client_name, year, number, pdf_bytes)
    publish(staged)
    return staged["rel"], staged["sha256"]


def remove(data_dir: str, rel: str) -> None:
    """Delete an old invoice PDF. Only ever touches .pdf files inside DATA_DIR/Invoices."""
    base = os.path.realpath(data_dir)
    full = os.path.realpath(os.path.join(base, rel))
    if (full.startswith(os.path.join(base, "Invoices") + os.sep) and full.endswith(".pdf")
            and os.path.isfile(full)):
        os.remove(full)
