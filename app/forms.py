"""Input validation. Every value from a form passes through one of these
before it touches the database. Bad input raises FormError with a message
that is safe to show on the page."""
import re
import unicodedata
from decimal import Decimal, InvalidOperation

_EMAIL = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}$")
# Commas only as thousands separators (1,250.00). "77,18" is rejected, not read as 7718.
_MONEY = re.compile(r"^\$?\s*(\d{1,3}(?:,\d{3})+|\d{1,7})(\.\d{1,2})?$")
_BLOCKED_CATEGORIES = {"Cc", "Cf", "Co", "Cs", "Zl", "Zp"}   # control, invisible, direction-override
MAX_RATE_CENTS = 10_000_000   # $100,000.00 — anything above is a typo


class FormError(ValueError):
    def __init__(self, field: str, message: str):
        super().__init__(message)
        self.field = field
        self.message = message


def text(form, field: str, label: str, max_len: int, required: bool = False, multiline: bool = False) -> str:
    value = unicodedata.normalize("NFC", (form.get(field) or "").replace("\r\n", "\n")).strip()
    allowed = "\n\t" if multiline else ""
    if any(unicodedata.category(ch) in _BLOCKED_CATEGORIES and ch not in allowed for ch in value):
        raise FormError(field, f"{label} contains characters that aren't allowed.")
    if required and not value:
        raise FormError(field, f"{label} is required.")
    if len(value) > max_len:
        raise FormError(field, f"{label} must be {max_len} characters or fewer.")
    return value


def email(form, field: str, label: str, required: bool = False) -> str:
    value = text(form, field, label, 254, required=required)
    if value and not _EMAIL.match(value):
        raise FormError(field, f"{label} doesn't look like a valid email address.")
    return value


def integer(form, field: str, label: str, lo: int, hi: int) -> int:
    raw = (form.get(field) or "").strip()
    if not raw.isascii() or not raw.isdigit():
        raise FormError(field, f"{label} must be a whole number.")
    value = int(raw)
    if not lo <= value <= hi:
        raise FormError(field, f"{label} must be between {lo} and {hi}.")
    return value


def money(form, field: str, label: str, required: bool = True) -> int | None:
    """'77.18', '$77.18', '1,250' -> cents. Returns None if empty and not required."""
    raw = (form.get(field) or "").strip()
    if not raw:
        if required:
            raise FormError(field, f"{label} is required.")
        return None
    m = _MONEY.match(raw)
    if not m or not raw.isascii():
        raise FormError(field, f"{label} must be an amount like 77.18.")
    try:
        cents = int(Decimal(m.group(1).replace(",", "") + (m.group(2) or "")) * 100)
    except InvalidOperation:
        raise FormError(field, f"{label} must be an amount like 77.18.")
    if cents > MAX_RATE_CENTS:
        raise FormError(field, f"{label} is too large.")
    return cents


def choice(form, field: str, label: str, options: tuple) -> str:
    value = (form.get(field) or "").strip()
    if value not in options:
        raise FormError(field, f"Choose a valid {label.lower()}.")
    return value


def format_money(cents: int | None) -> str:
    if cents is None:
        return "—"
    return f"${cents // 100:,}.{cents % 100:02d}"


def cents_to_input(cents: int | None) -> str:
    return "" if cents is None else f"{cents // 100}.{cents % 100:02d}"
