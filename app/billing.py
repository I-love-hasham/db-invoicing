"""The ONE rule for turning time into money. Screen, PDF and totals all use this,
so an invoice can never disagree with itself.

Rule: hours are rounded half-up to 2 decimals FIRST (what the invoice shows),
then billed as shown hours x rate, rounded half-up to the cent.
Example from the spec: 43.32 h x $77.18 = $3,343.44.
"""
from decimal import ROUND_HALF_UP, Decimal

TWO_PLACES = Decimal("0.01")


def billable_hours(seconds: int) -> Decimal:
    return (Decimal(seconds) / 3600).quantize(TWO_PLACES, rounding=ROUND_HALF_UP)


def line_amount_cents(seconds: int, rate_cents: int) -> int:
    hours = billable_hours(seconds)
    dollars = (hours * Decimal(rate_cents) / 100).quantize(TWO_PLACES, rounding=ROUND_HALF_UP)
    return int(dollars * 100)
