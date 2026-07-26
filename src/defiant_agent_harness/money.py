"""Exact and validated money handling.

All internal currency values are ``Decimal`` instances and all persisted
currency values are plain decimal strings. Binary floating-point is accepted at
API boundaries for convenience, but converted through ``str`` immediately.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import TypeAlias

MoneyLike: TypeAlias = Decimal | str | int | float
ZERO = Decimal("0")


def money(value: MoneyLike, *, field_name: str = "amount") -> Decimal:
    """Return a finite, non-negative ``Decimal`` or raise ``ValueError``."""
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a monetary number, not boolean")
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a valid monetary number") from exc
    if not result.is_finite():
        raise ValueError(f"{field_name} must be finite")
    if result < ZERO:
        raise ValueError(f"{field_name} must not be negative")
    return result


def money_text(value: MoneyLike) -> str:
    """Canonical non-exponent decimal text for persistence and hashing."""
    result = money(value)
    text = format(result, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"
