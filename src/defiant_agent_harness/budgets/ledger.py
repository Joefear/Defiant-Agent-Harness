"""Exact, persisted, action-bound budget ledger."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, DecimalException, InvalidOperation
from pathlib import Path

from ..contracts import utc_now
from ..money import ZERO, MoneyLike, money, money_text
from ..persistence import atomic_write_json, exclusive_file_lock, read_json


class BudgetError(RuntimeError):
    pass


@dataclass
class LedgerEntry:
    kind: str
    amount_usd: Decimal
    balance_after_usd: Decimal
    request_id: str = ""
    action_id: str = ""
    note: str = ""
    at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "amount_usd": money_text(self.amount_usd),
            "balance_after_usd": _decimal_text(self.balance_after_usd),
            "request_id": self.request_id,
            "action_id": self.action_id,
            "note": self.note,
            "at": self.at,
        }


@dataclass(frozen=True)
class BudgetCheck:
    ok: bool
    remaining_usd: Decimal
    estimate_usd: Decimal
    reason: str = ""


class BudgetLedger:
    def __init__(self, path: str | Path, starting_balance_usd: MoneyLike = ZERO):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        starting = money(starting_balance_usd, field_name="starting_balance_usd")
        if not self.path.exists():
            with exclusive_file_lock(self.path):
                if not self.path.exists():
                    self._write(
                        {
                            "schema_version": "0.1.0",
                            "balance_usd": money_text(starting),
                            "total_spent_usd": "0",
                            "total_estimated_usd": "0",
                            "reservations": {},
                            "entries": [],
                        }
                    )
        self._validated_read()

    # -- persistence --------------------------------------------------

    def _read(self) -> dict:
        return read_json(self.path)

    def _validated_read(self) -> dict:
        data = self._read()
        for key in ("balance_usd", "total_spent_usd", "total_estimated_usd"):
            _finite_decimal(data.get(key, "0"), key)
        reservations = data.setdefault("reservations", {})
        if not isinstance(reservations, dict):
            raise BudgetError("reservations must be an object")
        if (
            not reservations
            and _finite_decimal(data.get("reserved_usd", "0"), "reserved_usd") != ZERO
        ):
            raise BudgetError(
                "legacy ledger has unbound reservations; refusing unsafe migration"
            )
        for action_id, reservation in reservations.items():
            if not action_id or not isinstance(reservation, dict):
                raise BudgetError("invalid reservation entry")
            money(reservation.get("amount_usd", "0"), field_name="reservation amount")
            if not reservation.get("request_id"):
                raise BudgetError("reservation is missing request_id")
        if not isinstance(data.get("entries", []), list):
            raise BudgetError("entries must be a list")
        return data

    def _write(self, data: dict) -> None:
        atomic_write_json(self.path, data)

    def _append(self, data: dict, entry: LedgerEntry) -> None:
        data["entries"].append(entry.to_dict())
        self._write(data)

    # -- values -------------------------------------------------------

    @property
    def balance_usd(self) -> Decimal:
        return self._available(self._validated_read())

    def _available(self, data: dict) -> Decimal:
        balance = _finite_decimal(data["balance_usd"], "balance_usd")
        reserved = sum(
            (
                money(item["amount_usd"], field_name="reservation amount")
                for item in data.get("reservations", {}).values()
            ),
            ZERO,
        )
        return balance - reserved

    def reservation_for(self, action_id: str) -> Decimal:
        data = self._validated_read()
        reservation = data.get("reservations", {}).get(action_id)
        return (
            money(reservation["amount_usd"], field_name="reservation amount")
            if reservation
            else ZERO
        )

    # -- mutations ----------------------------------------------------

    def grant(self, amount_usd: MoneyLike, note: str = "") -> Decimal:
        amount = money(amount_usd, field_name="grant amount")
        with exclusive_file_lock(self.path):
            data = self._validated_read()
            balance = _finite_decimal(data["balance_usd"], "balance_usd") + amount
            data["balance_usd"] = _decimal_text(balance)
            available = self._available(data)
            self._append(
                data,
                LedgerEntry("grant", amount, available, note=note),
            )
            return available

    def preflight(
        self,
        worst_case_estimate_usd: MoneyLike,
        request_limit_usd: MoneyLike | None = None,
    ) -> BudgetCheck:
        estimate = money(worst_case_estimate_usd, field_name="worst_case_estimate_usd")
        remaining = self.balance_usd
        if request_limit_usd is not None:
            request_limit = money(request_limit_usd, field_name="request_limit_usd")
            if estimate > request_limit:
                return BudgetCheck(
                    False,
                    remaining,
                    estimate,
                    (
                        f"worst-case estimate ${estimate:.4f} exceeds this request's "
                        f"limit ${request_limit:.4f}"
                    ),
                )
        if estimate > remaining:
            return BudgetCheck(
                False,
                remaining,
                estimate,
                (
                    f"worst-case estimate ${estimate:.4f} exceeds remaining budget "
                    f"${remaining:.4f}"
                ),
            )
        return BudgetCheck(True, remaining, estimate)

    def reserve(
        self,
        amount_usd: MoneyLike,
        request_id: str,
        action_id: str,
    ) -> None:
        amount = money(amount_usd, field_name="reservation amount")
        if amount == ZERO:
            raise BudgetError("zero-value reservations are not recorded")
        if not request_id or not action_id:
            raise BudgetError("reservation requires request_id and action_id")
        with exclusive_file_lock(self.path):
            data = self._validated_read()
            if action_id in data["reservations"]:
                raise BudgetError(f"action {action_id} already has a reservation")
            if amount > self._available(data):
                raise BudgetError("cannot reserve more than the remaining balance")
            data["reservations"][action_id] = {
                "request_id": request_id,
                "amount_usd": money_text(amount),
                "created_at": utc_now(),
            }
            estimated = _finite_decimal(
                data["total_estimated_usd"], "total_estimated_usd"
            )
            data["total_estimated_usd"] = _decimal_text(estimated + amount)
            self._append(
                data,
                LedgerEntry(
                    "reserve",
                    amount,
                    self._available(data),
                    request_id=request_id,
                    action_id=action_id,
                ),
            )

    def settle(
        self,
        actual_usd: MoneyLike,
        request_id: str,
        action_id: str,
    ) -> Decimal:
        actual = money(actual_usd, field_name="actual_usd")
        with exclusive_file_lock(self.path):
            data = self._validated_read()
            reserved = self._pop_reservation(data, request_id, action_id)
            balance = _finite_decimal(data["balance_usd"], "balance_usd") - actual
            spent = _finite_decimal(data["total_spent_usd"], "total_spent_usd")
            data["balance_usd"] = _decimal_text(balance)
            data["total_spent_usd"] = _decimal_text(spent + actual)
            remaining = self._available(data)
            self._append(
                data,
                LedgerEntry(
                    "debit",
                    actual,
                    remaining,
                    request_id=request_id,
                    action_id=action_id,
                    note=f"reserved ${money_text(reserved)}",
                ),
            )
            return remaining

    def release(self, request_id: str, action_id: str) -> Decimal:
        with exclusive_file_lock(self.path):
            data = self._validated_read()
            reserved = self._pop_reservation(data, request_id, action_id)
            estimated = _finite_decimal(
                data["total_estimated_usd"], "total_estimated_usd"
            )
            data["total_estimated_usd"] = _decimal_text(estimated - reserved)
            remaining = self._available(data)
            self._append(
                data,
                LedgerEntry(
                    "release",
                    reserved,
                    remaining,
                    request_id=request_id,
                    action_id=action_id,
                    note="action did not execute",
                ),
            )
            return remaining

    def _pop_reservation(
        self,
        data: dict,
        request_id: str,
        action_id: str,
    ) -> Decimal:
        reservation = data["reservations"].get(action_id)
        if reservation is None:
            raise BudgetError(f"action {action_id} has no reservation")
        if reservation["request_id"] != request_id:
            raise BudgetError("reservation/request mismatch")
        amount = money(reservation["amount_usd"], field_name="reservation amount")
        del data["reservations"][action_id]
        return amount

    # -- reporting ----------------------------------------------------

    def drift(self) -> dict[str, str]:
        data = self._validated_read()
        estimated = _finite_decimal(data["total_estimated_usd"], "total_estimated_usd")
        actual = _finite_decimal(data["total_spent_usd"], "total_spent_usd")
        drift = actual - estimated
        percent = (drift / estimated * Decimal("100")) if estimated else ZERO
        return {
            "total_estimated_usd": _decimal_text(estimated),
            "total_spent_usd": _decimal_text(actual),
            "drift_usd": _decimal_text(drift),
            "drift_pct": _decimal_text(percent.quantize(Decimal("0.01"))),
        }

    def summary(self) -> dict[str, str | int]:
        data = self._validated_read()
        balance = _finite_decimal(data["balance_usd"], "balance_usd")
        available = self._available(data)
        reserved = balance - available
        return {
            "balance_usd": _decimal_text(balance),
            "reserved_usd": _decimal_text(reserved),
            "available_usd": _decimal_text(available),
            "total_spent_usd": _decimal_text(
                _finite_decimal(data["total_spent_usd"], "total_spent_usd")
            ),
            "entry_count": len(data["entries"]),
        }


def _finite_decimal(value: object, field_name: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError, DecimalException) as exc:
        raise BudgetError(f"{field_name} must be a decimal number") from exc
    if not result.is_finite():
        raise BudgetError(f"{field_name} must be finite")
    return result


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        raise BudgetError("cannot persist non-finite decimal")
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"
