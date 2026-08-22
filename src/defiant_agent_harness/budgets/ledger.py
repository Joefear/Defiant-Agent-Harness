"""Exact, persisted, action-bound budget ledger."""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal, DecimalException, InvalidOperation
from pathlib import Path
from typing import Any

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
                            "schema_version": "0.2.0",
                            "balance_usd": money_text(starting),
                            "total_spent_usd": "0",
                            "total_estimated_usd": "0",
                            "reservations": {},
                            "reconciliations": {},
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
            amount = money(
                reservation.get("amount_usd", "0"), field_name="reservation amount"
            )
            if amount == ZERO:
                raise BudgetError("reservation amount must be positive")
            if not reservation.get("request_id"):
                raise BudgetError("reservation is missing request_id")
            if not reservation.get("created_at"):
                raise BudgetError("reservation is missing created_at")
        reconciliations = data.setdefault("reconciliations", {})
        if not isinstance(reconciliations, dict):
            raise BudgetError("reconciliations must be an object")
        for action_id, reconciliation in reconciliations.items():
            if not action_id or not isinstance(reconciliation, dict):
                raise BudgetError("invalid reconciliation entry")
            if reconciliation.get("outcome") not in {
                "succeeded",
                "failed",
                "not_executed",
            }:
                raise BudgetError("invalid reconciliation outcome")
            for field_name in (
                "request_id",
                "reconciled_by",
                "note",
                "disposition",
                "at",
            ):
                if (
                    not isinstance(reconciliation.get(field_name), str)
                    or not reconciliation[field_name].strip()
                ):
                    raise BudgetError(
                        f"reconciliation is missing non-empty {field_name}"
                    )
            money(
                reconciliation.get("expected_usd", "0"),
                field_name="reconciliation expected_usd",
            )
            money(
                reconciliation.get("charged_usd", "0"),
                field_name="reconciliation charged_usd",
            )
            money(
                reconciliation.get("released_usd", "0"),
                field_name="reconciliation released_usd",
            )
            _finite_decimal(
                reconciliation.get("remaining_usd", "0"),
                "reconciliation remaining_usd",
            )
            authority_type = reconciliation.get("authority_type")
            if authority_type is not None:
                if authority_type != "authorization":
                    raise BudgetError("invalid reconciliation authority_type")
                for field_name in (
                    "authority_record_id",
                    "authority_record_hash",
                ):
                    if (
                        not isinstance(reconciliation.get(field_name), str)
                        or not reconciliation[field_name].strip()
                    ):
                        raise BudgetError(
                            f"reconciliation is missing non-empty {field_name}"
                        )
                attestation = reconciliation.get("attestation")
                if attestation is not None and not isinstance(attestation, dict):
                    raise BudgetError("reconciliation attestation must be an object")
        if not isinstance(data.get("entries", []), list):
            raise BudgetError("entries must be a list")
        for index, entry in enumerate(data.get("entries", [])):
            if not isinstance(entry, dict):
                raise BudgetError(f"entry {index} must be an object")
            if not isinstance(entry.get("kind"), str) or not entry["kind"]:
                raise BudgetError(f"entry {index} is missing kind")
            money(entry.get("amount_usd", "0"), field_name=f"entry {index} amount")
            _finite_decimal(
                entry.get("balance_after_usd"),
                f"entry {index} balance_after_usd",
            )
            if not isinstance(entry.get("at"), str) or not entry["at"]:
                raise BudgetError(f"entry {index} is missing timestamp")
            completion_record_id = entry.get("completion_record_id")
            if completion_record_id is not None and (
                not isinstance(completion_record_id, str)
                or not completion_record_id.startswith("evd_")
            ):
                raise BudgetError(f"entry {index} has invalid completion_record_id")
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

    def exposure_for(self, request_id: str, action_id: str) -> Decimal:
        """Return the durable worst-case estimate for one authorized action."""
        data = self._validated_read()
        reservation = data.get("reservations", {}).get(action_id)
        if reservation is not None:
            if reservation.get("request_id") != request_id:
                raise BudgetError("reservation/request mismatch")
            return money(reservation.get("amount_usd"), field_name="reservation amount")
        for entry in reversed(data.get("entries", [])):
            if (
                entry.get("kind") == "reserve"
                and entry.get("request_id") == request_id
                and entry.get("action_id") == action_id
            ):
                return money(entry.get("amount_usd"), field_name="reserved estimate")
        return ZERO

    def prior_debit_for(self, request_id: str, action_id: str) -> Decimal | None:
        """Return a durable prior debit amount, if execution already settled."""
        data = self._validated_read()
        for entry in reversed(data.get("entries", [])):
            if (
                entry.get("kind") == "debit"
                and entry.get("request_id") == request_id
                and entry.get("action_id") == action_id
            ):
                return money(entry.get("amount_usd"), field_name="prior debit")
        return None

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

    def ensure_reservation(
        self,
        amount_usd: MoneyLike,
        request_id: str,
        action_id: str,
    ) -> None:
        """Create or recognize one exact reservation during journal recovery."""
        amount = money(amount_usd, field_name="reservation amount")
        if amount == ZERO or not request_id or not action_id:
            raise BudgetError("journal reservation requires positive bound values")
        with exclusive_file_lock(self.path):
            data = self._validated_read()
            existing = data["reservations"].get(action_id)
            if existing is not None:
                if (
                    existing.get("request_id") == request_id
                    and money(existing.get("amount_usd"), field_name="reservation")
                    == amount
                ):
                    return
                raise BudgetError(
                    f"action {action_id} reservation conflicts with journal"
                )
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

    def preview_settlement(
        self,
        expected_usd: MoneyLike,
        actual_usd: MoneyLike,
        request_id: str,
        action_id: str,
    ) -> Decimal:
        """Validate and return the available balance after an exact settlement."""
        expected = money(expected_usd, field_name="expected reservation")
        actual = money(actual_usd, field_name="actual settlement")
        if not request_id or not action_id:
            raise BudgetError("settlement requires request_id and action_id")
        data = self._validated_read()
        reservation = data["reservations"].get(action_id)
        prior = [
            entry
            for entry in data["entries"]
            if entry.get("request_id") == request_id
            and entry.get("action_id") == action_id
            and entry.get("kind") in {"debit", "release", "reconcile"}
        ]
        if prior:
            raise BudgetError("settlement conflicts with a prior budget disposition")
        if expected > ZERO:
            if reservation is None:
                raise BudgetError(f"action {action_id} has no reservation")
            if (
                reservation.get("request_id") != request_id
                or money(reservation.get("amount_usd"), field_name="reservation")
                != expected
            ):
                raise BudgetError("settlement reservation does not match authority")
        elif reservation is not None:
            raise BudgetError("zero-estimate settlement has an unexpected reservation")
        return self._available(data) + expected - actual

    def ensure_settlement(
        self,
        expected_usd: MoneyLike,
        actual_usd: MoneyLike,
        request_id: str,
        action_id: str,
        completion_record_id: str,
    ) -> Decimal:
        """Apply or recognize one exact journaled result settlement."""
        expected = money(expected_usd, field_name="expected reservation")
        actual = money(actual_usd, field_name="actual settlement")
        if not request_id or not action_id:
            raise BudgetError("settlement requires request_id and action_id")
        if not isinstance(
            completion_record_id, str
        ) or not completion_record_id.startswith("evd_"):
            raise BudgetError("settlement requires a terminal evidence record id")
        with exclusive_file_lock(self.path):
            data = self._validated_read()
            reservation = data["reservations"].get(action_id)
            prior = [
                entry
                for entry in data["entries"]
                if entry.get("request_id") == request_id
                and entry.get("action_id") == action_id
                and entry.get("kind") in {"debit", "release", "reconcile"}
            ]
            if reservation is None:
                matching = [
                    entry
                    for entry in prior
                    if entry.get("kind") == "debit"
                    and money(entry.get("amount_usd"), field_name="debit") == actual
                    and entry.get("note") == f"reserved ${money_text(expected)}"
                    and entry.get("completion_record_id") == completion_record_id
                ]
                if len(prior) == 1 and len(matching) == 1:
                    return self._available(data)
                if prior:
                    raise BudgetError(
                        "settlement conflicts with a prior budget disposition"
                    )
                if expected > ZERO:
                    raise BudgetError(
                        f"action {action_id} has no reservation or matching debit"
                    )
            else:
                if prior:
                    raise BudgetError(
                        "live reservation conflicts with a prior budget disposition"
                    )
                if (
                    reservation.get("request_id") != request_id
                    or money(reservation.get("amount_usd"), field_name="reservation")
                    != expected
                ):
                    raise BudgetError("settlement reservation does not match authority")
                del data["reservations"][action_id]

            balance = _finite_decimal(data["balance_usd"], "balance_usd") - actual
            spent = _finite_decimal(data["total_spent_usd"], "total_spent_usd")
            data["balance_usd"] = _decimal_text(balance)
            data["total_spent_usd"] = _decimal_text(spent + actual)
            remaining = self._available(data)
            entry = LedgerEntry(
                "debit",
                actual,
                remaining,
                request_id=request_id,
                action_id=action_id,
                note=f"reserved ${money_text(expected)}",
            ).to_dict()
            entry["completion_record_id"] = completion_record_id
            data["entries"].append(entry)
            self._write(data)
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

    def ensure_release(
        self,
        expected_usd: MoneyLike,
        request_id: str,
        action_id: str,
    ) -> Decimal:
        """Release or recognize one exact journaled reservation disposition."""
        expected = money(expected_usd, field_name="expected reservation")
        if expected == ZERO:
            return self.balance_usd
        with exclusive_file_lock(self.path):
            data = self._validated_read()
            reservation = data["reservations"].get(action_id)
            if reservation is None:
                matching = [
                    entry
                    for entry in data["entries"]
                    if entry.get("kind") == "release"
                    and entry.get("request_id") == request_id
                    and entry.get("action_id") == action_id
                    and money(entry.get("amount_usd"), field_name="release") == expected
                ]
                if matching:
                    return self._available(data)
                raise BudgetError(
                    f"action {action_id} has no reservation or matching release"
                )
            if (
                reservation.get("request_id") != request_id
                or money(reservation.get("amount_usd"), field_name="reservation")
                != expected
            ):
                raise BudgetError(
                    f"action {action_id} reservation conflicts with journal"
                )
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

    def reconcile_reservation(
        self,
        expected_usd: MoneyLike,
        request_id: str,
        action_id: str,
        outcome: str,
        reconciled_by: str,
        note: str,
        *,
        authority_record_id: str = "",
        authority_record_hash: str = "",
        attestation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Resolve an uncertain execution budget exactly once.

        Successful and failed attempts are charged at the full reservation when
        actual cost is unknowable. Only an explicit ``not_executed`` outcome
        releases a live reservation. A durable per-action marker makes retries
        after a process crash idempotent.
        """
        expected = money(expected_usd, field_name="reconciliation expected_usd")
        if not request_id or not action_id:
            raise BudgetError("reconciliation requires request_id and action_id")
        if outcome not in {"succeeded", "failed", "not_executed"}:
            raise BudgetError("invalid reconciliation outcome")
        if not isinstance(reconciled_by, str) or not reconciled_by.strip():
            raise BudgetError("reconciled_by must be non-empty")
        if not isinstance(note, str) or not note.strip():
            raise BudgetError("reconciliation note must be non-empty")
        reconciled_by = reconciled_by.strip()
        note = note.strip()

        with exclusive_file_lock(self.path):
            data = self._validated_read()
            existing = data["reconciliations"].get(action_id)
            supplied = {
                "request_id": request_id,
                "outcome": outcome,
                "reconciled_by": reconciled_by,
                "note": note,
                "expected_usd": money_text(expected),
            }
            if authority_record_id or authority_record_hash or attestation is not None:
                if not authority_record_id or not authority_record_hash:
                    raise BudgetError(
                        "authorization reconciliation requires sealed authority ids"
                    )
                supplied |= {
                    "authority_type": "authorization",
                    "authority_record_id": authority_record_id,
                    "authority_record_hash": authority_record_hash,
                    "attestation": attestation,
                }
            if existing is not None:
                if any(existing.get(key) != value for key, value in supplied.items()):
                    raise BudgetError(
                        "budget reconciliation already exists with different input"
                    )
                return dict(existing)

            reservation = data["reservations"].get(action_id)
            reserved = ZERO
            if reservation is not None:
                if reservation["request_id"] != request_id:
                    raise BudgetError("reservation/request mismatch")
                reserved = money(
                    reservation["amount_usd"], field_name="reservation amount"
                )
                if reserved != expected:
                    raise BudgetError(
                        "authority and ledger reservation amounts do not match"
                    )
                del data["reservations"][action_id]

            prior = _latest_budget_disposition(data["entries"], request_id, action_id)
            if reservation is not None and prior:
                raise BudgetError(
                    "live reservation conflicts with a prior terminal budget entry"
                )
            charged = ZERO
            released = ZERO
            if outcome == "not_executed":
                if reservation is not None:
                    released = reserved
                    estimated = _finite_decimal(
                        data["total_estimated_usd"], "total_estimated_usd"
                    )
                    data["total_estimated_usd"] = _decimal_text(estimated - reserved)
                    disposition = "reservation_released"
                elif prior == "debit":
                    # Never refund a prior debit merely because its exact runtime
                    # outcome is now uncertain. That would create budget headroom
                    # that may already have been spent.
                    disposition = "prior_debit_preserved"
                else:
                    disposition = "no_live_reservation"
            else:
                if reservation is not None:
                    charged = reserved
                    disposition = "reservation_charged"
                elif prior == "debit":
                    disposition = "prior_debit_preserved"
                elif expected > ZERO:
                    # A missing reservation with no debit marker is inconsistent.
                    # Charge the durable approval estimate instead of guessing $0.
                    charged = expected
                    disposition = "missing_reservation_charged"
                else:
                    disposition = "no_budget_exposure"

                if charged > ZERO:
                    balance = _finite_decimal(data["balance_usd"], "balance_usd")
                    spent = _finite_decimal(data["total_spent_usd"], "total_spent_usd")
                    data["balance_usd"] = _decimal_text(balance - charged)
                    data["total_spent_usd"] = _decimal_text(spent + charged)

            remaining = self._available(data)
            reconciliation = supplied | {
                "charged_usd": money_text(charged),
                "released_usd": money_text(released),
                "disposition": disposition,
                "remaining_usd": _decimal_text(remaining),
                "at": utc_now(),
            }
            data["reconciliations"][action_id] = reconciliation
            data["entries"].append(
                LedgerEntry(
                    "reconcile",
                    charged if charged > ZERO else released,
                    remaining,
                    request_id=request_id,
                    action_id=action_id,
                    note=(
                        f"{outcome} by {reconciled_by}; {disposition}; "
                        f"operator note: {note}"
                    ),
                ).to_dict()
            )
            self._write(data)
            return dict(reconciliation)

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


def _latest_budget_disposition(
    entries: list[dict], request_id: str, action_id: str
) -> str:
    for entry in reversed(entries):
        if entry.get("request_id") != request_id or entry.get("action_id") != action_id:
            continue
        if entry.get("kind") in {"debit", "reconcile_debit"}:
            return "debit"
        if entry.get("kind") in {"release", "reconcile_release"}:
            return "release"
    return ""


def _decimal_text(value: Decimal) -> str:
    if not value.is_finite():
        raise BudgetError("cannot persist non-finite decimal")
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"
