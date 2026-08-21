"""Single-writer crash journal for deterministic cross-store mutations."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .approvals.store import PendingApproval
from .contracts import EvidenceRecord, ResultStatus, new_id, sha256_of, utc_now
from .money import money, money_text
from .persistence import atomic_write_json, exclusive_file_lock, read_json

JOURNAL_SCHEMA = "defiant.operation_journal"
JOURNAL_VERSION = "0.1.0"
OPERATION_KINDS = {"approval_create", "approval_reject", "approval_expire"}
_STATE_FIELDS = {"schema_name", "schema_version", "active"}
_OPERATION_FIELDS = {
    "operation_id",
    "kind",
    "prepared_at",
    "payload",
    "payload_hash",
}
_MAX_BYTES = 4 * 1024 * 1024


class OperationJournalError(RuntimeError):
    """A prepared local mutation cannot be recovered safely."""


@dataclass(frozen=True)
class JournalOperation:
    operation_id: str
    kind: str
    prepared_at: str
    payload: dict[str, Any]
    payload_hash: str

    @classmethod
    def prepare(cls, kind: str, payload: dict[str, Any]) -> "JournalOperation":
        if kind not in OPERATION_KINDS:
            raise OperationJournalError(f"unsupported journal operation: {kind}")
        if not isinstance(payload, dict) or not payload:
            raise OperationJournalError("journal payload must be a non-empty object")
        prepared = deepcopy(payload)
        _validate_payload(kind, prepared)
        return cls(new_id("op"), kind, utc_now(), prepared, sha256_of(prepared))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "JournalOperation":
        if set(raw) != _OPERATION_FIELDS:
            raise OperationJournalError("journal operation fields do not match schema")
        operation_id = raw.get("operation_id")
        kind = raw.get("kind")
        prepared_at = raw.get("prepared_at")
        payload = raw.get("payload")
        payload_hash = raw.get("payload_hash")
        if not isinstance(operation_id, str) or not operation_id.startswith("op_"):
            raise OperationJournalError("journal operation id is invalid")
        if kind not in OPERATION_KINDS:
            raise OperationJournalError("journal operation kind is invalid")
        if not isinstance(prepared_at, str) or not prepared_at:
            raise OperationJournalError("journal prepared_at is invalid")
        if not isinstance(payload, dict) or not payload:
            raise OperationJournalError("journal payload is invalid")
        if payload_hash != sha256_of(payload):
            raise OperationJournalError("journal payload hash is invalid")
        _validate_payload(kind, payload)
        return cls(operation_id, kind, prepared_at, deepcopy(payload), payload_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "kind": self.kind,
            "prepared_at": self.prepared_at,
            "payload": self.payload,
            "payload_hash": self.payload_hash,
        }


class OperationJournal:
    """Persist at most one recoverable cross-store operation."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def active(self) -> JournalOperation | None:
        if not self.path.exists():
            return None
        try:
            if self.path.stat().st_size > _MAX_BYTES:
                raise OperationJournalError("operation journal is too large")
            raw = read_json(self.path)
        except OperationJournalError:
            raise
        except (OSError, RuntimeError) as exc:
            raise OperationJournalError(str(exc)) from exc
        if set(raw) != _STATE_FIELDS:
            raise OperationJournalError("operation journal fields do not match schema")
        if raw.get("schema_name") != JOURNAL_SCHEMA:
            raise OperationJournalError("unsupported operation journal schema")
        if raw.get("schema_version") != JOURNAL_VERSION:
            raise OperationJournalError("unsupported operation journal version")
        active = raw.get("active")
        if active is None:
            return None
        if not isinstance(active, dict):
            raise OperationJournalError("active journal operation must be an object")
        return JournalOperation.from_dict(active)

    def prepare(self, kind: str, payload: dict[str, Any]) -> JournalOperation:
        operation = JournalOperation.prepare(kind, payload)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with exclusive_file_lock(self.path):
            active = self.active()
            if active is not None:
                raise OperationJournalError(
                    f"operation {active.operation_id} ({active.kind}) requires recovery"
                )
            self._write(operation)
        return operation

    def complete(self, operation_id: str) -> None:
        with exclusive_file_lock(self.path):
            active = self.active()
            if active is None:
                raise OperationJournalError("no active journal operation to complete")
            if active.operation_id != operation_id:
                raise OperationJournalError("journal completion id does not match")
            self._write(None)

    def _write(self, active: JournalOperation | None) -> None:
        atomic_write_json(
            self.path,
            {
                "schema_name": JOURNAL_SCHEMA,
                "schema_version": JOURNAL_VERSION,
                "active": active.to_dict() if active is not None else None,
            },
        )


def _validate_payload(kind: str, payload: dict[str, Any]) -> None:
    expected_fields = {
        "approval_create": {"approval", "reserved_usd", "evidence"},
        "approval_reject": {
            "approval_id",
            "action_id",
            "request_id",
            "reserved_usd",
            "decided_by",
            "note",
            "attestation",
            "evidence",
        },
        "approval_expire": {
            "approval_id",
            "action_id",
            "request_id",
            "reserved_usd",
            "evidence",
        },
    }[kind]
    if set(payload) != expected_fields:
        raise OperationJournalError("journal payload fields do not match operation")
    try:
        reserved = money(payload["reserved_usd"], field_name="journal reservation")
        evidence = EvidenceRecord(**payload["evidence"])
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise OperationJournalError(f"journal payload is invalid: {exc}") from exc
    if evidence.record_hash or evidence.previous_record_hash:
        raise OperationJournalError("journal evidence must be unsealed")
    expected_status = {
        "approval_create": ResultStatus.PENDING_APPROVAL,
        "approval_reject": ResultStatus.REJECTED,
        "approval_expire": ResultStatus.EXPIRED,
    }[kind]
    if evidence.result_status is not expected_status:
        raise OperationJournalError("journal evidence status does not match operation")
    if kind == "approval_create":
        try:
            approval = PendingApproval(**payload["approval"])
        except (TypeError, ValueError, RuntimeError) as exc:
            raise OperationJournalError(f"journal approval is invalid: {exc}") from exc
        if (
            approval.status != "pending"
            or approval.action_id != evidence.action_id
            or approval.request_id != evidence.request_id
            or approval.reserved_usd != money_text(reserved)
        ):
            raise OperationJournalError(
                "journal approval does not match its reservation or evidence"
            )
        return
    for field in ("approval_id", "action_id", "request_id"):
        if not isinstance(payload[field], str) or not payload[field].strip():
            raise OperationJournalError(f"journal {field} must be non-empty")
    if (
        payload["action_id"] != evidence.action_id
        or payload["request_id"] != evidence.request_id
    ):
        raise OperationJournalError("journal identifiers do not match evidence")
    if kind == "approval_reject":
        if (
            not isinstance(payload["decided_by"], str)
            or not payload["decided_by"].strip()
        ):
            raise OperationJournalError("journal rejection identity is invalid")
        if not isinstance(payload["note"], str):
            raise OperationJournalError("journal rejection note is invalid")
        if payload["attestation"] is not None and not isinstance(
            payload["attestation"], dict
        ):
            raise OperationJournalError("journal rejection attestation is invalid")
