"""Single-writer crash journal for deterministic cross-store mutations."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .approvals.store import PendingApproval
from .contracts import (
    Decision,
    EvidenceRecord,
    ResultStatus,
    new_id,
    sha256_of,
    utc_now,
)
from .money import money, money_text
from .operator_identity import AuthorizationReconciliationSubject
from .persistence import atomic_write_json, exclusive_file_lock, read_json

JOURNAL_SCHEMA = "defiant.operation_journal"
JOURNAL_VERSION = "0.3.0"
_SUPPORTED_JOURNAL_VERSIONS = {"0.1.0", "0.2.0", JOURNAL_VERSION}
OPERATION_KINDS = {
    "approval_create",
    "approval_reject",
    "approval_expire",
    "authorization_reconcile",
    "execution_complete",
}
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
class ExecutionCompletionSubject:
    """Exact sealed authorization whose tool result is already known."""

    authority_record_id: str
    authority_record_hash: str
    action_id: str
    request_id: str
    authorization_hash: str
    decision: str

    def __post_init__(self) -> None:
        for field in (
            "authority_record_id",
            "authority_record_hash",
            "action_id",
            "request_id",
            "authorization_hash",
            "decision",
        ):
            value = getattr(self, field)
            if not isinstance(value, str) or not value.strip():
                raise OperationJournalError(f"completion authority {field} is invalid")
        for field in ("authority_record_hash", "authorization_hash"):
            if not _is_sha256(getattr(self, field)):
                raise OperationJournalError(f"completion authority {field} is invalid")
        if self.decision not in {
            Decision.ALLOW.value,
            Decision.APPROVAL_REQUIRED.value,
        }:
            raise OperationJournalError("completion authority decision is invalid")

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> "ExecutionCompletionSubject":
        if not isinstance(record, dict):
            raise OperationJournalError("completion authorization must be an object")
        if record.get("result_status") != ResultStatus.SKIPPED.value:
            raise OperationJournalError(
                "completion evidence is not an execution authorization"
            )
        return cls(
            authority_record_id=record.get("record_id"),
            authority_record_hash=record.get("record_hash"),
            action_id=record.get("action_id"),
            request_id=record.get("request_id"),
            authorization_hash=record.get("authorization_hash"),
            decision=record.get("decision"),
        )


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
        if raw.get("schema_version") not in _SUPPORTED_JOURNAL_VERSIONS:
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
        "authorization_reconcile": {
            "authority",
            "expected_usd",
            "outcome",
            "reconciled_by",
            "note",
            "attestation",
            "evidence",
        },
        "execution_complete": {
            "authority",
            "approval_id",
            "reserved_usd",
            "actual_usd",
            "budget_disposition",
            "evidence",
        },
    }[kind]
    if set(payload) != expected_fields:
        raise OperationJournalError("journal payload fields do not match operation")
    try:
        amount_field = (
            "expected_usd" if kind == "authorization_reconcile" else "reserved_usd"
        )
        reserved = money(payload[amount_field], field_name="journal reservation")
        evidence = EvidenceRecord(**payload["evidence"])
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise OperationJournalError(f"journal payload is invalid: {exc}") from exc
    if evidence.record_hash or evidence.previous_record_hash:
        raise OperationJournalError("journal evidence must be unsealed")
    if kind == "execution_complete":
        _validate_execution_completion(payload, evidence, reserved)
        return
    expected_status = (
        {
            "succeeded": ResultStatus.SUCCEEDED,
            "failed": ResultStatus.FAILED,
            "not_executed": ResultStatus.NOT_EXECUTED,
        }.get(payload.get("outcome"))
        if kind == "authorization_reconcile"
        else {
            "approval_create": ResultStatus.PENDING_APPROVAL,
            "approval_reject": ResultStatus.REJECTED,
            "approval_expire": ResultStatus.EXPIRED,
        }[kind]
    )
    if evidence.result_status is not expected_status:
        raise OperationJournalError("journal evidence status does not match operation")
    if kind == "authorization_reconcile":
        try:
            authority = AuthorizationReconciliationSubject(**payload["authority"])
        except (TypeError, ValueError, RuntimeError) as exc:
            raise OperationJournalError(
                f"journal authorization authority is invalid: {exc}"
            ) from exc
        if (
            authority.action_id != evidence.action_id
            or authority.request_id != evidence.request_id
            or authority.authorization_hash != evidence.authorization_hash
        ):
            raise OperationJournalError(
                "journal authorization does not match terminal evidence"
            )
        for field in ("reconciled_by", "note"):
            if not isinstance(payload[field], str) or not payload[field].strip():
                raise OperationJournalError(f"journal {field} must be non-empty")
        if evidence.reconciliation_outcome != payload["outcome"]:
            raise OperationJournalError(
                "journal evidence reconciliation outcome does not match"
            )
        if (
            evidence.reconciled_by != payload["reconciled_by"].strip()
            or evidence.reconciliation_note != payload["note"].strip()
        ):
            raise OperationJournalError(
                "journal evidence operator input does not match"
            )
        if payload["attestation"] is not None and not isinstance(
            payload["attestation"], dict
        ):
            raise OperationJournalError("journal authorization attestation is invalid")
        return
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


def _validate_execution_completion(
    payload: dict[str, Any],
    evidence: EvidenceRecord,
    reserved: Any,
) -> None:
    try:
        authority = ExecutionCompletionSubject(**payload["authority"])
        actual = money(payload["actual_usd"], field_name="journal actual cost")
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise OperationJournalError(
            f"journal execution completion is invalid: {exc}"
        ) from exc
    approval_id = payload["approval_id"]
    if not isinstance(approval_id, str):
        raise OperationJournalError("journal completion approval_id is invalid")
    if approval_id and not approval_id.startswith("apr_"):
        raise OperationJournalError("journal completion approval_id is invalid")
    if approval_id and authority.decision != Decision.APPROVAL_REQUIRED.value:
        raise OperationJournalError(
            "approval completion is not bound to approval-required authority"
        )
    if not approval_id and authority.decision != Decision.ALLOW.value:
        raise OperationJournalError(
            "approval-free completion is not bound to allowed authority"
        )
    if evidence.result_status not in {ResultStatus.SUCCEEDED, ResultStatus.FAILED}:
        raise OperationJournalError("journal completion evidence is not a tool result")
    if (
        authority.action_id != evidence.action_id
        or authority.request_id != evidence.request_id
        or authority.authorization_hash != evidence.authorization_hash
        or authority.decision != evidence.decision.value
    ):
        raise OperationJournalError(
            "journal completion authority does not match terminal evidence"
        )
    disposition = payload["budget_disposition"]
    if disposition not in {"settle", "none"}:
        raise OperationJournalError("journal completion budget disposition is invalid")
    if disposition == "settle" and reserved == 0 and actual == 0:
        raise OperationJournalError(
            "zero-value completion must use no-budget disposition"
        )
    if disposition == "none" and (reserved != 0 or actual != 0):
        raise OperationJournalError(
            "no-budget completion cannot reserve or charge funds"
        )
    if money(evidence.cost_usd, field_name="completion evidence cost") != actual:
        raise OperationJournalError(
            "journal completion cost does not match terminal evidence"
        )
    if any(
        (
            evidence.reconciliation_outcome,
            evidence.reconciled_by,
            evidence.reconciled_at,
            evidence.reconciliation_note,
        )
    ):
        raise OperationJournalError(
            "known tool completion cannot contain operator reconciliation"
        )


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value[7:]
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)
