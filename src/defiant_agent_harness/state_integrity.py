"""Read-only cross-store integrity auditing for local Defiant state."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .approvals.store import PendingApproval
from .budgets.ledger import BudgetLedger
from .contracts import EvidenceRecord, ResultStatus, sha256_of, utc_now
from .evidence.store import GENESIS
from .money import ZERO, money, money_text
from .operator_identity import (
    DECISION_PURPOSE,
    RECONCILIATION_PURPOSE,
    OperatorTrustPolicy,
)
from .persistence import read_json

AUDIT_SCHEMA = "defiant.state_integrity"
AUDIT_VERSION = "0.1.0"

_TERMINAL_RESULTS = {
    ResultStatus.SUCCEEDED.value,
    ResultStatus.FAILED.value,
    ResultStatus.BLOCKED.value,
    ResultStatus.REJECTED.value,
    ResultStatus.EXPIRED.value,
    ResultStatus.NOT_EXECUTED.value,
}
_ACTIVE_APPROVALS = {"pending", "approved", "executing"}
_TERMINAL_APPROVALS = {"rejected", "expired", "consumed"}


class StateIntegrityError(RuntimeError):
    """Unsafe local state prevents an authority-bearing operation."""


@dataclass(frozen=True)
class IntegrityIssue:
    code: str
    severity: str
    store: str
    detail: str
    action_id: str = ""
    approval_id: str = ""
    record_id: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity,
            "store": self.store,
            "detail": self.detail,
            "action_id": self.action_id,
            "approval_id": self.approval_id,
            "record_id": self.record_id,
        }


@dataclass
class StateIntegrityReport:
    issues: list[IntegrityIssue] = field(default_factory=list)
    stores: dict[str, dict[str, Any]] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    generated_at: str = field(default_factory=utc_now)

    @property
    def critical_count(self) -> int:
        return sum(issue.severity == "critical" for issue in self.issues)

    @property
    def warning_count(self) -> int:
        return sum(issue.severity == "warning" for issue in self.issues)

    @property
    def safe_to_execute(self) -> bool:
        return self.critical_count == 0

    @property
    def recovery_required(self) -> bool:
        return self.warning_count > 0

    @property
    def status(self) -> str:
        if not self.safe_to_execute:
            return "unsafe"
        if self.recovery_required:
            return "recovery_required"
        return "healthy"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": AUDIT_SCHEMA,
            "schema_version": AUDIT_VERSION,
            "generated_at": self.generated_at,
            "status": self.status,
            "ok": self.safe_to_execute,
            "safe_to_execute": self.safe_to_execute,
            "recovery_required": self.recovery_required,
            "issue_counts": {
                "critical": self.critical_count,
                "warning": self.warning_count,
            },
            "stores": self.stores,
            "counts": self.counts,
            "issues": [issue.to_dict() for issue in self.issues],
        }


class StateIntegrityAuditor:
    """Audit evidence, approvals, and budget state without mutating any store."""

    def __init__(
        self,
        workdir: str | Path,
        operator_trust: OperatorTrustPolicy | None = None,
    ):
        self.workdir = Path(workdir)
        self.operator_trust = operator_trust

    def require_safe(self) -> StateIntegrityReport:
        report = self.audit()
        if not report.safe_to_execute:
            first = next(
                issue for issue in report.issues if issue.severity == "critical"
            )
            raise StateIntegrityError(
                f"unsafe local state ({first.code}): {first.detail}; "
                "run 'dah --workdir <path> doctor' for the full read-only report"
            )
        return report

    def audit(self) -> StateIntegrityReport:
        report = StateIntegrityReport()
        self._audit_locks(report)

        evidence, evidence_trusted = self._load_evidence(report)
        approvals = self._load_approvals(report)
        budget = self._load_budget(report)

        report.counts = {
            "evidence_records": len(evidence),
            "approvals": len(approvals),
            "reservations": len(budget.get("reservations", {})),
            "reconciliations": len(budget.get("reconciliations", {})),
        }
        self._audit_cross_store(
            report,
            evidence if evidence_trusted else [],
            approvals,
            budget,
            evidence_trusted=evidence_trusted,
        )
        report.issues.sort(
            key=lambda issue: (
                0 if issue.severity == "critical" else 1,
                issue.code,
                issue.approval_id,
                issue.action_id,
                issue.record_id,
            )
        )
        return report

    def _audit_locks(self, report: StateIntegrityReport) -> None:
        for filename in ("evidence.jsonl", "approvals.json", "budget.json"):
            lock_path = self.workdir / f"{filename}.lock"
            if lock_path.exists():
                self._issue(
                    report,
                    "state_lock_present",
                    "critical",
                    filename,
                    f"{lock_path.name} exists; a writer may be active or crashed",
                )

    def _load_evidence(
        self, report: StateIntegrityReport
    ) -> tuple[list[dict[str, Any]], bool]:
        path = self.workdir / "evidence.jsonl"
        if not path.exists():
            report.stores["evidence"] = {
                "state": "not_initialized",
                "record_count": 0,
            }
            return [], True

        records: list[dict[str, Any]] = []
        previous = GENESIS
        seen_ids: set[str] = set()
        trusted = True
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for index, line in enumerate(handle):
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(
                            f"record {index} is not valid JSON: {exc.msg}"
                        ) from exc
                    if not isinstance(record, dict):
                        raise ValueError(f"record {index} is not a JSON object")
                    if record.get("previous_record_hash") != previous:
                        raise ValueError(
                            f"record {index} does not extend the preceding hash"
                        )
                    body = {
                        key: value
                        for key, value in record.items()
                        if key != "record_hash"
                    }
                    if record.get("record_hash") != sha256_of(body):
                        raise ValueError(
                            f"record {index} content does not match its hash"
                        )
                    EvidenceRecord(**record)
                    record_id = record.get("record_id")
                    if not isinstance(record_id, str) or not record_id:
                        raise ValueError(f"record {index} has no record_id")
                    if record_id in seen_ids:
                        raise ValueError(
                            f"record {index} duplicates record_id {record_id}"
                        )
                    seen_ids.add(record_id)
                    previous = record["record_hash"]
                    records.append(record)
        except (OSError, TypeError, ValueError) as exc:
            trusted = False
            self._issue(
                report,
                "evidence_invalid",
                "critical",
                "evidence",
                str(exc),
            )

        report.stores["evidence"] = {
            "state": "ready" if trusted else "invalid",
            "record_count": len(records),
        }
        return records, trusted

    def _load_approvals(
        self, report: StateIntegrityReport
    ) -> dict[str, PendingApproval]:
        path = self.workdir / "approvals.json"
        if not path.exists():
            report.stores["approvals"] = {
                "state": "not_initialized",
                "approval_count": 0,
            }
            return {}

        approvals: dict[str, PendingApproval] = {}
        valid = True
        try:
            raw_approvals = read_json(path)
            for key, raw in raw_approvals.items():
                if not isinstance(raw, dict):
                    raise ValueError(f"approval {key} is not an object")
                approval = PendingApproval(**raw)
                if approval.approval_id != key:
                    raise ValueError(
                        f"approval key {key} does not match {approval.approval_id}"
                    )
                approvals[key] = approval
        except (OSError, TypeError, ValueError, RuntimeError) as exc:
            valid = False
            approvals = {}
            self._issue(
                report,
                "approvals_invalid",
                "critical",
                "approvals",
                str(exc),
            )

        if valid:
            active_actions: Counter[str] = Counter(
                approval.action_id
                for approval in approvals.values()
                if approval.status in _ACTIVE_APPROVALS
            )
            for action_id, count in active_actions.items():
                if count > 1:
                    self._issue(
                        report,
                        "duplicate_active_approval",
                        "critical",
                        "approvals",
                        f"action {action_id} has {count} active approvals",
                        action_id=action_id,
                    )
            for approval in approvals.values():
                self._audit_approval_shape(report, approval)

        report.stores["approvals"] = {
            "state": "ready" if valid else "invalid",
            "approval_count": len(approvals),
            "operator_identity_policy": (
                "signed_required"
                if self.operator_trust is not None
                else "not_configured"
            ),
        }
        return approvals

    def _audit_approval_shape(
        self, report: StateIntegrityReport, approval: PendingApproval
    ) -> None:
        if approval.status in {"approved", "executing"} and not approval.decided_by:
            self._issue(
                report,
                "approved_identity_missing",
                "critical",
                "approvals",
                "approved or executing approval has no operator identity",
                action_id=approval.action_id,
                approval_id=approval.approval_id,
            )
        if self.operator_trust is not None and approval.status in {
            "approved",
            "executing",
            "consumed",
            "rejected",
        }:
            status = self.operator_trust.assess(
                approval.decision_attestation,
                approval,
                purpose=DECISION_PURPOSE,
                outcome=("rejected" if approval.status == "rejected" else "approved"),
                operator=approval.decided_by or "",
                note=approval.note,
            )
            if not status.ok:
                self._issue(
                    report,
                    "operator_decision_identity_invalid",
                    "critical",
                    "approvals",
                    status.detail,
                    action_id=approval.action_id,
                    approval_id=approval.approval_id,
                )
        if self.operator_trust is not None and approval.reconciliation_outcome:
            status = self.operator_trust.assess(
                approval.reconciliation_attestation,
                approval,
                purpose=RECONCILIATION_PURPOSE,
                outcome=approval.reconciliation_outcome,
                operator=approval.reconciled_by,
                note=approval.reconciliation_note,
            )
            if not status.ok:
                self._issue(
                    report,
                    "operator_reconciliation_identity_invalid",
                    "critical",
                    "approvals",
                    status.detail,
                    action_id=approval.action_id,
                    approval_id=approval.approval_id,
                )
        if approval.status == "consumed" and not approval.execution_record_id:
            self._issue(
                report,
                "consumed_evidence_missing",
                "critical",
                "approvals",
                "consumed approval has no execution evidence reference",
                action_id=approval.action_id,
                approval_id=approval.approval_id,
            )
        if approval.status == "executing":
            state = (
                "operator reconciliation is in progress"
                if approval.reconciliation_outcome
                else "execution outcome is uncertain"
            )
            self._issue(
                report,
                "execution_recovery_required",
                "warning",
                "approvals",
                state,
                action_id=approval.action_id,
                approval_id=approval.approval_id,
            )

        snapshots = (
            approval.action_snapshot,
            approval.request_snapshot,
            approval.decision_snapshot,
        )
        if approval.status in _ACTIVE_APPROVALS and not all(snapshots):
            self._issue(
                report,
                "approval_snapshot_missing",
                "warning",
                "approvals",
                "active approval cannot be resumed without every durable snapshot",
                action_id=approval.action_id,
                approval_id=approval.approval_id,
            )
        if approval.action_snapshot is not None:
            try:
                action = approval.held_action()
                if (
                    action.action_id != approval.action_id
                    or action.request_id != approval.request_id
                    or action.payload_hash != approval.payload_hash
                    or action.authorization_hash != approval.authorization_hash
                ):
                    raise ValueError("held action does not match approval binding")
            except (TypeError, ValueError, RuntimeError) as exc:
                self._issue(
                    report,
                    "approval_action_mismatch",
                    "critical",
                    "approvals",
                    str(exc),
                    action_id=approval.action_id,
                    approval_id=approval.approval_id,
                )
        if approval.request_snapshot is not None:
            try:
                request = approval.held_request()
                if request.request_id != approval.request_id:
                    raise ValueError("held request does not match approval binding")
            except (TypeError, ValueError, RuntimeError) as exc:
                self._issue(
                    report,
                    "approval_request_mismatch",
                    "critical",
                    "approvals",
                    str(exc),
                    action_id=approval.action_id,
                    approval_id=approval.approval_id,
                )

    def _load_budget(self, report: StateIntegrityReport) -> dict[str, Any]:
        path = self.workdir / "budget.json"
        if not path.exists():
            report.stores["budget"] = {
                "state": "not_initialized",
                "reservation_count": 0,
                "reconciliation_count": 0,
            }
            return {}

        valid = True
        data: dict[str, Any] = {}
        try:
            # The constructor validates the existing file but cannot initialize it
            # here because existence was checked above. No store method mutates.
            ledger = BudgetLedger(path)
            ledger.summary()
            ledger.drift()
            data = read_json(path)
            data.setdefault("reservations", {})
            data.setdefault("reconciliations", {})
            entries = data.setdefault("entries", [])
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    raise ValueError(f"budget entry {index} is not an object")
                if not isinstance(entry.get("kind"), str) or not entry["kind"]:
                    raise ValueError(f"budget entry {index} has no kind")
                money(entry.get("amount_usd", "0"), field_name="entry amount")
                if "balance_after_usd" not in entry:
                    raise ValueError(f"budget entry {index} has no balance_after_usd")
        except (OSError, TypeError, ValueError, RuntimeError) as exc:
            valid = False
            data = {}
            self._issue(
                report,
                "budget_invalid",
                "critical",
                "budget",
                str(exc),
            )

        report.stores["budget"] = {
            "state": "ready" if valid else "invalid",
            "reservation_count": len(data.get("reservations", {})),
            "reconciliation_count": len(data.get("reconciliations", {})),
        }
        return data

    def _audit_cross_store(
        self,
        report: StateIntegrityReport,
        evidence: list[dict[str, Any]],
        approvals: dict[str, PendingApproval],
        budget: dict[str, Any],
        *,
        evidence_trusted: bool,
    ) -> None:
        records_by_id = {record["record_id"]: record for record in evidence}
        records_by_action: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for record in evidence:
            records_by_action[record.get("action_id", "")].append(record)

        approvals_by_action: dict[str, list[PendingApproval]] = defaultdict(list)
        for approval in approvals.values():
            approvals_by_action[approval.action_id].append(approval)

        reservations = budget.get("reservations", {})
        reconciliations = budget.get("reconciliations", {})
        entries = budget.get("entries", [])

        for action_id, reservation in reservations.items():
            matching = [
                approval
                for approval in approvals_by_action.get(action_id, [])
                if approval.status in _ACTIVE_APPROVALS
            ]
            if matching:
                for approval in matching:
                    self._check_reservation_binding(report, approval, reservation)
                continue
            if evidence_trusted and self._has_open_authorization(
                records_by_action.get(action_id, []), reservation.get("request_id", "")
            ):
                self._issue(
                    report,
                    "unbound_execution_recovery_required",
                    "warning",
                    "budget",
                    "live reservation belongs to a sealed execution authorization",
                    action_id=action_id,
                )
                continue
            self._issue(
                report,
                "orphan_reservation",
                "critical",
                "budget",
                "live reservation has no active approval or sealed authorization",
                action_id=action_id,
            )

        for approval in approvals.values():
            reservation = reservations.get(approval.action_id)
            expected = money(approval.reserved_usd, field_name="approval reservation")
            if approval.status in {"pending", "approved"} and expected > ZERO:
                if reservation is None:
                    self._issue(
                        report,
                        "active_reservation_missing",
                        "critical",
                        "cross_store",
                        "funded pending or approved action has no live reservation",
                        action_id=approval.action_id,
                        approval_id=approval.approval_id,
                    )
            if approval.status == "executing" and expected > ZERO:
                if not self._executing_budget_accounted(
                    approval,
                    reservation,
                    reconciliations,
                    entries,
                    records_by_action.get(approval.action_id, []),
                ):
                    self._issue(
                        report,
                        "executing_budget_unaccounted",
                        "critical",
                        "cross_store",
                        "executing approval has no reservation or terminal budget state",
                        action_id=approval.action_id,
                        approval_id=approval.approval_id,
                    )
            if approval.status in _TERMINAL_APPROVALS and reservation is not None:
                self._issue(
                    report,
                    "terminal_approval_has_reservation",
                    "critical",
                    "cross_store",
                    "terminal approval still owns a live reservation",
                    action_id=approval.action_id,
                    approval_id=approval.approval_id,
                )
            if approval.status == "consumed" and evidence_trusted:
                self._check_consumed_evidence(report, approval, records_by_id)
            if (
                approval.reconciliation_outcome
                and approval.action_id not in reconciliations
            ):
                severity = "critical" if approval.status == "consumed" else "warning"
                self._issue(
                    report,
                    "reconciliation_budget_missing",
                    severity,
                    "cross_store",
                    "operator intent has no durable budget reconciliation marker",
                    action_id=approval.action_id,
                    approval_id=approval.approval_id,
                )

        for action_id, reconciliation in reconciliations.items():
            if action_id in reservations:
                self._issue(
                    report,
                    "reconciliation_reservation_conflict",
                    "critical",
                    "budget",
                    "reconciled action still has a live reservation",
                    action_id=action_id,
                )
            candidates = approvals_by_action.get(action_id, [])
            approval = next(
                (item for item in candidates if item.reconciliation_outcome), None
            )
            if approval is None:
                self._issue(
                    report,
                    "orphan_budget_reconciliation",
                    "critical",
                    "budget",
                    "budget reconciliation has no matching operator intent",
                    action_id=action_id,
                )
                continue
            expected = {
                "request_id": approval.request_id,
                "outcome": approval.reconciliation_outcome,
                "reconciled_by": approval.reconciled_by,
                "note": approval.reconciliation_note,
                "expected_usd": money_text(approval.reserved_usd),
            }
            if any(reconciliation.get(key) != value for key, value in expected.items()):
                self._issue(
                    report,
                    "reconciliation_binding_mismatch",
                    "critical",
                    "cross_store",
                    "budget reconciliation differs from immutable operator intent",
                    action_id=action_id,
                    approval_id=approval.approval_id,
                )

    def _check_reservation_binding(
        self,
        report: StateIntegrityReport,
        approval: PendingApproval,
        reservation: dict[str, Any],
    ) -> None:
        try:
            amount_matches = money_text(
                reservation.get("amount_usd", "0")
            ) == money_text(approval.reserved_usd)
        except (TypeError, ValueError):
            amount_matches = False
        if reservation.get("request_id") != approval.request_id or not amount_matches:
            self._issue(
                report,
                "reservation_binding_mismatch",
                "critical",
                "cross_store",
                "reservation request or amount differs from its approval",
                action_id=approval.action_id,
                approval_id=approval.approval_id,
            )

    @staticmethod
    def _has_open_authorization(records: list[dict[str, Any]], request_id: str) -> bool:
        authorized = [
            record
            for record in records
            if record.get("request_id") == request_id
            and record.get("result_status") == ResultStatus.SKIPPED.value
        ]
        if not authorized:
            return False
        for authorization in reversed(authorized):
            auth_hash = authorization.get("authorization_hash")
            terminal = any(
                record.get("authorization_hash") == auth_hash
                and record.get("result_status") in _TERMINAL_RESULTS
                for record in records
            )
            if not terminal:
                return True
        return False

    @staticmethod
    def _executing_budget_accounted(
        approval: PendingApproval,
        reservation: dict[str, Any] | None,
        reconciliations: dict[str, Any],
        entries: list[dict[str, Any]],
        records: list[dict[str, Any]],
    ) -> bool:
        if reservation is not None or approval.action_id in reconciliations:
            return True
        if any(
            entry.get("action_id") == approval.action_id
            and entry.get("request_id") == approval.request_id
            and entry.get("kind") in {"debit", "release", "reconcile"}
            for entry in entries
        ):
            return True
        return any(
            record.get("authorization_hash") == approval.authorization_hash
            and record.get("result_status") in _TERMINAL_RESULTS
            for record in records
        )

    def _check_consumed_evidence(
        self,
        report: StateIntegrityReport,
        approval: PendingApproval,
        records_by_id: dict[str, dict[str, Any]],
    ) -> None:
        if not approval.execution_record_id:
            return
        record = records_by_id.get(approval.execution_record_id)
        if record is None:
            self._issue(
                report,
                "consumed_evidence_not_found",
                "critical",
                "cross_store",
                "consumed approval references an absent evidence record",
                action_id=approval.action_id,
                approval_id=approval.approval_id,
                record_id=approval.execution_record_id,
            )
            return
        if (
            record.get("action_id") != approval.action_id
            or record.get("request_id") != approval.request_id
            or record.get("authorization_hash") != approval.authorization_hash
            or record.get("result_status") not in _TERMINAL_RESULTS
        ):
            self._issue(
                report,
                "consumed_evidence_mismatch",
                "critical",
                "cross_store",
                "consumed evidence does not match the approval authority binding",
                action_id=approval.action_id,
                approval_id=approval.approval_id,
                record_id=approval.execution_record_id,
            )

    @staticmethod
    def _issue(
        report: StateIntegrityReport,
        code: str,
        severity: str,
        store: str,
        detail: str,
        *,
        action_id: str = "",
        approval_id: str = "",
        record_id: str = "",
    ) -> None:
        report.issues.append(
            IntegrityIssue(
                code=code,
                severity=severity,
                store=store,
                detail=detail,
                action_id=action_id,
                approval_id=approval_id,
                record_id=record_id,
            )
        )
