"""Read-only Command Core projection over local Defiant state.

Command Core is deliberately not another authority path. It never approves,
executes, or mutates harness state. It validates the evidence chain first and
then produces a small, JSON-safe operational snapshot for a future Command UI.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from ..approvals.store import APPROVAL_STATUSES, ApprovalError, PendingApproval
from ..budgets.ledger import BudgetError, BudgetLedger
from ..contracts import Decision, ResultStatus, utc_now
from ..evidence.store import ChainStatus, EvidenceError, EvidenceStore
from ..money import ZERO, money, money_text
from ..operator_identity import (
    DECISION_PURPOSE,
    RECONCILIATION_PURPOSE,
    OperatorIdentityStatus,
    OperatorTrustPolicy,
    unsigned_status,
    validate_external_trust_specs,
)
from ..persistence import PersistenceError, read_json
from ..state_integrity import StateIntegrityAuditor

SNAPSHOT_SCHEMA = "defiant.command.snapshot"
SNAPSHOT_VERSION = "0.4.0"


class CommandError(RuntimeError):
    """Command Core could not produce a trustworthy snapshot."""


class CommandCore:
    """Build a read-only operational snapshot from one harness work directory."""

    def __init__(
        self,
        workdir: str | Path,
        trusted_operator_keys: list[str] | None = None,
    ):
        self.workdir = Path(workdir)
        validate_external_trust_specs(trusted_operator_keys or [], self.workdir)
        self.operator_trust = (
            OperatorTrustPolicy.from_specs(trusted_operator_keys)
            if trusted_operator_keys
            else None
        )

    def snapshot(self, *, limit: int = 10, request_id: str = "") -> dict[str, Any]:
        if limit < 0:
            raise CommandError("limit must not be negative")

        try:
            audit = StateIntegrityAuditor(
                self.workdir, operator_trust=self.operator_trust
            ).audit()
            audit_payload = audit.to_dict()
            if audit.stores["evidence"]["state"] == "invalid":
                detail = _store_issue_detail(audit_payload, "evidence")
                integrity = ChainStatus(
                    False, audit.counts["evidence_records"], detail=detail
                )
                evidence, recent = None, []
            else:
                integrity, evidence, recent = self._evidence(limit, request_id)
            approvals = (
                _unavailable_approvals()
                if audit.stores["approvals"]["state"] == "invalid"
                else self._approvals()
            )
            budget = (
                _unavailable_budget()
                if audit.stores["budget"]["state"] == "invalid"
                else self._budget()
            )
            return {
                "schema_name": SNAPSHOT_SCHEMA,
                "schema_version": SNAPSHOT_VERSION,
                "generated_at": utc_now(),
                "authoritative": integrity.ok and audit.safe_to_execute,
                "state_integrity": audit_payload,
                "evidence_integrity": {
                    "ok": integrity.ok,
                    "count": integrity.count,
                    "broken_at": integrity.broken_at,
                    "detail": integrity.detail,
                },
                "evidence": evidence,
                "reconciliation_required": bool(
                    approvals["reconciliation_required_count"]
                ),
                "approvals": approvals,
                "budget": budget,
                "recent_activity": recent,
            }
        except (
            ApprovalError,
            BudgetError,
            EvidenceError,
            PersistenceError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            raise CommandError(f"cannot build Command snapshot: {exc}") from exc

    def _evidence(
        self,
        limit: int,
        request_id: str,
    ) -> tuple[ChainStatus, dict[str, Any] | None, list[dict[str, Any]]]:
        path = self.workdir / "evidence.jsonl"
        if not path.exists():
            status = ChainStatus(True, 0, detail="chain intact (no evidence store)")
            return status, _empty_evidence(request_id), []

        store = EvidenceStore(path)
        status = store.verify()
        if not status.ok:
            # A broken chain is itself operationally important, but aggregates
            # derived from altered records must not be presented as truth.
            return status, None, []

        records = store.records()
        if request_id:
            records = [r for r in records if r.get("request_id") == request_id]

        decisions = Counter({value.value: 0 for value in Decision})
        results = Counter({value.value: 0 for value in ResultStatus})
        request_ids: set[str] = set()
        action_ids: set[str] = set()
        ruleset_hashes: set[str] = set()
        total_cost = ZERO

        for index, record in enumerate(records):
            decision = _enum_value(record, "decision", Decision, index)
            result = _enum_value(record, "result_status", ResultStatus, index)
            req = _required_text(record, "request_id", index)
            action = _required_text(record, "action_id", index)
            _required_text(record, "record_id", index)
            _required_text(record, "timestamp", index)

            decisions[decision] += 1
            results[result] += 1
            request_ids.add(req)
            action_ids.add(action)
            total_cost += money(
                record.get("cost_usd", "0"),
                field_name=f"record {index} cost_usd",
            )
            ruleset_hash = record.get("ruleset_hash", "")
            if ruleset_hash:
                if not isinstance(ruleset_hash, str):
                    raise CommandError(f"record {index} ruleset_hash must be text")
                ruleset_hashes.add(ruleset_hash)

        recent_source = records[-limit:] if limit else []
        recent = [_recent_record(record) for record in reversed(recent_source)]
        return (
            status,
            {
                "filtered_request_id": request_id or None,
                "record_count": len(records),
                "request_count": len(request_ids),
                "action_count": len(action_ids),
                "decisions": dict(decisions),
                "results": dict(results),
                "total_cost_usd": money_text(total_cost),
                "ruleset_hashes": sorted(ruleset_hashes),
                "latest_event_at": records[-1]["timestamp"] if records else None,
            },
            recent,
        )

    def _approvals(self) -> dict[str, Any]:
        path = self.workdir / "approvals.json"
        status_counts = Counter({status: 0 for status in sorted(APPROVAL_STATUSES)})
        if not path.exists():
            return {
                "state": "not_initialized",
                "total_count": 0,
                "actionable_count": 0,
                "overdue_pending_count": 0,
                "reconciliation_required_count": 0,
                "operator_identity_policy": (
                    "signed_required"
                    if self.operator_trust is not None
                    else "not_configured"
                ),
                "identity_assurance": {},
                "statuses": dict(status_counts),
                "actionable": [],
            }

        raw_approvals = read_json(path)
        actionable: list[dict[str, Any]] = []
        identity_counts: Counter[str] = Counter()
        overdue = 0
        for approval_id, raw in raw_approvals.items():
            if not isinstance(raw, dict):
                raise CommandError(f"approval {approval_id} is not an object")
            approval = PendingApproval(**raw)
            if approval.approval_id != approval_id:
                raise CommandError(
                    f"approval key {approval_id} does not match its stored id"
                )
            status_counts[approval.status] += 1
            expired_pending = approval.status == "pending" and approval.is_expired()
            if expired_pending:
                overdue += 1
            if (
                approval.status in {"pending", "approved", "executing"}
                and not expired_pending
            ):
                identity = self._operator_identity(approval)
                identity_counts[identity.assurance] += 1
                reconciliation_identity = (
                    self._reconciliation_identity(approval)
                    if approval.reconciliation_outcome
                    else None
                )
                actionable.append(
                    {
                        "approval_id": approval.approval_id,
                        "request_id": approval.request_id,
                        "action_id": approval.action_id,
                        "tool_name": approval.tool_name,
                        "status": approval.status,
                        "created_at": approval.created_at,
                        "expires_at": approval.expires_at or None,
                        "reconciliation_required": approval.status == "executing",
                        "reconciliation_state": (
                            "in_progress"
                            if approval.reconciliation_outcome
                            else "required"
                            if approval.status == "executing"
                            else "none"
                        ),
                        "operator_identity": _identity_projection(identity),
                        "reconciliation_identity": (
                            _identity_projection(reconciliation_identity)
                            if reconciliation_identity is not None
                            else None
                        ),
                    }
                )

        actionable.sort(key=lambda item: (item["created_at"], item["approval_id"]))
        return {
            "state": "ready",
            "total_count": len(raw_approvals),
            "actionable_count": len(actionable),
            "overdue_pending_count": overdue,
            "reconciliation_required_count": status_counts["executing"],
            "operator_identity_policy": (
                "signed_required"
                if self.operator_trust is not None
                else "not_configured"
            ),
            "identity_assurance": dict(identity_counts),
            "statuses": dict(status_counts),
            "actionable": actionable,
        }

    def _operator_identity(self, approval: PendingApproval) -> OperatorIdentityStatus:
        if approval.status == "pending":
            return OperatorIdentityStatus(
                True,
                "not_applicable",
                "approval has not been decided",
            )
        if approval.decision_attestation is None:
            return unsigned_status(approval.decided_by or "")
        if self.operator_trust is None:
            return OperatorIdentityStatus(
                False,
                "unverified",
                "attestation present; no operator trust pins configured",
                operator=approval.decided_by or "",
                key_id=str(approval.decision_attestation.get("key_id", "")),
                signed_at=str(approval.decision_attestation.get("signed_at", "")),
            )
        return self.operator_trust.assess(
            approval.decision_attestation,
            approval,
            purpose=DECISION_PURPOSE,
            outcome="rejected" if approval.status == "rejected" else "approved",
            operator=approval.decided_by or "",
            note=approval.note,
        )

    def _reconciliation_identity(
        self, approval: PendingApproval
    ) -> OperatorIdentityStatus:
        if approval.reconciliation_attestation is None:
            return unsigned_status(approval.reconciled_by)
        if self.operator_trust is None:
            return OperatorIdentityStatus(
                False,
                "unverified",
                "attestation present; no operator trust pins configured",
                operator=approval.reconciled_by,
                key_id=str(approval.reconciliation_attestation.get("key_id", "")),
                signed_at=str(approval.reconciliation_attestation.get("signed_at", "")),
            )
        return self.operator_trust.assess(
            approval.reconciliation_attestation,
            approval,
            purpose=RECONCILIATION_PURPOSE,
            outcome=approval.reconciliation_outcome,
            operator=approval.reconciled_by,
            note=approval.reconciliation_note,
        )

    def _budget(self) -> dict[str, Any]:
        path = self.workdir / "budget.json"
        if not path.exists():
            return {
                "state": "not_initialized",
                "summary": {
                    "balance_usd": "0",
                    "reserved_usd": "0",
                    "available_usd": "0",
                    "total_spent_usd": "0",
                    "entry_count": 0,
                },
                "drift": {
                    "total_estimated_usd": "0",
                    "total_spent_usd": "0",
                    "drift_usd": "0",
                    "drift_pct": "0",
                },
            }

        ledger = BudgetLedger(path)
        return {
            "state": "ready",
            "summary": ledger.summary(),
            "drift": ledger.drift(),
        }


def _empty_evidence(request_id: str) -> dict[str, Any]:
    return {
        "filtered_request_id": request_id or None,
        "record_count": 0,
        "request_count": 0,
        "action_count": 0,
        "decisions": {value.value: 0 for value in Decision},
        "results": {value.value: 0 for value in ResultStatus},
        "total_cost_usd": "0",
        "ruleset_hashes": [],
        "latest_event_at": None,
    }


def _unavailable_approvals() -> dict[str, Any]:
    return {
        "state": "invalid",
        "total_count": 0,
        "actionable_count": 0,
        "overdue_pending_count": 0,
        "reconciliation_required_count": 0,
        "operator_identity_policy": "unavailable",
        "identity_assurance": {},
        "statuses": {status: 0 for status in sorted(APPROVAL_STATUSES)},
        "actionable": [],
    }


def _identity_projection(status: OperatorIdentityStatus) -> dict[str, Any]:
    """Expose assurance metadata only; signatures and operator notes stay sealed."""
    return {
        "ok": status.ok,
        "assurance": status.assurance,
        "detail": status.detail,
        "operator": status.operator or None,
        "key_id": status.key_id or None,
        "signed_at": status.signed_at or None,
    }


def _unavailable_budget() -> dict[str, Any]:
    return {
        "state": "invalid",
        "summary": {
            "balance_usd": "0",
            "reserved_usd": "0",
            "available_usd": "0",
            "total_spent_usd": "0",
            "entry_count": 0,
        },
        "drift": {
            "total_estimated_usd": "0",
            "total_spent_usd": "0",
            "drift_usd": "0",
            "drift_pct": "0",
        },
    }


def _store_issue_detail(audit: dict[str, Any], store: str) -> str:
    for issue in audit["issues"]:
        if issue["store"] == store and issue["severity"] == "critical":
            return issue["detail"]
    return f"{store} state is invalid"


def _required_text(record: dict[str, Any], field: str, index: int) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        raise CommandError(f"record {index} {field} must be non-empty text")
    return value


def _enum_value(record: dict[str, Any], field: str, enum_type, index: int) -> str:
    value = _required_text(record, field, index)
    try:
        return enum_type(value).value
    except ValueError as exc:
        raise CommandError(f"record {index} has invalid {field}: {value}") from exc


def _recent_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return only operational metadata; never expose target or payload material."""

    return {
        "record_id": record["record_id"],
        "timestamp": record["timestamp"],
        "request_id": record["request_id"],
        "action_id": record["action_id"],
        "agent_runner": record.get("agent_runner", ""),
        "workspace_id": record.get("workspace_id", ""),
        "tool_name": record.get("tool_name", ""),
        "decision": record["decision"],
        "result_status": record["result_status"],
        "cost_usd": money_text(record.get("cost_usd", "0")),
    }
