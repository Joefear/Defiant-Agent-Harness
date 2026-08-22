"""Read-only cross-store integrity auditing for local Defiant state."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .approvals.store import PendingApproval
from .authority_profile import AuthorityProfileStore
from .budgets.ledger import BudgetLedger
from .contracts import EvidenceRecord, ResultStatus, sha256_of, utc_now
from .evidence.store import GENESIS
from .money import ZERO, money, money_text
from .operator_identity import (
    AuthorizationReconciliationSubject,
    DECISION_PURPOSE,
    RECONCILIATION_PURPOSE,
    OperatorTrustPolicy,
)
from .operation_journal import JournalOperation, OperationJournal
from .operator_trust_state import OperatorTrustStateStore
from .launch_envelope import LaunchEnvelopeError, LaunchEnvelopeStateStore
from .persistence import open_state_file, read_json
from .runtime_artifacts import RuntimeArtifactError, RuntimeArtifactStateStore
from .state_storage import (
    StateStorageError,
    StateStorageStateStore,
    inspect_state_storage,
    inspect_state_storage_files,
)

AUDIT_SCHEMA = "defiant.state_integrity"
AUDIT_VERSION = "0.9.0"

_STATE_FILENAMES = (
    "approvals.json",
    "authority.lock",
    "authority_profile.json",
    "budget.json",
    "evidence.jsonl",
    "hook_executions.json",
    "launch_envelope.json",
    "operation_journal.json",
    "operator_trust.json",
    "runtime_artifacts.json",
    "state_storage.json",
)

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
        authority_profile_hash: str | None = None,
    ):
        self.workdir = Path(workdir)
        self.operator_trust = operator_trust
        self.authority_profile_hash = authority_profile_hash

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
        storage_file_count = self._audit_state_storage(report)
        self._audit_locks(report)
        trust_generation = self._audit_operator_trust(report)
        profile_generation = self._audit_authority_profile(report)
        artifact_count = self._audit_runtime_artifacts(report)
        launch_variable_count = self._audit_launch_envelope(report)
        journal_operation = self._audit_operation_journal(report)

        evidence, evidence_trusted = self._load_evidence(report)
        approvals = self._load_approvals(report, journal_operation)
        self._audit_legacy_signed_migration(report, approvals)
        budget = self._load_budget(report)

        report.counts = {
            "evidence_records": len(evidence),
            "approvals": len(approvals),
            "reservations": len(budget.get("reservations", {})),
            "reconciliations": len(budget.get("reconciliations", {})),
            "operator_trust_generation": trust_generation,
            "authority_profile_generation": profile_generation,
            "runtime_artifacts": artifact_count,
            "launch_environment_variables": launch_variable_count,
            "state_storage_files": storage_file_count,
            "active_journal_operations": int(journal_operation is not None),
            "authorization_reconciliations_required": 0,
        }
        self._audit_cross_store(
            report,
            evidence if evidence_trusted else [],
            approvals,
            budget,
            evidence_trusted=evidence_trusted,
            journal_operation=journal_operation,
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

    def _audit_state_storage(self, report: StateIntegrityReport) -> int:
        try:
            assurance = inspect_state_storage(self.workdir)
            if assurance is None:
                report.stores["state_storage"] = {
                    "state": "not_initialized",
                    "verification": "not_applicable",
                    "profile_hash": None,
                    "root_hash": None,
                    "private_permissions": None,
                    "directory_sync": None,
                    "files_checked": 0,
                    "temporary_files": 0,
                    "last_verified_at": None,
                }
                return 0
            checked, temporary = inspect_state_storage_files(
                assurance,
                (
                    *_STATE_FILENAMES,
                    *(f"{name}.lock" for name in _STATE_FILENAMES),
                ),
            )
            if temporary:
                self._issue(
                    report,
                    "state_temporary_file_present",
                    "critical",
                    "state_storage",
                    "an orphan atomic-write temporary file is present",
                )
            state = StateStorageStateStore(assurance.root / "state_storage.json").get()
            if state is None:
                report.stores["state_storage"] = {
                    "state": "not_recorded",
                    "verification": "migration_required",
                    "profile_hash": None,
                    **assurance.authority_dict(),
                    "files_checked": checked,
                    "temporary_files": temporary,
                    "last_verified_at": None,
                }
                profile = AuthorityProfileStore(
                    assurance.root / "authority_profile.json"
                ).get()
                if profile is not None:
                    self._issue(
                        report,
                        "state_storage_observation_missing",
                        "warning",
                        "state_storage.json",
                        "state storage has not been recorded for the active authority profile",
                    )
                return checked
            verification = "verified"
            if state.authority_dict() != assurance.authority_dict():
                verification = "root_mismatch"
                self._issue(
                    report,
                    "state_storage_root_mismatch",
                    "critical",
                    "state_storage.json",
                    "state directory identity or security posture changed",
                )
            profile = AuthorityProfileStore(
                assurance.root / "authority_profile.json"
            ).get()
            if profile is not None and profile.profile_hash != state.profile_hash:
                verification = "profile_mismatch"
                self._issue(
                    report,
                    "state_storage_profile_mismatch",
                    "critical",
                    "state_storage.json",
                    "state storage assurance is not bound to the active authority profile",
                )
            report.stores["state_storage"] = state.projection(
                verification=verification,
                files_checked=checked,
                temporary_files=temporary,
            )
            return checked
        except (StateStorageError, RuntimeError) as exc:
            report.stores["state_storage"] = {
                "state": "invalid",
                "verification": "invalid",
                "detail": str(exc),
                "profile_hash": None,
                "root_hash": None,
                "private_permissions": None,
                "directory_sync": None,
                "files_checked": 0,
                "temporary_files": 0,
                "last_verified_at": None,
            }
            self._issue(
                report,
                "state_storage_invalid",
                "critical",
                "state_storage",
                str(exc),
            )
            return 0

    def _audit_locks(self, report: StateIntegrityReport) -> None:
        for filename in (
            "evidence.jsonl",
            "approvals.json",
            "budget.json",
            "operator_trust.json",
            "authority_profile.json",
            "operation_journal.json",
            "runtime_artifacts.json",
            "launch_envelope.json",
            "state_storage.json",
            "hook_executions.json",
        ):
            lock_path = self.workdir / f"{filename}.lock"
            if lock_path.exists():
                self._issue(
                    report,
                    "state_lock_present",
                    "critical",
                    filename,
                    f"{lock_path.name} exists; a writer may be active or crashed",
                )

    def _audit_runtime_artifacts(self, report: StateIntegrityReport) -> int:
        store = RuntimeArtifactStateStore(self.workdir / "runtime_artifacts.json")
        try:
            state = store.get()
            if state is None:
                report.stores["runtime_artifacts"] = {
                    "state": "not_recorded",
                    "verification": "not_applicable",
                    "profile_hash": None,
                    "bundle_hash": None,
                    "artifact_count": 0,
                    "executable_pinned": False,
                    "last_verified_at": None,
                }
                return 0
            verification = "not_evaluated"
            try:
                profile = AuthorityProfileStore(
                    self.workdir / "authority_profile.json"
                ).get()
            except RuntimeError:
                profile = None
            if profile is not None:
                if profile.profile_hash == state.profile_hash:
                    verification = "verified"
                else:
                    verification = "profile_mismatch"
                    self._issue(
                        report,
                        "runtime_artifact_profile_mismatch",
                        "critical",
                        "runtime_artifacts.json",
                        "runtime artifact assurance is not bound to the active authority profile",
                    )
            report.stores["runtime_artifacts"] = state.projection(
                verification=verification
            )
            return state.artifact_count
        except RuntimeArtifactError as exc:
            report.stores["runtime_artifacts"] = {
                "state": "invalid",
                "verification": "invalid",
                "detail": str(exc),
                "profile_hash": None,
                "bundle_hash": None,
                "artifact_count": 0,
                "executable_pinned": False,
                "last_verified_at": None,
            }
            self._issue(
                report,
                "runtime_artifact_state_invalid",
                "critical",
                "runtime_artifacts.json",
                str(exc),
            )
            return 0

    def _audit_launch_envelope(self, report: StateIntegrityReport) -> int:
        store = LaunchEnvelopeStateStore(self.workdir / "launch_envelope.json")
        try:
            state = store.get()
            if state is None:
                report.stores["launch_envelope"] = {
                    "state": "not_recorded",
                    "verification": "not_applicable",
                    "profile_hash": None,
                    "environment_hash": None,
                    "variable_count": 0,
                    "secret_count": 0,
                    "unsafe_count": 0,
                    "cwd_hash": None,
                    "last_verified_at": None,
                }
                return 0
            verification = "not_evaluated"
            try:
                profile = AuthorityProfileStore(
                    self.workdir / "authority_profile.json"
                ).get()
            except RuntimeError:
                profile = None
            if profile is not None:
                if profile.profile_hash == state.profile_hash:
                    verification = "verified"
                else:
                    verification = "profile_mismatch"
                    self._issue(
                        report,
                        "launch_envelope_profile_mismatch",
                        "critical",
                        "launch_envelope.json",
                        "launch envelope assurance is not bound to the active authority profile",
                    )
            report.stores["launch_envelope"] = state.projection(
                verification=verification
            )
            return state.variable_count
        except LaunchEnvelopeError as exc:
            report.stores["launch_envelope"] = {
                "state": "invalid",
                "verification": "invalid",
                "detail": str(exc),
                "profile_hash": None,
                "environment_hash": None,
                "variable_count": 0,
                "secret_count": 0,
                "unsafe_count": 0,
                "cwd_hash": None,
                "last_verified_at": None,
            }
            self._issue(
                report,
                "launch_envelope_state_invalid",
                "critical",
                "launch_envelope.json",
                str(exc),
            )
            return 0

    def _audit_authority_profile(self, report: StateIntegrityReport) -> int:
        store = AuthorityProfileStore(self.workdir / "authority_profile.json")
        try:
            state = store.get()
            if state is None:
                report.stores["authority_profile"] = {
                    "state": "not_enrolled",
                    "generation": 0,
                    "profile_hash": None,
                    "verification": "not_applicable",
                    "rotation_required": False,
                    "pending_profile_hash": None,
                    "pending_assurance": "not_applicable",
                    "signed_transition_count": 0,
                    "unsigned_transition_count": 0,
                }
                return 0
            verification = "not_evaluated"
            if self.operator_trust is not None:
                state.verify(self.operator_trust)
            elif any(
                item["attestation"] is not None
                for item in [*state.transitions]
                + ([state.pending_rotation] if state.pending_rotation else [])
            ):
                verification = "operator_trust_required"
            candidate = self.authority_profile_hash
            if candidate is not None:
                if state.profile_hash == candidate:
                    verification = "verified"
                elif (
                    state.pending_rotation is not None
                    and state.pending_rotation["to_profile_hash"] == candidate
                ):
                    verification = "activation_required"
                    self._issue(
                        report,
                        "authority_profile_activation_required",
                        "warning",
                        "authority_profile",
                        "configured profile has an authorized pending rotation that "
                        "must be activated by authority startup",
                    )
                else:
                    verification = "mismatch"
                    self._issue(
                        report,
                        "authority_profile_mismatch",
                        "critical",
                        "authority_profile",
                        "configured authority profile does not match the active or "
                        "authorized pending profile",
                    )
            projection = state.projection(verification=verification)
            if (
                verification == "operator_trust_required"
                and projection["pending_assurance"] == "signed_trusted"
            ):
                projection["pending_assurance"] = "signed_unverified"
            report.stores["authority_profile"] = projection
            if state.pending_rotation is not None:
                self._issue(
                    report,
                    "authority_profile_rotation_required",
                    "warning",
                    "authority_profile",
                    "an operator-authorized authority profile rotation is pending",
                )
            return state.generation
        except RuntimeError as exc:
            report.stores["authority_profile"] = {
                "state": "invalid",
                "generation": 0,
                "profile_hash": None,
                "verification": "invalid",
                "rotation_required": False,
                "pending_profile_hash": None,
                "pending_assurance": "unknown",
                "signed_transition_count": 0,
                "unsigned_transition_count": 0,
            }
            self._issue(
                report,
                "authority_profile_invalid",
                "critical",
                "authority_profile",
                str(exc),
            )
            return 0

    def _audit_operation_journal(
        self, report: StateIntegrityReport
    ) -> JournalOperation | None:
        try:
            operation = OperationJournal(
                self.workdir / "operation_journal.json"
            ).active()
        except RuntimeError as exc:
            report.stores["operation_journal"] = {
                "state": "invalid",
                "active": False,
                "operation_id": None,
                "kind": None,
                "prepared_at": None,
            }
            self._issue(
                report,
                "operation_journal_invalid",
                "critical",
                "operation_journal",
                str(exc),
            )
            return None
        if operation is None:
            report.stores["operation_journal"] = {
                "state": "ready"
                if (self.workdir / "operation_journal.json").exists()
                else "not_initialized",
                "active": False,
                "operation_id": None,
                "kind": None,
                "prepared_at": None,
            }
            return None
        report.stores["operation_journal"] = {
            "state": "recovery_required",
            "active": True,
            "operation_id": operation.operation_id,
            "kind": operation.kind,
            "prepared_at": operation.prepared_at,
        }
        self._issue(
            report,
            "operation_recovery_required",
            "warning",
            "operation_journal",
            f"prepared {operation.kind} operation requires authority recovery",
        )
        return operation

    def _audit_operator_trust(self, report: StateIntegrityReport) -> int:
        store = OperatorTrustStateStore(self.workdir / "operator_trust.json")
        try:
            state = store.get()
            if state is None:
                report.stores["operator_trust"] = {
                    "state": "not_enrolled",
                    "mode": "legacy_unsigned",
                    "generation": 0,
                    "bindings_hash": None,
                    "operator_count": 0,
                    "key_count": 0,
                    "verification": (
                        "configured_not_enrolled"
                        if self.operator_trust is not None
                        else "not_applicable"
                    ),
                }
                if self.operator_trust is not None:
                    self._issue(
                        report,
                        "operator_trust_not_enrolled",
                        "warning",
                        "operator_trust",
                        "trusted keys are configured for this read-only process but "
                        "signed operator trust has not been durably enrolled",
                    )
                return 0
            if self.operator_trust is None:
                report.stores["operator_trust"] = state.projection(
                    verification="unverified"
                )
                self._issue(
                    report,
                    "operator_trust_unverified",
                    "critical",
                    "operator_trust",
                    "signed operator trust is enrolled but no trusted keys were "
                    "provided to verify it",
                )
                return state.generation
            try:
                state.verify(self.operator_trust)
            except RuntimeError as exc:
                report.stores["operator_trust"] = state.projection(
                    verification="mismatch"
                )
                self._issue(
                    report,
                    "operator_trust_mismatch",
                    "critical",
                    "operator_trust",
                    str(exc),
                )
                return state.generation
            report.stores["operator_trust"] = state.projection(verification="verified")
            return state.generation
        except RuntimeError as exc:
            report.stores["operator_trust"] = {
                "state": "invalid",
                "mode": "unknown",
                "generation": 0,
                "bindings_hash": None,
                "operator_count": 0,
                "key_count": 0,
                "verification": "invalid",
            }
            self._issue(
                report,
                "operator_trust_invalid",
                "critical",
                "operator_trust",
                str(exc),
            )
            return 0

    def _audit_legacy_signed_migration(
        self,
        report: StateIntegrityReport,
        approvals: dict[str, PendingApproval],
    ) -> None:
        trust = report.stores.get("operator_trust", {})
        if trust.get("state") != "not_enrolled" or self.operator_trust is not None:
            return
        if not any(
            approval.decision_attestation is not None
            or approval.reconciliation_attestation is not None
            for approval in approvals.values()
        ):
            return
        trust["verification"] = "migration_required"
        self._issue(
            report,
            "operator_trust_migration_required",
            "critical",
            "operator_trust",
            "signed operator attestations predate durable enrollment; trusted "
            "operator keys are required for the first authority migration",
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
            with open_state_file(path, "r", encoding="utf-8") as handle:
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
        except (OSError, TypeError, ValueError, RuntimeError) as exc:
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
        self,
        report: StateIntegrityReport,
        journal_operation: JournalOperation | None,
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
                self._audit_approval_shape(report, approval, journal_operation)

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
        self,
        report: StateIntegrityReport,
        approval: PendingApproval,
        journal_operation: JournalOperation | None,
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
            completion_known = self._journal_completes_approval(
                journal_operation, approval
            )
            state = (
                "known tool result requires deterministic local recovery"
                if completion_known
                else "operator reconciliation is in progress"
                if approval.reconciliation_outcome
                else "execution outcome is uncertain"
            )
            self._issue(
                report,
                (
                    "execution_completion_recovery_required"
                    if completion_known
                    else "execution_recovery_required"
                ),
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
        journal_operation: JournalOperation | None,
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
        open_authorizations = self._open_authorizations(evidence)
        open_authorization_ids = {
            record.get("record_id") for record in open_authorizations
        }

        if evidence_trusted:
            self._audit_known_result_settlements(
                report,
                entries,
                records_by_id,
                journal_operation,
            )

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
                continue
            if self._journal_expects_unbound_reservation(
                journal_operation, action_id, reservation
            ):
                continue
            if any(
                self._journal_expects_terminal_reservation(
                    journal_operation, approval, reservation
                )
                for approval in approvals_by_action.get(action_id, [])
            ):
                continue
            self._issue(
                report,
                "orphan_reservation",
                "critical",
                "budget",
                "live reservation has no active approval or sealed authorization",
                action_id=action_id,
            )

        if evidence_trusted:
            for authorization in open_authorizations:
                action_id = authorization.get("action_id", "")
                if self._journal_completes_authorization(
                    journal_operation, authorization
                ):
                    continue
                if approvals_by_action.get(action_id):
                    continue
                if authorization.get("decision") != "allow":
                    self._issue(
                        report,
                        "approval_authorization_missing",
                        "critical",
                        "cross_store",
                        "sealed approval-required authorization has no approval record",
                        action_id=action_id,
                        record_id=authorization.get("record_id", ""),
                    )
                    continue
                report.counts["authorization_reconciliations_required"] += 1
                self._issue(
                    report,
                    "authorization_reconciliation_required",
                    "warning",
                    "evidence",
                    "sealed approval-free authorization has no terminal outcome",
                    action_id=action_id,
                    record_id=authorization.get("record_id", ""),
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
                if self._journal_expects_terminal_reservation(
                    journal_operation, approval, reservation
                ):
                    continue
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

        if evidence_trusted:
            for record in evidence:
                action_id = record.get("action_id", "")
                if (
                    record.get("reconciliation_outcome")
                    and action_id not in reconciliations
                    and not approvals_by_action.get(action_id)
                ):
                    self._issue(
                        report,
                        "authorization_reconciliation_budget_missing",
                        "critical",
                        "cross_store",
                        "terminal authorization reconciliation has no budget marker",
                        action_id=action_id,
                        record_id=record.get("record_id", ""),
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
                if reconciliation.get("authority_type") == "authorization":
                    self._audit_authorization_reconciliation_marker(
                        report,
                        action_id,
                        reconciliation,
                        records_by_id,
                        records_by_action.get(action_id, []),
                        entries,
                        journal_operation,
                        open_authorization_ids,
                    )
                    continue
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

    def _audit_authorization_reconciliation_marker(
        self,
        report: StateIntegrityReport,
        action_id: str,
        reconciliation: dict[str, Any],
        records_by_id: dict[str, dict[str, Any]],
        action_records: list[dict[str, Any]],
        entries: list[dict[str, Any]],
        journal_operation: JournalOperation | None,
        open_authorization_ids: set[Any],
    ) -> None:
        authority_id = reconciliation.get("authority_record_id", "")
        authority = records_by_id.get(authority_id)
        if authority is None:
            self._issue(
                report,
                "authorization_reconciliation_authority_missing",
                "critical",
                "budget",
                "authorization reconciliation has no sealed authority record",
                action_id=action_id,
                record_id=authority_id,
            )
            return
        try:
            subject = AuthorizationReconciliationSubject.from_record(authority)
        except RuntimeError as exc:
            self._issue(
                report,
                "authorization_reconciliation_authority_invalid",
                "critical",
                "evidence",
                str(exc),
                action_id=action_id,
                record_id=authority_id,
            )
            return
        expected = {
            "request_id": subject.request_id,
            "authority_record_hash": subject.authority_record_hash,
        }
        if action_id != subject.action_id or any(
            reconciliation.get(field) != value for field, value in expected.items()
        ):
            self._issue(
                report,
                "authorization_reconciliation_binding_mismatch",
                "critical",
                "cross_store",
                "budget reconciliation differs from its sealed authorization",
                action_id=action_id,
                record_id=authority_id,
            )
            return
        reserve_entries = [
            entry
            for entry in entries
            if entry.get("kind") == "reserve"
            and entry.get("request_id") == subject.request_id
            and entry.get("action_id") == subject.action_id
        ]
        durable_expected = (
            money(reserve_entries[-1].get("amount_usd"), field_name="reserve entry")
            if reserve_entries
            else ZERO
        )
        if (
            money(
                reconciliation.get("expected_usd", "0"),
                field_name="authorization reconciliation expected_usd",
            )
            != durable_expected
        ):
            self._issue(
                report,
                "authorization_reconciliation_estimate_mismatch",
                "critical",
                "budget",
                "reconciliation estimate differs from durable authorization exposure",
                action_id=action_id,
                record_id=authority_id,
            )
            return
        if self.operator_trust is not None:
            identity = self.operator_trust.assess_authorization_reconciliation(
                reconciliation.get("attestation"),
                subject,
                outcome=reconciliation.get("outcome", ""),
                operator=reconciliation.get("reconciled_by", ""),
                note=reconciliation.get("note", ""),
            )
            if not identity.ok:
                self._issue(
                    report,
                    "authorization_reconciliation_identity_invalid",
                    "critical",
                    "budget",
                    identity.detail,
                    action_id=action_id,
                    record_id=authority_id,
                )
                return
        terminal = next(
            (
                record
                for record in reversed(action_records)
                if record.get("authorization_hash") == subject.authorization_hash
                and record.get("result_status") in _TERMINAL_RESULTS
            ),
            None,
        )
        if terminal is None:
            journal_matches = (
                journal_operation is not None
                and journal_operation.kind == "authorization_reconcile"
                and journal_operation.payload.get("authority", {}).get(
                    "authority_record_id"
                )
                == authority_id
                and authority_id in open_authorization_ids
            )
            if not journal_matches:
                self._issue(
                    report,
                    "authorization_reconciliation_evidence_missing",
                    "critical",
                    "cross_store",
                    "budget reconciliation has no matching terminal evidence",
                    action_id=action_id,
                    record_id=authority_id,
                )
            return
        observed_outcome = {
            ResultStatus.SUCCEEDED.value: "succeeded",
            ResultStatus.FAILED.value: "failed",
            ResultStatus.NOT_EXECUTED.value: "not_executed",
        }.get(terminal.get("result_status"))
        debit_entries = [
            entry
            for entry in entries
            if entry.get("kind") == "debit"
            and entry.get("request_id") == subject.request_id
            and entry.get("action_id") == subject.action_id
        ]
        if debit_entries:
            expected_cost = money(
                debit_entries[-1].get("amount_usd"), field_name="debit entry"
            )
        elif observed_outcome == "not_executed":
            expected_cost = ZERO
        else:
            expected_cost = durable_expected
        if (
            observed_outcome != reconciliation.get("outcome")
            or terminal.get("reconciliation_outcome") != observed_outcome
            or terminal.get("reconciled_by") != reconciliation.get("reconciled_by")
            or terminal.get("reconciliation_note") != reconciliation.get("note")
            or money(terminal.get("cost_usd", "0"), field_name="terminal cost")
            != expected_cost
        ):
            self._issue(
                report,
                "authorization_reconciliation_evidence_mismatch",
                "critical",
                "cross_store",
                "terminal evidence differs from operator reconciliation",
                action_id=action_id,
                record_id=terminal.get("record_id", ""),
            )

    def _audit_known_result_settlements(
        self,
        report: StateIntegrityReport,
        entries: list[dict[str, Any]],
        records_by_id: dict[str, dict[str, Any]],
        journal_operation: JournalOperation | None,
    ) -> None:
        seen: set[str] = set()
        for entry in entries:
            record_id = entry.get("completion_record_id")
            if not record_id:
                continue
            if record_id in seen:
                self._issue(
                    report,
                    "known_result_settlement_duplicate",
                    "critical",
                    "budget",
                    "terminal evidence is referenced by multiple settlements",
                    action_id=entry.get("action_id", ""),
                    record_id=record_id,
                )
                continue
            seen.add(record_id)
            record = records_by_id.get(record_id)
            if record is None:
                prepared = (
                    journal_operation.payload.get("evidence", {})
                    if journal_operation is not None
                    and journal_operation.kind == "execution_complete"
                    else {}
                )
                if (
                    prepared.get("record_id") == record_id
                    and prepared.get("request_id") == entry.get("request_id")
                    and prepared.get("action_id") == entry.get("action_id")
                    and money(prepared.get("cost_usd", "0"))
                    == money(entry.get("amount_usd", "0"))
                    and money(prepared.get("budget_remaining_usd", "0"))
                    == money(entry.get("balance_after_usd", "0"))
                ):
                    continue
                self._issue(
                    report,
                    "known_result_evidence_missing",
                    "critical",
                    "cross_store",
                    "known-result settlement references absent terminal evidence",
                    action_id=entry.get("action_id", ""),
                    record_id=record_id,
                )
                continue
            if (
                entry.get("kind") != "debit"
                or record.get("request_id") != entry.get("request_id")
                or record.get("action_id") != entry.get("action_id")
                or record.get("result_status")
                not in {ResultStatus.SUCCEEDED.value, ResultStatus.FAILED.value}
                or money(record.get("cost_usd", "0"))
                != money(entry.get("amount_usd", "0"))
                or money(record.get("budget_remaining_usd", "0"))
                != money(entry.get("balance_after_usd", "0"))
            ):
                self._issue(
                    report,
                    "known_result_settlement_mismatch",
                    "critical",
                    "cross_store",
                    "known-result settlement differs from terminal evidence",
                    action_id=entry.get("action_id", ""),
                    record_id=record_id,
                )

    @staticmethod
    def _open_authorizations(evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
        terminal_hashes = {
            record.get("authorization_hash")
            for record in evidence
            if record.get("result_status") in _TERMINAL_RESULTS
        }
        return [
            record
            for record in evidence
            if record.get("result_status") == ResultStatus.SKIPPED.value
            and record.get("authorization_hash") not in terminal_hashes
        ]

    def _journal_expects_unbound_reservation(
        self,
        operation: JournalOperation | None,
        action_id: str,
        reservation: dict[str, Any],
    ) -> bool:
        if operation is None or operation.kind != "approval_create":
            return False
        approval = operation.payload["approval"]
        try:
            return (
                approval["action_id"] == action_id
                and approval["request_id"] == reservation.get("request_id")
                and money(approval["reserved_usd"])
                == money(reservation.get("amount_usd"))
            )
        except (KeyError, TypeError, ValueError):
            return False

    def _journal_expects_terminal_reservation(
        self,
        operation: JournalOperation | None,
        approval: PendingApproval,
        reservation: dict[str, Any],
    ) -> bool:
        if operation is None or operation.kind not in {
            "approval_reject",
            "approval_expire",
        }:
            return False
        payload = operation.payload
        try:
            return (
                payload["approval_id"] == approval.approval_id
                and payload["action_id"] == approval.action_id
                and payload["request_id"] == approval.request_id
                and reservation.get("request_id") == approval.request_id
                and money(payload["reserved_usd"])
                == money(approval.reserved_usd)
                == money(reservation.get("amount_usd"))
            )
        except (KeyError, TypeError, ValueError):
            return False

    @staticmethod
    def _journal_completes_approval(
        operation: JournalOperation | None,
        approval: PendingApproval,
    ) -> bool:
        if operation is None or operation.kind != "execution_complete":
            return False
        payload = operation.payload
        authority = payload.get("authority", {})
        return (
            payload.get("approval_id") == approval.approval_id
            and authority.get("action_id") == approval.action_id
            and authority.get("request_id") == approval.request_id
            and authority.get("authorization_hash") == approval.authorization_hash
        )

    @staticmethod
    def _journal_completes_authorization(
        operation: JournalOperation | None,
        authorization: dict[str, Any],
    ) -> bool:
        if operation is None or operation.kind != "execution_complete":
            return False
        authority = operation.payload.get("authority", {})
        return (
            authority.get("authority_record_id") == authorization.get("record_id")
            and authority.get("authority_record_hash")
            == authorization.get("record_hash")
            and authority.get("action_id") == authorization.get("action_id")
            and authority.get("request_id") == authorization.get("request_id")
            and authority.get("authorization_hash")
            == authorization.get("authorization_hash")
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
