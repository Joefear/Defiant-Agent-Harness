"""The deterministic local control loop."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from decimal import Decimal
from functools import wraps
from pathlib import Path

from ..adapters.base import AgentAdapter, ToolCall, ToolCallOutcome
from ..approvals.store import ApprovalError, ApprovalStore, PendingApproval
from ..authority_profile import AuthorityProfileStore
from ..budgets.ledger import BudgetLedger
from ..contracts import (
    Decision,
    EvidenceRecord,
    GuardrailDecision,
    HarnessRequest,
    ProposedAction,
    ResultStatus,
    sha256_of,
    utc_now,
)
from ..evidence.store import EvidenceError, EvidenceStore
from ..money import ZERO, MoneyLike, money
from ..operation_journal import (
    ExecutionCompletionSubject,
    JournalOperation,
    OperationJournal,
)
from ..operator_identity import (
    AuthorizationReconciliationSubject,
    OperatorIdentityError,
    validate_external_trust_specs,
)
from ..operator_trust_state import OperatorTrustStateStore
from ..policy.engine import PolicyEngine
from ..persistence import AuthorityTransactionLock
from ..state_storage import (
    StateStorageStateStore,
    prepare_state_storage,
    require_state_storage_unchanged,
)
from ..state_integrity import StateIntegrityAuditor
from ..tools.registry import ToolContractError, ToolRegistry, ToolResult


def _authority_entrypoint(method):
    @wraps(method)
    def protected(self, *args, **kwargs):
        with self.authority_lock.acquire():
            return method(self, *args, **kwargs)

    return protected


@dataclass
class ActionOutcome:
    action: ProposedAction
    decision: GuardrailDecision
    status: ResultStatus
    evidence_record_id: str
    approval_id: str = ""
    result: ToolResult | None = None
    detail: str = ""

    def as_tool_outcome(self) -> ToolCallOutcome:
        blocked = self.status in {
            ResultStatus.BLOCKED,
            ResultStatus.REJECTED,
            ResultStatus.EXPIRED,
            ResultStatus.FAILED,
            ResultStatus.NOT_EXECUTED,
        }
        incomplete = self.status is ResultStatus.PENDING_APPROVAL
        if self.status is ResultStatus.PENDING_APPROVAL:
            content = (
                f"Action held for human approval ({self.approval_id}). "
                f"Reason: {self.decision.reason}"
            )
        elif blocked:
            content = f"Permission denied by policy: {self.decision.reason}"
        else:
            content = self.result.output if self.result else "ok"
        return ToolCallOutcome(
            is_error=blocked or incomplete,
            content=content,
            harness_status=self.status.value,
            evidence_record_id=self.evidence_record_id,
            approval_id=self.approval_id,
        )


@dataclass(frozen=True)
class AuthorizationReconciliationOutcome:
    authority_record_id: str
    action_id: str
    request_id: str
    status: ResultStatus
    evidence_record_id: str
    detail: str


class Harness:
    def __init__(
        self,
        policy: PolicyEngine,
        tools: ToolRegistry,
        evidence: EvidenceStore,
        approvals: ApprovalStore,
        budget: BudgetLedger,
        adapter: AgentAdapter,
        state_integrity: StateIntegrityAuditor,
        operation_journal: OperationJournal,
        dry_run: bool = False,
        authority_lock: AuthorityTransactionLock | None = None,
        execution_disabled: bool = False,
    ):
        self.policy = policy
        self.tools = tools
        self.evidence = evidence
        self.approvals = approvals
        self.budget = budget
        self.adapter = adapter
        self.state_integrity = state_integrity
        self.operation_journal = operation_journal
        self.authority_lock = authority_lock or AuthorityTransactionLock(
            operation_journal.path.parent / "authority.lock"
        )
        self.dry_run = dry_run
        self.execution_disabled = execution_disabled

    # -- entry points -------------------------------------------------

    @_authority_entrypoint
    def run(self, request: HarnessRequest) -> list[ActionOutcome]:
        self._require_execution_enabled()
        return [
            self.handle_call(call, request)
            for call in self.adapter.propose(request.task)
        ]

    @_authority_entrypoint
    def handle_call(
        self,
        call: ToolCall,
        request: HarnessRequest,
        *,
        execution_owner: str = "",
        execution_key: str = "",
    ) -> ActionOutcome:
        self._require_execution_enabled()
        action = self.adapter.to_action(call, request.request_id)
        return self._handle(
            action,
            request,
            execution_owner=execution_owner,
            execution_key=execution_key,
        )

    @_authority_entrypoint
    def preflight_external_call(
        self,
        call: ToolCall,
        request: HarnessRequest,
        *,
        execution_owner: str,
        execution_key: str,
    ) -> ActionOutcome:
        """Authorize an externally executed tool without claiming it already ran.

        Native agent hooks sit before a tool owned by another runtime. The
        harness can decide whether that call may proceed, but it must not invoke
        a simulated handler and record a false success. A successful preflight
        therefore ends at a sealed ``SKIPPED`` authorization record. The
        matching post-tool hook calls :meth:`complete_external_call` after the
        external runtime reports success.
        """
        self._require_execution_enabled()
        action = self.adapter.to_action(call, request.request_id)
        return self._handle(
            action,
            request,
            execution_owner=execution_owner,
            execution_key=execution_key,
            external_execution=True,
        )

    # -- initial control loop ----------------------------------------

    def _handle(
        self,
        action: ProposedAction,
        request: HarnessRequest,
        *,
        execution_owner: str = "",
        execution_key: str = "",
        external_execution: bool = False,
    ) -> ActionOutcome:
        self.recover_operation()
        self.reconcile_expired_approvals()
        self.state_integrity.require_safe()
        if self.evidence.by_action(action.action_id):
            decision = self._control_decision(
                action,
                Decision.BLOCK,
                "duplicate action_id; replay refused",
                "duplicate_action",
            )
            return self._terminal(action, request, decision, ResultStatus.BLOCKED)

        contract_error = self._tool_contract_error(action)
        if contract_error:
            decision = self._control_decision(
                action,
                Decision.BLOCK,
                contract_error,
                "tool_contract",
            )
            return self._terminal(action, request, decision, ResultStatus.BLOCKED)

        if request.allowed_tools and action.tool_name not in request.allowed_tools:
            decision = self._control_decision(
                action,
                Decision.BLOCK,
                f"tool '{action.tool_name}' is not in this request's allowed_tools",
                "request_scope",
                {"allowed_tools": request.allowed_tools},
            )
            return self._terminal(action, request, decision, ResultStatus.BLOCKED)

        decision = self.policy.evaluate(action, self._context(request))
        if decision.decision is Decision.BLOCK:
            return self._terminal(action, request, decision, ResultStatus.BLOCKED)

        estimate = max(action.estimated_cost_usd, self._spec_cost(action))
        if estimate > ZERO:
            check = self.budget.preflight(estimate, request.budget_limit_usd)
            if not check.ok:
                decision = self._control_decision(
                    action,
                    Decision.BLOCK,
                    f"budget: {check.reason}",
                    "budget_limit",
                    {
                        "estimate_usd": check.estimate_usd,
                        "remaining_usd": check.remaining_usd,
                        "request_limit_usd": request.budget_limit_usd,
                    },
                )
                return self._terminal(action, request, decision, ResultStatus.BLOCKED)
        if decision.decision is Decision.APPROVAL_REQUIRED:
            pending = self.approvals.prepare(
                action=action,
                decision_reason=decision.reason,
                approval_scope=decision.approval_scope,
                policy_ids=decision.policy_ids,
                request=request,
                decision=decision,
                reserved_usd=estimate,
                execution_owner=execution_owner,
                execution_key=execution_key,
            )
            record = self._make_record(
                action,
                request,
                decision,
                ResultStatus.PENDING_APPROVAL,
                detail=f"held for approval {pending.approval_id}",
                budget_remaining_usd=self.budget.balance_usd - estimate,
            )
            operation = self.operation_journal.prepare(
                "approval_create",
                {
                    "approval": asdict(pending),
                    "reserved_usd": pending.reserved_usd,
                    "evidence": record.to_dict(),
                },
            )
            self._recover_operation(operation)
            return ActionOutcome(
                action,
                decision,
                ResultStatus.PENDING_APPROVAL,
                record.record_id,
                approval_id=pending.approval_id,
                detail=decision.reason,
            )

        if estimate > ZERO:
            self.budget.reserve(estimate, request.request_id, action.action_id)

        if external_execution:
            return self._authorize_external(
                action,
                request,
                decision,
            )

        return self._execute(action, request, decision, estimate, approved_by=None)

    # -- durable approval resume ------------------------------------

    @_authority_entrypoint
    def resume_external(self, approval_id: str) -> ActionOutcome:
        """Authorize an approved exact retry for execution by another runtime."""
        self._require_execution_enabled()
        self.recover_operation()
        self.reconcile_expired_approvals()
        self.state_integrity.require_safe()
        pending = self.approvals.get(approval_id)
        if pending is None:
            raise ApprovalError(f"unknown approval {approval_id}")
        if pending.status == "executing":
            raise ApprovalError(
                f"approval {approval_id} is already executing; prior external "
                "outcome is uncertain"
            )
        if pending.status != "approved":
            raise ApprovalError(
                f"approval {approval_id} is {pending.status}, not approved"
            )

        action = pending.held_action()
        request = pending.held_request()
        original_decision = pending.held_decision()
        if original_decision.ruleset_hash != self.policy.ruleset_hash:
            current_decision = self._control_decision(
                action,
                Decision.BLOCK,
                (
                    "loaded policy ruleset differs from the ruleset that created "
                    "this approval; explicit re-proposal is required"
                ),
                "policy_changed",
                {
                    "approved_ruleset_hash": original_decision.ruleset_hash,
                    "current_ruleset_hash": self.policy.ruleset_hash,
                },
            )
        else:
            current_decision = self._resume_decision(action, request)

        self.approvals.begin_execution(approval_id, action)
        if current_decision.decision is Decision.BLOCK:
            self._release_reservation(pending)
            record = self._record(
                action,
                request,
                current_decision,
                ResultStatus.BLOCKED,
                approved_by=pending.decided_by,
                detail=current_decision.reason,
            )
            self.approvals.mark_consumed(approval_id, record.record_id)
            return ActionOutcome(
                action,
                current_decision,
                ResultStatus.BLOCKED,
                record.record_id,
                approval_id=approval_id,
                detail=current_decision.reason,
            )

        return self._authorize_external(
            action,
            request,
            current_decision,
            approved_by=pending.decided_by,
            approval_id=approval_id,
        )

    @_authority_entrypoint
    def complete_external_call(
        self,
        action: ProposedAction,
        request: HarnessRequest,
        decision: GuardrailDecision,
        *,
        tool_response: object,
        approval_id: str = "",
    ) -> ActionOutcome:
        """Seal a successful result reported by a matching post-tool hook."""
        self._require_execution_enabled()
        self.recover_operation()
        self.state_integrity.require_safe()
        records = self.evidence.by_action(action.action_id)
        authorization = next(
            (
                record
                for record in reversed(records)
                if record.get("result_status") == ResultStatus.SKIPPED.value
                and record.get("authorization_hash") == action.authorization_hash
            ),
            None,
        )
        if authorization is None:
            raise ToolContractError(
                "external completion has no matching sealed authorization"
            )
        if authorization.get("request_id") != request.request_id:
            raise ToolContractError("external completion request does not match")
        if authorization.get("decision") != decision.decision.value:
            raise ToolContractError("external completion decision does not match")
        if authorization.get("ruleset_hash") != decision.ruleset_hash:
            raise ToolContractError("external completion ruleset does not match")
        terminal = {
            ResultStatus.SUCCEEDED.value,
            ResultStatus.FAILED.value,
            ResultStatus.BLOCKED.value,
            ResultStatus.REJECTED.value,
            ResultStatus.EXPIRED.value,
        }
        if any(record.get("result_status") in terminal for record in records):
            raise ToolContractError("external action already has a terminal outcome")

        result = ToolResult(
            status="succeeded",
            summary=f"external tool {action.tool_name} completed",
            output=tool_response,
        )
        approved_by = None
        if approval_id:
            approval = self.approvals.get(approval_id)
            if approval is None:
                raise ApprovalError(f"unknown approval {approval_id}")
            if approval.status != "executing":
                raise ApprovalError(
                    f"approval {approval_id} is {approval.status}, not executing"
                )
            if approval.reconciliation_outcome:
                raise ApprovalError(
                    f"approval {approval_id} has operator reconciliation in progress"
                )
            if approval.action_id != action.action_id:
                raise ApprovalError("approval does not belong to external action")
            if approval.authorization_hash != action.authorization_hash:
                raise ApprovalError("external action changed after approval")
            approved_by = approval.decided_by
        estimate = self.budget.reservation_for(action.action_id)
        record = self._complete_known_result(
            authorization,
            action,
            request,
            decision,
            result,
            estimate,
            approved_by,
            approval_id,
        )
        return ActionOutcome(
            action,
            decision,
            ResultStatus.SUCCEEDED,
            record.record_id,
            approval_id=approval_id,
            result=result,
            detail=result.summary,
        )

    @_authority_entrypoint
    def resume(
        self,
        approval_id: str,
        approved: bool,
        decided_by: str,
        note: str = "",
        *,
        attestation: dict | None = None,
    ) -> ActionOutcome:
        if approved:
            self._require_execution_enabled()
        self.recover_operation()
        self.reconcile_expired_approvals()
        self.state_integrity.require_safe()
        pending = self.approvals.get(approval_id)
        if pending is None:
            raise ApprovalError(f"unknown approval {approval_id}")
        if pending.status == "executing":
            raise ApprovalError(
                f"approval {approval_id} was already marked executing; refusing "
                "automatic replay because the prior outcome is uncertain"
            )
        if pending.status in {"consumed", "rejected", "expired"}:
            raise ApprovalError(
                f"approval {approval_id} is already {pending.status}; cannot resume"
            )

        action = pending.held_action()
        request = pending.held_request()
        original_decision = pending.held_decision()

        if pending.status == "pending" and approved:
            pending = self.approvals.decide(
                approval_id,
                approved,
                decided_by,
                note,
                attestation=attestation,
            )
        elif pending.status != "pending" and not approved:
            raise ApprovalError("an approved action cannot later be rejected")

        if not approved:
            decided_by, note = self.approvals.validate_decision(
                approval_id,
                False,
                decided_by,
                note,
                attestation=attestation,
            )
            record = self._make_record(
                action,
                request,
                original_decision,
                ResultStatus.REJECTED,
                approved_by=decided_by,
                detail=note or "rejected by human reviewer",
                budget_remaining_usd=(
                    self.budget.balance_usd + money(pending.reserved_usd)
                ),
            )
            operation = self.operation_journal.prepare(
                "approval_reject",
                {
                    "approval_id": approval_id,
                    "action_id": pending.action_id,
                    "request_id": pending.request_id,
                    "reserved_usd": pending.reserved_usd,
                    "decided_by": decided_by,
                    "note": note,
                    "attestation": attestation,
                    "evidence": record.to_dict(),
                },
            )
            self._recover_operation(operation)
            return ActionOutcome(
                action,
                original_decision,
                ResultStatus.REJECTED,
                record.record_id,
                approval_id=approval_id,
                detail="rejected",
            )

        # Re-check current mechanical and policy boundaries. A stale approval
        # never overrides a policy that became more restrictive.
        if original_decision.ruleset_hash != self.policy.ruleset_hash:
            current_decision = self._control_decision(
                action,
                Decision.BLOCK,
                (
                    "loaded policy ruleset differs from the ruleset that created "
                    "this approval; explicit re-proposal is required"
                ),
                "policy_changed",
                {
                    "approved_ruleset_hash": original_decision.ruleset_hash,
                    "current_ruleset_hash": self.policy.ruleset_hash,
                },
            )
        else:
            current_decision = self._resume_decision(action, request)
        self.approvals.begin_execution(approval_id, action)
        if current_decision.decision is Decision.BLOCK:
            self._release_reservation(pending)
            record = self._record(
                action,
                request,
                current_decision,
                ResultStatus.BLOCKED,
                approved_by=decided_by,
                detail=current_decision.reason,
            )
            self.approvals.mark_consumed(approval_id, record.record_id)
            return ActionOutcome(
                action,
                current_decision,
                ResultStatus.BLOCKED,
                record.record_id,
                approval_id=approval_id,
                detail=current_decision.reason,
            )

        estimate = self.budget.reservation_for(action.action_id)
        outcome = self._execute(
            action,
            request,
            current_decision,
            estimate,
            approved_by=decided_by,
            approval_id=approval_id,
        )
        return outcome

    @_authority_entrypoint
    def reconcile_expired_approvals(self) -> list[ActionOutcome]:
        self.recover_operation()
        self.state_integrity.require_safe()
        outcomes: list[ActionOutcome] = []
        for approval in self.approvals.due():
            try:
                action = approval.held_action()
                request = approval.held_request()
                decision = approval.held_decision()
            except ApprovalError:
                # Legacy/unresumable records remain non-actionable and unchanged.
                continue
            reserved = money(approval.reserved_usd)
            record = self._make_record(
                action,
                request,
                decision,
                ResultStatus.EXPIRED,
                detail=f"approval expired at {approval.expires_at}",
                budget_remaining_usd=self.budget.balance_usd + reserved,
            )
            operation = self.operation_journal.prepare(
                "approval_expire",
                {
                    "approval_id": approval.approval_id,
                    "action_id": approval.action_id,
                    "request_id": approval.request_id,
                    "reserved_usd": approval.reserved_usd,
                    "evidence": record.to_dict(),
                },
            )
            self._recover_operation(operation)
            outcomes.append(
                ActionOutcome(
                    action,
                    decision,
                    ResultStatus.EXPIRED,
                    record.record_id,
                    approval_id=approval.approval_id,
                    detail="approval expired",
                )
            )
        return outcomes

    @_authority_entrypoint
    def reconcile_execution(
        self,
        approval_id: str,
        outcome: str,
        reconciled_by: str,
        note: str,
        *,
        attestation: dict | None = None,
    ) -> ActionOutcome:
        """Terminally reconcile an approval stranded in ``executing``.

        The approval store records the exact operator input first. Budget and
        evidence mutations are then individually idempotent, so repeating the
        same command after a crash completes the transaction without replaying
        the tool or charging twice.
        """
        self.recover_operation()
        self.state_integrity.require_safe()
        terminal_outcomes = {
            ResultStatus.SUCCEEDED.value: "succeeded",
            ResultStatus.FAILED.value: "failed",
            ResultStatus.NOT_EXECUTED.value: "not_executed",
            ResultStatus.BLOCKED.value: "not_executed",
            ResultStatus.REJECTED.value: "not_executed",
            ResultStatus.EXPIRED.value: "not_executed",
        }
        existing_approval = self.approvals.get(approval_id)
        if existing_approval is None:
            raise ApprovalError(f"unknown approval {approval_id}")
        action = existing_approval.held_action()
        terminal_record = next(
            (
                record
                for record in reversed(self.evidence.by_action(action.action_id))
                if record.get("authorization_hash") == action.authorization_hash
                and record.get("result_status") in terminal_outcomes
            ),
            None,
        )
        if terminal_record is not None:
            observed = terminal_outcomes[terminal_record["result_status"]]
            if observed != outcome:
                raise ApprovalError(
                    "operator outcome conflicts with the existing terminal evidence"
                )

        approval = self.approvals.begin_reconciliation(
            approval_id,
            outcome,
            reconciled_by,
            note,
            attestation=attestation,
        )
        request = approval.held_request()
        decision = approval.held_decision()

        budget_result = self.budget.reconcile_reservation(
            approval.reserved_usd,
            approval.request_id,
            approval.action_id,
            outcome,
            approval.reconciled_by,
            approval.reconciliation_note,
        )

        if terminal_record is None:
            status = {
                "succeeded": ResultStatus.SUCCEEDED,
                "failed": ResultStatus.FAILED,
                "not_executed": ResultStatus.NOT_EXECUTED,
            }[outcome]
            charged = Decimal(budget_result["charged_usd"])
            result = None
            if outcome != "not_executed":
                result = ToolResult(
                    status=outcome,
                    summary=(
                        f"operator reconciled an uncertain execution as {outcome}"
                    ),
                    output={"operator_reconciled": True},
                    cost_usd=charged,
                )
            terminal_record = self._record(
                action,
                request,
                decision,
                status,
                approved_by=approval.decided_by,
                result=result,
                detail=(
                    f"operator reconciliation: {outcome}; "
                    f"budget {budget_result['disposition']}"
                ),
                reconciliation_outcome=outcome,
                reconciled_by=approval.reconciled_by,
                reconciled_at=approval.reconciliation_started_at,
                reconciliation_note=approval.reconciliation_note,
            ).to_dict()

        self.approvals.mark_reconciled(approval_id, terminal_record["record_id"])
        status = ResultStatus(terminal_record["result_status"])
        return ActionOutcome(
            action,
            decision,
            status,
            terminal_record["record_id"],
            approval_id=approval_id,
            detail=f"operator reconciled execution as {outcome}",
        )

    @_authority_entrypoint
    def reconcile_authorization(
        self,
        authority_record_id: str,
        outcome: str,
        reconciled_by: str,
        note: str,
        *,
        attestation: dict | None = None,
    ) -> AuthorizationReconciliationOutcome:
        """Resolve an uncertain execution not backed by an approval."""
        self.recover_operation()
        self.state_integrity.require_safe()
        if outcome not in {"succeeded", "failed", "not_executed"}:
            raise ValueError("outcome must be one of: succeeded, failed, not_executed")
        if not isinstance(reconciled_by, str) or not reconciled_by.strip():
            raise ValueError("reconciled_by must be non-empty")
        if not isinstance(note, str) or not note.strip():
            raise ValueError("reconciliation note must be non-empty")
        reconciled_by = reconciled_by.strip()
        note = note.strip()

        authority_record = self.evidence.get(authority_record_id)
        if authority_record is None:
            raise ValueError(f"unknown evidence record {authority_record_id}")
        subject = AuthorizationReconciliationSubject.from_record(authority_record)
        approvals = self.approvals.for_action(subject.action_id)
        if approvals:
            raise ApprovalError(
                "authorization belongs to an approval; reconcile by approval id"
            )
        self._require_authorization_reconciliation_identity(
            subject,
            outcome,
            reconciled_by,
            note,
            attestation,
        )

        terminal = self._authorization_terminal(subject)
        if terminal is not None:
            self._validate_existing_authorization_reconciliation(
                terminal, outcome, reconciled_by, note
            )
            return AuthorizationReconciliationOutcome(
                subject.authority_record_id,
                subject.action_id,
                subject.request_id,
                ResultStatus(terminal["result_status"]),
                terminal["record_id"],
                f"operator reconciled authorization as {outcome}",
            )

        expected = self.budget.exposure_for(subject.request_id, subject.action_id)
        prior_debit = self.budget.prior_debit_for(subject.request_id, subject.action_id)
        if prior_debit is not None:
            evidence_cost = prior_debit
        elif outcome == "not_executed":
            evidence_cost = ZERO
        else:
            evidence_cost = expected
        status = {
            "succeeded": ResultStatus.SUCCEEDED,
            "failed": ResultStatus.FAILED,
            "not_executed": ResultStatus.NOT_EXECUTED,
        }[outcome]
        reconciled_at = (
            attestation["signed_at"] if attestation is not None else utc_now()
        )
        terminal_record = self._make_authorization_reconciliation_record(
            authority_record,
            status,
            evidence_cost,
            outcome,
            reconciled_by,
            reconciled_at,
            note,
        )
        operation = self.operation_journal.prepare(
            "authorization_reconcile",
            {
                "authority": asdict(subject),
                "expected_usd": str(expected),
                "outcome": outcome,
                "reconciled_by": reconciled_by,
                "note": note,
                "attestation": attestation,
                "evidence": terminal_record.to_dict(),
            },
        )
        self._recover_operation(operation)
        return AuthorizationReconciliationOutcome(
            subject.authority_record_id,
            subject.action_id,
            subject.request_id,
            status,
            terminal_record.record_id,
            f"operator reconciled authorization as {outcome}",
        )

    # -- execution ----------------------------------------------------

    def _authorize_external(
        self,
        action: ProposedAction,
        request: HarnessRequest,
        decision: GuardrailDecision,
        *,
        approved_by: str | None = None,
        approval_id: str = "",
    ) -> ActionOutcome:
        record = self._record(
            action,
            request,
            decision,
            ResultStatus.SKIPPED,
            approved_by=approved_by,
            detail="authorized; external execution pending",
        )
        return ActionOutcome(
            action,
            decision,
            ResultStatus.SKIPPED,
            record.record_id,
            approval_id=approval_id,
            detail="authorized; external execution pending",
        )

    def _execute(
        self,
        action: ProposedAction,
        request: HarnessRequest,
        decision: GuardrailDecision,
        estimate: Decimal,
        approved_by: str | None,
        approval_id: str = "",
    ) -> ActionOutcome:
        authorization = self._record(
            action,
            request,
            decision,
            ResultStatus.SKIPPED,
            approved_by=approved_by,
            detail="authorized; execution pending",
        )
        grant = self.tools.authorize(action, authorization)
        result = self.tools.execute(action, grant, dry_run=self.dry_run)
        final = self._complete_known_result(
            authorization.to_dict(),
            action,
            request,
            decision,
            result,
            estimate,
            approved_by,
            approval_id,
        )
        status = ResultStatus(final.result_status)
        return ActionOutcome(
            action,
            decision,
            status,
            final.record_id,
            approval_id=approval_id,
            result=result,
            detail=result.summary,
        )

    def _complete_known_result(
        self,
        authorization: dict,
        action: ProposedAction,
        request: HarnessRequest,
        decision: GuardrailDecision,
        result: ToolResult,
        estimate: Decimal,
        approved_by: str | None,
        approval_id: str,
    ) -> EvidenceRecord:
        """Journal a known tool result before completing local state."""
        actual = (
            ZERO
            if result.dry_run
            else result.cost_usd
            if result.cost_usd > ZERO
            else estimate
        )
        result.cost_usd = actual
        status = (
            ResultStatus.SUCCEEDED
            if result.status == "succeeded"
            else ResultStatus.FAILED
        )
        disposition = "settle" if estimate > ZERO or actual > ZERO else "none"
        remaining = (
            self.budget.preview_settlement(
                estimate,
                actual,
                request.request_id,
                action.action_id,
            )
            if disposition == "settle"
            else self.budget.balance_usd
        )
        record = self._make_record(
            action,
            request,
            decision,
            status,
            approved_by=approved_by,
            result=result,
            detail=result.summary,
            budget_remaining_usd=remaining,
        )
        subject = ExecutionCompletionSubject.from_record(authorization)
        operation = self.operation_journal.prepare(
            "execution_complete",
            {
                "authority": asdict(subject),
                "approval_id": approval_id,
                "reserved_usd": str(estimate),
                "actual_usd": str(actual),
                "budget_disposition": disposition,
                "evidence": record.to_dict(),
            },
        )
        self._recover_operation(operation)
        return record

    # -- decisions and helpers --------------------------------------

    def _resume_decision(
        self,
        action: ProposedAction,
        request: HarnessRequest,
    ) -> GuardrailDecision:
        contract_error = self._tool_contract_error(action)
        if contract_error:
            return self._control_decision(
                action, Decision.BLOCK, contract_error, "tool_contract"
            )
        if request.allowed_tools and action.tool_name not in request.allowed_tools:
            return self._control_decision(
                action,
                Decision.BLOCK,
                f"tool '{action.tool_name}' is not in this request's allowed_tools",
                "request_scope",
            )
        return self.policy.evaluate(action, self._context(request))

    def _tool_contract_error(self, action: ProposedAction) -> str:
        try:
            self.tools.validate_action(action)
        except ToolContractError as exc:
            return str(exc)
        return ""

    def _control_decision(
        self,
        action: ProposedAction,
        decision: Decision,
        reason: str,
        policy_id: str,
        extra_inputs: dict | None = None,
    ) -> GuardrailDecision:
        inputs = {
            "tool_name": action.tool_name,
            "target": action.target,
            "authorization_hash": action.authorization_hash,
            "authority_inputs": self.policy.authority_inputs,
        }
        inputs.update(extra_inputs or {})
        return GuardrailDecision(
            decision,
            reason,
            policy_ids=[policy_id],
            policy_version=self.policy.version,
            ruleset_hash=self.policy.ruleset_hash,
            decision_inputs=inputs,
        )

    def _terminal(
        self,
        action: ProposedAction,
        request: HarnessRequest,
        decision: GuardrailDecision,
        status: ResultStatus,
    ) -> ActionOutcome:
        record = self._record(action, request, decision, status, detail=decision.reason)
        return ActionOutcome(
            action,
            decision,
            status,
            record.record_id,
            detail=decision.reason,
        )

    def _record(
        self,
        action: ProposedAction,
        request: HarnessRequest,
        decision: GuardrailDecision,
        status: ResultStatus,
        approved_by: str | None = None,
        result: ToolResult | None = None,
        detail: str = "",
        reconciliation_outcome: str = "",
        reconciled_by: str = "",
        reconciled_at: str | None = None,
        reconciliation_note: str = "",
    ) -> EvidenceRecord:
        return self.evidence.append(
            self._make_record(
                action,
                request,
                decision,
                status,
                approved_by=approved_by,
                result=result,
                detail=detail,
                reconciliation_outcome=reconciliation_outcome,
                reconciled_by=reconciled_by,
                reconciled_at=reconciled_at,
                reconciliation_note=reconciliation_note,
            )
        )

    def _make_record(
        self,
        action: ProposedAction,
        request: HarnessRequest,
        decision: GuardrailDecision,
        status: ResultStatus,
        approved_by: str | None = None,
        result: ToolResult | None = None,
        detail: str = "",
        reconciliation_outcome: str = "",
        reconciled_by: str = "",
        reconciled_at: str | None = None,
        reconciliation_note: str = "",
        budget_remaining_usd: Decimal | None = None,
    ) -> EvidenceRecord:
        return EvidenceRecord(
            request_id=request.request_id,
            action_id=action.action_id,
            decision=decision.decision,
            result_status=status,
            agent_runner=self.adapter.runner_name,
            model_id=self.adapter.model_id,
            user_id=request.user_id,
            workspace_id=request.workspace_id,
            tool_name=action.tool_name,
            target=action.target,
            side_effect_level=action.side_effect_level.value,
            policy_ids=decision.policy_ids,
            policy_version=decision.policy_version,
            ruleset_hash=decision.ruleset_hash,
            decision_reason=decision.reason,
            decision_inputs=decision.decision_inputs,
            approved_by=approved_by,
            approved_at=utc_now() if approved_by else None,
            payload_hash=action.payload_hash,
            authorization_hash=action.authorization_hash,
            payload_trust=action.payload_trust.value,
            input_refs=[
                ref.__dict__ | {"trust": ref.trust.value}
                for ref in action.payload_sources
            ],
            output_hash=result.output_hash if result else "",
            result_summary=detail or (result.summary if result else ""),
            cost_usd=result.cost_usd if result else ZERO,
            budget_remaining_usd=(
                self.budget.balance_usd
                if budget_remaining_usd is None
                else budget_remaining_usd
            ),
            dry_run=bool(result.dry_run) if result else self.dry_run,
            reconciliation_outcome=reconciliation_outcome,
            reconciled_by=reconciled_by,
            reconciled_at=reconciled_at,
            reconciliation_note=reconciliation_note,
        )

    def _make_authorization_reconciliation_record(
        self,
        authority: dict,
        status: ResultStatus,
        evidence_cost: Decimal,
        outcome: str,
        reconciled_by: str,
        reconciled_at: str,
        note: str,
    ) -> EvidenceRecord:
        executed = outcome != "not_executed"
        return EvidenceRecord(
            request_id=authority["request_id"],
            action_id=authority["action_id"],
            decision=authority["decision"],
            result_status=status,
            agent_runner=authority.get("agent_runner", ""),
            model_id=authority.get("model_id", ""),
            user_id=authority.get("user_id", ""),
            workspace_id=authority.get("workspace_id", ""),
            tool_name=authority.get("tool_name", ""),
            target=authority.get("target", ""),
            side_effect_level=authority.get("side_effect_level", "none"),
            policy_ids=list(authority.get("policy_ids", [])),
            policy_version=authority.get("policy_version", ""),
            ruleset_hash=authority.get("ruleset_hash", ""),
            decision_reason=authority.get("decision_reason", ""),
            decision_inputs=dict(authority.get("decision_inputs", {})),
            payload_hash=authority.get("payload_hash", ""),
            authorization_hash=authority["authorization_hash"],
            payload_trust=authority.get("payload_trust", "derived"),
            input_refs=list(authority.get("input_refs", [])),
            output_hash=(
                sha256_of({"operator_reconciled": True, "outcome": outcome})
                if executed
                else ""
            ),
            result_summary=f"operator reconciliation: {outcome}",
            cost_usd=evidence_cost,
            budget_remaining_usd=None,
            dry_run=bool(authority.get("dry_run", False)),
            reconciliation_outcome=outcome,
            reconciled_by=reconciled_by,
            reconciled_at=reconciled_at,
            reconciliation_note=note,
        )

    @_authority_entrypoint
    def recover_operation(self) -> JournalOperation | None:
        operation = self.operation_journal.active()
        if operation is not None:
            self._recover_operation(operation)
        return operation

    def _recover_operation(self, operation: JournalOperation) -> None:
        chain = self.evidence.verify()
        if not chain.ok:
            raise EvidenceError(
                "refusing journal recovery with broken evidence chain: " + chain.detail
            )
        payload = operation.payload
        record = EvidenceRecord(**payload["evidence"])
        if record.record_hash or record.previous_record_hash:
            raise ValueError("journal evidence must be an unsealed prepared record")
        reserved = money(payload.get("expected_usd", payload.get("reserved_usd", "0")))
        if operation.kind == "approval_create":
            approval = PendingApproval(**payload["approval"])
            if reserved > ZERO:
                self.budget.ensure_reservation(
                    reserved, approval.request_id, approval.action_id
                )
            self.approvals.create_prepared(approval)
        elif operation.kind == "approval_reject":
            self._validate_journaled_approval(payload, reserved)
            self.approvals.ensure_rejected(
                payload["approval_id"],
                payload["decided_by"],
                payload["note"],
                attestation=payload.get("attestation"),
            )
            if reserved > ZERO:
                self.budget.ensure_release(
                    reserved, payload["request_id"], payload["action_id"]
                )
        elif operation.kind == "approval_expire":
            self._validate_journaled_approval(payload, reserved)
            self.approvals.expire_one(payload["approval_id"])
            if reserved > ZERO:
                self.budget.ensure_release(
                    reserved, payload["request_id"], payload["action_id"]
                )
        elif operation.kind == "authorization_reconcile":
            subject = AuthorizationReconciliationSubject(**payload["authority"])
            authority = self.evidence.get(subject.authority_record_id)
            if authority is None:
                raise ValueError(
                    f"unknown authorization evidence {subject.authority_record_id}"
                )
            if AuthorizationReconciliationSubject.from_record(authority) != subject:
                raise ValueError("authorization evidence conflicts with journal")
            if self.approvals.for_action(subject.action_id):
                raise ApprovalError("journaled authorization belongs to an approval")
            self._require_authorization_reconciliation_identity(
                subject,
                payload["outcome"],
                payload["reconciled_by"],
                payload["note"],
                payload.get("attestation"),
            )
            terminal = self._authorization_terminal(subject)
            if terminal is not None and terminal.get("record_id") != record.record_id:
                raise ValueError("authorization has conflicting terminal evidence")
            self.budget.reconcile_reservation(
                reserved,
                subject.request_id,
                subject.action_id,
                payload["outcome"],
                payload["reconciled_by"],
                payload["note"],
                authority_record_id=subject.authority_record_id,
                authority_record_hash=subject.authority_record_hash,
                attestation=payload.get("attestation"),
            )
        elif operation.kind == "execution_complete":
            subject = ExecutionCompletionSubject(**payload["authority"])
            authority = self.evidence.get(subject.authority_record_id)
            if authority is None:
                raise ValueError(
                    f"unknown completion authority {subject.authority_record_id}"
                )
            if ExecutionCompletionSubject.from_record(authority) != subject:
                raise ValueError("completion authority conflicts with journal")
            approval_id = payload["approval_id"]
            if approval_id:
                approval = self.approvals.get(approval_id)
                if approval is None:
                    raise ApprovalError(f"unknown approval {approval_id}")
                if (
                    approval.action_id != subject.action_id
                    or approval.request_id != subject.request_id
                    or approval.authorization_hash != subject.authorization_hash
                ):
                    raise ApprovalError(
                        "journaled completion does not match approval authority"
                    )
                if approval.status not in {"executing", "consumed"}:
                    raise ApprovalError(
                        f"approval {approval_id} is {approval.status}, not recoverable"
                    )
                if approval.status == "consumed" and (
                    approval.execution_record_id != record.record_id
                ):
                    raise ApprovalError(
                        "consumed approval references different completion evidence"
                    )
                if approval.reconciliation_outcome:
                    raise ApprovalError(
                        "approval has operator reconciliation in progress"
                    )
                if self.approvals.operator_trust is not None:
                    identity = self.approvals.decision_identity(approval)
                    if not identity.ok:
                        raise ApprovalError(
                            "operator identity verification failed: " + identity.detail
                        )
            elif self.approvals.for_action(subject.action_id):
                raise ApprovalError(
                    "approval-free completion belongs to an approval action"
                )
            terminal = self._authorization_terminal(subject)
            if terminal is not None and terminal.get("record_id") != record.record_id:
                raise ValueError(
                    "completion authority has conflicting terminal evidence"
                )
            if payload["budget_disposition"] == "settle":
                self.budget.ensure_settlement(
                    reserved,
                    payload["actual_usd"],
                    subject.request_id,
                    subject.action_id,
                    record.record_id,
                )
            elif self.budget.reservation_for(subject.action_id) > ZERO:
                raise ValueError("no-budget completion has a live reservation")
            self.evidence.append_idempotent(record)
            if approval_id:
                self.approvals.ensure_consumed(approval_id, record.record_id)
            self.operation_journal.complete(operation.operation_id)
            return
        else:
            raise ValueError(f"unsupported journal operation: {operation.kind}")
        self.evidence.append_idempotent(record)
        self.operation_journal.complete(operation.operation_id)

    def _require_authorization_reconciliation_identity(
        self,
        subject: AuthorizationReconciliationSubject,
        outcome: str,
        reconciled_by: str,
        note: str,
        attestation: dict | None,
    ) -> None:
        trust = self.approvals.operator_trust
        if attestation is not None and trust is None:
            raise OperatorIdentityError(
                "trusted operator keys are required to store an attestation"
            )
        if trust is not None:
            trust.require_authorization_reconciliation(
                attestation,
                subject,
                outcome=outcome,
                operator=reconciled_by,
                note=note,
            )

    def _authorization_terminal(
        self, subject: AuthorizationReconciliationSubject
    ) -> dict | None:
        terminal_statuses = {
            ResultStatus.SUCCEEDED.value,
            ResultStatus.FAILED.value,
            ResultStatus.BLOCKED.value,
            ResultStatus.REJECTED.value,
            ResultStatus.EXPIRED.value,
            ResultStatus.NOT_EXECUTED.value,
        }
        return next(
            (
                item
                for item in reversed(self.evidence.by_action(subject.action_id))
                if item.get("authorization_hash") == subject.authorization_hash
                and item.get("result_status") in terminal_statuses
            ),
            None,
        )

    @staticmethod
    def _validate_existing_authorization_reconciliation(
        terminal: dict,
        outcome: str,
        reconciled_by: str,
        note: str,
    ) -> None:
        observed = {
            ResultStatus.SUCCEEDED.value: "succeeded",
            ResultStatus.FAILED.value: "failed",
            ResultStatus.NOT_EXECUTED.value: "not_executed",
        }.get(terminal.get("result_status"))
        if observed != outcome:
            raise ValueError(
                "operator outcome conflicts with existing terminal evidence"
            )
        if (
            terminal.get("reconciliation_outcome") != outcome
            or terminal.get("reconciled_by") != reconciled_by
            or terminal.get("reconciliation_note") != note
        ):
            raise ValueError(
                "authorization reconciliation already exists with different input"
            )

    def _validate_journaled_approval(
        self, payload: dict, reserved: Decimal
    ) -> PendingApproval:
        approval = self.approvals.get(payload["approval_id"])
        if approval is None:
            raise ApprovalError(f"unknown approval {payload['approval_id']}")
        if (
            approval.action_id != payload["action_id"]
            or approval.request_id != payload["request_id"]
            or money(approval.reserved_usd) != reserved
        ):
            raise ApprovalError(
                f"approval {approval.approval_id} conflicts with journal bindings"
            )
        return approval

    def _context(self, request: HarnessRequest) -> dict:
        return {
            "sensitivity": request.sensitivity.value,
            "task_type": request.task_type,
            "workspace_id": request.workspace_id,
        }

    def _require_execution_enabled(self) -> None:
        if self.execution_disabled:
            raise RuntimeError(
                "operator-control harness cannot execute or authorize tool actions"
            )

    def _spec_cost(self, action: ProposedAction) -> Decimal:
        spec = self.tools.spec(action.tool_name)
        return spec.cost_estimate_usd if spec else ZERO

    def _release_reservation(self, approval: PendingApproval) -> None:
        if self.budget.reservation_for(approval.action_id) > ZERO:
            self.budget.release(approval.request_id, approval.action_id)


def build_harness(
    workdir: str | Path,
    adapter: AgentAdapter,
    policy_packs: list[str] | None = None,
    starting_budget_usd: MoneyLike = "25",
    dry_run: bool = False,
    tools: ToolRegistry | None = None,
    workspace_root: str | Path | None = None,
    authority_context: dict | None = None,
    runtime_artifact_assurance=None,
    launch_envelope_assurance=None,
    trusted_operator_keys: list[str] | None = None,
    _operator_control: bool = False,
) -> Harness:
    from ..control_plane_isolation import (
        ControlPlaneIsolationStateStore,
        build_control_plane_isolation,
    )
    from ..tools.builtin import default_registry

    state_storage = prepare_state_storage(workdir)
    state_root = state_storage.root
    validate_external_trust_specs(trusted_operator_keys or [], state_root)
    authority_lock = AuthorityTransactionLock(state_root / "authority.lock")
    allowed_workspace = (
        Path(workspace_root) if workspace_root is not None else Path.cwd() / "workspace"
    )
    registry = tools or default_registry(
        dry_run=dry_run,
        workspace_root=allowed_workspace,
    )
    control_plane_isolation = build_control_plane_isolation(
        registry.workspace_root,
        state_root,
    )
    registry._protect_roots(control_plane_isolation.protected_roots)
    policy = PolicyEngine.default(
        policy_packs,
        additional_known_tools=(registry.names() if tools is not None else None),
        authority_inputs={
            "tool_registry": [
                spec.authority_dict()
                for spec in sorted(registry.specs(), key=lambda item: item.name)
            ],
            "workspace_root_hash": sha256_of(str(registry.workspace_root)),
            "dry_run": dry_run,
            "adapter": authority_context or {},
            "state_storage": state_storage.authority_dict(),
            "control_plane_isolation": control_plane_isolation.authority_dict(),
        },
    )
    with authority_lock.acquire():
        require_state_storage_unchanged(state_storage)
        trust_store = OperatorTrustStateStore(state_root / "operator_trust.json")
        operator_trust = trust_store.preview_for_authority(trusted_operator_keys or [])
        trust_resolved = False
        if trust_store.get() is None and operator_trust is not None:
            # Enroll signed-required mode before the first profile write. A crash
            # between the two files must never permit an unsigned restart.
            operator_trust = trust_store.resolve_for_authority(
                trusted_operator_keys or []
            )
            trust_resolved = True
        profile_store = AuthorityProfileStore(state_root / "authority_profile.json")
        if _operator_control:
            profile_state = profile_store.get()
            if profile_state is None:
                raise RuntimeError(
                    "authority profile is not enrolled; start the owning authority "
                    "runtime once first"
                )
            profile_state.verify(operator_trust)
            audit_profile_hash = profile_state.profile_hash
        else:
            profile_store.resolve_for_authority(policy.ruleset_hash, operator_trust)
            audit_profile_hash = policy.ruleset_hash
            StateStorageStateStore(state_root / "state_storage.json").record(
                policy.ruleset_hash, state_storage
            )
            ControlPlaneIsolationStateStore(
                state_root / "control_plane_isolation.json"
            ).record(policy.ruleset_hash, control_plane_isolation)
        if runtime_artifact_assurance is not None:
            from ..runtime_artifacts import RuntimeArtifactStateStore

            RuntimeArtifactStateStore(state_root / "runtime_artifacts.json").record(
                policy.ruleset_hash, runtime_artifact_assurance
            )
        if launch_envelope_assurance is not None:
            from ..launch_envelope import LaunchEnvelopeStateStore

            LaunchEnvelopeStateStore(state_root / "launch_envelope.json").record(
                policy.ruleset_hash, launch_envelope_assurance
            )
        if not trust_resolved:
            operator_trust = trust_store.resolve_for_authority(
                trusted_operator_keys or []
            )
        harness = Harness(
            policy=policy,
            tools=registry,
            evidence=EvidenceStore(state_root / "evidence.jsonl"),
            approvals=ApprovalStore(
                state_root / "approvals.json", operator_trust=operator_trust
            ),
            budget=BudgetLedger(
                state_root / "budget.json",
                starting_balance_usd=starting_budget_usd,
            ),
            adapter=adapter,
            state_integrity=StateIntegrityAuditor(
                state_root,
                operator_trust=operator_trust,
                authority_profile_hash=audit_profile_hash,
            ),
            operation_journal=OperationJournal(state_root / "operation_journal.json"),
            authority_lock=authority_lock,
            dry_run=dry_run,
            execution_disabled=_operator_control,
        )
        harness.recover_operation()
        harness.reconcile_expired_approvals()
    return harness
