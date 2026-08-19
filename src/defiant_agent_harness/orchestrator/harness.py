"""The deterministic local control loop."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from ..adapters.base import AgentAdapter, ToolCall, ToolCallOutcome
from ..approvals.store import ApprovalError, ApprovalStore, PendingApproval
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
from ..evidence.store import EvidenceStore
from ..money import ZERO, MoneyLike
from ..policy.engine import PolicyEngine
from ..state_integrity import StateIntegrityAuditor
from ..tools.registry import ToolContractError, ToolRegistry, ToolResult


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
        dry_run: bool = False,
    ):
        self.policy = policy
        self.tools = tools
        self.evidence = evidence
        self.approvals = approvals
        self.budget = budget
        self.adapter = adapter
        self.state_integrity = state_integrity
        self.dry_run = dry_run

    # -- entry points -------------------------------------------------

    def run(self, request: HarnessRequest) -> list[ActionOutcome]:
        return [
            self.handle_call(call, request)
            for call in self.adapter.propose(request.task)
        ]

    def handle_call(
        self,
        call: ToolCall,
        request: HarnessRequest,
        *,
        execution_owner: str = "",
        execution_key: str = "",
    ) -> ActionOutcome:
        action = self.adapter.to_action(call, request.request_id)
        return self._handle(
            action,
            request,
            execution_owner=execution_owner,
            execution_key=execution_key,
        )

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
            self.budget.reserve(estimate, request.request_id, action.action_id)

        if decision.decision is Decision.APPROVAL_REQUIRED:
            try:
                pending = self.approvals.create(
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
            except Exception:
                if estimate > ZERO:
                    self.budget.release(request.request_id, action.action_id)
                raise
            record = self._record(
                action,
                request,
                decision,
                ResultStatus.PENDING_APPROVAL,
                detail=f"held for approval {pending.approval_id}",
            )
            return ActionOutcome(
                action,
                decision,
                ResultStatus.PENDING_APPROVAL,
                record.record_id,
                approval_id=pending.approval_id,
                detail=decision.reason,
            )

        if external_execution:
            return self._authorize_external(
                action,
                request,
                decision,
            )

        return self._execute(action, request, decision, estimate, approved_by=None)

    # -- durable approval resume ------------------------------------

    def resume_external(self, approval_id: str) -> ActionOutcome:
        """Authorize an approved exact retry for execution by another runtime."""
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
        if estimate > ZERO:
            self.budget.settle(ZERO, request.request_id, action.action_id)
        record = self._record(
            action,
            request,
            decision,
            ResultStatus.SUCCEEDED,
            approved_by=approved_by,
            result=result,
            detail=result.summary,
        )
        if approval_id:
            self.approvals.mark_consumed(approval_id, record.record_id)
        return ActionOutcome(
            action,
            decision,
            ResultStatus.SUCCEEDED,
            record.record_id,
            approval_id=approval_id,
            result=result,
            detail=result.summary,
        )

    def resume(
        self,
        approval_id: str,
        approved: bool,
        decided_by: str,
        note: str = "",
    ) -> ActionOutcome:
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

        if pending.status == "pending":
            pending = self.approvals.decide(approval_id, approved, decided_by, note)
        elif not approved:
            raise ApprovalError("an approved action cannot later be rejected")

        if not approved:
            self._release_reservation(pending)
            record = self._record(
                action,
                request,
                original_decision,
                ResultStatus.REJECTED,
                approved_by=decided_by,
                detail=note or "rejected by human reviewer",
            )
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
        self.approvals.mark_consumed(approval_id, outcome.evidence_record_id)
        return outcome

    def reconcile_expired_approvals(self) -> list[ActionOutcome]:
        self.state_integrity.require_safe()
        outcomes: list[ActionOutcome] = []
        for approval in self.approvals.expire_due():
            try:
                action = approval.held_action()
                request = approval.held_request()
                decision = approval.held_decision()
            except ApprovalError:
                # Legacy/unresumable records remain expired and inert.
                continue
            self._release_reservation(approval)
            record = self._record(
                action,
                request,
                decision,
                ResultStatus.EXPIRED,
                detail=f"approval expired at {approval.expires_at}",
            )
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

    def reconcile_execution(
        self,
        approval_id: str,
        outcome: str,
        reconciled_by: str,
        note: str,
    ) -> ActionOutcome:
        """Terminally reconcile an approval stranded in ``executing``.

        The approval store records the exact operator input first. Budget and
        evidence mutations are then individually idempotent, so repeating the
        same command after a crash completes the transaction without replaying
        the tool or charging twice.
        """
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

        if estimate > ZERO:
            actual = result.cost_usd if result.status == "succeeded" else ZERO
            self.budget.settle(actual, request.request_id, action.action_id)

        status = (
            ResultStatus.SUCCEEDED
            if result.status == "succeeded"
            else ResultStatus.FAILED
        )
        final = self._record(
            action,
            request,
            decision,
            status,
            approved_by=approved_by,
            result=result,
            detail=result.summary,
        )
        return ActionOutcome(
            action,
            decision,
            status,
            final.record_id,
            approval_id=approval_id,
            result=result,
            detail=result.summary,
        )

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
        record = EvidenceRecord(
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
            budget_remaining_usd=self.budget.balance_usd,
            dry_run=bool(result.dry_run) if result else self.dry_run,
            reconciliation_outcome=reconciliation_outcome,
            reconciled_by=reconciled_by,
            reconciled_at=reconciled_at,
            reconciliation_note=reconciliation_note,
        )
        return self.evidence.append(record)

    def _context(self, request: HarnessRequest) -> dict:
        return {
            "sensitivity": request.sensitivity.value,
            "task_type": request.task_type,
            "workspace_id": request.workspace_id,
        }

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
) -> Harness:
    from ..tools.builtin import default_registry

    state_root = Path(workdir)
    state_root.mkdir(parents=True, exist_ok=True)
    allowed_workspace = (
        Path(workspace_root) if workspace_root is not None else Path.cwd() / "workspace"
    )
    registry = tools or default_registry(
        dry_run=dry_run,
        workspace_root=allowed_workspace,
    )
    harness = Harness(
        policy=PolicyEngine.default(
            policy_packs,
            additional_known_tools=registry.names() if tools is not None else None,
            authority_inputs={
                "tool_registry": [
                    spec.authority_dict()
                    for spec in sorted(registry.specs(), key=lambda item: item.name)
                ],
                "workspace_root_hash": sha256_of(str(registry.workspace_root)),
                "dry_run": dry_run,
                "adapter": authority_context or {},
            },
        ),
        tools=registry,
        evidence=EvidenceStore(state_root / "evidence.jsonl"),
        approvals=ApprovalStore(state_root / "approvals.json"),
        budget=BudgetLedger(
            state_root / "budget.json",
            starting_balance_usd=starting_budget_usd,
        ),
        adapter=adapter,
        state_integrity=StateIntegrityAuditor(state_root),
        dry_run=dry_run,
    )
    harness.reconcile_expired_approvals()
    return harness
