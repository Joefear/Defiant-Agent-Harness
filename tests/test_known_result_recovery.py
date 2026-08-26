from __future__ import annotations

import json
from decimal import Decimal

import pytest

from defiant_agent_harness.adapters.base import ToolCall
from defiant_agent_harness.adapters.mock import MockAgentAdapter, SCRIPTS
from defiant_agent_harness import contracts as contracts_module
from defiant_agent_harness.budgets.ledger import BudgetError, BudgetLedger
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import HarnessRequest, ResultStatus, SideEffect
from defiant_agent_harness.evidence.store import EvidenceStore
from defiant_agent_harness.evidence.signing import generate_key_pair
from defiant_agent_harness.operation_journal import OperationJournal
from defiant_agent_harness.operator_identity import (
    DECISION_PURPOSE,
    sign_operator_action,
)
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.state_integrity import StateIntegrityAuditor
from defiant_agent_harness.tools.registry import (
    ToolRegistry,
    ToolResult,
    ToolResultLimitError,
    ToolSpec,
)


class SimulatedCrash(RuntimeError):
    pass


def _request() -> HarnessRequest:
    return HarnessRequest(
        task="known result recovery",
        user_id="operator",
        workspace_id="workspace",
    )


def _direct_registry(counter: dict[str, int], *, status="succeeded", cost="2"):
    registry = ToolRegistry()

    def execute(_action):
        counter["calls"] += 1
        return ToolResult(
            status=status,
            summary=f"fixture {status}",
            output={"fixture": status},
            cost_usd=Decimal(cost),
        )

    registry.register(
        ToolSpec(
            "summarize",
            SideEffect.NONE,
            "Summarize fixture input.",
            cost_estimate_usd=Decimal("5"),
        ),
        execute,
    )
    return registry


def _direct_harness(state, counter, *, status="succeeded", cost="2"):
    adapter = MockAgentAdapter(
        script=[ToolCall(name="summarize", arguments={"text": "fixture"})]
    )
    return build_harness(
        state,
        adapter,
        starting_budget_usd="20",
        tools=_direct_registry(counter, status=status, cost=cost),
    )


def _approval_registry(counter: dict[str, int]):
    registry = ToolRegistry()

    def execute(_action):
        counter["calls"] += 1
        return ToolResult(
            status="succeeded",
            summary="provider charged seven dollars",
            output={"receipt": "fixture"},
            cost_usd=Decimal("7"),
        )

    registry.register(
        ToolSpec(
            "spend",
            SideEffect.SPEND,
            "Spend against a fixture provider.",
            cost_estimate_usd=Decimal("250"),
        ),
        execute,
    )
    return registry


def _approval_harness(state, counter, *, trusted_keys=None):
    return build_harness(
        state,
        MockAgentAdapter(script=SCRIPTS["overspend"]),
        starting_budget_usd="500",
        tools=_approval_registry(counter),
        trusted_operator_keys=trusted_keys,
    )


def _budget_entries(state, kind):
    budget = json.loads((state / "budget.json").read_text(encoding="utf-8"))
    return [entry for entry in budget["entries"] if entry["kind"] == kind]


def _oversized_result_registry(monkeypatch, counter, *, approval_backed=False):
    registry = ToolRegistry()
    tool_name = "spend" if approval_backed else "summarize"
    side_effect = SideEffect.SPEND if approval_backed else SideEffect.NONE
    estimate = Decimal("250") if approval_backed else Decimal("5")

    def execute(_action):
        counter["calls"] += 1
        with monkeypatch.context() as bounded:
            bounded.setattr(contracts_module, "MAX_ACTION_HASH_SCALAR_CHARACTERS", 4)
            return ToolResult(
                status="succeeded",
                summary="provider reported success",
                output="12345-secret-result",
                cost_usd=Decimal("7"),
            )

    registry.register(
        ToolSpec(
            tool_name,
            side_effect,
            "Return a deliberately oversized post-execution result.",
            cost_estimate_usd=estimate,
        ),
        execute,
    )
    return registry


def test_oversized_direct_result_preserves_open_authorization_for_reconciliation(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    counter = {"calls": 0}
    harness = build_harness(
        state,
        MockAgentAdapter(
            script=[ToolCall(name="summarize", arguments={"text": "fixture"})]
        ),
        starting_budget_usd="20",
        tools=_oversized_result_registry(monkeypatch, counter),
    )

    with pytest.raises(ToolResultLimitError) as exc:
        harness.run(_request())

    assert "secret-result" not in str(exc.value)
    assert counter["calls"] == 1
    assert harness.budget.summary()["reserved_usd"] == "5"
    [authorization] = harness.evidence.records()
    assert authorization["result_status"] == "skipped"
    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()
    assert report.status == "recovery_required"
    assert report.counts["authorization_reconciliations_required"] == 1
    assert snapshot["reconciliation_required"] is True
    assert "secret-result" not in json.dumps(snapshot)


def test_oversized_approval_result_preserves_execution_and_reservation(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    counter = {"calls": 0}
    harness = build_harness(
        state,
        MockAgentAdapter(script=SCRIPTS["overspend"]),
        starting_budget_usd="500",
        tools=_oversized_result_registry(
            monkeypatch,
            counter,
            approval_backed=True,
        ),
    )
    [pending] = harness.run(_request())

    with pytest.raises(ToolResultLimitError):
        harness.resume(pending.approval_id, True, "alice", "approved exact spend")

    approval = harness.approvals.get(pending.approval_id)
    assert approval is not None and approval.status == "executing"
    assert counter["calls"] == 1
    assert harness.budget.summary()["reserved_usd"] == "250"
    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()
    assert report.status == "recovery_required"
    assert snapshot["reconciliation_required"] is True
    assert snapshot["approvals"]["reconciliation_required_count"] == 1


def test_oversized_external_completion_preserves_open_authorization(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    counter = {"calls": 0}
    harness = _direct_harness(state, counter)
    request = _request()
    authorized = harness.preflight_external_call(
        ToolCall(name="summarize", arguments={"text": "external fixture"}),
        request,
        execution_owner="fixture:external-result-limit",
        execution_key="fixture-result-limit",
    )

    with monkeypatch.context() as bounded:
        bounded.setattr(contracts_module, "MAX_ACTION_HASH_SCALAR_CHARACTERS", 4)
        with pytest.raises(ToolResultLimitError):
            harness.complete_external_call(
                authorized.action,
                request,
                authorized.decision,
                tool_response="12345-secret-result",
            )

    assert counter["calls"] == 0
    assert harness.budget.summary()["reserved_usd"] == "5"
    report = StateIntegrityAuditor(state).audit()
    assert report.status == "recovery_required"
    assert report.counts["authorization_reconciliations_required"] == 1


def test_restart_recovers_known_result_before_budget_without_reexecution(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    counter = {"calls": 0}
    harness = _direct_harness(state, counter)

    def crash_before_budget(*_args, **_kwargs):
        raise SimulatedCrash("before settlement")

    monkeypatch.setattr(harness.budget, "ensure_settlement", crash_before_budget)
    with pytest.raises(SimulatedCrash):
        harness.run(_request())

    operation = OperationJournal(state / "operation_journal.json").active()
    assert operation is not None and operation.kind == "execution_complete"
    assert counter["calls"] == 1
    assert len(EvidenceStore(state / "evidence.jsonl").records()) == 1
    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()
    assert report.status == "recovery_required"
    assert report.counts["authorization_reconciliations_required"] == 0
    assert not any(
        issue.code == "authorization_reconciliation_required" for issue in report.issues
    )
    assert snapshot["reconciliation_required"] is False
    assert snapshot["authorization_reconciliation"]["required_count"] == 0

    recovered = _direct_harness(state, counter)

    assert counter["calls"] == 1
    assert OperationJournal(state / "operation_journal.json").active() is None
    assert recovered.budget.summary()["total_spent_usd"] == "2"
    assert len(_budget_entries(state, "debit")) == 1
    assert len(recovered.evidence.records()) == 2


def test_restart_recovers_after_budget_without_double_debit(tmp_path, monkeypatch):
    state = tmp_path / "state"
    counter = {"calls": 0}
    harness = _direct_harness(state, counter)

    def crash_before_evidence(_record):
        raise SimulatedCrash("after settlement")

    monkeypatch.setattr(harness.evidence, "append_idempotent", crash_before_evidence)
    with pytest.raises(SimulatedCrash):
        harness.run(_request())

    assert BudgetLedger(state / "budget.json").summary()["total_spent_usd"] == "2"
    assert len(_budget_entries(state, "debit")) == 1
    assert StateIntegrityAuditor(state).audit().status == "recovery_required"

    recovered = _direct_harness(state, counter)

    assert counter["calls"] == 1
    assert recovered.budget.summary()["total_spent_usd"] == "2"
    assert len(_budget_entries(state, "debit")) == 1
    assert len(recovered.evidence.records()) == 2


def test_restart_recognizes_terminal_evidence_without_duplicate(tmp_path, monkeypatch):
    state = tmp_path / "state"
    counter = {"calls": 0}
    harness = _direct_harness(state, counter)

    def crash_before_complete(_operation_id):
        raise SimulatedCrash("after evidence")

    monkeypatch.setattr(harness.operation_journal, "complete", crash_before_complete)
    with pytest.raises(SimulatedCrash):
        harness.run(_request())

    assert len(EvidenceStore(state / "evidence.jsonl").records()) == 2

    recovered = _direct_harness(state, counter)

    assert counter["calls"] == 1
    assert len(recovered.evidence.records()) == 2
    assert OperationJournal(state / "operation_journal.json").active() is None


def test_approval_completion_recovers_consumption_and_is_not_manual_reconciliation(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    counter = {"calls": 0}
    harness = _approval_harness(state, counter)
    [pending] = harness.run(_request())

    def crash_before_consumption(*_args, **_kwargs):
        raise SimulatedCrash("before approval consumption")

    monkeypatch.setattr(harness.approvals, "ensure_consumed", crash_before_consumption)
    with pytest.raises(SimulatedCrash):
        harness.resume(pending.approval_id, True, "alice", "approved")

    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()
    projected = next(
        item
        for item in snapshot["approvals"]["actionable"]
        if item["approval_id"] == pending.approval_id
    )
    assert report.status == "recovery_required"
    assert any(
        issue.code == "execution_completion_recovery_required"
        for issue in report.issues
    )
    assert not any(
        issue.code == "execution_recovery_required" for issue in report.issues
    )
    assert snapshot["reconciliation_required"] is False
    assert snapshot["approvals"]["reconciliation_required_count"] == 0
    assert projected["reconciliation_state"] == "known_result_recovery"

    recovered = _approval_harness(state, counter)

    approval = recovered.approvals.get(pending.approval_id)
    assert approval is not None and approval.status == "consumed"
    assert counter["calls"] == 1
    assert recovered.budget.summary()["total_spent_usd"] == "7"
    assert StateIntegrityAuditor(state).audit().status == "healthy"


def test_failed_result_without_actual_cost_charges_conservative_estimate(tmp_path):
    state = tmp_path / "state"
    counter = {"calls": 0}
    harness = _direct_harness(state, counter, status="failed", cost="0")

    [outcome] = harness.run(_request())

    assert outcome.status is ResultStatus.FAILED
    assert outcome.result is not None and outcome.result.cost_usd == Decimal("5")
    assert harness.budget.summary()["total_spent_usd"] == "5"
    evidence = harness.evidence.get(outcome.evidence_record_id)
    assert evidence is not None and evidence["cost_usd"] == "5"


def test_signed_approval_completion_revalidates_identity_during_recovery(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    private = tmp_path / "operator-private.pem"
    public = tmp_path / "operator-public.pem"
    passphrase = b"known-result-test-passphrase"
    generate_key_pair(private, public, passphrase)
    trusted_keys = [f"alice={public}"]
    counter = {"calls": 0}
    harness = _approval_harness(state, counter, trusted_keys=trusted_keys)
    [pending] = harness.run(_request())
    approval = harness.approvals.get(pending.approval_id)
    assert approval is not None
    attestation = sign_operator_action(
        approval,
        private,
        passphrase,
        purpose=DECISION_PURPOSE,
        outcome="approved",
        operator="alice",
        note="approved exact fixture spend",
    )

    def crash_before_consumption(*_args, **_kwargs):
        raise SimulatedCrash("before signed approval consumption")

    monkeypatch.setattr(harness.approvals, "ensure_consumed", crash_before_consumption)
    with pytest.raises(SimulatedCrash):
        harness.resume(
            pending.approval_id,
            True,
            "alice",
            "approved exact fixture spend",
            attestation=attestation,
        )

    recovered = _approval_harness(state, counter, trusted_keys=trusted_keys)

    stored = recovered.approvals.get(pending.approval_id)
    assert stored is not None and stored.status == "consumed"
    assert stored.decision_attestation == attestation
    assert counter["calls"] == 1


def test_external_completion_uses_known_result_journal_and_conservative_cost(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    counter = {"calls": 0}
    harness = _direct_harness(state, counter)
    request = _request()
    call = ToolCall(name="summarize", arguments={"text": "external fixture"})
    authorized = harness.preflight_external_call(
        call,
        request,
        execution_owner="fixture:external",
        execution_key="fixture-key",
    )

    def crash_before_evidence(_record):
        raise SimulatedCrash("external result persisted before evidence")

    monkeypatch.setattr(harness.evidence, "append_idempotent", crash_before_evidence)
    with pytest.raises(SimulatedCrash):
        harness.complete_external_call(
            authorized.action,
            request,
            authorized.decision,
            tool_response={"content": "fixture response"},
        )

    operation = OperationJournal(state / "operation_journal.json").active()
    assert operation is not None and operation.kind == "execution_complete"
    assert counter["calls"] == 0
    assert BudgetLedger(state / "budget.json").summary()["total_spent_usd"] == "5"

    recovered = _direct_harness(state, counter)

    assert counter["calls"] == 0
    assert recovered.budget.summary()["total_spent_usd"] == "5"
    terminal = recovered.evidence.records()[-1]
    assert terminal["result_status"] == "succeeded"
    assert terminal["cost_usd"] == "5"


def test_tampered_completion_authority_refuses_recovery_before_budget(tmp_path):
    state = tmp_path / "state"
    counter = {"calls": 0}
    harness = _direct_harness(state, counter)

    def crash_before_budget(*_args, **_kwargs):
        raise SimulatedCrash("before settlement")

    harness.budget.ensure_settlement = crash_before_budget
    with pytest.raises(SimulatedCrash):
        harness.run(_request())

    journal_path = state / "operation_journal.json"
    journal = json.loads(journal_path.read_text(encoding="utf-8"))
    journal["active"]["payload"]["authority"]["authority_record_hash"] = (
        "sha256:" + "f" * 64
    )
    from defiant_agent_harness.contracts import sha256_of

    journal["active"]["payload_hash"] = sha256_of(journal["active"]["payload"])
    journal_path.write_text(json.dumps(journal), encoding="utf-8")

    with pytest.raises(ValueError, match="conflicts with journal"):
        _direct_harness(state, counter)

    budget = BudgetLedger(state / "budget.json")
    assert budget.summary()["total_spent_usd"] == "0"
    assert budget.summary()["reserved_usd"] == "5"


def test_settlement_refuses_live_reservation_with_prior_disposition(tmp_path):
    path = tmp_path / "budget.json"
    ledger = BudgetLedger(path, starting_balance_usd="20")
    ledger.reserve("5", "req_conflict", "act_conflict")
    raw = json.loads(path.read_text(encoding="utf-8"))
    prior = dict(raw["entries"][-1])
    prior |= {
        "kind": "debit",
        "amount_usd": "2",
        "note": "reserved $5",
    }
    raw["entries"].append(prior)
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(BudgetError, match="live reservation conflicts"):
        ledger.ensure_settlement(
            "5", "2", "req_conflict", "act_conflict", "evd_conflict"
        )


def test_tampered_known_result_settlement_is_unsafe(tmp_path):
    state = tmp_path / "state"
    counter = {"calls": 0}
    harness = _direct_harness(state, counter)
    harness.run(_request())
    path = state / "budget.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    debit = next(entry for entry in raw["entries"] if entry["kind"] == "debit")
    debit["amount_usd"] = "3"
    path.write_text(json.dumps(raw), encoding="utf-8")

    report = StateIntegrityAuditor(state).audit()

    assert report.status == "unsafe"
    assert any(
        issue.code == "known_result_settlement_mismatch" for issue in report.issues
    )


def test_truncated_terminal_evidence_is_detected_from_settlement_marker(tmp_path):
    state = tmp_path / "state"
    counter = {"calls": 0}
    harness = _direct_harness(state, counter)
    harness.run(_request())
    evidence_path = state / "evidence.jsonl"
    [authorization, _terminal] = evidence_path.read_text(encoding="utf-8").splitlines()
    evidence_path.write_text(authorization + "\n", encoding="utf-8")

    report = StateIntegrityAuditor(state).audit()

    assert report.status == "unsafe"
    assert any(issue.code == "known_result_evidence_missing" for issue in report.issues)
