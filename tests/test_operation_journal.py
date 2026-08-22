from __future__ import annotations

import json

import pytest

from defiant_agent_harness.adapters.mock import MockAgentAdapter, SCRIPTS
from defiant_agent_harness.approvals.store import ApprovalStore
from defiant_agent_harness.budgets.ledger import BudgetLedger
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import HarnessRequest, sha256_of
from defiant_agent_harness.evidence.store import EvidenceStore
from defiant_agent_harness.evidence.signing import generate_key_pair
from defiant_agent_harness.operation_journal import (
    OperationJournal,
    OperationJournalError,
)
from defiant_agent_harness.operator_identity import (
    DECISION_PURPOSE,
    sign_operator_action,
)
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.state_integrity import StateIntegrityAuditor


class SimulatedCrash(RuntimeError):
    pass


PASSPHRASE = b"test-only journal operator passphrase"


def _harness(state, scenario="overspend"):
    return build_harness(
        state,
        MockAgentAdapter(script=SCRIPTS[scenario]),
        starting_budget_usd="500",
    )


def _request():
    return HarnessRequest(task="journal test", user_id="operator", workspace_id="ws")


def _entries(state, kind):
    raw = json.loads((state / "budget.json").read_text(encoding="utf-8"))
    return [entry for entry in raw["entries"] if entry["kind"] == kind]


def test_restart_recovers_crash_after_prepared_approval_was_stored(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)
    original = harness.approvals.create_prepared

    def crash_after_store(approval):
        original(approval)
        raise SimulatedCrash("after approval store")

    monkeypatch.setattr(harness.approvals, "create_prepared", crash_after_store)
    with pytest.raises(SimulatedCrash):
        harness.run(_request())

    operation = OperationJournal(state / "operation_journal.json").active()
    assert operation is not None and operation.kind == "approval_create"
    assert len(_entries(state, "reserve")) == 1
    assert len(ApprovalStore(state / "approvals.json").list_pending()) == 1
    assert EvidenceStore(state / "evidence.jsonl").records() == []

    _harness(state)

    assert OperationJournal(state / "operation_journal.json").active() is None
    assert len(_entries(state, "reserve")) == 1
    assert len(ApprovalStore(state / "approvals.json").list_pending()) == 1
    assert len(EvidenceStore(state / "evidence.jsonl").records()) == 1


def test_restart_recognizes_evidence_when_crash_precedes_journal_completion(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)
    original = harness.operation_journal.complete

    def crash_before_complete(operation_id):
        raise SimulatedCrash(operation_id)

    monkeypatch.setattr(harness.operation_journal, "complete", crash_before_complete)
    with pytest.raises(SimulatedCrash):
        harness.run(_request())

    before = EvidenceStore(state / "evidence.jsonl").records()
    assert len(before) == 1
    monkeypatch.setattr(harness.operation_journal, "complete", original)

    _harness(state)

    after = EvidenceStore(state / "evidence.jsonl").records()
    assert after == before
    assert len(_entries(state, "reserve")) == 1


def test_restart_finishes_rejection_after_reservation_was_released(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)
    [held] = harness.run(_request())
    original = harness.budget.ensure_release

    def crash_after_release(*args):
        original(*args)
        raise SimulatedCrash("after release")

    monkeypatch.setattr(harness.budget, "ensure_release", crash_after_release)
    with pytest.raises(SimulatedCrash):
        harness.resume(held.approval_id, False, "alice", "declined")

    rejected = ApprovalStore(state / "approvals.json").get(held.approval_id)
    assert rejected is not None and rejected.status == "rejected"
    assert len(_entries(state, "release")) == 1

    _harness(state)

    records = EvidenceStore(state / "evidence.jsonl").records()
    assert [record["result_status"] for record in records] == [
        "pending_approval",
        "rejected",
    ]
    assert len(_entries(state, "release")) == 1


def test_terminal_approval_with_exact_journal_reservation_is_recovery_required(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)
    [held] = harness.run(_request())

    def crash_before_release(*_args):
        raise SimulatedCrash("before release")

    monkeypatch.setattr(harness.budget, "ensure_release", crash_before_release)
    with pytest.raises(SimulatedCrash):
        harness.resume(held.approval_id, False, "alice", "declined")

    report = StateIntegrityAuditor(state).audit()
    assert report.status == "recovery_required"
    assert report.safe_to_execute
    assert not any(
        issue.code == "terminal_approval_has_reservation" for issue in report.issues
    )


def test_signed_rejection_recovery_revalidates_durable_operator_identity(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    private = tmp_path / "operator-private.pem"
    public = tmp_path / "operator-public.pem"
    generate_key_pair(private, public, PASSPHRASE)
    trusted_keys = [f"alice={public}"]
    harness = build_harness(
        state,
        MockAgentAdapter(script=SCRIPTS["overspend"]),
        starting_budget_usd="500",
        trusted_operator_keys=trusted_keys,
    )
    [held] = harness.run(_request())
    approval = harness.approvals.get(held.approval_id)
    assert approval is not None
    attestation = sign_operator_action(
        approval,
        private,
        PASSPHRASE,
        purpose=DECISION_PURPOSE,
        outcome="rejected",
        operator="alice",
        note="declined",
    )

    def crash_before_evidence(_record):
        raise SimulatedCrash("after signed rejection")

    monkeypatch.setattr(harness.evidence, "append_idempotent", crash_before_evidence)
    with pytest.raises(SimulatedCrash):
        harness.resume(
            held.approval_id,
            False,
            "alice",
            "declined",
            attestation=attestation,
        )

    recovered = build_harness(
        state,
        MockAgentAdapter(script=SCRIPTS["overspend"]),
        starting_budget_usd="500",
        trusted_operator_keys=trusted_keys,
    )
    rejected = recovered.approvals.get(held.approval_id)
    assert rejected is not None and rejected.status == "rejected"
    assert recovered.approvals.decision_identity(rejected).assurance == "signed_trusted"
    assert OperationJournal(state / "operation_journal.json").active() is None
    records = EvidenceStore(state / "evidence.jsonl").records()
    assert [record["result_status"] for record in records] == [
        "pending_approval",
        "rejected",
    ]
    assert len(_entries(state, "release")) == 1


def test_restart_finishes_expiry_without_double_release(tmp_path, monkeypatch):
    state = tmp_path / "state"
    harness = _harness(state)
    [held] = harness.run(_request())
    approval = harness.approvals.get(held.approval_id)
    assert approval is not None
    approval.expires_at = "2020-01-01T00:00:00Z"
    harness.approvals._save(approval)

    def crash_before_evidence(_record):
        raise SimulatedCrash("before evidence")

    monkeypatch.setattr(harness.evidence, "append_idempotent", crash_before_evidence)
    with pytest.raises(SimulatedCrash):
        harness.reconcile_expired_approvals()

    expired = ApprovalStore(state / "approvals.json").get(held.approval_id)
    assert expired is not None and expired.status == "expired"
    assert len(_entries(state, "release")) == 1

    _harness(state)

    records = EvidenceStore(state / "evidence.jsonl").records()
    assert [record["result_status"] for record in records] == [
        "pending_approval",
        "expired",
    ]
    assert len(_entries(state, "release")) == 1


def test_command_core_reports_active_journal_without_exposing_payload(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)
    original = harness.budget.ensure_reservation

    def crash_after_reservation(*args):
        original(*args)
        raise SimulatedCrash("after reservation")

    monkeypatch.setattr(harness.budget, "ensure_reservation", crash_after_reservation)
    with pytest.raises(SimulatedCrash):
        harness.run(_request())
    journal_before = (state / "operation_journal.json").read_bytes()

    snapshot = CommandCore(state).snapshot()
    projected = snapshot["operation_journal"]

    assert projected["active"] is True
    assert projected["kind"] == "approval_create"
    assert "payload" not in projected
    assert "merchant" not in json.dumps(snapshot)
    assert snapshot["state_integrity"]["status"] == "recovery_required"
    assert snapshot["state_integrity"]["safe_to_execute"] is True
    assert (state / "operation_journal.json").read_bytes() == journal_before


def test_tampered_journal_is_critical_and_authority_refuses_recovery(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    path = state / "operation_journal.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "defiant.operation_journal",
                "schema_version": "0.1.0",
                "active": {
                    "operation_id": "op_tampered",
                    "kind": "approval_create",
                    "prepared_at": "2026-08-21T00:00:00Z",
                    "payload": {"forged": True},
                    "payload_hash": "sha256:" + "0" * 64,
                },
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)

    report = StateIntegrityAuditor(state).audit()
    assert not report.safe_to_execute
    assert any(issue.code == "operation_journal_invalid" for issue in report.issues)
    with pytest.raises(OperationJournalError):
        _harness(state)


def test_structurally_invalid_journal_fails_even_with_matching_payload_hash(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    payload = {"forged": True}
    (state / "operation_journal.json").write_text(
        json.dumps(
            {
                "schema_name": "defiant.operation_journal",
                "schema_version": "0.1.0",
                "active": {
                    "operation_id": "op_forged",
                    "kind": "approval_create",
                    "prepared_at": "2026-08-21T00:00:00Z",
                    "payload": payload,
                    "payload_hash": sha256_of(payload),
                },
            }
        ),
        encoding="utf-8",
    )
    (state / "operation_journal.json").chmod(0o600)

    report = StateIntegrityAuditor(state).audit()
    assert not report.safe_to_execute
    assert any(issue.code == "operation_journal_invalid" for issue in report.issues)
    with pytest.raises(OperationJournalError):
        _harness(state)


def test_conflicting_partial_reservation_fails_closed_and_keeps_journal(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)

    def crash_before_reservation(*_args):
        raise SimulatedCrash("before reservation")

    monkeypatch.setattr(harness.budget, "ensure_reservation", crash_before_reservation)
    with pytest.raises(SimulatedCrash):
        harness.run(_request())

    journal = OperationJournal(state / "operation_journal.json")
    operation = journal.active()
    assert operation is not None
    approval = operation.payload["approval"]
    BudgetLedger(state / "budget.json").reserve(
        "1.00", "conflicting_request", approval["action_id"]
    )

    with pytest.raises(RuntimeError, match="conflicts with journal"):
        _harness(state)

    assert StateIntegrityAuditor(state).audit().status == "unsafe"
    assert journal.active() == operation
    assert EvidenceStore(state / "evidence.jsonl").records() == []


def test_conflicting_approval_binding_fails_closed_and_keeps_journal(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)
    original = harness.approvals.ensure_rejected

    def crash_after_rejection(*args, **kwargs):
        original(*args, **kwargs)
        raise SimulatedCrash("after rejection")

    [held] = harness.run(_request())
    monkeypatch.setattr(harness.approvals, "ensure_rejected", crash_after_rejection)
    with pytest.raises(SimulatedCrash):
        harness.resume(held.approval_id, False, "alice", "declined")

    approval = ApprovalStore(state / "approvals.json").get(held.approval_id)
    assert approval is not None
    approval.request_id = "conflicting_request"
    ApprovalStore(state / "approvals.json")._save(approval)
    operation = OperationJournal(state / "operation_journal.json").active()

    with pytest.raises(RuntimeError, match="conflicts with journal bindings"):
        _harness(state)

    assert OperationJournal(state / "operation_journal.json").active() == operation


def test_journal_lock_is_a_critical_state_integrity_issue(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "operation_journal.json.lock").write_text("locked", encoding="utf-8")
    (state / "operation_journal.json.lock").chmod(0o600)

    report = StateIntegrityAuditor(state).audit()

    assert not report.safe_to_execute
    assert any(issue.code == "state_lock_present" for issue in report.issues)


def test_nonapproval_execution_completes_its_local_journal(tmp_path):
    state = tmp_path / "state"
    harness = _harness(state, scenario="read_statement")

    harness.run(_request())

    assert OperationJournal(state / "operation_journal.json").active() is None
    assert (state / "operation_journal.json").exists()
    assert BudgetLedger(state / "budget.json").summary()["reserved_usd"] == "0"
