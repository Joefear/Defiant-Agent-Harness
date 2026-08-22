from __future__ import annotations

import json

import pytest

from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.approvals.store import PendingApproval
from defiant_agent_harness.cli.main import build_parser, main
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import (
    Decision,
    EvidenceRecord,
    ResultStatus,
    sha256_of,
)
from defiant_agent_harness.evidence.signing import generate_key_pair
from defiant_agent_harness.evidence.store import EvidenceError
from defiant_agent_harness.operation_journal import OperationJournal
from defiant_agent_harness.operator_identity import (
    AuthorizationReconciliationSubject,
    RECONCILIATION_PURPOSE,
    sign_authorization_reconciliation,
    sign_operator_action,
)
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.state_integrity import StateIntegrityAuditor

PASSPHRASE = b"test-only authorization reconciliation passphrase"


class SimulatedCrash(RuntimeError):
    pass


def _open_authorization(state, *, amount="10", trusted_keys=None):
    harness = build_harness(
        state,
        MockAgentAdapter(),
        starting_budget_usd="100",
        trusted_operator_keys=trusted_keys,
    )
    authorization = EvidenceRecord(
        request_id="req_authorization_reconciliation",
        action_id="act_authorization_reconciliation",
        decision=Decision.ALLOW,
        result_status=ResultStatus.SKIPPED,
        tool_name="paid_read",
        target="fixture",
        policy_ids=["allow_fixture"],
        decision_reason="fixture allowed",
        authorization_hash=sha256_of({"fixture": "authorization"}),
        payload_hash=sha256_of({"fixture": "payload"}),
        result_summary="authorized; execution pending",
    )
    harness.evidence.append(authorization)
    if amount != "0":
        harness.budget.reserve(
            amount, authorization.request_id, authorization.action_id
        )
    return harness, authorization


def test_succeeded_authorization_reconciliation_charges_and_seals_terminal_evidence(
    tmp_path,
):
    state = tmp_path / "state"
    harness, authorization = _open_authorization(state)

    outcome = harness.reconcile_authorization(
        authorization.record_id,
        "succeeded",
        "alice",
        "provider confirms dispatch",
    )

    assert outcome.status is ResultStatus.SUCCEEDED
    assert harness.budget.summary()["total_spent_usd"] == "10"
    assert harness.budget.reservation_for(authorization.action_id) == 0
    terminal = harness.evidence.get(outcome.evidence_record_id)
    assert terminal is not None
    assert terminal["reconciliation_outcome"] == "succeeded"
    assert terminal["reconciled_by"] == "alice"
    assert terminal["reconciliation_note"] == "provider confirms dispatch"
    assert harness.evidence.open_authorizations() == []
    assert StateIntegrityAuditor(state).audit().status == "healthy"


def test_not_executed_authorization_reconciliation_releases_reservation(tmp_path):
    state = tmp_path / "state"
    harness, authorization = _open_authorization(state)

    outcome = harness.reconcile_authorization(
        authorization.record_id,
        "not_executed",
        "alice",
        "worker stopped before dispatch",
    )

    assert outcome.status is ResultStatus.NOT_EXECUTED
    assert harness.budget.summary()["available_usd"] == "100"
    assert harness.budget.summary()["total_spent_usd"] == "0"


def test_zero_cost_authorization_still_requires_and_accepts_explicit_outcome(tmp_path):
    state = tmp_path / "state"
    harness, authorization = _open_authorization(state, amount="0")

    before = StateIntegrityAuditor(state).audit()
    outcome = harness.reconcile_authorization(
        authorization.record_id,
        "failed",
        "alice",
        "zero-cost provider failed after dispatch",
    )

    assert before.status == "recovery_required"
    assert before.counts["authorization_reconciliations_required"] == 1
    assert outcome.status is ResultStatus.FAILED
    assert harness.budget.summary()["total_spent_usd"] == "0"
    assert StateIntegrityAuditor(state).audit().status == "healthy"


def test_prior_known_debit_is_preserved_without_conservative_double_charge(tmp_path):
    state = tmp_path / "state"
    harness, authorization = _open_authorization(state)
    harness.budget.settle("3", authorization.request_id, authorization.action_id)

    outcome = harness.reconcile_authorization(
        authorization.record_id,
        "succeeded",
        "alice",
        "tool returned before terminal evidence was sealed",
    )

    assert harness.budget.summary()["total_spent_usd"] == "3"
    terminal = harness.evidence.get(outcome.evidence_record_id)
    assert terminal is not None and terminal["cost_usd"] == "3"


def test_not_executed_does_not_erase_a_prior_known_debit(tmp_path):
    state = tmp_path / "state"
    harness, authorization = _open_authorization(state)
    harness.budget.settle("3", authorization.request_id, authorization.action_id)

    outcome = harness.reconcile_authorization(
        authorization.record_id,
        "not_executed",
        "alice",
        "dispatch did not complete but provider retained the attempt charge",
    )

    assert harness.budget.summary()["total_spent_usd"] == "3"
    terminal = harness.evidence.get(outcome.evidence_record_id)
    assert terminal is not None and terminal["cost_usd"] == "3"
    assert StateIntegrityAuditor(state).audit().status == "healthy"


def test_exact_authorization_reconciliation_retry_is_idempotent(tmp_path):
    state = tmp_path / "state"
    harness, authorization = _open_authorization(state)

    first = harness.reconcile_authorization(
        authorization.record_id, "failed", "alice", "provider rejected request"
    )
    before = harness.evidence.records()
    second = harness.reconcile_authorization(
        authorization.record_id, "failed", "alice", "provider rejected request"
    )

    assert second.evidence_record_id == first.evidence_record_id
    assert harness.evidence.records() == before
    assert harness.budget.summary()["total_spent_usd"] == "10"
    with pytest.raises(ValueError, match="conflicts|different|outcome"):
        harness.reconcile_authorization(
            authorization.record_id,
            "not_executed",
            "alice",
            "provider rejected request",
        )


def test_restart_finishes_crash_after_budget_without_double_charge(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness, authorization = _open_authorization(state)

    def crash_before_evidence(_record):
        raise SimulatedCrash("after budget")

    monkeypatch.setattr(harness.evidence, "append_idempotent", crash_before_evidence)
    with pytest.raises(SimulatedCrash):
        harness.reconcile_authorization(
            authorization.record_id,
            "failed",
            "alice",
            "provider accepted but returned no result",
        )

    assert harness.budget.summary()["total_spent_usd"] == "10"
    assert OperationJournal(state / "operation_journal.json").active() is not None
    assert StateIntegrityAuditor(state).audit().status == "recovery_required"

    recovered = build_harness(state, MockAgentAdapter(), starting_budget_usd="100")

    assert recovered.budget.summary()["total_spent_usd"] == "10"
    assert OperationJournal(state / "operation_journal.json").active() is None
    assert len(recovered.evidence.records()) == 2
    assert StateIntegrityAuditor(state).audit().status == "healthy"


def test_restart_finishes_crash_after_evidence_without_duplicate(tmp_path, monkeypatch):
    state = tmp_path / "state"
    harness, authorization = _open_authorization(state)

    def crash_before_journal_completion(_operation_id):
        raise SimulatedCrash("after evidence")

    monkeypatch.setattr(
        harness.operation_journal, "complete", crash_before_journal_completion
    )
    with pytest.raises(SimulatedCrash):
        harness.reconcile_authorization(
            authorization.record_id,
            "failed",
            "alice",
            "provider accepted but returned no result",
        )

    assert len(harness.evidence.records()) == 2
    assert OperationJournal(state / "operation_journal.json").active() is not None

    recovered = build_harness(state, MockAgentAdapter(), starting_budget_usd="100")

    assert len(recovered.evidence.records()) == 2
    assert recovered.budget.summary()["total_spent_usd"] == "10"
    assert OperationJournal(state / "operation_journal.json").active() is None
    assert StateIntegrityAuditor(state).audit().status == "healthy"


def test_recovery_refuses_broken_evidence_before_budget_mutation(tmp_path, monkeypatch):
    state = tmp_path / "state"
    harness, authorization = _open_authorization(state)

    def crash_before_budget(*_args, **_kwargs):
        raise SimulatedCrash("before budget")

    monkeypatch.setattr(harness.budget, "reconcile_reservation", crash_before_budget)
    with pytest.raises(SimulatedCrash):
        harness.reconcile_authorization(
            authorization.record_id,
            "failed",
            "alice",
            "provider outcome uncertain",
        )

    evidence_path = state / "evidence.jsonl"
    [record] = [
        json.loads(line)
        for line in evidence_path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    record["tool_name"] = "tampered"
    evidence_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    with pytest.raises(EvidenceError, match="broken evidence chain"):
        build_harness(state, MockAgentAdapter(), starting_budget_usd="100")

    assert harness.budget.reservation_for(authorization.action_id) == 10
    budget = json.loads((state / "budget.json").read_text(encoding="utf-8"))
    assert authorization.action_id not in budget["reconciliations"]


def test_signed_authorization_reconciliation_survives_restart(tmp_path, monkeypatch):
    state = tmp_path / "state"
    private = tmp_path / "operator-private.pem"
    public = tmp_path / "operator-public.pem"
    generate_key_pair(private, public, PASSPHRASE)
    trusted_keys = [f"alice={public}"]
    harness, authorization = _open_authorization(state, trusted_keys=trusted_keys)
    subject = AuthorizationReconciliationSubject.from_record(
        harness.evidence.get(authorization.record_id)
    )
    attestation = sign_authorization_reconciliation(
        subject,
        private,
        PASSPHRASE,
        outcome="failed",
        operator="alice",
        note="provider logs checked",
    )

    def crash_before_evidence(_record):
        raise SimulatedCrash("after signed budget marker")

    monkeypatch.setattr(harness.evidence, "append_idempotent", crash_before_evidence)
    with pytest.raises(SimulatedCrash):
        harness.reconcile_authorization(
            authorization.record_id,
            "failed",
            "alice",
            "provider logs checked",
            attestation=attestation,
        )

    recovered = build_harness(
        state,
        MockAgentAdapter(),
        starting_budget_usd="100",
        trusted_operator_keys=trusted_keys,
    )
    marker = json.loads((state / "budget.json").read_text(encoding="utf-8"))[
        "reconciliations"
    ][authorization.action_id]
    assert marker["attestation"] == attestation
    assert recovered.evidence.open_authorizations() == []
    assert (
        StateIntegrityAuditor(state, operator_trust=recovered.approvals.operator_trust)
        .audit()
        .status
        == "healthy"
    )


def test_signed_mode_rejects_unsigned_or_tampered_authorization_outcome(tmp_path):
    state = tmp_path / "state"
    private = tmp_path / "operator-private.pem"
    public = tmp_path / "operator-public.pem"
    generate_key_pair(private, public, PASSPHRASE)
    trusted_keys = [f"alice={public}"]
    harness, authorization = _open_authorization(state, trusted_keys=trusted_keys)
    subject = AuthorizationReconciliationSubject.from_record(
        harness.evidence.get(authorization.record_id)
    )

    with pytest.raises(RuntimeError, match="signed authorization reconciliation"):
        harness.reconcile_authorization(
            authorization.record_id, "failed", "alice", "provider logs checked"
        )

    attestation = sign_authorization_reconciliation(
        subject,
        private,
        PASSPHRASE,
        outcome="failed",
        operator="alice",
        note="provider logs checked",
    )
    attestation["outcome"] = "succeeded"
    with pytest.raises(RuntimeError, match="invalid|does not match"):
        harness.reconcile_authorization(
            authorization.record_id,
            "failed",
            "alice",
            "provider logs checked",
            attestation=attestation,
        )


def test_approval_reconciliation_signature_cannot_replay_for_authorization(tmp_path):
    state = tmp_path / "state"
    private = tmp_path / "operator-private.pem"
    public = tmp_path / "operator-public.pem"
    generate_key_pair(private, public, PASSPHRASE)
    trusted_keys = [f"alice={public}"]
    harness, authorization = _open_authorization(state, trusted_keys=trusted_keys)
    approval_subject = PendingApproval(
        action_id=authorization.action_id,
        request_id=authorization.request_id,
        tool_name="paid_read",
        target="fixture",
        payload_hash=authorization.payload_hash,
        authorization_hash=authorization.authorization_hash,
        payload_preview="fixture",
        approval_scope="exact",
        reason="fixture",
        policy_ids=["allow_fixture"],
        reserved_usd="10",
    )
    replay = sign_operator_action(
        approval_subject,
        private,
        PASSPHRASE,
        purpose=RECONCILIATION_PURPOSE,
        outcome="failed",
        operator="alice",
        note="provider logs checked",
    )

    with pytest.raises(RuntimeError, match="schema|fields"):
        harness.reconcile_authorization(
            authorization.record_id,
            "failed",
            "alice",
            "provider logs checked",
            attestation=replay,
        )


def test_tampered_authorization_reconciliation_marker_is_unsafe(tmp_path):
    state = tmp_path / "state"
    harness, authorization = _open_authorization(state)
    harness.reconcile_authorization(
        authorization.record_id,
        "failed",
        "alice",
        "provider rejected request",
    )
    budget_path = state / "budget.json"
    budget = json.loads(budget_path.read_text(encoding="utf-8"))
    budget["reconciliations"][authorization.action_id]["expected_usd"] = "9"
    budget_path.write_text(json.dumps(budget), encoding="utf-8")

    report = StateIntegrityAuditor(state).audit()

    assert report.status == "unsafe"
    assert any(
        issue.code == "authorization_reconciliation_estimate_mismatch"
        for issue in report.issues
    )


def test_terminal_authorization_reconciliation_without_budget_marker_is_unsafe(
    tmp_path,
):
    state = tmp_path / "state"
    harness, authorization = _open_authorization(state)
    harness.reconcile_authorization(
        authorization.record_id,
        "failed",
        "alice",
        "provider rejected request",
    )
    budget_path = state / "budget.json"
    budget = json.loads(budget_path.read_text(encoding="utf-8"))
    del budget["reconciliations"][authorization.action_id]
    budget_path.write_text(json.dumps(budget), encoding="utf-8")

    report = StateIntegrityAuditor(state).audit()

    assert report.status == "unsafe"
    assert any(
        issue.code == "authorization_reconciliation_budget_missing"
        for issue in report.issues
    )


def test_approval_backed_authorization_cannot_use_action_level_reconciliation(
    tmp_path,
):
    state = tmp_path / "state"
    harness, authorization = _open_authorization(state)
    pending = PendingApproval(
        action_id=authorization.action_id,
        request_id=authorization.request_id,
        tool_name="paid_read",
        target="fixture",
        payload_hash=authorization.payload_hash,
        authorization_hash=authorization.authorization_hash,
        payload_preview="fixture",
        approval_scope="exact",
        reason="fixture",
        policy_ids=["allow_fixture"],
        reserved_usd="10",
    )
    harness.approvals.create_prepared(pending)

    with pytest.raises(RuntimeError, match="reconcile by approval id"):
        harness.reconcile_authorization(
            authorization.record_id,
            "failed",
            "alice",
            "provider logs checked",
        )


def test_missing_approval_cannot_reclassify_authority_as_approval_free(tmp_path):
    state = tmp_path / "state"
    harness = build_harness(state, MockAgentAdapter(), starting_budget_usd="100")
    authorization = EvidenceRecord(
        request_id="req_missing_approval",
        action_id="act_missing_approval",
        decision=Decision.APPROVAL_REQUIRED,
        result_status=ResultStatus.SKIPPED,
        tool_name="paid_read",
        target="fixture",
        policy_ids=["require_fixture_approval"],
        decision_reason="fixture requires approval",
        authorization_hash=sha256_of({"fixture": "missing approval"}),
        payload_hash=sha256_of({"fixture": "payload"}),
        result_summary="authorized; execution pending",
    )
    harness.evidence.append(authorization)

    report = StateIntegrityAuditor(state).audit()

    assert report.status == "unsafe"
    assert any(
        issue.code == "approval_authorization_missing" for issue in report.issues
    )
    with pytest.raises(RuntimeError, match="approval_authorization_missing"):
        harness.reconcile_authorization(
            authorization.record_id,
            "failed",
            "alice",
            "provider logs checked",
        )
    assert (
        CommandCore(state).snapshot()["authorization_reconciliation"]["required_count"]
        == 0
    )


def test_command_core_and_dashboard_expose_sanitized_read_only_recovery_state(
    tmp_path,
):
    state = tmp_path / "state"
    _, authorization = _open_authorization(state)
    before = (state / "evidence.jsonl").read_bytes()

    snapshot = CommandCore(state).snapshot()
    projection = snapshot["authorization_reconciliation"]

    assert snapshot["reconciliation_required"] is True
    assert projection["required_count"] == 1
    assert projection["items"] == [
        {
            "authority_record_id": authorization.record_id,
            "request_id": authorization.request_id,
            "action_id": authorization.action_id,
            "tool_name": "paid_read",
            "authorized_at": authorization.timestamp,
            "reconciliation_state": "required",
        }
    ]
    assert "target" not in json.dumps(projection)
    assert "payload" not in json.dumps(projection)
    assert (state / "evidence.jsonl").read_bytes() == before


def test_reconcile_authorization_cli_requires_explicit_operator_fields(tmp_path):
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["--workdir", str(tmp_path), "reconcile-authorization", "evd_missing"]
        )


def test_reconcile_authorization_cli_records_terminal_outcome(tmp_path, capsys):
    state = tmp_path / "state"
    _, authorization = _open_authorization(state)

    exit_code = main(
        [
            "--workdir",
            str(state),
            "reconcile-authorization",
            authorization.record_id,
            "--outcome",
            "not_executed",
            "--operator",
            "alice",
            "--note",
            "worker stopped before dispatch",
        ]
    )

    assert exit_code == 0
    assert "not_executed" in capsys.readouterr().out
