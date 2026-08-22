from __future__ import annotations

from dataclasses import asdict
import json

import pytest

from defiant_agent_harness.adapters.base import ToolCall
from defiant_agent_harness.adapters.mock import MockAgentAdapter, SCRIPTS
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import (
    Decision,
    EvidenceRecord,
    HarnessRequest,
    ResultStatus,
)
from defiant_agent_harness.evidence.store import EvidenceStore
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.persistence import atomic_write_json, read_json
from defiant_agent_harness.state_integrity import (
    StateIntegrityAuditor,
    StateIntegrityError,
)


def _request() -> HarnessRequest:
    return HarnessRequest(task="audit test", user_id="tester", workspace_id="ws")


def _pending_spend(tmp_path):
    harness = build_harness(
        tmp_path,
        MockAgentAdapter(script=SCRIPTS["overspend"]),
        starting_budget_usd="300",
    )
    [outcome] = harness.run(_request())
    approval = harness.approvals.get(outcome.approval_id)
    assert approval is not None
    return harness, approval


def _issue_codes(report) -> set[str]:
    return {issue.code for issue in report.issues}


def test_empty_audit_is_healthy_and_strictly_read_only(tmp_path):
    workdir = tmp_path / "never-created"

    report = StateIntegrityAuditor(workdir).audit()

    assert report.status == "healthy"
    assert report.safe_to_execute is True
    assert report.recovery_required is False
    assert not workdir.exists()


def test_consistent_pending_approval_is_healthy(tmp_path):
    _pending_spend(tmp_path)

    report = StateIntegrityAuditor(tmp_path).audit()

    assert report.status == "healthy"
    assert report.counts["approvals"] == 1
    assert report.counts["reservations"] == 1
    assert report.issues == []


def test_executing_approval_is_recoverable_not_corrupt(tmp_path):
    harness, pending = _pending_spend(tmp_path)
    harness.approvals.decide(pending.approval_id, True, "operator-7")
    harness.approvals.begin_execution(pending.approval_id, pending.held_action())

    report = StateIntegrityAuditor(tmp_path).audit()

    assert report.status == "recovery_required"
    assert report.safe_to_execute is True
    assert "execution_recovery_required" in _issue_codes(report)


def test_orphan_reservation_is_unsafe_and_blocks_new_authority(tmp_path):
    harness = build_harness(tmp_path, MockAgentAdapter())
    harness.budget.reserve("1", "req_orphan", "act_orphan")
    before = harness.evidence.records()

    report = StateIntegrityAuditor(tmp_path).audit()

    assert report.status == "unsafe"
    assert "orphan_reservation" in _issue_codes(report)
    with pytest.raises(StateIntegrityError, match="orphan_reservation"):
        harness.handle_call(
            ToolCall(name="read_file", arguments={"path": "workspace/a.txt"}),
            _request(),
        )
    assert harness.evidence.records() == before


def test_reservation_binding_mismatch_fails_closed(tmp_path):
    _, approval = _pending_spend(tmp_path)
    path = tmp_path / "budget.json"
    budget = read_json(path)
    budget["reservations"][approval.action_id]["request_id"] = "req_tampered"
    atomic_write_json(path, budget)

    report = StateIntegrityAuditor(tmp_path).audit()

    assert report.safe_to_execute is False
    assert "reservation_binding_mismatch" in _issue_codes(report)


def test_zero_value_persisted_reservation_is_invalid_store_state(tmp_path):
    build_harness(tmp_path, MockAgentAdapter())
    path = tmp_path / "budget.json"
    budget = read_json(path)
    budget["reservations"]["act_zero"] = {
        "request_id": "req_zero",
        "amount_usd": "0",
        "created_at": "2026-01-01T00:00:00Z",
    }
    atomic_write_json(path, budget)

    report = StateIntegrityAuditor(tmp_path).audit()

    assert report.safe_to_execute is False
    assert report.stores["budget"]["state"] == "invalid"
    assert "budget_invalid" in _issue_codes(report)


def test_terminal_approval_cannot_retain_live_reservation(tmp_path):
    _, approval = _pending_spend(tmp_path)
    path = tmp_path / "approvals.json"
    approvals = read_json(path)
    approvals[approval.approval_id]["status"] = "rejected"
    approvals[approval.approval_id]["decided_by"] = "operator-7"
    approvals[approval.approval_id]["decided_at"] = "2026-01-01T00:00:00Z"
    approvals[approval.approval_id]["consumed_at"] = "2026-01-01T00:00:00Z"
    atomic_write_json(path, approvals)

    report = StateIntegrityAuditor(tmp_path).audit()

    assert report.safe_to_execute is False
    assert "terminal_approval_has_reservation" in _issue_codes(report)


def test_consumed_approval_must_reference_matching_terminal_evidence(tmp_path):
    harness = build_harness(
        tmp_path,
        MockAgentAdapter(script=SCRIPTS["send_email"]),
    )
    [outcome] = harness.run(_request())
    approval = harness.approvals.get(outcome.approval_id)
    assert approval is not None
    raw = asdict(approval)
    raw["status"] = "consumed"
    raw["decided_by"] = "operator-7"
    raw["decided_at"] = "2026-01-01T00:00:00Z"
    raw["execution_record_id"] = "evd_missing"
    raw["consumed_at"] = "2026-01-01T00:00:00Z"
    atomic_write_json(tmp_path / "approvals.json", {approval.approval_id: raw})

    report = StateIntegrityAuditor(tmp_path).audit()

    assert report.safe_to_execute is False
    assert "consumed_evidence_not_found" in _issue_codes(report)


def test_invalid_approval_timestamp_is_diagnosed_without_projection_crash(tmp_path):
    harness = build_harness(
        tmp_path,
        MockAgentAdapter(script=SCRIPTS["send_email"]),
    )
    [outcome] = harness.run(_request())
    path = tmp_path / "approvals.json"
    approvals = read_json(path)
    approvals[outcome.approval_id]["expires_at"] = "not-a-timestamp"
    atomic_write_json(path, approvals)

    report = StateIntegrityAuditor(tmp_path).audit()
    snapshot = CommandCore(tmp_path).snapshot()

    assert report.safe_to_execute is False
    assert report.stores["approvals"]["state"] == "invalid"
    assert snapshot["authoritative"] is False
    assert snapshot["approvals"]["state"] == "invalid"


def test_reconciliation_marker_cannot_diverge_from_operator_intent(tmp_path):
    harness, pending = _pending_spend(tmp_path)
    harness.approvals.decide(pending.approval_id, True, "operator-7")
    harness.approvals.begin_execution(pending.approval_id, pending.held_action())
    harness.reconcile_execution(
        pending.approval_id,
        "failed",
        "operator-7",
        "provider confirms an attempted call",
    )
    path = tmp_path / "budget.json"
    budget = read_json(path)
    budget["reconciliations"][pending.action_id]["note"] = "changed story"
    atomic_write_json(path, budget)

    report = StateIntegrityAuditor(tmp_path).audit()

    assert report.safe_to_execute is False
    assert "reconciliation_binding_mismatch" in _issue_codes(report)


def test_sealed_unbound_authorization_is_recovery_state_not_orphan(tmp_path):
    harness = build_harness(tmp_path, MockAgentAdapter())
    harness.budget.reserve("1", "req_external", "act_external")
    harness.evidence.append(
        EvidenceRecord(
            request_id="req_external",
            action_id="act_external",
            decision=Decision.ALLOW,
            result_status=ResultStatus.SKIPPED,
            authorization_hash="sha256:authorization",
        )
    )

    report = StateIntegrityAuditor(tmp_path).audit()

    assert report.safe_to_execute is True
    assert report.recovery_required is True
    assert "authorization_reconciliation_required" in _issue_codes(report)
    assert "orphan_reservation" not in _issue_codes(report)


def test_broken_evidence_is_reported_without_trusting_cross_store_links(tmp_path):
    path = tmp_path / "evidence.jsonl"
    EvidenceStore(path).append(
        EvidenceRecord(
            request_id="req_one",
            action_id="act_one",
            decision=Decision.ALLOW,
            result_status=ResultStatus.SUCCEEDED,
        )
    )
    path.write_text(
        path.read_text().replace('"decision":"allow"', '"decision":"block"')
    )

    report = StateIntegrityAuditor(tmp_path).audit()

    assert report.safe_to_execute is False
    assert report.stores["evidence"]["state"] == "invalid"
    assert "evidence_invalid" in _issue_codes(report)


def test_lock_file_is_an_unsafe_concurrent_or_crash_signal(tmp_path):
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "budget.json.lock").write_text("pid=99999\n")

    report = StateIntegrityAuditor(tmp_path).audit()

    assert report.safe_to_execute is False
    assert "state_lock_present" in _issue_codes(report)


def test_doctor_emits_json_exit_status_and_does_not_initialize_state(tmp_path, capsys):
    workdir = tmp_path / "new"

    exit_code = main(["--workdir", str(workdir), "doctor"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["schema_name"] == "defiant.state_integrity"
    assert payload["schema_version"] == "0.10.0"
    assert payload["safe_to_execute"] is True
    assert not workdir.exists()


def test_command_core_surfaces_invalid_store_without_mutating_or_raising(tmp_path):
    (tmp_path / "budget.json").write_text("not-json")

    snapshot = CommandCore(tmp_path).snapshot()

    assert snapshot["authoritative"] is False
    assert snapshot["state_integrity"]["status"] == "unsafe"
    assert snapshot["budget"]["state"] == "invalid"
    assert (tmp_path / "budget.json").read_text() == "not-json"
