from __future__ import annotations

from dataclasses import asdict
from decimal import Decimal
import json

from defiant_agent_harness.approvals.store import PendingApproval
from defiant_agent_harness.budgets.ledger import BudgetLedger
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import Decision, EvidenceRecord, ResultStatus
from defiant_agent_harness.evidence.store import EvidenceStore
from defiant_agent_harness.persistence import atomic_write_json


def _record(
    request_id: str,
    action_id: str,
    decision: Decision,
    result: ResultStatus,
    cost: str = "0",
) -> EvidenceRecord:
    return EvidenceRecord(
        request_id=request_id,
        action_id=action_id,
        decision=decision,
        result_status=result,
        tool_name="read_file" if decision is Decision.ALLOW else "delete_file",
        workspace_id="demo",
        ruleset_hash="sha256:rules",
        cost_usd=Decimal(cost),
    )


def test_empty_snapshot_is_read_only(tmp_path):
    workdir = tmp_path / "never-created"

    snapshot = CommandCore(workdir).snapshot()

    assert snapshot["authoritative"] is True
    assert snapshot["evidence"]["record_count"] == 0
    assert snapshot["approvals"]["state"] == "not_initialized"
    assert snapshot["budget"]["state"] == "not_initialized"
    assert snapshot["recent_activity"] == []
    assert not workdir.exists()


def test_snapshot_aggregates_evidence_approvals_and_budget(tmp_path):
    workdir = tmp_path / "state"
    evidence = EvidenceStore(workdir / "evidence.jsonl")
    evidence.append(
        _record("req_one", "act_one", Decision.ALLOW, ResultStatus.SUCCEEDED, "0.25")
    )
    evidence.append(_record("req_one", "act_two", Decision.BLOCK, ResultStatus.BLOCKED))

    pending = PendingApproval(
        action_id="act_three",
        request_id="req_two",
        tool_name="send_email",
        target="recipient@example.test",
        payload_hash="sha256:payload",
        authorization_hash="sha256:authorization",
        payload_preview="sensitive content is retained only in the approval store",
        approval_scope="external_send",
        reason="operator decision required",
        expires_at="2999-01-01T00:00:00Z",
    )
    atomic_write_json(
        workdir / "approvals.json",
        {pending.approval_id: asdict(pending)},
    )
    BudgetLedger(workdir / "budget.json").grant("10", "demo balance")

    snapshot = CommandCore(workdir).snapshot(limit=1)

    assert snapshot["authoritative"] is True
    assert snapshot["evidence"]["record_count"] == 2
    assert snapshot["evidence"]["request_count"] == 1
    assert snapshot["evidence"]["action_count"] == 2
    assert snapshot["evidence"]["decisions"]["allow"] == 1
    assert snapshot["evidence"]["decisions"]["block"] == 1
    assert snapshot["evidence"]["results"]["succeeded"] == 1
    assert snapshot["evidence"]["results"]["blocked"] == 1
    assert snapshot["evidence"]["total_cost_usd"] == "0.25"
    assert snapshot["approvals"]["actionable_count"] == 1
    assert snapshot["approvals"]["actionable"][0]["approval_id"] == pending.approval_id
    assert "target" not in snapshot["approvals"]["actionable"][0]
    assert "payload_preview" not in snapshot["approvals"]["actionable"][0]
    assert snapshot["budget"]["summary"]["available_usd"] == "10"
    assert len(snapshot["recent_activity"]) == 1
    assert "target" not in snapshot["recent_activity"][0]


def test_snapshot_exposes_executing_approval_as_reconciliation_required(tmp_path):
    executing = PendingApproval(
        action_id="act_stranded",
        request_id="req_stranded",
        tool_name="send_email",
        target="recipient@example.test",
        payload_hash="sha256:payload",
        authorization_hash="sha256:authorization",
        payload_preview="sensitive",
        approval_scope="external_send",
        reason="operator decision required",
        status="executing",
        decided_by="operator-7",
        decided_at="2025-12-31T23:59:00Z",
        expires_at="2026-01-01T00:00:00Z",
    )
    atomic_write_json(
        tmp_path / "approvals.json",
        {executing.approval_id: asdict(executing)},
    )

    snapshot = CommandCore(tmp_path).snapshot()

    assert snapshot["reconciliation_required"] is True
    assert snapshot["approvals"]["reconciliation_required_count"] == 1
    item = snapshot["approvals"]["actionable"][0]
    assert item["reconciliation_required"] is True
    assert item["reconciliation_state"] == "required"
    assert "target" not in item
    assert "reconciliation_note" not in item


def test_request_filter_limits_aggregates_and_recent_activity(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    evidence.append(
        _record("req_one", "act_one", Decision.ALLOW, ResultStatus.SUCCEEDED)
    )
    evidence.append(_record("req_two", "act_two", Decision.BLOCK, ResultStatus.BLOCKED))

    snapshot = CommandCore(tmp_path).snapshot(request_id="req_one")

    assert snapshot["evidence"]["filtered_request_id"] == "req_one"
    assert snapshot["evidence"]["record_count"] == 1
    assert snapshot["recent_activity"][0]["request_id"] == "req_one"


def test_broken_chain_is_reported_without_untrusted_aggregates(tmp_path):
    path = tmp_path / "evidence.jsonl"
    EvidenceStore(path).append(
        _record("req_one", "act_one", Decision.ALLOW, ResultStatus.SUCCEEDED)
    )
    path.write_text(
        path.read_text().replace('"tool_name":"read_file"', '"tool_name":"tampered"')
    )

    snapshot = CommandCore(tmp_path).snapshot()

    assert snapshot["authoritative"] is False
    assert snapshot["evidence_integrity"]["ok"] is False
    assert snapshot["evidence"] is None
    assert snapshot["recent_activity"] == []


def test_command_cli_emits_json_snapshot(tmp_path, capsys):
    exit_code = main(["--workdir", str(tmp_path), "command", "--limit", "0"])

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["schema_name"] == "defiant.command.snapshot"
    assert output["schema_version"] == "0.20.0"
    assert output["resource_limits"] == {
        "durable_json_bytes": 64 * 1024 * 1024,
        "evidence_record_bytes": 16 * 1024 * 1024,
        "mcp_message_bytes": 10 * 1024 * 1024,
        "hook_event_bytes": 10 * 1024 * 1024,
        "mcp_config_bytes": 1024 * 1024,
    }
    assert output["authority_profile"]["state"] == "not_enrolled"
    assert output["state_integrity"]["status"] == "healthy"
    assert output["authoritative"] is True


def test_command_cli_rejects_negative_limit(tmp_path, capsys):
    exit_code = main(["--workdir", str(tmp_path), "command", "--limit", "-1"])

    assert exit_code == 1
    assert "limit must not be negative" in capsys.readouterr().err
