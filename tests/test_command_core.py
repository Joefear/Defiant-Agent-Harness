from __future__ import annotations

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
        {pending.approval_id: pending.to_dict()},
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
        {executing.approval_id: executing.to_dict()},
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
    assert output["schema_version"] == "0.67.0"
    assert output["resource_limits"] == {
        "tool_call_name_characters": 4096,
        "tool_call_identifier_characters": 4096,
        "tool_call_mapping_entries": 65_536,
        "tool_call_mapping_sort_work_units": 64 * 1024 * 1024,
        "tool_call_nesting_depth": 64,
        "tool_call_nodes": 1_100_000,
        "tool_call_number_characters": 1024,
        "tool_call_scalar_characters": 8 * 1024 * 1024,
        "tool_call_string_token_bytes": 64 * 1024 * 1024,
        "tool_call_canonical_bytes": 64 * 1024 * 1024,
        "action_hash_canonical_bytes": 64 * 1024 * 1024,
        "action_hash_mapping_entries": 65_536,
        "action_hash_mapping_sort_work_units": 64 * 1024 * 1024,
        "action_hash_nesting_depth": 64,
        "action_hash_nodes": 1_100_000,
        "action_hash_number_characters": 1024,
        "action_hash_scalar_characters": 8 * 1024 * 1024,
        "action_hash_string_token_bytes": 64 * 1024 * 1024,
        "tool_result_summary_characters": 64 * 1024,
        "tool_result_output_nesting_depth": 64,
        "tool_result_output_nodes": 1_100_000,
        "tool_result_output_number_characters": 1024,
        "tool_result_output_scalar_characters": 8 * 1024 * 1024,
        "tool_result_output_string_token_bytes": 64 * 1024 * 1024,
        "tool_result_output_canonical_bytes": 64 * 1024 * 1024,
        "tool_result_output_mapping_entries": 65_536,
        "tool_result_output_mapping_sort_work_units": 64 * 1024 * 1024,
        "durable_json_bytes": 64 * 1024 * 1024,
        "evidence_export_bytes": 64 * 1024 * 1024,
        "evidence_record_bytes": 16 * 1024 * 1024,
        "mcp_message_bytes": 10 * 1024 * 1024,
        "hook_event_bytes": 10 * 1024 * 1024,
        "hook_execution_state_bytes": 64 * 1024 * 1024,
        "approval_state_bytes": 64 * 1024 * 1024,
        "budget_state_bytes": 64 * 1024 * 1024,
        "evidence_head_state_bytes": 64 * 1024,
        "evidence_witness_policy_state_bytes": 256 * 1024,
        "operation_journal_bytes": 4 * 1024 * 1024,
        "authority_profile_state_bytes": 1024 * 1024,
        "authority_publication_state_bytes": 64 * 1024,
        "authority_publication_manifest_bytes": 64 * 1024,
        "operator_trust_state_bytes": 1024 * 1024,
        "runtime_artifact_state_bytes": 64 * 1024,
        "launch_envelope_state_bytes": 64 * 1024,
        "state_storage_state_bytes": 64 * 1024,
        "control_plane_isolation_state_bytes": 64 * 1024,
        "workspace_integrity_state_bytes": 64 * 1024,
        "json_lexical_tokens": 1_000_000,
        "json_nesting_depth": 64,
        "json_number_token_characters": 1024,
        "json_string_token_characters": 8 * 1024 * 1024,
        "mcp_config_bytes": 1024 * 1024,
        "mcp_config_collection_items": 4096,
        "mcp_dependency_file_pins": 8192,
        "mcp_launch_environment_entries": 4096,
        "policy_pack_bytes": 1024 * 1024,
        "policy_pack_count": 64,
        "policy_rule_count": 4096,
        "policy_known_tool_count": 4096,
        "policy_rule_field_items": 4096,
        "policy_rule_list_items": 65_536,
        "policy_text_item_characters": 4096,
        "policy_text_characters": 8 * 1024 * 1024,
        "policy_match_payload_nesting_depth": 64,
        "policy_match_payload_nodes": 100_000,
        "policy_match_payload_characters": 1024 * 1024,
        "policy_payload_match_work_units": 64 * 1024 * 1024,
        "policy_match_tool_name_characters": 4096,
        "policy_match_target_characters": 1024 * 1024,
        "policy_glob_match_work_units": 64 * 1024 * 1024,
        "policy_context_entries": 64,
        "policy_context_key_characters": 256,
        "policy_context_value_characters": 4096,
        "policy_context_characters": 256 * 1024,
        "request_task_characters": 1024 * 1024,
        "request_identifier_characters": 4096,
        "request_allowed_tool_count": 4096,
        "request_allowed_tool_characters": 4096,
        "request_text_characters": 8 * 1024 * 1024,
        "provenance_ref_count": 100_000,
        "provenance_text_item_characters": 8192,
        "provenance_text_characters": 8 * 1024 * 1024,
        "trusted_public_key_count": 1024,
        "trusted_public_key_bytes": 64 * 1024,
        "trusted_public_key_set_bytes": 8 * 1024 * 1024,
        "yaml_nesting_depth": 64,
        "yaml_nodes": 100_000,
    }
    assert output["authority_configuration"] == {
        "yaml_parser_profile": "strict_yaml_v2",
        "json_parser_profile": "strict_json_v3",
        "json_structural_preflight": True,
        "json_scalar_preflight": True,
        "mcp_collection_preflight": True,
        "policy_text_preflight": True,
        "policy_payload_match_preflight": True,
        "policy_glob_match_preflight": True,
        "action_hash_preflight": True,
        "canonical_number_preflight": True,
        "canonical_string_preflight": True,
        "canonical_value_preflight": True,
        "canonical_mapping_preflight": True,
        "canonical_mapping_sort_preflight": True,
        "canonical_mapping_key_preflight": True,
        "complete_mapping_key_preflight": True,
        "validated_canonical_snapshot": True,
        "validated_snapshot_ownership": True,
        "validated_contract_collection_snapshots": True,
        "validated_scalar_ownership": True,
        "validated_authority_record_ownership": True,
        "validated_policy_snapshot_ownership": True,
        "sealed_policy_runtime_state": True,
        "validated_policy_context_snapshot": True,
        "validated_operation_journal_snapshot": True,
        "validated_native_hook_event_snapshot": True,
        "sealed_authority_continuity_state": True,
        "bounded_authority_continuity_io": True,
        "crash_safe_authority_publication": True,
        "validated_authority_publication_snapshot": True,
        "verified_authority_publication_manifest": True,
        "verified_active_authority_publication_phase": True,
        "validated_runtime_artifact_state_snapshot": True,
        "validated_launch_envelope_state_snapshot": True,
        "validated_state_storage_state_snapshot": True,
        "validated_control_plane_isolation_state_snapshot": True,
        "validated_workspace_integrity_state_snapshot": True,
        "sealed_native_hook_correlation_state": True,
        "sealed_approval_record_state": True,
        "validated_budget_ledger_snapshot": True,
        "validated_evidence_head_snapshot": True,
        "validated_evidence_witness_policy_snapshot": True,
        "request_contract_preflight": True,
        "tool_call_contract_preflight": True,
        "tool_result_contract_preflight": True,
        "yaml_aliases_allowed": False,
        "duplicate_keys_allowed": False,
        "non_finite_json_numbers_allowed": False,
        "json_encoding": "utf-8",
    }
    assert output["authority_profile"]["state"] == "not_enrolled"
    assert output["state_integrity"]["status"] == "healthy"
    assert output["authoritative"] is True


def test_command_cli_rejects_negative_limit(tmp_path, capsys):
    exit_code = main(["--workdir", str(tmp_path), "command", "--limit", "-1"])

    assert exit_code == 1
    assert "limit must not be negative" in capsys.readouterr().err
