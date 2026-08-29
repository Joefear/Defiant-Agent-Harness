from __future__ import annotations

from contextlib import contextmanager
from decimal import Decimal
from http.client import HTTPConnection
import json
from threading import Thread

import pytest

from defiant_agent_harness.cli.main import build_parser
from defiant_agent_harness.command.server import (
    LOOPBACK_HOST,
    MAX_LIMIT,
    CommandCenterError,
    CommandCenterServer,
    command_center_url,
)
from defiant_agent_harness.contracts import (
    Decision,
    EvidenceRecord,
    ResultStatus,
)
from defiant_agent_harness.evidence.store import EvidenceStore


@contextmanager
def _running_server(workdir, *, default_limit=25):
    server = CommandCenterServer(workdir, port=0, default_limit=default_limit)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _request(server, method: str, path: str):
    host, port = server.server_address[:2]
    connection = HTTPConnection(host, port, timeout=5)
    try:
        connection.request(method, path, body=b"{}" if method != "GET" else None)
        response = connection.getresponse()
        body = response.read()
        return response.status, dict(response.getheaders()), body
    finally:
        connection.close()


def _record(
    request_id: str,
    action_id: str,
    decision: Decision,
    result: ResultStatus,
) -> EvidenceRecord:
    return EvidenceRecord(
        request_id=request_id,
        action_id=action_id,
        decision=decision,
        result_status=result,
        tool_name="read_file" if decision is Decision.ALLOW else "delete_file",
        workspace_id="command-center-test",
        ruleset_hash="sha256:rules",
        cost_usd=Decimal("0.25"),
    )


def test_server_is_loopback_only_and_snapshot_read_does_not_create_state(tmp_path):
    workdir = tmp_path / "not-created"

    with _running_server(workdir) as server:
        assert server.server_address[0] == LOOPBACK_HOST
        assert command_center_url(server).startswith(f"http://{LOOPBACK_HOST}:")

        status, headers, body = _request(server, "GET", "/api/snapshot")

    assert status == 200
    snapshot = json.loads(body)
    assert snapshot["schema_name"] == "defiant.command.snapshot"
    assert snapshot["authoritative"] is True
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert not workdir.exists()


def test_server_packages_dashboard_assets_and_supports_head(tmp_path):
    with _running_server(tmp_path / "state") as server:
        status, _, body = _request(server, "GET", "/")
        head_status, head_headers, head_body = _request(server, "HEAD", "/")
        css_status, _, css = _request(server, "GET", "/assets/styles.css")
        js_status, _, javascript = _request(server, "GET", "/assets/app.js")

    assert status == head_status == css_status == js_status == 200
    assert b"Operational truth" in body
    assert b"Operator queue" in body
    assert b"Operator reconciliation required" in body
    assert b"State integrity alert" in body
    assert b"Authority profile" in body
    assert int(head_headers["Content-Length"]) == len(body)
    assert head_body == b""
    assert b".dashboard-grid" in css
    assert b"/api/snapshot" in javascript
    assert b"reconciliation_required_count" in javascript
    assert b"approval-free" in javascript
    assert b"state_integrity" in javascript
    assert b"known_result_recovery" in javascript
    assert b"Automatic recovery" in javascript
    assert b"renderAuthorityProfile" in javascript
    assert b"runtime_artifacts" in javascript
    assert b"launch_envelope" in javascript
    assert b"state_storage" in javascript
    assert b"acl_principal_count" in javascript
    assert b"protected ACL" in javascript
    assert b"control_plane_isolation" in javascript
    assert b"workspace_integrity" in javascript
    assert b"evidence_head" in javascript
    assert b"max_unwitnessed_records" in javascript
    assert b"unwitnessed_record_count" in javascript
    assert b"resource-limits" in body
    assert b"renderResourceLimits" in javascript
    assert b"tool_call_name_characters" in javascript
    assert b"tool_call_identifier_characters" in javascript
    assert b"tool_call_mapping_entries" in javascript
    assert b"tool_call_mapping_sort_work_units" in javascript
    assert b"tool_call_nesting_depth" in javascript
    assert b"tool_call_nodes" in javascript
    assert b"tool_call_number_characters" in javascript
    assert b"tool_call_scalar_characters" in javascript
    assert b"tool_call_string_token_bytes" in javascript
    assert b"tool_call_canonical_bytes" in javascript
    assert b"durable_json_bytes" in javascript
    assert b"evidence_export_bytes" in javascript
    assert b"operation_journal_bytes" in javascript
    assert b"hook_execution_state_bytes" in javascript
    assert b"approval_state_bytes" in javascript
    assert b"budget_state_bytes" in javascript
    assert b"evidence_head_state_bytes" in javascript
    assert b"evidence_witness_policy_state_bytes" in javascript
    assert b"authority_profile_state_bytes" in javascript
    assert b"authority_publication_state_bytes" in javascript
    assert b"authority_publication_manifest_bytes" in javascript
    assert b"operator_trust_state_bytes" in javascript
    assert b"mcp_config_collection_items" in javascript
    assert b"mcp_dependency_file_pins" in javascript
    assert b"mcp_launch_environment_entries" in javascript
    assert b"MCP collections bounded before transformation" in javascript
    assert b"policy_pack_bytes" in javascript
    assert b"policy_pack_count" in javascript
    assert b"policy_rule_count" in javascript
    assert b"policy_known_tool_count" in javascript
    assert b"policy_rule_field_items" in javascript
    assert b"policy_rule_list_items" in javascript
    assert b"policy_text_item_characters" in javascript
    assert b"policy_text_characters" in javascript
    assert b"policy text bounded before transformation" in javascript
    assert b"policy_match_payload_nesting_depth" in javascript
    assert b"policy_match_payload_nodes" in javascript
    assert b"policy_match_payload_characters" in javascript
    assert b"policy_payload_match_work_units" in javascript
    assert b"policy_match_tool_name_characters" in javascript
    assert b"policy_match_target_characters" in javascript
    assert b"policy_glob_match_work_units" in javascript
    assert b"policy_context_entries" in javascript
    assert b"policy_context_key_characters" in javascript
    assert b"policy_context_value_characters" in javascript
    assert b"policy_context_characters" in javascript
    assert b"action_hash_canonical_bytes" in javascript
    assert b"action_hash_mapping_entries" in javascript
    assert b"action_hash_mapping_sort_work_units" in javascript
    assert b"action_hash_nesting_depth" in javascript
    assert b"action_hash_nodes" in javascript
    assert b"action_hash_number_characters" in javascript
    assert b"action_hash_scalar_characters" in javascript
    assert b"action_hash_string_token_bytes" in javascript
    assert b"tool_result_summary_characters" in javascript
    assert b"tool_result_output_nesting_depth" in javascript
    assert b"tool_result_output_nodes" in javascript
    assert b"tool_result_output_number_characters" in javascript
    assert b"tool_result_output_scalar_characters" in javascript
    assert b"tool_result_output_string_token_bytes" in javascript
    assert b"tool_result_output_canonical_bytes" in javascript
    assert b"tool_result_output_mapping_entries" in javascript
    assert b"tool_result_output_mapping_sort_work_units" in javascript
    assert b"request_task_characters" in javascript
    assert b"request_identifier_characters" in javascript
    assert b"request_allowed_tool_count" in javascript
    assert b"request_allowed_tool_characters" in javascript
    assert b"request_text_characters" in javascript
    assert b"provenance_ref_count" in javascript
    assert b"provenance_text_item_characters" in javascript
    assert b"provenance_text_characters" in javascript
    assert (
        b"canonical mapping key families and complete key tokens, size, sort work, "
        b"values, strings, and numbers preflighted into a detached validated "
        b"snapshot adopted directly by action, tool-call, and tool-result owners; "
        b"request allowlist, request input, and action provenance collections "
        b"snapshotted from built-in storage before validation; "
        b"accepted scalar subclasses normalized to exact built-in values before "
        b"ownership; "
        b"policy decisions, capability grants, evidence records, and operation "
        b"journals retain "
        b"bounded exact built-in snapshots; "
        b"governed request construction, tool-call translation, "
        b"action hashing, "
        b"tool-result capture, "
        b"payload matching, glob matching, policy context, and journal "
        b"publication bounded "
        b"and fail-closed" in javascript
    )
    assert b"trusted_public_key_count" in javascript
    assert b"trusted_public_key_bytes" in javascript
    assert b"trusted_public_key_set_bytes" in javascript
    assert b"yaml_nesting_depth" in javascript
    assert b"yaml_nodes" in javascript
    assert b"authority_configuration" in javascript
    assert b"validated_policy_snapshot_ownership" in javascript
    assert b"policy rules, known tools, and authority inputs retained" in javascript
    assert b"sealed_policy_runtime_state" in javascript
    assert b"policy runtime rules and tool patterns immutable" in javascript
    assert b"validated_policy_context_snapshot" in javascript
    assert b"policy decision context bounded and retained" in javascript
    assert b"validated_operation_journal_snapshot" in javascript
    assert b"operation journal payload bounded" in javascript
    assert b"validated_native_hook_event_snapshot" in javascript
    assert b"native hook retry identity" in javascript
    assert b"sealed_authority_continuity_state" in javascript
    assert b"bounded_authority_continuity_io" in javascript
    assert b"crash_safe_authority_publication" in javascript
    assert b"validated_authority_publication_snapshot" in javascript
    assert b"verified_authority_publication_manifest" in javascript
    assert b"authority continuity recovery and publication" in javascript
    assert b"runtime_artifact_state_bytes" in javascript
    assert b"validated_runtime_artifact_state_snapshot" in javascript
    assert b"runtime artifact assurance validation and publication" in javascript
    assert b"launch_envelope_state_bytes" in javascript
    assert b"validated_launch_envelope_state_snapshot" in javascript
    assert b"launch envelope assurance validation and publication" in javascript
    assert b"state_storage_state_bytes" in javascript
    assert b"validated_state_storage_state_snapshot" in javascript
    assert b"state storage assurance validation and publication" in javascript
    assert b"control_plane_isolation_state_bytes" in javascript
    assert b"validated_control_plane_isolation_state_snapshot" in javascript
    assert b"control-plane isolation validation and publication" in javascript
    assert b"workspace_integrity_state_bytes" in javascript
    assert b"validated_workspace_integrity_state_snapshot" in javascript
    assert b"workspace-root validation and publication" in javascript
    assert b"sealed_native_hook_correlation_state" in javascript
    assert b"sealed_approval_record_state" in javascript
    assert b"approval records and held authority snapshots retained" in javascript
    assert b"validated_budget_ledger_snapshot" in javascript
    assert b"validated_evidence_head_snapshot" in javascript
    assert b"validated_evidence_witness_policy_snapshot" in javascript
    assert b"evidence-witness policy validation and publication" in javascript
    assert b"evidence-head checkpoint validation and publication" in javascript
    assert b"budget validation and publication use detached" in javascript
    assert b"authority profile and operator trust state retained" in javascript
    assert b"json_parser_profile" in javascript
    assert b"json_nesting_depth" in javascript
    assert b"json_lexical_tokens" in javascript
    assert b"json_string_token_characters" in javascript
    assert b"json_number_token_characters" in javascript
    assert b"bounded structure and scalars" in javascript
    assert b"duplicate keys refused" in javascript
    assert b"#resource-limits" in css


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_server_exposes_no_mutating_http_methods(tmp_path, method):
    workdir = tmp_path / "not-created"

    with _running_server(workdir) as server:
        status, headers, body = _request(server, method, "/api/snapshot")

    assert status == 405
    assert headers["Allow"] == "GET, HEAD, OPTIONS"
    assert body == b""
    assert not workdir.exists()


def test_snapshot_endpoint_filters_and_bounds_recent_activity(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    evidence.append(
        _record("req_one", "act_one", Decision.ALLOW, ResultStatus.SUCCEEDED)
    )
    evidence.append(_record("req_two", "act_two", Decision.BLOCK, ResultStatus.BLOCKED))

    with _running_server(tmp_path) as server:
        status, _, body = _request(
            server,
            "GET",
            "/api/snapshot?request_id=req_one&limit=1",
        )

    assert status == 200
    snapshot = json.loads(body)
    assert snapshot["evidence"]["filtered_request_id"] == "req_one"
    assert snapshot["evidence"]["record_count"] == 1
    assert len(snapshot["recent_activity"]) == 1
    assert snapshot["recent_activity"][0]["request_id"] == "req_one"


@pytest.mark.parametrize(
    "query",
    [
        "limit=101",
        "limit=-1",
        "limit=not-a-number",
        "limit=10&limit=20",
        "unknown=value",
        f"request_id={'x' * 257}",
    ],
)
def test_snapshot_endpoint_rejects_invalid_queries(tmp_path, query):
    with _running_server(tmp_path / "state") as server:
        status, _, body = _request(server, "GET", f"/api/snapshot?{query}")

    assert status == 400
    assert json.loads(body)["error"] == "invalid_request"


def test_broken_chain_is_visible_but_untrusted_evidence_is_withheld(tmp_path):
    path = tmp_path / "evidence.jsonl"
    EvidenceStore(path).append(
        _record("req_one", "act_one", Decision.ALLOW, ResultStatus.SUCCEEDED)
    )
    path.write_text(
        path.read_text().replace('"tool_name":"read_file"', '"tool_name":"changed"')
    )

    with _running_server(tmp_path) as server:
        status, _, body = _request(server, "GET", "/api/snapshot")

    assert status == 200
    snapshot = json.loads(body)
    assert snapshot["authoritative"] is False
    assert snapshot["evidence_integrity"]["ok"] is False
    assert snapshot["evidence"] is None
    assert snapshot["recent_activity"] == []


def test_server_configuration_is_bounded(tmp_path):
    with pytest.raises(CommandCenterError, match="port"):
        CommandCenterServer(tmp_path, port=65536)
    with pytest.raises(CommandCenterError, match="default limit"):
        CommandCenterServer(tmp_path, port=0, default_limit=MAX_LIMIT + 1)


def test_command_center_cli_is_loopback_server_configuration():
    args = build_parser().parse_args(
        [
            "--workdir",
            "local-state",
            "command-center",
            "--port",
            "9000",
            "--limit",
            "50",
        ]
    )

    assert args.fn.__name__ == "cmd_command_center"
    assert args.workdir == "local-state"
    assert args.port == 9000
    assert args.limit == 50
