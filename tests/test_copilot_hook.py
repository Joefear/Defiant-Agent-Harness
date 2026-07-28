from __future__ import annotations

import json
from pathlib import Path

import pytest

from defiant_agent_harness.approvals.store import ApprovalStore
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.evidence.store import EvidenceStore
from defiant_agent_harness.hooks.copilot import CopilotHookGate
from defiant_agent_harness.hooks.state import HookStateError

ROOT = Path(__file__).parents[1]


def hook_event(
    tool_name: str,
    tool_input: dict,
    tool_use_id: str,
    *,
    session_id: str = "session-1",
) -> dict:
    return {
        "timestamp": "2026-07-26T18:00:00Z",
        "cwd": str(ROOT),
        "session_id": session_id,
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": tool_use_id,
    }


def permission(response: dict) -> str:
    assert (
        response["permissionDecision"]
        == (response["hookSpecificOutput"]["permissionDecision"])
    )
    return response["permissionDecision"]


def cli_hook_event(
    tool_name: str,
    tool_args: dict | str,
    *,
    session_id: str = "session-cli",
) -> dict:
    return {
        "timestamp": 1785088800000,
        "cwd": str(ROOT),
        "sessionId": session_id,
        "toolName": tool_name,
        "toolArgs": tool_args,
    }


def test_read_is_authorized_then_sealed_without_raw_output(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    gate = CopilotHookGate(workspace, state)
    event = hook_event("Read", {"file_path": "briefing.txt"}, "read-1")

    allowed = gate.pre_tool_use(event)
    assert permission(allowed) == "allow"

    post = dict(event)
    post["hook_event_name"] = "PostToolUse"
    post["tool_response"] = "sensitive file body"
    completed = gate.post_tool_use(post)
    assert "Defiant sealed" in completed["hookSpecificOutput"]["additionalContext"]

    records = EvidenceStore(state / "evidence.jsonl").records()
    assert [record["result_status"] for record in records] == [
        "skipped",
        "succeeded",
    ]
    assert [record["tool_name"] for record in records] == [
        "read_file",
        "read_file",
    ]
    assert "sensitive file body" not in (state / "evidence.jsonl").read_text(
        encoding="utf-8"
    )


def test_cli_payload_without_tool_id_is_correlated_and_sealed(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    gate = CopilotHookGate(workspace, state)
    event = cli_hook_event(
        "view",
        json.dumps({"path": "briefing.txt"}),
    )

    assert permission(gate.pre_tool_use(event)) == "allow"

    post = dict(event)
    post["timestamp"] += 1
    post["toolResult"] = {
        "resultType": "success",
        "textResultForLlm": "sensitive file body",
    }
    completed = gate.post_tool_use(post)
    assert "Defiant sealed" in completed["additionalContext"]

    records = EvidenceStore(state / "evidence.jsonl").records()
    assert [record["result_status"] for record in records] == [
        "skipped",
        "succeeded",
    ]
    assert "sensitive file body" not in (state / "evidence.jsonl").read_text(
        encoding="utf-8"
    )


def test_cli_terminal_denial_reports_policy_reason(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    gate = CopilotHookGate(workspace, tmp_path / "state")

    response = gate.pre_tool_use(
        cli_hook_event("powershell", {"command": "Get-Location"})
    )

    assert permission(response) == "deny"
    assert "Destructive actions are disabled" in response["permissionDecisionReason"]


@pytest.mark.parametrize(
    "tool_name",
    [
        "defiant-filesystem-list_allowed_directories",
        "defiant-filesystem-read_text_file",
        "defiant-filesystem-write_file",
    ],
)
def test_known_defiant_mcp_tools_are_delegated_to_inner_proxy(tmp_path, tool_name):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    gate = CopilotHookGate(workspace, state)

    response = gate.pre_tool_use(cli_hook_event(tool_name, {}))

    assert permission(response) == "allow"
    [record] = EvidenceStore(state / "evidence.jsonl").records()
    assert record["tool_name"] == "proxied_mcp"
    assert record["side_effect_level"] == "none"


def test_retried_defiant_mcp_call_does_not_require_outer_post_event(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    gate = CopilotHookGate(workspace, state)
    event = cli_hook_event(
        "defiant-filesystem-write_file",
        {"path": "generated/note.txt", "content": "governed"},
    )

    assert permission(gate.pre_tool_use(event)) == "allow"
    assert permission(gate.pre_tool_use(event)) == "allow"
    assert (
        json.loads((state / "hook_executions.json").read_text(encoding="utf-8")) == {}
    )

    post = dict(event)
    post["toolResult"] = {"resultType": "success"}
    completed = gate.post_tool_use(post)
    assert "inner MCP proxy" in completed["additionalContext"]

    records = EvidenceStore(state / "evidence.jsonl").records()
    assert [record["result_status"] for record in records] == ["skipped", "skipped"]


def test_unknown_defiant_mcp_tool_still_fails_closed(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    gate = CopilotHookGate(workspace, tmp_path / "state")

    response = gate.pre_tool_use(
        cli_hook_event("defiant-filesystem-unclassified_tool", {})
    )

    assert permission(response) == "deny"
    assert "Destructive actions are disabled" in response["permissionDecisionReason"]


def test_repeated_identical_cli_reads_can_complete_serially(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    event = cli_hook_event("view", {"path": "briefing.txt"})
    gate = CopilotHookGate(workspace, state)

    for result in ("first", "second"):
        assert permission(gate.pre_tool_use(event)) == "allow"
        post = dict(event)
        post["toolResult"] = {
            "resultType": "success",
            "textResultForLlm": result,
        }
        gate.post_tool_use(post)

    records = EvidenceStore(state / "evidence.jsonl").records()
    assert [record["result_status"] for record in records] == [
        "skipped",
        "succeeded",
        "skipped",
        "succeeded",
    ]


def test_write_requires_durable_exact_retry_then_records_success(tmp_path, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    tool_input = {
        "file_path": "generated/note.txt",
        "content": "governed content",
    }
    gate = CopilotHookGate(workspace, state)

    first = gate.pre_tool_use(hook_event("Write", tool_input, "write-1"))
    assert permission(first) == "deny"
    [approval] = ApprovalStore(state / "approvals.json").list_pending()
    assert approval.tool_name == "write_file"
    assert approval.target == "workspace/generated/note.txt"

    repeated = gate.pre_tool_use(hook_event("Write", tool_input, "write-2"))
    assert permission(repeated) == "deny"
    assert (
        approval.approval_id
        in repeated["hookSpecificOutput"]["permissionDecisionReason"]
    )
    assert len(ApprovalStore(state / "approvals.json").list_pending()) == 1

    assert (
        main(
            [
                "--workdir",
                str(state),
                "--workspace-root",
                str(workspace),
                "--user",
                "sam",
                "approve",
                approval.approval_id,
            ]
        )
        == 0
    )
    assert ApprovalStore(state / "approvals.json").get(approval.approval_id).status == (
        "approved"
    )
    capsys.readouterr()

    restarted = CopilotHookGate(workspace, state)
    retry_event = hook_event("Write", tool_input, "write-3")
    retry = restarted.pre_tool_use(retry_event)
    assert permission(retry) == "allow"
    assert ApprovalStore(state / "approvals.json").get(approval.approval_id).status == (
        "executing"
    )

    post = dict(retry_event)
    post["hook_event_name"] = "PostToolUse"
    post["tool_response"] = {"message": "created"}
    restarted.post_tool_use(post)
    consumed = ApprovalStore(state / "approvals.json").get(approval.approval_id)
    assert consumed.status == "consumed"

    records = EvidenceStore(state / "evidence.jsonl").records()
    assert [record["result_status"] for record in records] == [
        "pending_approval",
        "skipped",
        "succeeded",
    ]
    assert records[-1]["approved_by"] == "sam"
    assert EvidenceStore(state / "evidence.jsonl").verify().ok


def test_changed_write_does_not_inherit_approval(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    original = {"file_path": "note.txt", "content": "one"}
    gate = CopilotHookGate(workspace, state)
    gate.pre_tool_use(hook_event("Write", original, "write-1"))
    [approval] = ApprovalStore(state / "approvals.json").list_pending()
    ApprovalStore(state / "approvals.json").decide(
        approval.approval_id,
        True,
        "sam",
    )

    changed = {"file_path": "note.txt", "content": "two"}
    response = CopilotHookGate(workspace, state).pre_tool_use(
        hook_event("Write", changed, "write-2")
    )
    assert permission(response) == "deny"
    actionable = ApprovalStore(state / "approvals.json").list_actionable()
    assert len(actionable) == 2
    assert len({item.payload_hash for item in actionable}) == 2
    assert {item.status for item in actionable} == {"approved", "pending"}


@pytest.mark.parametrize(
    ("tool_name", "tool_input", "reason_fragment"),
    [
        (
            "Write",
            {"file_path": "../outside.txt", "content": "escape"},
            "workspace file target",
        ),
        (
            "Write",
            {"file_path": ".github/hooks/defiant.json", "content": "{}"},
            "operator-controlled and immutable",
        ),
        (
            "Write",
            {
                "file_path": "src/defiant_agent_harness/orchestrator/harness.py",
                "content": "# bypass",
            },
            "operator-controlled and immutable",
        ),
        (
            "Write",
            {"file_path": ".mcp.json", "content": "{}"},
            "operator-controlled and immutable",
        ),
        (
            "Write",
            {"file_path": ".vscode/mcp.json", "content": "{}"},
            "operator-controlled and immutable",
        ),
        (
            "Write",
            {
                "file_path": "examples/filesystem/mcp-proxy.yaml",
                "content": "tools: {}",
            },
            "operator-controlled and immutable",
        ),
        (
            "Bash",
            {"command": "echo bypass > bypass.txt"},
            "Destructive actions are disabled",
        ),
        (
            "unclassifiedVendorTool",
            {"anything": "goes"},
            "Destructive actions are disabled",
        ),
        (
            "Agent",
            {"prompt": "use an ungoverned subagent"},
            "Destructive actions are disabled",
        ),
    ],
)
def test_native_bypass_paths_fail_closed(
    tmp_path,
    tool_name,
    tool_input,
    reason_fragment,
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    gate = CopilotHookGate(workspace, tmp_path / "state")
    response = gate.pre_tool_use(hook_event(tool_name, tool_input, "blocked-1"))
    assert permission(response) == "deny"
    assert reason_fragment in response["hookSpecificOutput"]["permissionDecisionReason"]


def test_multi_file_edit_blocks_when_any_path_escapes(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    gate = CopilotHookGate(workspace, tmp_path / "state")
    response = gate.pre_tool_use(
        hook_event(
            "editFiles",
            {"files": ["safe.txt", "../outside.txt"]},
            "edit-1",
        )
    )
    assert permission(response) == "deny"
    assert (
        "workspace file target"
        in response["hookSpecificOutput"]["permissionDecisionReason"]
    )


def test_post_tool_input_must_match_pre_tool_input(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    gate = CopilotHookGate(workspace, state)
    event = hook_event("Read", {"file_path": "one.txt"}, "read-1")
    assert permission(gate.pre_tool_use(event)) == "allow"

    changed = dict(event)
    changed["hook_event_name"] = "PostToolUse"
    changed["tool_input"] = {"file_path": "two.txt"}
    changed["tool_response"] = "done"
    with pytest.raises(HookStateError, match="differs"):
        gate.post_tool_use(changed)


def test_post_without_pre_authorization_stops_processing(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    gate = CopilotHookGate(workspace, tmp_path / "state")
    event = hook_event("Read", {"file_path": "one.txt"}, "missing")
    event["hook_event_name"] = "PostToolUse"
    event["tool_response"] = "done"
    with pytest.raises(HookStateError, match="no Defiant authorization"):
        gate.post_tool_use(event)


def test_workspace_hook_profile_uses_repository_launcher():
    profile = json.loads(
        (ROOT / ".github" / "hooks" / "defiant.json").read_text(encoding="utf-8")
    )
    assert profile["version"] == 1
    assert profile["hooks"]["preToolUse"][0]["powershell"] == (
        r"python scripts\defiant_hook.py pre"
    )
    assert profile["hooks"]["postToolUse"][0]["powershell"] == (
        r"python scripts\defiant_hook.py post"
    )
    assert (ROOT / "scripts" / "defiant_hook.py").is_file()
