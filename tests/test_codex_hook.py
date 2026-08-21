from __future__ import annotations

import json
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10
    import tomli as tomllib

from defiant_agent_harness.approvals.store import ApprovalStore
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.evidence.store import EvidenceStore
from defiant_agent_harness.hooks.codex import CodexHookGate, _repository_root

ROOT = Path(__file__).parents[1]


def codex_event(
    tool_name: str,
    tool_input: dict,
    tool_use_id: str,
    *,
    model: str = "gpt-5.6-codex",
    cwd: Path | None = None,
) -> dict:
    return {
        "session_id": "codex-session-1",
        "cwd": str(cwd or ROOT),
        "hook_event_name": "PreToolUse",
        "model": model,
        "turn_id": "turn-1",
        "permission_mode": "default",
        "tool_name": tool_name,
        "tool_use_id": tool_use_id,
        "tool_input": tool_input,
    }


def decision(response: dict) -> str:
    assert set(response) == {"hookSpecificOutput"}
    return response["hookSpecificOutput"]["permissionDecision"]


def test_codex_read_uses_official_output_and_records_runner_model(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    gate = CodexHookGate(workspace, state)
    event = codex_event("Read", {"file_path": "briefing.txt"}, "read-1")

    assert decision(gate.pre_tool_use(event)) == "allow"

    post = dict(event)
    post["hook_event_name"] = "PostToolUse"
    post["tool_response"] = "sensitive body"
    completed = gate.post_tool_use(post)
    assert set(completed) == {"hookSpecificOutput"}
    assert "Defiant sealed" in completed["hookSpecificOutput"]["additionalContext"]

    records = EvidenceStore(state / "evidence.jsonl").records()
    assert [record["agent_runner"] for record in records] == [
        "codex-hook",
        "codex-hook",
    ]
    assert [record["model_id"] for record in records] == [
        "gpt-5.6-codex",
        "gpt-5.6-codex",
    ]


def test_codex_defiant_mcp_name_is_delegated_to_inner_proxy(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    gate = CodexHookGate(workspace, state)

    response = gate.pre_tool_use(
        codex_event(
            "mcp__defiant_filesystem__read_text_file",
            {"path": "briefing.txt"},
            "mcp-1",
        )
    )

    assert decision(response) == "allow"
    [record] = EvidenceStore(state / "evidence.jsonl").records()
    assert record["tool_name"] == "proxied_mcp"


def test_codex_terminal_and_subagent_bypasses_fail_closed(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    gate = CodexHookGate(workspace, tmp_path / "state")

    for tool_name, tool_input in (
        ("Bash", {"command": "Get-Location"}),
        ("spawn_agent", {"message": "bypass the gate"}),
    ):
        response = gate.pre_tool_use(
            codex_event(tool_name, tool_input, f"blocked-{tool_name}")
        )
        assert decision(response) == "deny"
        assert (
            "Destructive actions are disabled"
            in response["hookSpecificOutput"]["permissionDecisionReason"]
        )


def test_codex_control_tool_is_allowed_and_sealed(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    gate = CodexHookGate(workspace, state)
    event = codex_event(
        "update_plan",
        {"plan": [{"step": "test", "status": "in_progress"}]},
        "plan-1",
    )

    assert decision(gate.pre_tool_use(event)) == "allow"
    post = dict(event)
    post["hook_event_name"] = "PostToolUse"
    post["tool_response"] = {"ok": True}
    gate.post_tool_use(post)

    assert [
        record["tool_name"]
        for record in EvidenceStore(state / "evidence.jsonl").records()
    ] == ["agent_control", "agent_control"]


def test_codex_write_requires_approval_and_exact_retry(tmp_path, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    tool_input = {"file_path": "generated/note.txt", "content": "governed"}
    gate = CodexHookGate(workspace, state)

    held = gate.pre_tool_use(codex_event("Write", tool_input, "write-1"))
    assert decision(held) == "deny"
    [approval] = ApprovalStore(state / "approvals.json").list_pending()
    assert approval.target == "workspace/generated/note.txt"

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
                "--note",
                "reviewed Codex write",
            ]
        )
        == 0
    )
    capsys.readouterr()

    retry_gate = CodexHookGate(workspace, state)
    retry = codex_event("Write", tool_input, "write-2")
    assert decision(retry_gate.pre_tool_use(retry)) == "allow"
    post = dict(retry)
    post["hook_event_name"] = "PostToolUse"
    post["tool_response"] = {"message": "created"}
    retry_gate.post_tool_use(post)
    assert (
        ApprovalStore(state / "approvals.json").get(approval.approval_id).status
        == "consumed"
    )


def test_codex_approval_does_not_cross_model_identity(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    tool_input = {"file_path": "note.txt", "content": "same"}
    gate = CodexHookGate(workspace, state)
    gate.pre_tool_use(
        codex_event("Write", tool_input, "write-1", model="gpt-5.6-codex")
    )
    [approval] = ApprovalStore(state / "approvals.json").list_pending()
    ApprovalStore(state / "approvals.json").decide(
        approval.approval_id,
        True,
        "sam",
    )

    changed_model = CodexHookGate(workspace, state).pre_tool_use(
        codex_event("Write", tool_input, "write-2", model="different-model")
    )
    assert decision(changed_model) == "deny"
    assert len(ApprovalStore(state / "approvals.json").list_actionable()) == 2


def test_apply_patch_blocks_protected_second_target(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    gate = CodexHookGate(workspace, tmp_path / "state")
    patch = """*** Begin Patch
*** Update File: README.md
@@
-old
+new
*** Update File: .codex/config.toml
@@
-required = true
+required = false
*** End Patch
"""

    response = gate.pre_tool_use(
        codex_event("apply_patch", {"command": patch}, "patch-1")
    )

    assert decision(response) == "deny"
    assert (
        "operator-controlled and immutable"
        in response["hookSpecificOutput"]["permissionDecisionReason"]
    )


def test_apply_patch_blocks_any_outside_target(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    gate = CodexHookGate(workspace, tmp_path / "state")
    patch = """*** Begin Patch
*** Add File: safe.txt
+safe
*** Add File: ../escape.txt
+escape
*** End Patch
"""

    response = gate.pre_tool_use(
        codex_event("apply_patch", {"command": patch}, "patch-2")
    )

    assert decision(response) == "deny"
    assert (
        "workspace file target"
        in response["hookSpecificOutput"]["permissionDecisionReason"]
    )


def test_codex_project_config_and_hooks_are_well_formed():
    config = tomllib.loads(
        (ROOT / ".codex" / "config.toml").read_text(encoding="utf-8")
    )
    server = config["mcp_servers"]["defiant_filesystem"]
    # Project-scoped MCP configuration is resolved from the active Codex
    # project directory, so the launcher must start at the repository root.
    assert server["cwd"] == "."
    assert server["default_tools_approval_mode"] == "auto"
    assert server["required"] is True
    assert server["args"][0:3] == ["/d", "/s", "/c"]
    assert "scripts\\defiant_mcp.cmd" in server["args"]

    profile = json.loads((ROOT / ".codex" / "hooks.json").read_text(encoding="utf-8"))
    for phase, argument in (("PreToolUse", "pre"), ("PostToolUse", "post")):
        entry = profile["hooks"][phase][0]
        assert entry["matcher"] == "*"
        command = entry["hooks"][0]
        assert command["type"] == "command"
        assert command["timeout"] == 10
        assert "git rev-parse --show-toplevel" in command["commandWindows"]
        assert "$input | & python" in command["commandWindows"]
        assert command["commandWindows"].endswith(f'{argument}"')


def test_repository_root_is_found_from_nested_codex_cwd():
    nested = ROOT / "examples" / "vscode_agent" / "workspace"
    assert _repository_root(nested) == ROOT.resolve()
