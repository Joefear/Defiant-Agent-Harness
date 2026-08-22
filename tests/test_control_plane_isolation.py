from __future__ import annotations

import json

import pytest

from defiant_agent_harness.adapters.base import ToolCall
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import (
    Decision,
    EvidenceRecord,
    HarnessRequest,
    ProposedAction,
    ResultStatus,
    SideEffect,
)
from defiant_agent_harness.evidence.store import GENESIS
from defiant_agent_harness.control_plane_isolation import (
    ControlPlaneIsolationError,
    ControlPlaneIsolationStateStore,
)
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.persistence import atomic_write_json, read_json
from defiant_agent_harness.state_integrity import StateIntegrityAuditor
from defiant_agent_harness.tools.registry import (
    ToolContractError,
    ToolRegistry,
    ToolResult,
    ToolSpec,
)


def _read_action(target: str) -> ProposedAction:
    return ProposedAction(
        tool_name="read_file",
        target=target,
        payload={"path": target},
        side_effect_level=SideEffect.NONE,
        request_id="req_isolation",
    )


def test_harness_records_sanitized_profile_bound_isolation(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = workspace / ".dah"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)

    isolation = CommandCore(state).snapshot()["control_plane_isolation"]
    serialized = json.dumps(isolation)
    assert isolation["state"] == "protected_state_root"
    assert isolation["verification"] == "verified"
    assert isolation["relationship"] == "state_within_workspace"
    assert isolation["protected_root_count"] == 1
    assert isolation["contract_hash"].startswith("sha256:")
    assert isolation["workspace_hash"].startswith("sha256:")
    assert str(workspace) not in serialized
    assert str(state) not in serialized


def test_direct_and_symlinked_state_targets_are_refused(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = workspace / ".dah"
    harness = build_harness(state, MockAgentAdapter(), workspace_root=workspace)

    with pytest.raises(ToolContractError, match="protected control-plane"):
        harness.tools.validate_action(_read_action("workspace/.dah/approvals.json"))

    link = workspace / "apparently-safe"
    try:
        link.symlink_to(state, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation is unavailable")
    with pytest.raises(ToolContractError, match="protected control-plane"):
        harness.tools.validate_action(
            _read_action("workspace/apparently-safe/approvals.json")
        )


def test_symlink_retarget_after_authorization_is_refused_before_execution(tmp_path):
    workspace = tmp_path / "workspace"
    safe = workspace / "safe"
    safe.mkdir(parents=True)
    (safe / "note.txt").write_text("safe", encoding="utf-8")
    state = workspace / ".dah"
    harness = build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    link = workspace / "current"
    try:
        link.symlink_to(safe, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation is unavailable")
    action = _read_action("workspace/current/note.txt")
    authorization = EvidenceRecord(
        request_id=action.request_id,
        action_id=action.action_id,
        decision=Decision.ALLOW,
        result_status=ResultStatus.SKIPPED,
        tool_name=action.tool_name,
        target=action.target,
        side_effect_level=action.side_effect_level.value,
        payload_hash=action.payload_hash,
        authorization_hash=action.authorization_hash,
    ).seal(GENESIS)
    grant = harness.tools.authorize(action, authorization)

    link.unlink()
    link.symlink_to(state, target_is_directory=True)
    with pytest.raises(ToolContractError, match="protected control-plane"):
        harness.tools.execute(action, grant)
    assert grant.spent is False


def test_directory_scope_cannot_contain_protected_state(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = workspace / ".dah"
    registry = ToolRegistry(workspace_root=workspace)
    registry.register(
        ToolSpec(
            "list_directory",
            SideEffect.NONE,
            "List one directory.",
            target_scope="workspace_path",
        ),
        lambda action: ToolResult(status="succeeded", summary=action.target),
    )
    harness = build_harness(
        state,
        MockAgentAdapter(),
        tools=registry,
        workspace_root=workspace,
    )
    root_action = ProposedAction(
        tool_name="list_directory",
        target="workspace",
        payload={"path": "."},
        side_effect_level=SideEffect.NONE,
        request_id="req_directory",
    )

    with pytest.raises(ToolContractError, match="protected control-plane"):
        harness.tools.validate_action(root_action)


def test_ordinary_workspace_target_remains_available(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = workspace / ".dah"
    harness = build_harness(state, MockAgentAdapter(), workspace_root=workspace)

    harness.tools.validate_action(_read_action("workspace/customer.txt"))


def test_harness_blocks_state_read_with_terminal_evidence(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = workspace / ".dah"
    harness = build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    request = HarnessRequest(
        task="attempt control-plane read",
        user_id="tester",
        workspace_id="ws",
    )

    outcome = harness.handle_call(
        ToolCall("read_file", {"path": "workspace/.dah/approvals.json"}),
        request,
    )

    assert outcome.status is ResultStatus.BLOCKED
    assert outcome.decision.policy_ids == ["tool_contract"]
    assert "protected control-plane" in outcome.decision.reason
    record = harness.evidence.get(outcome.evidence_record_id)
    assert record["result_status"] == "blocked"


def test_isolation_state_tamper_fails_read_only_integrity_gate(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    path = state / "control_plane_isolation.json"
    raw = read_json(path)
    raw["relationship"] = "forged"
    atomic_write_json(path, raw)

    with pytest.raises(ControlPlaneIsolationError, match="relationship"):
        ControlPlaneIsolationStateStore(path).get()
    report = StateIntegrityAuditor(state).audit()
    assert report.safe_to_execute is False
    assert any(
        issue.code == "control_plane_isolation_invalid" for issue in report.issues
    )


def test_missing_profile_bound_observation_requires_migration(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    (state / "control_plane_isolation.json").unlink()

    report = StateIntegrityAuditor(state).audit()
    assert report.safe_to_execute is True
    assert report.recovery_required is True
    assert any(
        issue.code == "control_plane_isolation_observation_missing"
        for issue in report.issues
    )


def test_profile_binding_tamper_is_reported_without_paths(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    path = state / "control_plane_isolation.json"
    raw = read_json(path)
    raw["profile_hash"] = "sha256:" + "0" * 64
    atomic_write_json(path, raw)

    report = StateIntegrityAuditor(state).audit()
    serialized = json.dumps(report.to_dict())
    assert report.safe_to_execute is False
    assert any(
        issue.code == "control_plane_isolation_profile_mismatch"
        for issue in report.issues
    )
    assert str(state) not in serialized
