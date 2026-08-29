from __future__ import annotations

import json

import pytest

import defiant_agent_harness.control_plane_isolation as isolation_module
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
    ControlPlaneIsolationAssurance,
    ControlPlaneIsolationError,
    ControlPlaneIsolationState,
    ControlPlaneIsolationStateStore,
    build_control_plane_isolation,
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

    link.unlink()
    link.symlink_to(safe, target_is_directory=True)
    result = harness.tools.execute(action, grant)
    assert result.status == "succeeded"


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


def test_isolation_store_owns_hostile_bounded_snapshot(tmp_path, monkeypatch):
    class HostileDict(dict):
        def __deepcopy__(self, memo):
            raise AssertionError("isolation snapshot invoked deepcopy hook")

        def __iter__(self):
            raise AssertionError("isolation snapshot invoked mapping iterator hook")

        def get(self, key, default=None):
            raise AssertionError("isolation snapshot invoked mapping get hook")

        def items(self):
            raise AssertionError("isolation snapshot invoked mapping items hook")

        def keys(self):
            raise AssertionError("isolation snapshot invoked mapping keys hook")

    class HostileString(str):
        def __deepcopy__(self, memo):
            raise AssertionError("isolation snapshot invoked scalar deepcopy hook")

        def __str__(self):
            raise AssertionError("isolation snapshot invoked scalar rendering hook")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    build_harness(state_root, MockAgentAdapter(), workspace_root=workspace)
    path = state_root / "control_plane_isolation.json"
    store = ControlPlaneIsolationStateStore(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    supplied = HostileDict(
        {
            key: HostileString(value) if type(value) is str else value
            for key, value in raw.items()
        }
    )
    observed = []

    def hostile_read(path, *, max_bytes=None):
        observed.append(max_bytes)
        return supplied

    monkeypatch.setattr(isolation_module, "read_json", hostile_read)
    stored = store.get()
    expected = stored.to_dict()
    dict.__setitem__(supplied, "contract_hash", HostileString("sha256:" + "0" * 64))

    assert stored.to_dict() == expected
    assert type(stored.profile_hash) is str
    assert type(stored.mode) is str
    assert type(stored.contract_hash) is str
    assert type(stored.workspace_hash) is str
    assert type(stored.relationship) is str
    assert type(stored.verified_at) is str
    assert observed == [isolation_module._MAX_STATE_BYTES]


def test_isolation_record_detaches_inputs_before_comparison_and_write(
    tmp_path, monkeypatch
):
    class HostileString(str):
        def __str__(self):
            raise AssertionError("isolation record rendered caller scalar")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    observed_assurance = build_control_plane_isolation(workspace, state_root)
    profile = HostileString("sha256:" + "1" * 64)
    contract_hash = HostileString(observed_assurance.contract_hash)
    assurance = ControlPlaneIsolationAssurance(
        HostileString(observed_assurance.mode),
        contract_hash,
        HostileString(observed_assurance.workspace_hash),
        observed_assurance.protected_root_count,
        HostileString(observed_assurance.relationship),
        observed_assurance.workspace_root,
        observed_assurance.protected_roots,
    )
    original_write = isolation_module.atomic_write_json
    observed = []

    def mutating_write(path, data, *, max_bytes=None):
        object.__setattr__(assurance, "contract_hash", "sha256:" + "2" * 64)
        observed.append(
            (
                max_bytes,
                type(data["profile_hash"]),
                type(data["mode"]),
                type(data["contract_hash"]),
                type(data["relationship"]),
            )
        )
        return original_write(path, data, max_bytes=max_bytes)

    monkeypatch.setattr(isolation_module, "atomic_write_json", mutating_write)
    store = ControlPlaneIsolationStateStore(state_root / "control_plane_isolation.json")
    stored = store.record(profile, assurance)

    assert stored.contract_hash == contract_hash
    assert store.get().contract_hash == contract_hash
    assert observed == [(isolation_module._MAX_STATE_BYTES, str, str, str, str)]


def test_isolation_state_rejects_noncanonical_input_without_secret_echo():
    class SecretValue:
        def __repr__(self):
            return "secret-isolation-value"

    with pytest.raises(ControlPlaneIsolationError) as failure:
        ControlPlaneIsolationState.from_dict({"secret": SecretValue()})

    assert "secret-isolation-value" not in str(failure.value)
    assert "SecretValue" not in str(failure.value)


def test_oversized_isolation_state_fails_at_opened_stream_ceiling(tmp_path):
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    path = state_root / "control_plane_isolation.json"
    path.write_bytes(b" " * (isolation_module._MAX_STATE_BYTES + 1))
    path.chmod(0o600)

    with pytest.raises(ControlPlaneIsolationError, match="exceeds 65536 bytes"):
        ControlPlaneIsolationStateStore(path).get()


def test_isolation_refuses_unrecoverable_publication_without_replacement(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    store = ControlPlaneIsolationStateStore(state_root / "control_plane_isolation.json")
    current = store.record(
        "sha256:" + "1" * 64,
        build_control_plane_isolation(workspace, state_root),
    )
    prior = store.path.read_bytes()
    original_limit = isolation_module._MAX_STATE_BYTES
    monkeypatch.setattr(isolation_module, "_MAX_STATE_BYTES", 1)

    with pytest.raises(ControlPlaneIsolationError, match="bounded canonical state"):
        isolation_module._write_state(store.path, current)

    assert store.path.read_bytes() == prior
    monkeypatch.setattr(isolation_module, "_MAX_STATE_BYTES", original_limit)
    assert store.get() == current
