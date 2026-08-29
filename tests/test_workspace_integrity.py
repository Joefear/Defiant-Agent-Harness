from __future__ import annotations

import json

import pytest

import defiant_agent_harness.workspace_integrity as workspace_module
from defiant_agent_harness.adapters.base import ToolCall
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.cli.main import main
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
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.persistence import atomic_write_json, read_json
from defiant_agent_harness.state_integrity import (
    StateIntegrityAuditor,
    StateIntegrityError,
)
from defiant_agent_harness.tools.registry import (
    ToolContractError,
    ToolRegistry,
    ToolResult,
    ToolSpec,
)
from defiant_agent_harness.workspace_integrity import (
    WorkspaceIntegrityState,
    WorkspaceIntegrityError,
    WorkspaceIntegrityStateStore,
    WorkspaceRootAssurance,
    inspect_workspace_root,
    prepare_workspace_root,
)


def _action() -> ProposedAction:
    return ProposedAction(
        tool_name="read_file",
        target="workspace/note.txt",
        payload={"path": "workspace/note.txt"},
        side_effect_level=SideEffect.NONE,
        request_id="req_workspace_identity",
    )


def _authorization(action: ProposedAction) -> EvidenceRecord:
    return EvidenceRecord(
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


def test_authority_startup_creates_and_records_workspace_root(tmp_path):
    workspace = tmp_path / "missing-workspace"
    state = tmp_path / "state"

    build_harness(state, MockAgentAdapter(), workspace_root=workspace)

    assert workspace.is_dir()
    stored = WorkspaceIntegrityStateStore(state / "workspace_integrity.json").get()
    assert stored is not None
    assert stored.authority_dict() == inspect_workspace_root(workspace).authority_dict()
    projection = CommandCore(state, workspace_root=workspace).snapshot()[
        "workspace_integrity"
    ]
    serialized = json.dumps(projection)
    assert projection["state"] == "identity_bound"
    assert projection["verification"] == "verified"
    assert str(workspace) not in serialized


def test_read_only_commands_do_not_create_missing_workspace_or_state(tmp_path, capsys):
    workspace = tmp_path / "missing-workspace"
    state = tmp_path / "missing-state"

    exit_code = main(
        [
            "--workdir",
            str(state),
            "--workspace-root",
            str(workspace),
            "doctor",
        ]
    )

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "healthy"
    assert not workspace.exists()
    assert not state.exists()


def test_workspace_root_must_be_a_real_directory(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.write_text("not a directory", encoding="utf-8")

    with pytest.raises(WorkspaceIntegrityError, match="directory"):
        build_harness(tmp_path / "state", MockAgentAdapter(), workspace_root=workspace)


def test_symlinked_workspace_root_is_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    workspace = tmp_path / "workspace"
    try:
        workspace.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation is unavailable")

    with pytest.raises(WorkspaceIntegrityError, match="symlink|reparse"):
        build_harness(tmp_path / "state", MockAgentAdapter(), workspace_root=workspace)


def test_workspace_contents_may_change_without_root_drift(tmp_path):
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)

    (workspace / "mutable.txt").write_text("changed", encoding="utf-8")
    report = StateIntegrityAuditor(state, workspace_root=workspace).audit()

    assert report.safe_to_execute is True
    assert report.stores["workspace_integrity"]["verification"] == "verified"


def test_replaced_workspace_root_blocks_harness_before_evidence(tmp_path):
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    adapter = MockAgentAdapter([ToolCall("read_file", {"path": "workspace/note.txt"})])
    harness = build_harness(state, adapter, workspace_root=workspace)
    displaced = tmp_path / "displaced"
    workspace.rename(displaced)
    workspace.mkdir()

    with pytest.raises(StateIntegrityError, match="workspace_root_mismatch"):
        harness.run(HarnessRequest(task="read", user_id="tester", workspace_id="ws"))

    assert harness.evidence.records() == []


def test_registry_rechecks_root_before_dispatch_without_spending_grant(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    invoked: list[str] = []
    registry = ToolRegistry(workspace_root=workspace)
    registry.register(
        ToolSpec(
            "read_file",
            SideEffect.NONE,
            "test workspace read",
            target_scope="workspace",
        ),
        lambda action: (
            invoked.append(action.target)
            or ToolResult(status="succeeded", summary="read")
        ),
    )
    harness = build_harness(
        tmp_path / "state",
        MockAgentAdapter(),
        tools=registry,
        workspace_root=workspace,
    )
    action = _action()
    grant = harness.tools.authorize(action, _authorization(action))
    displaced = tmp_path / "displaced"
    workspace.rename(displaced)
    workspace.mkdir()

    with pytest.raises(ToolContractError, match="identity changed"):
        harness.tools.execute(action, grant)
    assert invoked == []

    workspace.rmdir()
    displaced.rename(workspace)
    result = harness.tools.execute(action, grant)
    assert result.status == "succeeded"
    assert invoked == ["workspace/note.txt"]


def test_live_command_projection_reports_missing_root_without_paths(tmp_path):
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    workspace.rmdir()

    snapshot = CommandCore(state, workspace_root=workspace).snapshot()
    serialized = json.dumps(snapshot["workspace_integrity"])

    assert snapshot["authoritative"] is False
    assert snapshot["workspace_integrity"]["verification"] == "root_missing"
    assert any(
        issue["code"] == "workspace_root_missing"
        for issue in snapshot["state_integrity"]["issues"]
    )
    assert str(workspace) not in serialized


def test_read_only_projection_without_workspace_is_profile_bound(tmp_path):
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)

    projection = CommandCore(state).snapshot()["workspace_integrity"]

    assert projection["verification"] == "profile_bound"


def test_workspace_state_schema_and_profile_tamper_are_critical(tmp_path):
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    path = state / "workspace_integrity.json"
    raw = read_json(path)
    raw["unexpected"] = True
    atomic_write_json(path, raw)

    malformed = StateIntegrityAuditor(state, workspace_root=workspace).audit()
    assert malformed.safe_to_execute is False
    assert any(
        issue.code == "workspace_integrity_invalid" for issue in malformed.issues
    )

    del raw["unexpected"]
    raw["profile_hash"] = "sha256:" + "0" * 64
    atomic_write_json(path, raw)
    mismatched = StateIntegrityAuditor(state, workspace_root=workspace).audit()
    assert mismatched.safe_to_execute is False
    assert any(
        issue.code == "workspace_integrity_profile_mismatch"
        for issue in mismatched.issues
    )


def test_workspace_store_owns_hostile_bounded_snapshot(tmp_path, monkeypatch):
    class HostileDict(dict):
        def __deepcopy__(self, memo):
            raise AssertionError("workspace snapshot invoked deepcopy hook")

        def __iter__(self):
            raise AssertionError("workspace snapshot invoked mapping iterator hook")

        def get(self, key, default=None):
            raise AssertionError("workspace snapshot invoked mapping get hook")

        def items(self):
            raise AssertionError("workspace snapshot invoked mapping items hook")

        def keys(self):
            raise AssertionError("workspace snapshot invoked mapping keys hook")

    class HostileString(str):
        def __deepcopy__(self, memo):
            raise AssertionError("workspace snapshot invoked scalar deepcopy hook")

        def __str__(self):
            raise AssertionError("workspace snapshot invoked scalar rendering hook")

    workspace = tmp_path / "workspace"
    state_root = tmp_path / "state"
    build_harness(state_root, MockAgentAdapter(), workspace_root=workspace)
    path = state_root / "workspace_integrity.json"
    store = WorkspaceIntegrityStateStore(path)
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

    monkeypatch.setattr(workspace_module, "read_json", hostile_read)
    stored = store.get()
    expected = stored.to_dict()
    dict.__setitem__(supplied, "root_hash", HostileString("sha256:" + "0" * 64))

    assert stored.to_dict() == expected
    assert type(stored.profile_hash) is str
    assert type(stored.mode) is str
    assert type(stored.root_hash) is str
    assert type(stored.verified_at) is str
    assert observed == [workspace_module._MAX_STATE_BYTES]


def test_workspace_record_detaches_inputs_before_comparison_and_write(
    tmp_path, monkeypatch
):
    class HostileString(str):
        def __str__(self):
            raise AssertionError("workspace record rendered caller scalar")

    workspace = tmp_path / "workspace"
    observed_assurance = prepare_workspace_root(workspace)
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    profile = HostileString("sha256:" + "1" * 64)
    root_hash = HostileString(observed_assurance.root_hash)
    assurance = WorkspaceRootAssurance(
        HostileString(observed_assurance.mode),
        root_hash,
        observed_assurance.root,
        observed_assurance.identity,
    )
    original_write = workspace_module.atomic_write_json
    observed = []

    def mutating_write(path, data, *, max_bytes=None):
        object.__setattr__(assurance, "root_hash", "sha256:" + "2" * 64)
        observed.append(
            (
                max_bytes,
                type(data["profile_hash"]),
                type(data["mode"]),
                type(data["root_hash"]),
            )
        )
        return original_write(path, data, max_bytes=max_bytes)

    monkeypatch.setattr(workspace_module, "atomic_write_json", mutating_write)
    store = WorkspaceIntegrityStateStore(state_root / "workspace_integrity.json")
    stored = store.record(profile, assurance)

    assert stored.root_hash == root_hash
    assert store.get().root_hash == root_hash
    assert observed == [(workspace_module._MAX_STATE_BYTES, str, str, str)]


def test_workspace_state_rejects_noncanonical_input_without_secret_echo():
    class SecretValue:
        def __repr__(self):
            return "secret-workspace-value"

    with pytest.raises(WorkspaceIntegrityError) as failure:
        WorkspaceIntegrityState.from_dict({"secret": SecretValue()})

    assert "secret-workspace-value" not in str(failure.value)
    assert "SecretValue" not in str(failure.value)


def test_oversized_workspace_state_fails_at_opened_stream_ceiling(tmp_path):
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    path = state_root / "workspace_integrity.json"
    path.write_bytes(b" " * (workspace_module._MAX_STATE_BYTES + 1))
    path.chmod(0o600)

    with pytest.raises(WorkspaceIntegrityError, match="exceeds 65536 bytes"):
        WorkspaceIntegrityStateStore(path).get()


def test_workspace_refuses_unrecoverable_publication_without_replacement(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    assurance = prepare_workspace_root(workspace)
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    store = WorkspaceIntegrityStateStore(state_root / "workspace_integrity.json")
    current = store.record("sha256:" + "1" * 64, assurance)
    prior = store.path.read_bytes()
    original_limit = workspace_module._MAX_STATE_BYTES
    monkeypatch.setattr(workspace_module, "_MAX_STATE_BYTES", 1)

    with pytest.raises(WorkspaceIntegrityError, match="bounded canonical state"):
        workspace_module._write_state(store.path, current)

    assert store.path.read_bytes() == prior
    monkeypatch.setattr(workspace_module, "_MAX_STATE_BYTES", original_limit)
    assert store.get() == current
