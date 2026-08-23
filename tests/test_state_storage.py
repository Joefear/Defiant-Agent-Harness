from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

import pytest

from defiant_agent_harness.adapters.base import ToolCall
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.authority_profile import (
    AuthorityProfileError,
    AuthorityProfileStore,
)
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import HarnessRequest, sha256_of
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.persistence import (
    PersistenceError,
    atomic_write_json,
    open_state_file,
    read_json,
)
from defiant_agent_harness.state_integrity import (
    StateIntegrityAuditor,
    StateIntegrityError,
)
from defiant_agent_harness.state_storage import (
    StateStorageError,
    StateStorageStateStore,
    prepare_state_storage,
    require_state_storage_unchanged,
)
from defiant_agent_harness.windows_acl import WindowsAclError, WindowsAclObservation


def _request() -> HarnessRequest:
    return HarnessRequest(task="storage test", user_id="tester", workspace_id="ws")


def test_harness_records_sanitized_profile_bound_storage_posture(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())

    storage = CommandCore(state).snapshot()["state_storage"]
    serialized = json.dumps(storage)
    assert storage["state"] in {"posix_private", "structural_only"}
    assert storage["verification"] == "verified"
    assert storage["root_hash"].startswith("sha256:")
    assert storage["files_checked"] >= 6
    assert storage["temporary_files"] == 0
    assert str(state) not in serialized
    assert "approvals.json" not in serialized


def test_secure_read_does_not_create_missing_state_directory(tmp_path):
    state = tmp_path / "missing"
    with pytest.raises(PersistenceError, match="does not exist"):
        read_json(state / "budget.json")
    assert not state.exists()


def test_state_root_replacement_conflicts_before_operational_recovery(tmp_path):
    state = tmp_path / "state"
    harness = build_harness(state, MockAgentAdapter())
    evidence_before = harness.evidence.records()
    displaced = tmp_path / "displaced"
    state.rename(displaced)
    shutil.copytree(displaced, state)

    with pytest.raises(AuthorityProfileError, match="does not match"):
        build_harness(state, MockAgentAdapter())

    assert CommandCore(displaced).snapshot()["recent_activity"] == evidence_before


def test_root_identity_change_after_assurance_fails_closed(tmp_path):
    state = tmp_path / "state"
    assurance = prepare_state_storage(state)
    displaced = tmp_path / "displaced"
    state.rename(displaced)
    state.mkdir(mode=0o700)

    with pytest.raises(StateStorageError, match="identity changed"):
        require_state_storage_unchanged(assurance)


def test_symlinked_state_root_is_refused_when_supported(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "state-link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation is unavailable")

    with pytest.raises(StateStorageError, match="symlink or reparse"):
        prepare_state_storage(link)


def test_symlinked_state_file_is_never_read_or_repaired(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    budget = state / "budget.json"
    external = tmp_path / "external.json"
    external.write_text('{"attacker":true}', encoding="utf-8")
    budget.unlink()
    try:
        budget.symlink_to(external)
    except (OSError, NotImplementedError):
        pytest.skip("file symlink creation is unavailable")

    with pytest.raises(PersistenceError, match="symlink or reparse"):
        read_json(budget)
    report = StateIntegrityAuditor(state).audit()
    assert report.safe_to_execute is False
    assert any(issue.code == "state_storage_invalid" for issue in report.issues)
    assert str(state) not in json.dumps(report.to_dict())
    assert str(external) not in json.dumps(report.to_dict())
    assert external.read_text(encoding="utf-8") == '{"attacker":true}'


def test_symlinked_evidence_is_reported_without_auditor_crash(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    evidence = state / "evidence.jsonl"
    external = tmp_path / "external.jsonl"
    external.write_text("", encoding="utf-8")
    evidence.unlink()
    try:
        evidence.symlink_to(external)
    except (OSError, NotImplementedError):
        pytest.skip("file symlink creation is unavailable")

    report = StateIntegrityAuditor(state).audit()
    assert report.safe_to_execute is False
    codes = {issue.code for issue in report.issues}
    assert "state_storage_invalid" in codes
    assert "evidence_invalid" in codes


def test_hard_linked_state_file_is_refused(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    budget = state / "budget.json"
    alias = tmp_path / "budget-alias.json"
    try:
        os.link(budget, alias)
    except OSError:
        pytest.skip("hard-link creation is unavailable")

    with pytest.raises(PersistenceError, match="exactly one hard link"):
        read_json(budget)
    report = StateIntegrityAuditor(state).audit()
    assert report.safe_to_execute is False
    assert any(issue.code == "state_storage_invalid" for issue in report.issues)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is unavailable")
def test_nonregular_state_file_is_rejected_without_blocking_on_open(tmp_path):
    state = tmp_path / "state"
    prepare_state_storage(state)
    path = state / "budget.json"
    os.mkfifo(path, 0o600)

    with pytest.raises(PersistenceError, match="must be regular"):
        read_json(path)
    report = StateIntegrityAuditor(state).audit()
    assert report.safe_to_execute is False
    assert any(issue.code == "state_storage_invalid" for issue in report.issues)


def test_orphan_atomic_temporary_file_is_a_critical_read_only_finding(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    temporary = state / ".budget.json.crashed.tmp"
    with open_state_file(temporary, "x", encoding="utf-8") as handle:
        handle.write("{}")
        handle.flush()
        os.fsync(handle.fileno())

    report = StateIntegrityAuditor(state).audit()
    assert report.safe_to_execute is False
    assert report.stores["state_storage"]["temporary_files"] == 1
    assert any(issue.code == "state_temporary_file_present" for issue in report.issues)
    assert temporary.exists()


@pytest.mark.parametrize(
    ("field", "issue_code"),
    [
        ("root_hash", "state_storage_root_mismatch"),
        ("profile_hash", "state_storage_profile_mismatch"),
    ],
)
def test_tampered_storage_binding_is_critical(tmp_path, field, issue_code):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    path = state / "state_storage.json"
    raw = read_json(path)
    raw[field] = sha256_of({"tampered": field})
    atomic_write_json(path, raw)

    report = StateIntegrityAuditor(state).audit()
    assert report.safe_to_execute is False
    assert any(issue.code == issue_code for issue in report.issues)


def test_file_replacement_during_open_is_detected(tmp_path, monkeypatch):
    state = tmp_path / "state"
    prepare_state_storage(state)
    target = state / "budget.json"
    replacement = state / "replacement.json"
    atomic_write_json(target, {"value": "trusted"})
    atomic_write_json(replacement, {"value": "replacement"})
    real_open = os.open
    swapped = False

    def swapping_open(path, flags, mode=0o777):
        nonlocal swapped
        if Path(path) == target and not swapped:
            swapped = True
            os.replace(replacement, target)
        return real_open(path, flags, mode)

    monkeypatch.setattr("defiant_agent_harness.persistence.os.open", swapping_open)
    with pytest.raises(PersistenceError, match="changed while opening"):
        read_json(target)
    assert swapped is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission semantics")
def test_posix_state_modes_are_private_and_overbroad_file_fails_closed(tmp_path):
    state = tmp_path / "state"
    prepare_state_storage(state)
    path = state / "budget.json"
    atomic_write_json(path, {"value": "private"})
    assert state.stat().st_mode & 0o777 == 0o700
    assert path.stat().st_mode & 0o777 == 0o600

    path.chmod(0o644)
    with pytest.raises(PersistenceError, match="permissions must be private"):
        read_json(path)

    open_root = tmp_path / "overbroad"
    open_root.mkdir(mode=0o755)
    with pytest.raises(StateStorageError, match="permissions must be private"):
        prepare_state_storage(open_root)


def test_storage_failure_blocks_tool_authority(tmp_path):
    state = tmp_path / "state"
    harness = build_harness(state, MockAgentAdapter())
    temporary = state / ".approvals.json.uncertain.tmp"
    with open_state_file(temporary, "x", encoding="utf-8") as handle:
        handle.write("{}")

    with pytest.raises(StateIntegrityError, match="state_temporary_file_present"):
        harness.handle_call(
            ToolCall(name="read_file", arguments={"path": "workspace/a.txt"}),
            _request(),
        )


def _private_windows_acl(_path, *, directory):
    return WindowsAclObservation(
        owner_current_user=True,
        dacl_protected=directory,
        principal_count=3,
        ace_count=3,
    )


def test_windows_private_acl_mode_is_profile_bound_and_sanitized(
    tmp_path,
    monkeypatch,
):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    monkeypatch.setattr(
        "defiant_agent_harness.state_storage.inspect_windows_private_acl",
        _private_windows_acl,
    )

    with pytest.raises(AuthorityProfileError, match="does not match") as mismatch:
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            require_windows_private_state_acl=True,
        )
    candidate = re.search(r"configured (sha256:[0-9a-f]{64})", str(mismatch.value))
    assert candidate is not None
    AuthorityProfileStore(state / "authority_profile.json").request_rotation(
        candidate.group(1),
        operator="storage-operator",
        note="require reviewed private Windows ACL posture",
        operator_trust=None,
    )
    build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        require_windows_private_state_acl=True,
    )

    snapshot = CommandCore(state, workspace_root=workspace).snapshot()
    storage = snapshot["state_storage"]
    serialized = json.dumps(storage)
    assert snapshot["authoritative"] is True
    assert storage["state"] == "windows_private_acl"
    assert storage["private_permissions"] is True
    assert storage["acl_policy"] == "current_user_system_administrators"
    assert storage["acl_protected"] is True
    assert storage["acl_principal_count"] == 3
    assert "S-1-" not in serialized
    assert str(state) not in serialized

    with pytest.raises(StateStorageError, match="requires"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
        )
    with pytest.raises(StateStorageError, match="requires"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            _operator_control=True,
        )
    operator_harness = build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        require_windows_private_state_acl=True,
        _operator_control=True,
    )
    assert operator_harness.execution_disabled is True


def test_windows_private_acl_drift_blocks_read_only_and_tool_authority(
    tmp_path,
    monkeypatch,
):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    unsafe_name = ""

    def inspect_acl(path, *, directory):
        if Path(path).name == unsafe_name:
            raise WindowsAclError(
                "Windows state DACL grants access to an unapproved principal"
            )
        return _private_windows_acl(path, directory=directory)

    monkeypatch.setattr(
        "defiant_agent_harness.state_storage.inspect_windows_private_acl",
        inspect_acl,
    )
    harness = build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        require_windows_private_state_acl=True,
    )
    unsafe_name = "budget.json"

    report = StateIntegrityAuditor(state, workspace_root=workspace).audit()
    rendered = json.dumps(report.to_dict())
    assert report.safe_to_execute is False
    assert report.stores["state_storage"]["verification"] == "invalid"
    assert any(issue.code == "state_storage_invalid" for issue in report.issues)
    assert "S-1-" not in rendered
    assert str(state) not in rendered
    with pytest.raises(StateIntegrityError, match="state_storage_invalid"):
        harness.handle_call(
            ToolCall(name="read_file", arguments={"path": "workspace/a.txt"}),
            _request(),
        )


def test_windows_private_acl_failure_precedes_authority_state_mutation(
    tmp_path,
    monkeypatch,
):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    harness = build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    before = (state / "authority_profile.json").read_bytes()

    def broad_acl(_path, *, directory):
        raise WindowsAclError(
            "Windows state DACL grants access to an unapproved principal"
        )

    monkeypatch.setattr(
        "defiant_agent_harness.state_storage.inspect_windows_private_acl",
        broad_acl,
    )
    with pytest.raises(StateStorageError, match="unapproved principal"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            require_windows_private_state_acl=True,
        )
    assert (state / "authority_profile.json").read_bytes() == before
    assert harness.evidence.records() == []


def test_v1_state_storage_observation_remains_readable(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    path = state / "state_storage.json"
    raw = read_json(path)
    raw["schema_version"] = "0.1.0"
    raw.pop("acl_policy")
    raw.pop("acl_protected")
    raw.pop("acl_principal_count")
    atomic_write_json(path, raw)

    stored = StateStorageStateStore(path).get()
    assert stored is not None
    assert stored.acl_policy is None
    assert stored.acl_protected is None
    assert stored.acl_principal_count == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"private_permissions": False},
        {"acl_policy": "S-1-5-21-attacker"},
        {"acl_protected": False},
        {"acl_principal_count": True},
        {"acl_principal_count": 0},
        {"acl_principal_count": 4},
    ],
)
def test_v2_windows_acl_observation_rejects_inconsistent_fields(tmp_path, changes):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    path = state / "state_storage.json"
    raw = read_json(path)
    raw.update(
        {
            "mode": "windows_private_acl",
            "private_permissions": True,
            "acl_policy": "current_user_system_administrators",
            "acl_protected": True,
            "acl_principal_count": 3,
            **changes,
        }
    )
    atomic_write_json(path, raw)

    with pytest.raises(StateStorageError):
        StateStorageStateStore(path).get()

    report = StateIntegrityAuditor(state).audit()
    serialized = json.dumps(report.to_dict())
    assert report.safe_to_execute is False
    assert report.stores["state_storage"]["verification"] == "invalid"
    assert "S-1-5-21-attacker" not in serialized
