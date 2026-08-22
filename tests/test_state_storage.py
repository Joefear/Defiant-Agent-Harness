from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from defiant_agent_harness.adapters.base import ToolCall
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.authority_profile import AuthorityProfileError
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
    prepare_state_storage,
    require_state_storage_unchanged,
)


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
