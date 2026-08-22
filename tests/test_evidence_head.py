from __future__ import annotations

import json
import re

import pytest

from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.authority_profile import (
    AuthorityProfileError,
    AuthorityProfileStore,
)
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import (
    Decision,
    EvidenceRecord,
    ResultStatus,
)
from defiant_agent_harness.evidence.store import EvidenceError, EvidenceStore
from defiant_agent_harness.evidence_head import (
    GENESIS_HEAD,
    EvidenceHeadError,
    EvidenceHeadStateStore,
)
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.persistence import atomic_write_json, read_json
from defiant_agent_harness.state_integrity import StateIntegrityAuditor


def _terminal(index: int) -> EvidenceRecord:
    return EvidenceRecord(
        request_id=f"req_head_{index}",
        action_id=f"act_head_{index}",
        decision=Decision.BLOCK,
        result_status=ResultStatus.BLOCKED,
        tool_name="read_file",
        target=f"workspace/{index}.txt",
    )


def _build(tmp_path):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    harness = build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    return state, workspace, harness


def test_authority_startup_records_sanitized_profile_bound_empty_head(tmp_path):
    state, workspace, _harness = _build(tmp_path)

    stored = EvidenceHeadStateStore(state / "evidence_head.json").get()
    assert stored is not None
    assert stored.record_count == 0
    assert stored.head_hash == GENESIS_HEAD
    assert (
        stored.profile_hash
        == AuthorityProfileStore(state / "authority_profile.json").get().profile_hash
    )

    projection = CommandCore(state, workspace_root=workspace).snapshot()[
        "evidence_head"
    ]
    serialized = json.dumps(projection)
    assert projection["state"] == "durable_checkpoint"
    assert projection["verification"] == "verified"
    assert projection["record_count"] == 0
    assert str(state) not in serialized
    assert str(workspace) not in serialized


def test_every_bound_append_advances_the_checkpoint(tmp_path):
    state, _workspace, harness = _build(tmp_path)

    first = harness.evidence.append(_terminal(1))
    second = harness.evidence.append(_terminal(2))

    stored = EvidenceHeadStateStore(state / "evidence_head.json").get()
    assert stored is not None
    assert stored.record_count == 2
    assert stored.head_hash == second.record_hash
    assert first.record_hash != second.record_hash
    assert StateIntegrityAuditor(state).audit().status == "healthy"


def test_valid_chain_tail_truncation_is_critical_without_other_store_markers(tmp_path):
    state, workspace, harness = _build(tmp_path)
    harness.evidence.append(_terminal(1))
    harness.evidence.append(_terminal(2))
    path = state / "evidence.jsonl"
    first, _second = path.read_text(encoding="utf-8").splitlines()
    path.write_text(first + "\n", encoding="utf-8")

    report = StateIntegrityAuditor(state).audit()

    assert report.safe_to_execute is False
    assert any(issue.code == "evidence_tail_rollback" for issue in report.issues)
    with pytest.raises(EvidenceError, match="behind its durable checkpoint"):
        build_harness(state, MockAgentAdapter(), workspace_root=workspace)


def test_valid_same_length_chain_replacement_is_divergence(tmp_path):
    state, _workspace, harness = _build(tmp_path)
    harness.evidence.append(_terminal(1))
    harness.evidence.append(_terminal(2))
    replacement_path = tmp_path / "replacement" / "evidence.jsonl"
    replacement = EvidenceStore(replacement_path)
    replacement.append(_terminal(10))
    replacement.append(_terminal(20))
    (state / "evidence.jsonl").write_text(
        replacement_path.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    report = StateIntegrityAuditor(state).audit()

    assert report.stores["evidence"]["state"] == "ready"
    assert report.safe_to_execute is False
    assert any(issue.code == "evidence_head_divergence" for issue in report.issues)


def test_crash_after_evidence_fsync_is_visible_and_recovers_forward_only(
    tmp_path,
    monkeypatch,
):
    state, workspace, harness = _build(tmp_path)
    head_store = harness.evidence.head_store
    assert head_store is not None

    def crash_before_checkpoint(*_args, **_kwargs):
        raise EvidenceHeadError("simulated checkpoint crash")

    monkeypatch.setattr(head_store, "advance", crash_before_checkpoint)
    with pytest.raises(EvidenceError, match="simulated checkpoint crash"):
        harness.evidence.append(_terminal(1))

    before = StateIntegrityAuditor(state).audit()
    assert before.safe_to_execute is True
    assert before.recovery_required is True
    assert before.stores["evidence_head"]["verification"] == "forward_recovery"
    assert any(
        issue.code == "evidence_head_checkpoint_behind" for issue in before.issues
    )

    reopened = build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    after = StateIntegrityAuditor(state).audit()
    assert after.status == "healthy"
    assert after.stores["evidence_head"]["verification"] == "verified"
    assert EvidenceHeadStateStore(state / "evidence_head.json").get().record_count == 1
    assert len(reopened.evidence.records()) == 1


def test_missing_checkpoint_is_read_only_migration_state(tmp_path):
    state, workspace, _harness = _build(tmp_path)
    path = state / "evidence_head.json"
    path.unlink()

    snapshot = CommandCore(state, workspace_root=workspace).snapshot()

    assert snapshot["authoritative"] is True
    assert snapshot["state_integrity"]["recovery_required"] is True
    assert snapshot["evidence_head"]["verification"] == "migration_required"
    assert not path.exists()


def test_operator_control_cannot_downgrade_after_checkpoint_deletion(tmp_path):
    state, workspace, harness = _build(tmp_path)
    harness.evidence.append(_terminal(1))
    path = state / "evidence_head.json"
    path.unlink()

    with pytest.raises(EvidenceError, match="not initialized"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            _operator_control=True,
        )

    assert len(EvidenceStore(state / "evidence.jsonl").records()) == 1
    assert not path.exists()


def test_checkpoint_schema_and_profile_tamper_are_critical(tmp_path):
    state, _workspace, _harness = _build(tmp_path)
    path = state / "evidence_head.json"
    raw = read_json(path)
    raw["unexpected"] = True
    atomic_write_json(path, raw)

    malformed = StateIntegrityAuditor(state).audit()
    assert malformed.safe_to_execute is False
    assert any(issue.code == "evidence_head_invalid" for issue in malformed.issues)

    del raw["unexpected"]
    raw["profile_hash"] = "sha256:" + "0" * 64
    atomic_write_json(path, raw)
    mismatched = StateIntegrityAuditor(state).audit()
    assert mismatched.safe_to_execute is False
    assert any(
        issue.code == "evidence_head_profile_mismatch" for issue in mismatched.issues
    )


def test_read_only_audit_does_not_initialize_absent_state(tmp_path):
    state = tmp_path / "missing-state"

    report = StateIntegrityAuditor(state).audit()

    assert report.stores["evidence_head"]["state"] == "not_recorded"
    assert report.status == "healthy"
    assert not state.exists()


def test_profile_rotation_is_not_activated_over_evidence_rollback(tmp_path):
    state, workspace, harness = _build(tmp_path)
    harness.evidence.append(_terminal(1))
    harness.evidence.append(_terminal(2))
    profile_store = AuthorityProfileStore(state / "authority_profile.json")
    current = profile_store.get()
    assert current is not None

    with pytest.raises(AuthorityProfileError, match="does not match") as mismatch:
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            dry_run=True,
        )
    match = re.search(r"configured (sha256:[0-9a-f]{64})", str(mismatch.value))
    assert match is not None
    candidate = match.group(1)
    staged = profile_store.request_rotation(
        candidate,
        operator="release-operator",
        note="test evidence rollback preflight",
        operator_trust=None,
    )
    path = state / "evidence.jsonl"
    first, _second = path.read_text(encoding="utf-8").splitlines()
    path.write_text(first + "\n", encoding="utf-8")

    with pytest.raises(EvidenceError, match="behind its durable checkpoint"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            dry_run=True,
        )

    unchanged = profile_store.get()
    assert unchanged is not None
    assert unchanged.profile_hash == current.profile_hash
    assert unchanged.pending_rotation == staged.pending_rotation
