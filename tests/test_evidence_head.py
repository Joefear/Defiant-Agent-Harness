from __future__ import annotations

import json
import re

import pytest

import defiant_agent_harness.evidence_head as evidence_head_module
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
    EvidenceHeadState,
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


class HostileText(str):
    def __str__(self):
        raise AssertionError("caller string rendering hook invoked")

    def __len__(self):
        raise AssertionError("caller string length hook invoked")

    def startswith(self, *args, **kwargs):
        raise AssertionError("caller string prefix hook invoked")

    def removeprefix(self, *args, **kwargs):
        raise AssertionError("caller string removal hook invoked")

    def replace(self, *args, **kwargs):
        raise AssertionError("caller string replacement hook invoked")

    def __deepcopy__(self, memo):
        raise AssertionError("caller string copy hook invoked")


class HostileDict(dict):
    def __iter__(self):
        raise AssertionError("caller mapping iterator hook invoked")

    def __len__(self):
        raise AssertionError("caller mapping length hook invoked")

    def keys(self):
        raise AssertionError("caller mapping keys hook invoked")

    def items(self):
        raise AssertionError("caller mapping items hook invoked")

    def get(self, key, default=None):
        raise AssertionError("caller mapping get hook invoked")

    def __deepcopy__(self, memo):
        raise AssertionError("caller mapping copy hook invoked")


def _hostile_document(raw):
    return HostileDict(
        {
            key: HostileText(value) if type(value) is str else value
            for key, value in raw.items()
        }
    )


def test_evidence_head_reader_captures_one_hostile_state_snapshot(
    tmp_path, monkeypatch
):
    state, _workspace, _harness = _build(tmp_path)
    path = state / "evidence_head.json"
    raw = read_json(path)
    supplied = _hostile_document(raw)
    observed_limits = []

    def hostile_read(source, *, max_bytes=None):
        assert source == path
        observed_limits.append(max_bytes)
        return supplied

    monkeypatch.setattr(evidence_head_module, "read_json", hostile_read)

    restored = EvidenceHeadStateStore(path).get()

    assert restored is not None
    assert restored.to_dict() == raw
    assert type(restored.profile_hash) is str
    assert type(restored.checkpointed_at) is str
    assert observed_limits == [evidence_head_module._MAX_STATE_BYTES]
    dict.__setitem__(supplied, "profile_hash", "sha256:" + "f" * 64)
    assert restored.to_dict() == raw


def test_evidence_head_public_state_and_hash_inputs_are_detached(tmp_path):
    state, _workspace, _harness = _build(tmp_path)
    path = state / "evidence_head.json"
    current = EvidenceHeadStateStore(path).get()
    assert current is not None

    constructed = EvidenceHeadState(
        HostileText(current.profile_hash),
        HostileText(current.mode),
        current.record_count,
        HostileText(current.head_hash),
        HostileText(current.checkpointed_at),
    )
    reconciled = EvidenceHeadStateStore(path).reconcile_for_authority(
        HostileText(current.profile_hash),
        [],
    )

    assert constructed.to_dict() == current.to_dict()
    assert reconciled.to_dict() == current.to_dict()
    assert all(type(value) in {str, int} for value in constructed.to_dict().values())


def test_evidence_head_rejects_noncanonical_input_without_secret_echo():
    class SecretValue:
        def __str__(self):
            raise AssertionError("secret rendered")

        def __repr__(self):
            raise AssertionError("secret represented")

        def __deepcopy__(self, memo):
            raise AssertionError("secret copied")

    with pytest.raises(
        EvidenceHeadError, match="exceeds bounded canonical state"
    ) as failure:
        EvidenceHeadState.from_dict(HostileDict({"secret": SecretValue()}))

    assert "SecretValue" not in str(failure.value)


def test_evidence_head_store_uses_one_explicit_read_write_ceiling(
    tmp_path, monkeypatch
):
    read_limits = []
    write_limits = []
    original_read = evidence_head_module.read_json
    original_write = evidence_head_module.atomic_write_json

    def observed_read(path, *, max_bytes=None):
        read_limits.append(max_bytes)
        return original_read(path, max_bytes=max_bytes)

    def observed_write(path, data, *, max_bytes=None):
        write_limits.append(max_bytes)
        return original_write(path, data, max_bytes=max_bytes)

    monkeypatch.setattr(evidence_head_module, "read_json", observed_read)
    monkeypatch.setattr(evidence_head_module, "atomic_write_json", observed_write)
    path = tmp_path / "state" / "evidence_head.json"
    store = EvidenceHeadStateStore(path)
    store.reconcile_for_authority("sha256:" + "1" * 64, [])
    assert store.get() is not None

    assert read_limits
    assert write_limits
    assert set(read_limits) == {evidence_head_module._MAX_STATE_BYTES}
    assert set(write_limits) == {evidence_head_module._MAX_STATE_BYTES}


def test_evidence_head_refuses_unrecoverable_publication_without_replacement(
    tmp_path, monkeypatch
):
    path = tmp_path / "state" / "evidence_head.json"
    store = EvidenceHeadStateStore(path)
    current = store.reconcile_for_authority("sha256:" + "1" * 64, [])
    prior = path.read_bytes()
    original_limit = evidence_head_module._MAX_STATE_BYTES
    monkeypatch.setattr(evidence_head_module, "_MAX_STATE_BYTES", 1)

    with pytest.raises(EvidenceHeadError, match="bounded canonical state"):
        store._write(current.profile_hash, 1, "sha256:" + "2" * 64)

    assert path.read_bytes() == prior
    monkeypatch.setattr(
        evidence_head_module,
        "_MAX_STATE_BYTES",
        original_limit,
    )
    assert store.get() == current


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


def test_missing_completed_publication_checkpoint_is_read_only_unsafe_state(tmp_path):
    state, workspace, _harness = _build(tmp_path)
    path = state / "evidence_head.json"
    path.unlink()

    snapshot = CommandCore(state, workspace_root=workspace).snapshot()

    assert snapshot["authoritative"] is False
    assert snapshot["state_integrity"]["status"] == "unsafe"
    assert snapshot["evidence_head"]["verification"] == "migration_required"
    assert snapshot["authority_publication"]["verification"] == ("dependency_invalid")
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
