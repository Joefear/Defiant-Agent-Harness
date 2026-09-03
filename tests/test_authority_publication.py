from __future__ import annotations

import json
import re

import pytest

import defiant_agent_harness.authority_publication as publication_module
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.authority_publication import (
    AuthorityPublicationCheckpoint,
    AuthorityPublicationError,
    AuthorityPublicationIntent,
    AuthorityPublicationState,
    AuthorityPublicationStore,
    authority_manifest_hash,
    authority_manifest_hash_for,
)
from defiant_agent_harness.authority_profile import (
    AuthorityProfileError,
    AuthorityProfileStore,
)
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.control_plane_isolation import (
    ControlPlaneIsolationStateStore,
)
from defiant_agent_harness.evidence_witness import EvidenceWitnessPolicyStore
from defiant_agent_harness.launch_envelope import (
    LaunchEnvelopeStateStore,
    remote_launch_envelope,
)
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.runtime_artifacts import (
    RuntimeArtifactStateStore,
    remote_artifacts,
    unverified_artifacts,
)
from defiant_agent_harness.state_integrity import StateIntegrityAuditor
from defiant_agent_harness.state_storage import StateStorageStateStore
from defiant_agent_harness.workspace_integrity import WorkspaceIntegrityStateStore


PROFILE = "sha256:" + "1" * 64
MANIFEST = "sha256:" + "2" * 64
STORE_HASHES = {
    "state_storage": "sha256:" + "3" * 64,
    "control_plane_isolation": "sha256:" + "4" * 64,
    "workspace_integrity": "sha256:" + "5" * 64,
    "evidence_witness_policy": "sha256:" + "6" * 64,
    "runtime_artifacts": None,
    "launch_envelope": None,
    "evidence_head": "sha256:" + "7" * 64,
}


def test_publication_store_prepares_idempotently_and_completes(tmp_path):
    store = AuthorityPublicationStore(tmp_path / "authority_publication.json")

    first = store.prepare(PROFILE, 1, MANIFEST, STORE_HASHES)
    assert store.prepare(PROFILE, 1, MANIFEST, STORE_HASHES) == first
    assert first.record_hash is not None
    assert first.prior_checkpoint_hash == "GENESIS"
    assert store.get().projection()["state"] == "recovery_required"
    assert store.get().projection()["store_commitments"] == "recorded"
    assert store.get().projection()["intent_record_seal"] == "verified"
    assert store.get().projection()["intent_checkpoint_link"] == "verified"

    completed = store.complete(first)
    assert completed.active is None
    assert completed.completed is not None
    assert completed.completed.profile_hash == PROFILE
    assert dict(completed.completed.store_hashes) == STORE_HASHES
    assert completed.completed.record_hash is not None
    assert completed.completed.prepared_at == first.prepared_at
    assert completed.completed.prior_checkpoint_hash == "GENESIS"
    assert completed.completed.intent_record_hash == first.record_hash
    assert completed.projection()["verification"] == "verified"
    assert completed.projection()["store_commitments"] == "not_applicable"
    assert completed.projection()["checkpoint_store_commitments"] == "recorded"
    assert completed.projection()["checkpoint_record_seal"] == "verified"
    assert completed.projection()["checkpoint_intent_link"] == "verified"


def test_valid_active_record_with_wrong_checkpoint_link_is_critical_and_refused(
    tmp_path,
):
    store = AuthorityPublicationStore(tmp_path / "authority_publication.json")
    completed = store.complete(store.prepare(PROFILE, 1, MANIFEST, STORE_HASHES))
    assert completed.completed is not None
    active = store.prepare(PROFILE, 1, MANIFEST, STORE_HASHES)
    substituted = AuthorityPublicationIntent(
        profile_hash=active.profile_hash,
        generation=active.generation,
        manifest_hash=active.manifest_hash,
        prepared_at=active.prepared_at,
        store_hashes=active.store_hashes,
        prior_checkpoint_hash="sha256:" + "9" * 64,
    ).sealed()
    raw = json.loads(store.path.read_text(encoding="utf-8"))
    raw["active"] = substituted.to_dict()
    store.path.write_text(json.dumps(raw), encoding="utf-8")
    before = store.path.read_bytes()

    with pytest.raises(AuthorityPublicationError, match="prior checkpoint link"):
        store.get()
    report = StateIntegrityAuditor(tmp_path).audit()
    snapshot = CommandCore(tmp_path).snapshot()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["intent_checkpoint_link"] == (
        "invalid"
    )
    assert any(issue.code == "authority_publication_invalid" for issue in report.issues)
    assert snapshot["authoritative"] is False
    assert "prior_checkpoint_hash" not in json.dumps(snapshot)
    assert store.path.read_bytes() == before

    with pytest.raises(AuthorityPublicationError, match="prior checkpoint link"):
        build_harness(tmp_path, MockAgentAdapter())
    assert store.path.read_bytes() == before


def test_valid_checkpoint_record_with_wrong_intent_link_is_critical_and_refused(
    tmp_path,
):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    store = AuthorityPublicationStore(state / "authority_publication.json")
    loaded = store.get()
    assert loaded is not None
    checkpoint = loaded.completed
    assert checkpoint is not None
    substituted = AuthorityPublicationCheckpoint(
        profile_hash=checkpoint.profile_hash,
        generation=checkpoint.generation,
        manifest_hash=checkpoint.manifest_hash,
        completed_at=checkpoint.completed_at,
        store_hashes=checkpoint.store_hashes,
        prepared_at=checkpoint.prepared_at,
        prior_checkpoint_hash=checkpoint.prior_checkpoint_hash,
        intent_record_hash="sha256:" + "9" * 64,
    ).sealed()
    raw = json.loads(store.path.read_text(encoding="utf-8"))
    raw["completed"] = substituted.to_dict()
    store.path.write_text(json.dumps(raw), encoding="utf-8")
    before = store.path.read_bytes()

    with pytest.raises(AuthorityPublicationError, match="originating intent hash"):
        store.get()
    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["checkpoint_intent_link"] == (
        "invalid"
    )
    assert snapshot["authoritative"] is False
    assert "intent_record_hash" not in json.dumps(snapshot)
    assert store.path.read_bytes() == before

    with pytest.raises(AuthorityPublicationError, match="originating intent hash"):
        build_harness(state, MockAgentAdapter())
    assert store.path.read_bytes() == before


def test_prepared_publication_record_substitution_is_critical_and_refused(
    tmp_path,
    monkeypatch,
):
    original = AuthorityProfileStore.resolve_for_authority
    calls = 0

    def crash_before_activation(self, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("simulated activation crash")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(
        AuthorityProfileStore,
        "resolve_for_authority",
        crash_before_activation,
    )
    state = tmp_path / "state"
    with pytest.raises(RuntimeError, match="simulated activation crash"):
        build_harness(state, MockAgentAdapter())

    path = state / "authority_publication.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["active"]["store_hashes"]["state_storage"] = "sha256:" + "9" * 64
    path.write_text(json.dumps(raw), encoding="utf-8")
    before = {
        candidate.name: candidate.read_bytes()
        for candidate in state.iterdir()
        if candidate.is_file()
    }

    with pytest.raises(AuthorityPublicationError, match="record hash"):
        AuthorityPublicationStore(path).get()
    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["state"] == "invalid"
    assert any(issue.code == "authority_publication_invalid" for issue in report.issues)
    assert snapshot["authoritative"] is False
    assert "record_hash" not in json.dumps(snapshot)
    assert {
        candidate.name: candidate.read_bytes()
        for candidate in state.iterdir()
        if candidate.is_file()
    } == before

    with pytest.raises(AuthorityPublicationError, match="record hash"):
        build_harness(state, MockAgentAdapter())

    assert {
        candidate.name: candidate.read_bytes()
        for candidate in state.iterdir()
        if candidate.is_file()
    } == before


def test_completed_publication_record_substitution_is_critical_and_refused(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    path = state / "authority_publication.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["completed"]["completed_at"] = "2026-09-02T00:00:00Z"
    path.write_text(json.dumps(raw), encoding="utf-8")
    before = {
        candidate.name: candidate.read_bytes()
        for candidate in state.iterdir()
        if candidate.is_file()
    }

    with pytest.raises(AuthorityPublicationError, match="record hash"):
        AuthorityPublicationStore(path).get()
    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["checkpoint_record_seal"] == (
        "invalid"
    )
    assert any(issue.code == "authority_publication_invalid" for issue in report.issues)
    assert snapshot["authoritative"] is False
    assert "record_hash" not in json.dumps(snapshot)
    assert {
        candidate.name: candidate.read_bytes()
        for candidate in state.iterdir()
        if candidate.is_file()
    } == before

    with pytest.raises(AuthorityPublicationError, match="record hash"):
        build_harness(state, MockAgentAdapter())

    assert {
        candidate.name: candidate.read_bytes()
        for candidate in state.iterdir()
        if candidate.is_file()
    } == before


def test_publication_store_refuses_a_different_active_candidate(tmp_path):
    store = AuthorityPublicationStore(tmp_path / "authority_publication.json")
    store.prepare(PROFILE, 1, MANIFEST, STORE_HASHES)
    before = store.path.read_bytes()

    with pytest.raises(AuthorityPublicationError, match="different"):
        store.prepare(PROFILE, 1, "sha256:" + "8" * 64, STORE_HASHES)

    changed_store_hashes = dict(STORE_HASHES)
    changed_store_hashes["evidence_head"] = "sha256:" + "9" * 64
    with pytest.raises(AuthorityPublicationError, match="different"):
        store.prepare(PROFILE, 1, MANIFEST, changed_store_hashes)

    assert store.path.read_bytes() == before


def test_publication_store_bounds_the_opened_state_stream(tmp_path):
    path = tmp_path / "authority_publication.json"
    path.write_bytes(
        b"{" + b"x" * publication_module.MAX_AUTHORITY_PUBLICATION_STATE_BYTES + b"}"
    )
    path.chmod(0o600)

    with pytest.raises(AuthorityPublicationError, match="exceeds"):
        AuthorityPublicationStore(path).get()


def test_oversized_publication_preserves_the_completed_checkpoint(
    tmp_path,
    monkeypatch,
):
    store = AuthorityPublicationStore(tmp_path / "authority_publication.json")
    intent = store.prepare(PROFILE, 1, MANIFEST, STORE_HASHES)
    store.complete(intent)
    before = store.path.read_bytes()
    completed = store.get()
    monkeypatch.setattr(store, "get", lambda: completed)
    monkeypatch.setattr(
        publication_module,
        "MAX_AUTHORITY_PUBLICATION_STATE_BYTES",
        1,
    )

    with pytest.raises(AuthorityPublicationError, match="exceeds"):
        store.prepare(PROFILE, 1, MANIFEST, STORE_HASHES)

    assert store.path.read_bytes() == before


def test_publication_state_owns_hostile_bounded_snapshot(tmp_path, monkeypatch):
    class HostileDict(dict):
        def __deepcopy__(self, memo):
            raise AssertionError("publication snapshot invoked deepcopy hook")

        def __iter__(self):
            raise AssertionError("publication snapshot invoked iterator hook")

        def get(self, key, default=None):
            raise AssertionError("publication snapshot invoked get hook")

        def items(self):
            raise AssertionError("publication snapshot invoked items hook")

        def keys(self):
            raise AssertionError("publication snapshot invoked keys hook")

    class HostileString(str):
        def __str__(self):
            raise AssertionError("publication snapshot rendered hostile scalar")

    store = AuthorityPublicationStore(tmp_path / "authority_publication.json")
    store.prepare(PROFILE, 1, MANIFEST, STORE_HASHES)
    raw = json.loads(store.path.read_text(encoding="utf-8"))

    def hostile(value):
        if type(value) is dict:
            return HostileDict({key: hostile(child) for key, child in value.items()})
        if type(value) is str:
            return HostileString(value)
        return value

    supplied = hostile(raw)
    observed = []

    def hostile_read(path, *, max_bytes=None):
        observed.append(max_bytes)
        return supplied

    monkeypatch.setattr(publication_module, "read_json", hostile_read)
    state = store.get()
    expected = state.to_dict()
    dict.__setitem__(
        dict.__getitem__(supplied, "active"),
        "manifest_hash",
        HostileString("sha256:" + "4" * 64),
    )

    assert state.to_dict() == expected
    assert type(state.active.profile_hash) is str
    assert type(state.active.manifest_hash) is str
    assert observed == [publication_module.MAX_AUTHORITY_PUBLICATION_STATE_BYTES]


def test_manifest_hash_is_bounded_and_owns_the_candidate(monkeypatch):
    manifest = {"profile_hash": PROFILE, "stores": {"one": {"mode": "ready"}}}
    digest = authority_manifest_hash(manifest)
    manifest["stores"]["one"]["mode"] = "changed"

    assert digest != authority_manifest_hash(manifest)
    monkeypatch.setattr(
        publication_module,
        "MAX_AUTHORITY_PUBLICATION_MANIFEST_BYTES",
        32,
    )
    with pytest.raises(AuthorityPublicationError, match="bounded canonical state"):
        authority_manifest_hash({"secret": "do-not-render" * 20})


def test_component_manifest_hash_matches_the_complete_contract():
    stores = {
        "state_storage": {"mode": "structural_only"},
        "control_plane_isolation": {"mode": "enforced"},
        "workspace_integrity": {"mode": "verified"},
        "evidence_witness_policy": {"mode": "not_configured"},
        "runtime_artifacts": None,
        "launch_envelope": None,
        "evidence_head": {"mode": "checkpointed"},
    }

    assert authority_manifest_hash_for(
        profile_hash=PROFILE,
        generation=1,
        **stores,
    ) == authority_manifest_hash(
        {"profile_hash": PROFILE, "generation": 1, "stores": stores}
    )


@pytest.mark.parametrize(
    "store_type",
    [
        StateStorageStateStore,
        ControlPlaneIsolationStateStore,
        WorkspaceIntegrityStateStore,
        EvidenceWitnessPolicyStore,
        RuntimeArtifactStateStore,
        LaunchEnvelopeStateStore,
    ],
)
def test_restart_replays_exact_publication_after_each_store_boundary(
    tmp_path,
    monkeypatch,
    store_type,
):
    original = store_type.record
    calls = 0

    def crash_after_record(self, *args, **kwargs):
        nonlocal calls
        result = original(self, *args, **kwargs)
        calls += 1
        if calls == 1:
            raise RuntimeError("simulated publication crash")
        return result

    monkeypatch.setattr(store_type, "record", crash_after_record)
    options = {
        "workspace_root": tmp_path / "workspace",
        "runtime_artifact_assurance": unverified_artifacts(("test-tool",)),
        "launch_envelope_assurance": remote_launch_envelope(),
    }

    with pytest.raises(RuntimeError, match="simulated publication crash"):
        build_harness(tmp_path / "state", MockAgentAdapter(), **options)

    interrupted = AuthorityPublicationStore(
        tmp_path / "state" / "authority_publication.json"
    ).get()
    assert interrupted is not None
    assert interrupted.active is not None
    build_harness(tmp_path / "state", MockAgentAdapter(), **options)

    recovered = AuthorityPublicationStore(
        tmp_path / "state" / "authority_publication.json"
    ).get()
    assert recovered is not None
    assert recovered.active is None
    assert recovered.completed is not None
    assert (
        StateIntegrityAuditor(
            tmp_path / "state",
            workspace_root=tmp_path / "workspace",
        )
        .audit()
        .status
        == "healthy"
    )


def test_restart_recovers_after_evidence_head_before_completion(tmp_path, monkeypatch):
    original = AuthorityPublicationStore.complete
    calls = 0

    def crash_before_complete(self, intent):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("simulated completion crash")
        return original(self, intent)

    monkeypatch.setattr(AuthorityPublicationStore, "complete", crash_before_complete)
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    with pytest.raises(RuntimeError, match="simulated completion crash"):
        build_harness(state, MockAgentAdapter(), workspace_root=workspace)

    snapshot = CommandCore(state, workspace_root=workspace).snapshot()
    assert snapshot["authority_publication"]["state"] == "recovery_required"
    assert snapshot["authority_publication"]["verification"] == "ready_to_complete"
    assert snapshot["state_integrity"]["status"] == "recovery_required"
    assert snapshot["state_integrity"]["safe_to_execute"] is True

    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    assert (
        CommandCore(state, workspace_root=workspace).snapshot()[
            "authority_publication"
        ]["state"]
        == "complete"
    )


def test_restart_recovers_when_crash_precedes_profile_activation(tmp_path, monkeypatch):
    original = AuthorityProfileStore.resolve_for_authority
    calls = 0

    def crash_before_activation(self, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("simulated activation crash")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(
        AuthorityProfileStore,
        "resolve_for_authority",
        crash_before_activation,
    )
    state = tmp_path / "state"
    with pytest.raises(RuntimeError, match="simulated activation crash"):
        build_harness(state, MockAgentAdapter())

    report = StateIntegrityAuditor(state).audit()
    assert report.status == "recovery_required"
    assert report.stores["authority_profile"]["state"] == "not_enrolled"
    assert report.stores["authority_publication"]["state"] == "recovery_required"
    assert report.stores["authority_publication"]["verification"] == "prepared"

    build_harness(state, MockAgentAdapter())
    assert (
        AuthorityPublicationStore(state / "authority_publication.json")
        .get()
        .projection()["state"]
        == "complete"
    )


def test_read_only_audit_classifies_active_publication_while_applying(
    tmp_path,
    monkeypatch,
):
    original = StateStorageStateStore.record

    def crash_after_first_dependency(self, *args, **kwargs):
        original(self, *args, **kwargs)
        raise RuntimeError("simulated dependency crash")

    monkeypatch.setattr(
        StateStorageStateStore,
        "record",
        crash_after_first_dependency,
    )
    state = tmp_path / "state"
    with pytest.raises(RuntimeError, match="simulated dependency crash"):
        build_harness(state, MockAgentAdapter())

    before = {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    }
    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()

    assert report.status == "recovery_required"
    assert report.safe_to_execute is True
    assert report.stores["authority_publication"]["verification"] == "applying"
    assert snapshot["authority_publication"]["verification"] == "applying"
    assert {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    } == before


def test_active_publication_rejects_partial_target_store_substitution(
    tmp_path,
    monkeypatch,
):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        launch_envelope_assurance=remote_launch_envelope(),
    )
    profile_store = AuthorityProfileStore(state / "authority_profile.json")
    with pytest.raises(AuthorityProfileError, match="does not match") as mismatch:
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            launch_envelope_assurance=remote_launch_envelope(),
            dry_run=True,
        )
    match = re.search(r"configured (sha256:[0-9a-f]{64})", str(mismatch.value))
    assert match is not None
    profile_store.request_rotation(
        match.group(1),
        operator="release-operator",
        note="verify partial target commitments",
        operator_trust=None,
    )

    original = LaunchEnvelopeStateStore.record

    def crash_after_target_store(self, *args, **kwargs):
        original(self, *args, **kwargs)
        raise RuntimeError("simulated partial replay crash")

    monkeypatch.setattr(LaunchEnvelopeStateStore, "record", crash_after_target_store)
    with pytest.raises(RuntimeError, match="simulated partial replay crash"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            launch_envelope_assurance=remote_launch_envelope(),
            dry_run=True,
        )

    launch_path = state / "launch_envelope.json"
    launch = json.loads(launch_path.read_text(encoding="utf-8"))
    launch.update(
        {
            "mode": "inherited_unrestricted",
            "environment_hash": None,
            "variable_count": 0,
            "secret_count": 0,
            "unsafe_count": 0,
            "cwd_hash": "sha256:" + "9" * 64,
        }
    )
    launch_path.write_text(json.dumps(launch), encoding="utf-8")
    before = {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    }

    report = StateIntegrityAuditor(state, workspace_root=workspace).audit()
    snapshot = CommandCore(state, workspace_root=workspace).snapshot()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["verification"] == (
        "store_commitment_mismatch"
    )
    assert report.stores["authority_publication"]["store_commitments"] == "recorded"
    assert any(
        issue.code == "authority_publication_active_store_mismatch"
        for issue in report.issues
    )
    assert snapshot["authority_publication"]["verification"] == (
        "store_commitment_mismatch"
    )
    assert {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    } == before


def test_read_only_audit_accepts_exact_partial_profile_rotation(tmp_path, monkeypatch):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    current = build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    store = AuthorityProfileStore(state / "authority_profile.json")
    with pytest.raises(AuthorityProfileError, match="does not match") as mismatch:
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            dry_run=True,
        )
    match = re.search(r"configured (sha256:[0-9a-f]{64})", str(mismatch.value))
    assert match is not None
    store.request_rotation(
        match.group(1),
        operator="release-operator",
        note="exercise crash-safe rotation",
        operator_trust=None,
    )

    original = ControlPlaneIsolationStateStore.record

    def crash_during_rotation(self, *args, **kwargs):
        original(self, *args, **kwargs)
        raise RuntimeError("simulated rotation crash")

    monkeypatch.setattr(
        ControlPlaneIsolationStateStore,
        "record",
        crash_during_rotation,
    )
    with pytest.raises(RuntimeError, match="simulated rotation crash"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            dry_run=True,
        )

    report = StateIntegrityAuditor(state, workspace_root=workspace).audit()

    assert current.policy.ruleset_hash != match.group(1)
    assert report.status == "recovery_required"
    assert report.safe_to_execute is True
    assert report.stores["authority_publication"]["verification"] == "applying"
    assert (
        report.stores["authority_publication"]["checkpoint_store_commitments"]
        == "recorded"
    )
    assert report.stores["workspace_integrity"]["verification"] == (
        "publication_recovery"
    )
    assert not any(issue.code.endswith("_profile_mismatch") for issue in report.issues)

    (state / "workspace_integrity.json").unlink()
    unsafe = StateIntegrityAuditor(state, workspace_root=workspace).audit()
    assert unsafe.safe_to_execute is False
    assert unsafe.stores["authority_publication"]["verification"] == (
        "dependency_invalid"
    )
    assert any(
        issue.code == "authority_publication_active_dependency_invalid"
        for issue in unsafe.issues
    )


def test_active_publication_rejects_partial_checkpoint_store_substitution(
    tmp_path,
    monkeypatch,
):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    profile_store = AuthorityProfileStore(state / "authority_profile.json")
    with pytest.raises(AuthorityProfileError, match="does not match") as mismatch:
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            dry_run=True,
        )
    match = re.search(r"configured (sha256:[0-9a-f]{64})", str(mismatch.value))
    assert match is not None
    profile_store.request_rotation(
        match.group(1),
        operator="release-operator",
        note="verify prior checkpoint commitments",
        operator_trust=None,
    )

    original = StateStorageStateStore.record

    def crash_after_first_target(self, *args, **kwargs):
        original(self, *args, **kwargs)
        raise RuntimeError("simulated mixed-generation crash")

    monkeypatch.setattr(
        StateStorageStateStore,
        "record",
        crash_after_first_target,
    )
    with pytest.raises(RuntimeError, match="simulated mixed-generation crash"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            dry_run=True,
        )

    workspace_path = state / "workspace_integrity.json"
    raw = json.loads(workspace_path.read_text(encoding="utf-8"))
    prior_profile_hash = raw["profile_hash"]
    assert prior_profile_hash != match.group(1)
    raw["root_hash"] = "sha256:" + "8" * 64
    workspace_path.write_text(json.dumps(raw), encoding="utf-8")
    before = {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    }

    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["verification"] == (
        "checkpoint_store_commitment_mismatch"
    )
    assert (
        report.stores["authority_publication"]["checkpoint_store_commitments"]
        == "recorded"
    )
    assert any(
        issue.code == "authority_publication_active_checkpoint_store_mismatch"
        for issue in report.issues
    )
    assert snapshot["authoritative"] is False
    assert snapshot["authority_publication"]["verification"] == (
        "checkpoint_store_commitment_mismatch"
    )
    assert "store_hashes" not in snapshot["authority_publication"]
    assert {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    } == before


def test_read_only_audit_verifies_pre_activation_rotation_checkpoint(
    tmp_path,
    monkeypatch,
):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    store = AuthorityProfileStore(state / "authority_profile.json")
    with pytest.raises(AuthorityProfileError, match="does not match") as mismatch:
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            dry_run=True,
        )
    match = re.search(r"configured (sha256:[0-9a-f]{64})", str(mismatch.value))
    assert match is not None
    store.request_rotation(
        match.group(1),
        operator="release-operator",
        note="verify prepared rotation",
        operator_trust=None,
    )

    def crash_before_activation(self, *args, **kwargs):
        raise RuntimeError("simulated activation crash")

    monkeypatch.setattr(
        AuthorityProfileStore,
        "resolve_for_authority",
        crash_before_activation,
    )
    with pytest.raises(RuntimeError, match="simulated activation crash"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            dry_run=True,
        )

    report = StateIntegrityAuditor(state, workspace_root=workspace).audit()

    assert report.status == "recovery_required"
    assert report.safe_to_execute is True
    assert report.stores["authority_publication"]["verification"] == "prepared"


def test_active_publication_profile_contradiction_is_critical(tmp_path, monkeypatch):
    def crash_before_complete(self, intent):
        raise RuntimeError("simulated completion crash")

    monkeypatch.setattr(AuthorityPublicationStore, "complete", crash_before_complete)
    state = tmp_path / "state"
    with pytest.raises(RuntimeError, match="simulated completion crash"):
        build_harness(state, MockAgentAdapter())
    path = state / "authority_publication.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["active"]["profile_hash"] = "sha256:" + "6" * 64
    path.write_text(json.dumps(raw), encoding="utf-8")

    report = StateIntegrityAuditor(state).audit()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["verification"] == "invalid"
    assert any(issue.code == "authority_publication_invalid" for issue in report.issues)


def test_active_publication_final_manifest_contradiction_is_critical(
    tmp_path,
    monkeypatch,
):
    def crash_before_complete(self, intent):
        raise RuntimeError("simulated completion crash")

    monkeypatch.setattr(AuthorityPublicationStore, "complete", crash_before_complete)
    state = tmp_path / "state"
    with pytest.raises(RuntimeError, match="simulated completion crash"):
        build_harness(state, MockAgentAdapter())
    workspace_path = state / "workspace_integrity.json"
    raw = json.loads(workspace_path.read_text(encoding="utf-8"))
    raw["root_hash"] = "sha256:" + "5" * 64
    workspace_path.write_text(json.dumps(raw), encoding="utf-8")
    before = {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    }

    report = StateIntegrityAuditor(state).audit()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["verification"] == (
        "store_commitment_mismatch"
    )
    assert any(
        issue.code == "authority_publication_active_store_mismatch"
        for issue in report.issues
    )
    assert {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    } == before


def test_active_publication_refuses_a_different_manifest(tmp_path, monkeypatch):
    original = AuthorityPublicationStore.complete

    def crash_before_complete(self, intent):
        raise RuntimeError("simulated completion crash")

    monkeypatch.setattr(AuthorityPublicationStore, "complete", crash_before_complete)
    state = tmp_path / "state"
    first = unverified_artifacts(("first-tool",))
    with pytest.raises(RuntimeError, match="simulated completion crash"):
        build_harness(
            state,
            MockAgentAdapter(),
            runtime_artifact_assurance=first,
        )
    before = (state / "authority_publication.json").read_bytes()

    monkeypatch.setattr(AuthorityPublicationStore, "complete", original)
    with pytest.raises(AuthorityPublicationError, match="does not match"):
        build_harness(
            state,
            MockAgentAdapter(),
            runtime_artifact_assurance=remote_artifacts(),
        )

    assert (state / "authority_publication.json").read_bytes() == before


def test_completed_publication_refuses_dependent_store_tampering(tmp_path):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    publication_before = (state / "authority_publication.json").read_bytes()
    workspace_path = state / "workspace_integrity.json"
    raw = json.loads(workspace_path.read_text(encoding="utf-8"))
    raw["root_hash"] = "sha256:" + "9" * 64
    workspace_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(AuthorityPublicationError, match="workspace_integrity"):
        build_harness(state, MockAgentAdapter(), workspace_root=workspace)

    assert (state / "authority_publication.json").read_bytes() == publication_before


def test_read_only_audit_detects_completed_manifest_tampering(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter(), workspace_root=tmp_path / "workspace")
    workspace_path = state / "workspace_integrity.json"
    raw = json.loads(workspace_path.read_text(encoding="utf-8"))
    raw["root_hash"] = "sha256:" + "8" * 64
    workspace_path.write_text(json.dumps(raw), encoding="utf-8")
    before = {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    }

    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()

    assert report.safe_to_execute is False
    assert report.stores["workspace_integrity"]["verification"] == "profile_bound"
    assert report.stores["authority_publication"]["verification"] == (
        "manifest_mismatch"
    )
    assert any(
        issue.code == "authority_publication_manifest_mismatch"
        for issue in report.issues
    )
    assert snapshot["authoritative"] is False
    assert snapshot["authority_publication"]["verification"] == "manifest_mismatch"
    assert {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    } == before


@pytest.mark.parametrize(
    "store_name",
    ["workspace_integrity", "runtime_artifacts"],
)
def test_completed_checkpoint_commitment_poisoning_is_critical_and_refused(
    tmp_path,
    store_name,
):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    publication_path = state / "authority_publication.json"
    publication = json.loads(publication_path.read_text(encoding="utf-8"))
    publication["completed"]["store_hashes"][store_name] = "sha256:" + "9" * 64
    publication_path.write_text(json.dumps(publication), encoding="utf-8")
    before = {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    }

    report = StateIntegrityAuditor(state, workspace_root=workspace).audit()
    snapshot = CommandCore(state, workspace_root=workspace).snapshot()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["verification"] == "invalid"
    issue = next(
        issue
        for issue in report.issues
        if issue.code == "authority_publication_invalid"
    )
    assert "record hash" in issue.detail
    assert snapshot["authoritative"] is False
    assert snapshot["authority_publication"]["verification"] == "invalid"
    assert {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    } == before

    with pytest.raises(AuthorityPublicationError, match="record hash"):
        build_harness(state, MockAgentAdapter(), workspace_root=workspace)

    with pytest.raises(AuthorityPublicationError, match="record hash"):
        AuthorityPublicationStore(publication_path).get()
    assert {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    } == before


def test_read_only_audit_requires_every_completed_manifest_dependency(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    (state / "control_plane_isolation.json").unlink()

    report = StateIntegrityAuditor(state).audit()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["verification"] == (
        "dependency_invalid"
    )
    issue = next(
        issue
        for issue in report.issues
        if issue.code == "authority_publication_dependency_invalid"
    )
    assert "control_plane_isolation" in issue.detail


def test_read_only_manifest_verification_requires_dependency_profile_binding(
    tmp_path,
):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    workspace_path = state / "workspace_integrity.json"
    raw = json.loads(workspace_path.read_text(encoding="utf-8"))
    raw["profile_hash"] = "sha256:" + "7" * 64
    workspace_path.write_text(json.dumps(raw), encoding="utf-8")

    report = StateIntegrityAuditor(state).audit()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["verification"] == (
        "dependency_invalid"
    )
    issue = next(
        issue
        for issue in report.issues
        if issue.code == "authority_publication_dependency_invalid"
    )
    assert "workspace_integrity" in issue.detail
    assert "profile mismatch" in issue.detail


def test_completed_publication_refuses_unexpected_optional_store(tmp_path):
    state = tmp_path / "state"
    harness = build_harness(state, MockAgentAdapter())
    RuntimeArtifactStateStore(state / "runtime_artifacts.json").record(
        harness.policy.ruleset_hash,
        unverified_artifacts(("injected-tool",)),
    )

    report = StateIntegrityAuditor(state).audit()
    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["verification"] == (
        "manifest_mismatch"
    )

    with pytest.raises(AuthorityPublicationError, match="runtime_artifacts"):
        build_harness(state, MockAgentAdapter())


def test_operator_control_cannot_bypass_active_publication(tmp_path, monkeypatch):
    def crash_before_complete(self, intent):
        raise RuntimeError("simulated completion crash")

    monkeypatch.setattr(AuthorityPublicationStore, "complete", crash_before_complete)
    state = tmp_path / "state"
    with pytest.raises(RuntimeError, match="simulated completion crash"):
        build_harness(state, MockAgentAdapter())

    with pytest.raises(AuthorityPublicationError, match="owning runtime"):
        build_harness(state, MockAgentAdapter(), _operator_control=True)


def test_legacy_active_publication_remains_recoverable(tmp_path, monkeypatch):
    original = AuthorityPublicationStore.complete

    def crash_before_complete(self, intent):
        raise RuntimeError("simulated legacy completion crash")

    monkeypatch.setattr(AuthorityPublicationStore, "complete", crash_before_complete)
    state = tmp_path / "state"
    with pytest.raises(RuntimeError, match="simulated legacy completion crash"):
        build_harness(state, MockAgentAdapter())

    path = state / "authority_publication.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["schema_version"] = "0.1.0"
    raw["active"].pop("store_hashes")
    raw["active"].pop("prior_checkpoint_hash")
    raw["active"].pop("record_hash")
    path.write_text(json.dumps(raw), encoding="utf-8")
    before = path.read_bytes()

    loaded = AuthorityPublicationStore(path).get()
    assert loaded is not None
    assert loaded.active is not None
    assert loaded.active.store_hashes is None
    assert loaded.projection()["store_commitments"] == "legacy_unavailable"
    report = StateIntegrityAuditor(state).audit()
    assert report.status == "recovery_required"
    assert report.safe_to_execute is True
    assert path.read_bytes() == before

    monkeypatch.setattr(AuthorityPublicationStore, "complete", original)
    build_harness(state, MockAgentAdapter())
    migrated = json.loads(path.read_text(encoding="utf-8"))
    assert migrated["schema_version"] == "0.5.0"
    assert migrated["active"] is None
    assert set(migrated["completed"]["store_hashes"]) == set(STORE_HASHES)
    assert migrated["completed"]["record_hash"].startswith("sha256:")


def test_legacy_v04_active_intent_completes_without_fabricating_transition_link(
    tmp_path,
    monkeypatch,
):
    original = AuthorityPublicationStore.complete

    def crash_before_complete(self, intent):
        raise RuntimeError("simulated legacy sealed completion crash")

    monkeypatch.setattr(AuthorityPublicationStore, "complete", crash_before_complete)
    state = tmp_path / "state"
    with pytest.raises(RuntimeError, match="legacy sealed completion crash"):
        build_harness(state, MockAgentAdapter())

    store = AuthorityPublicationStore(state / "authority_publication.json")
    loaded = store.get()
    assert loaded is not None
    active = loaded.active
    assert active is not None
    legacy = AuthorityPublicationIntent(
        profile_hash=active.profile_hash,
        generation=active.generation,
        manifest_hash=active.manifest_hash,
        prepared_at=active.prepared_at,
        store_hashes=active.store_hashes,
    ).sealed(schema_version="0.4.0")
    raw = json.loads(store.path.read_text(encoding="utf-8"))
    raw["schema_version"] = "0.4.0"
    raw["active"] = legacy.to_dict(schema_version="0.4.0")
    store.path.write_text(json.dumps(raw), encoding="utf-8")
    before = store.path.read_bytes()

    legacy_state = store.get()
    assert legacy_state is not None
    assert legacy_state.projection()["intent_record_seal"] == "verified"
    assert legacy_state.projection()["intent_checkpoint_link"] == ("legacy_unavailable")
    report = StateIntegrityAuditor(state).audit()
    assert report.status == "recovery_required"
    assert report.safe_to_execute is True
    assert store.path.read_bytes() == before

    monkeypatch.setattr(AuthorityPublicationStore, "complete", original)
    build_harness(state, MockAgentAdapter())
    migrated = store.get()
    assert migrated is not None
    assert migrated.schema_version == "0.5.0"
    assert migrated.projection()["checkpoint_intent_link"] == "legacy_unavailable"

    build_harness(state, MockAgentAdapter())
    republished = store.get()
    assert republished is not None
    assert republished.projection()["checkpoint_intent_link"] == "verified"


def test_legacy_v02_checkpoint_is_readable_and_migrates_on_successful_startup(
    tmp_path,
):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    path = state / "authority_publication.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["schema_version"] = "0.2.0"
    raw["completed"].pop("store_hashes")
    raw["completed"].pop("prepared_at")
    raw["completed"].pop("prior_checkpoint_hash")
    raw["completed"].pop("intent_record_hash")
    raw["completed"].pop("record_hash")
    path.write_text(json.dumps(raw), encoding="utf-8")
    before = path.read_bytes()

    loaded = AuthorityPublicationStore(path).get()
    assert loaded is not None
    assert loaded.completed is not None
    assert loaded.completed.store_hashes is None
    assert loaded.projection()["checkpoint_store_commitments"] == ("legacy_unavailable")
    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()
    assert report.status == "healthy"
    assert report.safe_to_execute is True
    assert snapshot["authority_publication"]["checkpoint_store_commitments"] == (
        "legacy_unavailable"
    )
    assert path.read_bytes() == before

    build_harness(state, MockAgentAdapter())
    migrated = json.loads(path.read_text(encoding="utf-8"))
    assert migrated["schema_version"] == "0.5.0"
    assert migrated["completed"]["store_hashes"] is not None
    assert migrated["completed"]["record_hash"].startswith("sha256:")


def test_legacy_v02_checkpoint_remains_recoverable_during_partial_rotation(
    tmp_path,
    monkeypatch,
):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    publication_path = state / "authority_publication.json"
    publication = json.loads(publication_path.read_text(encoding="utf-8"))
    publication["schema_version"] = "0.2.0"
    publication["completed"].pop("store_hashes")
    publication["completed"].pop("prepared_at")
    publication["completed"].pop("prior_checkpoint_hash")
    publication["completed"].pop("intent_record_hash")
    publication["completed"].pop("record_hash")
    publication_path.write_text(json.dumps(publication), encoding="utf-8")

    profile_store = AuthorityProfileStore(state / "authority_profile.json")
    with pytest.raises(AuthorityProfileError, match="does not match") as mismatch:
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            dry_run=True,
        )
    match = re.search(r"configured (sha256:[0-9a-f]{64})", str(mismatch.value))
    assert match is not None
    profile_store.request_rotation(
        match.group(1),
        operator="release-operator",
        note="migrate legacy checkpoint after partial replay",
        operator_trust=None,
    )

    original = StateStorageStateStore.record

    def crash_after_first_target(self, *args, **kwargs):
        original(self, *args, **kwargs)
        raise RuntimeError("simulated legacy checkpoint crash")

    monkeypatch.setattr(
        StateStorageStateStore,
        "record",
        crash_after_first_target,
    )
    with pytest.raises(RuntimeError, match="simulated legacy checkpoint crash"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            dry_run=True,
        )

    before = {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    }
    report = StateIntegrityAuditor(state, workspace_root=workspace).audit()
    assert report.status == "recovery_required"
    assert report.safe_to_execute is True
    assert report.stores["authority_publication"]["verification"] == "applying"
    assert (
        report.stores["authority_publication"]["checkpoint_store_commitments"]
        == "legacy_unavailable"
    )
    assert {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    } == before

    monkeypatch.setattr(StateStorageStateStore, "record", original)
    build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        dry_run=True,
    )
    migrated = json.loads(publication_path.read_text(encoding="utf-8"))
    assert migrated["schema_version"] == "0.5.0"
    assert migrated["completed"]["store_hashes"] is not None
    assert migrated["completed"]["record_hash"].startswith("sha256:")


def test_legacy_v03_checkpoint_is_readable_and_migrates_with_a_record_seal(
    tmp_path,
):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    path = state / "authority_publication.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["schema_version"] = "0.3.0"
    raw["completed"].pop("prepared_at")
    raw["completed"].pop("prior_checkpoint_hash")
    raw["completed"].pop("intent_record_hash")
    raw["completed"].pop("record_hash")
    path.write_text(json.dumps(raw), encoding="utf-8")
    before = path.read_bytes()

    loaded = AuthorityPublicationStore(path).get()
    assert loaded is not None
    assert loaded.completed is not None
    assert loaded.completed.store_hashes is not None
    assert loaded.completed.record_hash is None
    assert loaded.projection()["checkpoint_record_seal"] == "legacy_unavailable"
    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()
    assert report.status == "healthy"
    assert report.safe_to_execute is True
    assert snapshot["authority_publication"]["checkpoint_record_seal"] == (
        "legacy_unavailable"
    )
    assert path.read_bytes() == before

    build_harness(state, MockAgentAdapter())
    migrated = json.loads(path.read_text(encoding="utf-8"))
    assert migrated["schema_version"] == "0.5.0"
    assert migrated["completed"]["record_hash"].startswith("sha256:")


def test_legacy_v04_checkpoint_is_readable_and_migrates_with_transition_links(
    tmp_path,
):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    store = AuthorityPublicationStore(state / "authority_publication.json")
    loaded = store.get()
    assert loaded is not None
    checkpoint = loaded.completed
    assert checkpoint is not None
    legacy = AuthorityPublicationCheckpoint(
        profile_hash=checkpoint.profile_hash,
        generation=checkpoint.generation,
        manifest_hash=checkpoint.manifest_hash,
        completed_at=checkpoint.completed_at,
        store_hashes=checkpoint.store_hashes,
        record_hash=checkpoint.expected_record_hash(schema_version="0.4.0"),
    )
    raw = json.loads(store.path.read_text(encoding="utf-8"))
    raw["schema_version"] = "0.4.0"
    raw["completed"] = legacy.to_dict(schema_version="0.4.0")
    store.path.write_text(json.dumps(raw), encoding="utf-8")
    before = store.path.read_bytes()

    legacy_state = store.get()
    assert legacy_state is not None
    assert legacy_state.projection()["checkpoint_record_seal"] == "verified"
    assert legacy_state.projection()["checkpoint_intent_link"] == ("legacy_unavailable")
    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()
    assert report.status == "healthy"
    assert report.safe_to_execute is True
    assert snapshot["authority_publication"]["checkpoint_intent_link"] == (
        "legacy_unavailable"
    )
    assert store.path.read_bytes() == before

    build_harness(state, MockAgentAdapter())
    migrated = store.get()
    assert migrated is not None
    assert migrated.schema_version == "0.5.0"
    assert migrated.completed is not None
    assert migrated.projection()["checkpoint_intent_link"] == "verified"


def test_publication_state_rejects_unknown_fields():
    with pytest.raises(AuthorityPublicationError, match="fields"):
        AuthorityPublicationState.from_dict(
            {
                "schema_name": "defiant.authority_publication",
                "schema_version": "0.1.0",
                "active": None,
                "completed": None,
                "unexpected": True,
            }
        )

    with pytest.raises(AuthorityPublicationError, match="requires store commitments"):
        AuthorityPublicationState.from_dict(
            {
                "schema_name": "defiant.authority_publication",
                "schema_version": "0.3.0",
                "active": None,
                "completed": {
                    "profile_hash": PROFILE,
                    "generation": 1,
                    "manifest_hash": MANIFEST,
                    "completed_at": "2026-09-01T00:00:00Z",
                    "store_hashes": None,
                },
            }
        )

    with pytest.raises(AuthorityPublicationError, match="requires"):
        AuthorityPublicationState.from_dict(
            {
                "schema_name": "defiant.authority_publication",
                "schema_version": "0.1.0",
                "active": None,
                "completed": None,
            }
        )
