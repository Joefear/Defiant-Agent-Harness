from __future__ import annotations

import json

import pytest

import defiant_agent_harness.authority_publication as publication_module
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.authority_publication import (
    AuthorityPublicationError,
    AuthorityPublicationState,
    AuthorityPublicationStore,
    authority_manifest_hash,
)
from defiant_agent_harness.authority_profile import AuthorityProfileStore
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


def test_publication_store_prepares_idempotently_and_completes(tmp_path):
    store = AuthorityPublicationStore(tmp_path / "authority_publication.json")

    first = store.prepare(PROFILE, 1, MANIFEST)
    assert store.prepare(PROFILE, 1, MANIFEST) == first
    assert store.get().projection()["state"] == "recovery_required"

    completed = store.complete(first)
    assert completed.active is None
    assert completed.completed is not None
    assert completed.completed.profile_hash == PROFILE
    assert completed.projection()["verification"] == "verified"


def test_publication_store_refuses_a_different_active_candidate(tmp_path):
    store = AuthorityPublicationStore(tmp_path / "authority_publication.json")
    store.prepare(PROFILE, 1, MANIFEST)
    before = store.path.read_bytes()

    with pytest.raises(AuthorityPublicationError, match="different"):
        store.prepare(PROFILE, 1, "sha256:" + "3" * 64)

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
    intent = store.prepare(PROFILE, 1, MANIFEST)
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
        store.prepare(PROFILE, 1, MANIFEST)

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
    store.prepare(PROFILE, 1, MANIFEST)
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

    build_harness(state, MockAgentAdapter())
    assert (
        AuthorityPublicationStore(state / "authority_publication.json")
        .get()
        .projection()["state"]
        == "complete"
    )


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


def test_completed_publication_refuses_unexpected_optional_store(tmp_path):
    state = tmp_path / "state"
    harness = build_harness(state, MockAgentAdapter())
    RuntimeArtifactStateStore(state / "runtime_artifacts.json").record(
        harness.policy.ruleset_hash,
        unverified_artifacts(("injected-tool",)),
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

    with pytest.raises(AuthorityPublicationError, match="requires"):
        AuthorityPublicationState.from_dict(
            {
                "schema_name": "defiant.authority_publication",
                "schema_version": "0.1.0",
                "active": None,
                "completed": None,
            }
        )
