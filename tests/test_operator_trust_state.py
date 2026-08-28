from __future__ import annotations

import copy
import json

import pytest

import defiant_agent_harness.operator_trust_state as operator_trust_state_module
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.approvals.store import ApprovalStore
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.contracts import ProposedAction, SideEffect
from defiant_agent_harness.evidence.signing import generate_key_pair
from defiant_agent_harness.hooks.copilot import CopilotHookGate
from defiant_agent_harness.operator_identity import (
    DECISION_PURPOSE,
    OperatorTrustPolicy,
    sign_operator_action,
    sign_trust_transition,
)
from defiant_agent_harness.operator_trust_state import (
    OperatorTrustState,
    OperatorTrustStateError,
    OperatorTrustStateStore,
)
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.state_integrity import StateIntegrityAuditor

PASSPHRASE = b"test-only trust rotation passphrase"


def _key(tmp_path, name: str, operator: str = "alice"):
    private = tmp_path / f"{name}-private.pem"
    public = tmp_path / f"{name}-public.pem"
    generate_key_pair(private, public, PASSPHRASE)
    return private, f"{operator}={public}"


def _transition(state, candidate, private, *, operator="alice", note="add key"):
    return sign_trust_transition(
        private,
        PASSPHRASE,
        from_generation=state.generation,
        from_bindings_hash=state.bindings_hash,
        to_bindings_hash=candidate.bindings_hash,
        operator=operator,
        note=note,
    )


def test_first_trusted_authority_startup_enrolls_and_restart_requires_pins(tmp_path):
    _, spec = _key(tmp_path, "old")
    state = tmp_path / "state"

    build_harness(state, MockAgentAdapter(), trusted_operator_keys=[spec])
    trust_path = state / "operator_trust.json"
    before = {
        path.name: path.read_bytes() for path in state.iterdir() if path.is_file()
    }

    enrolled = json.loads(trust_path.read_text(encoding="utf-8"))
    assert enrolled["mode"] == "signed_required"
    assert enrolled["generation"] == 1
    assert enrolled["bindings_hash"].startswith("sha256:")
    assert spec.split("=", 1)[1] not in json.dumps(enrolled)

    with pytest.raises(OperatorTrustStateError, match="durably enrolled"):
        build_harness(state, MockAgentAdapter())

    after = {path.name: path.read_bytes() for path in state.iterdir() if path.is_file()}
    assert after == before


def test_trust_state_owns_hostile_snapshot_and_defensive_projections(tmp_path):
    class HostileDict(dict):
        def __deepcopy__(self, memo):
            raise AssertionError("trust snapshot invoked deepcopy hook")

        def __iter__(self):
            raise AssertionError("trust snapshot invoked mapping iterator hook")

        def get(self, key, default=None):
            raise AssertionError("trust snapshot invoked mapping get hook")

        def items(self):
            raise AssertionError("trust snapshot invoked mapping items hook")

        def keys(self):
            raise AssertionError("trust snapshot invoked mapping keys hook")

    class HostileList(list):
        def __deepcopy__(self, memo):
            raise AssertionError("trust snapshot invoked list deepcopy hook")

        def __iter__(self):
            raise AssertionError("trust snapshot invoked list iterator hook")

    class HostileString(str):
        def __deepcopy__(self, memo):
            raise AssertionError("trust snapshot invoked scalar deepcopy hook")

        def __str__(self):
            raise AssertionError("trust snapshot invoked scalar rendering hook")

    _, spec = _key(tmp_path, "old")
    path = tmp_path / "state" / "operator_trust.json"
    store = OperatorTrustStateStore(path)
    store.resolve_for_authority([spec])
    raw = json.loads(path.read_text(encoding="utf-8"))

    def hostile(value):
        if type(value) is dict:
            return HostileDict({key: hostile(child) for key, child in value.items()})
        if type(value) is list:
            return HostileList([hostile(child) for child in value])
        if type(value) is str:
            return HostileString(value)
        return value

    supplied = hostile(raw)
    state = OperatorTrustState.from_dict(supplied)
    expected = state.to_dict()
    first_operator = next(iter(raw["bindings"]))
    supplied_bindings = dict.__getitem__(supplied, "bindings")
    dict.__getitem__(supplied_bindings, first_operator).append("sha256:" + "0" * 64)
    projection = state.to_dict()
    projection["bindings"][first_operator].append("sha256:" + "1" * 64)
    state.bindings[first_operator].append("sha256:" + "2" * 64)

    assert state.to_dict() == expected
    assert state.bindings == raw["bindings"]
    assert type(state.to_dict()["bindings"]) is dict
    assert type(state.to_dict()["bindings"][first_operator]) is list


def test_trust_rotation_refuses_unrecoverable_state_size(tmp_path, monkeypatch):
    old_private, old_spec = _key(tmp_path, "old")
    _, new_spec = _key(tmp_path, "new")
    path = tmp_path / "state" / "operator_trust.json"
    store = OperatorTrustStateStore(path)
    current = store.resolve_for_authority([old_spec])
    candidate = OperatorTrustPolicy.from_specs([old_spec, new_spec])
    enrolled = store.get()
    attestation = _transition(enrolled, candidate, old_private)
    before = path.read_bytes()
    monkeypatch.setattr(
        operator_trust_state_module,
        "_MAX_STATE_BYTES",
        len(before) + 32,
    )

    with pytest.raises(OperatorTrustStateError, match="bounded canonical state"):
        store.rotate(current, candidate, attestation)

    assert path.read_bytes() == before
    assert store.get().generation == 1


def test_trust_publication_uses_recovery_read_ceiling(tmp_path, monkeypatch):
    _, spec = _key(tmp_path, "old")
    observed = []
    original_write = operator_trust_state_module.atomic_write_json

    def recording_write(path, data, *, max_bytes=None):
        observed.append(max_bytes)
        return original_write(path, data, max_bytes=max_bytes)

    monkeypatch.setattr(
        operator_trust_state_module,
        "atomic_write_json",
        recording_write,
    )
    OperatorTrustStateStore(
        tmp_path / "state" / "operator_trust.json"
    ).resolve_for_authority([spec])

    assert observed == [operator_trust_state_module._MAX_STATE_BYTES]


def test_changed_mapping_requires_explicit_rotation(tmp_path):
    _, old_spec = _key(tmp_path, "old")
    _, replacement_spec = _key(tmp_path, "replacement")
    store = OperatorTrustStateStore(tmp_path / "state" / "operator_trust.json")
    store.resolve_for_authority([old_spec])

    with pytest.raises(OperatorTrustStateError, match="explicit signed additive"):
        store.resolve_for_authority([replacement_spec])


def test_v09_signed_state_requires_pins_for_first_v010_migration(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "approvals.json").write_text(
        json.dumps({"legacy": {"decision_attestation": {"signature": "sealed"}}}),
        encoding="utf-8",
    )
    (state / "approvals.json").chmod(0o600)
    store = OperatorTrustStateStore(state / "operator_trust.json")

    with pytest.raises(OperatorTrustStateError, match="required to migrate"):
        store.resolve_for_authority([])


def test_read_only_marks_unenrolled_v09_signed_state_as_migration_required(tmp_path):
    private, spec = _key(tmp_path, "old")
    state = tmp_path / "state"
    trust = OperatorTrustPolicy.from_specs([spec])
    approvals = ApprovalStore(state / "approvals.json", operator_trust=trust)
    pending = approvals.create(
        ProposedAction(
            tool_name="send_email",
            target="recipient@example.com",
            payload={"body": "reviewed"},
            side_effect_level=SideEffect.EXTERNAL_SEND,
            request_id="req_migrate",
        ),
        "review",
        "exact action",
        ["r1"],
    )
    attestation = sign_operator_action(
        pending,
        private,
        PASSPHRASE,
        purpose=DECISION_PURPOSE,
        outcome="approved",
        operator="alice",
        note="reviewed",
    )
    approvals.decide(
        pending.approval_id,
        True,
        "alice",
        "reviewed",
        attestation=attestation,
    )

    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()

    assert not report.safe_to_execute
    assert any(
        issue.code == "operator_trust_migration_required" for issue in report.issues
    )
    assert snapshot["operator_trust"]["verification"] == "migration_required"


def test_read_only_surfaces_enrolled_but_unverified_without_mutating(tmp_path):
    _, spec = _key(tmp_path, "old")
    state = tmp_path / "state"
    store = OperatorTrustStateStore(state / "operator_trust.json")
    store.resolve_for_authority([spec])
    before = (state / "operator_trust.json").read_bytes()

    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()

    assert not report.safe_to_execute
    assert any(issue.code == "operator_trust_unverified" for issue in report.issues)
    assert snapshot["authoritative"] is False
    assert snapshot["operator_trust"]["verification"] == "unverified"
    assert snapshot["operator_trust"]["generation"] == 1
    assert "signature" not in json.dumps(snapshot)
    assert (state / "operator_trust.json").read_bytes() == before


def test_matching_read_only_pins_verify_enrollment(tmp_path):
    _, spec = _key(tmp_path, "old")
    state = tmp_path / "state"
    OperatorTrustStateStore(state / "operator_trust.json").resolve_for_authority([spec])

    report = StateIntegrityAuditor(
        state, operator_trust=OperatorTrustPolicy.from_specs([spec])
    ).audit()
    snapshot = CommandCore(state, trusted_operator_keys=[spec]).snapshot()

    assert report.safe_to_execute
    assert report.stores["operator_trust"]["verification"] == "verified"
    assert snapshot["operator_trust"]["verification"] == "verified"


def test_old_key_signed_additive_rotation_survives_restart(tmp_path):
    old_private, old_spec = _key(tmp_path, "old")
    _, new_spec = _key(tmp_path, "new")
    path = tmp_path / "state" / "operator_trust.json"
    store = OperatorTrustStateStore(path)
    current = store.resolve_for_authority([old_spec])
    assert current is not None
    candidate = OperatorTrustPolicy.from_specs([old_spec, new_spec])
    enrolled = store.get()
    assert enrolled is not None
    attestation = _transition(enrolled, candidate, old_private, note="stage new key")

    rotated = store.rotate(current, candidate, attestation)

    assert rotated.generation == 2
    assert rotated.transitions[-1]["attestation"]["note"] == "stage new key"
    assert (
        store.resolve_for_authority([old_spec, new_spec]).bindings == candidate.bindings
    )
    assert store.rotate(current, candidate, attestation) == rotated


@pytest.mark.parametrize("change", ["removal", "reassignment"])
def test_online_rotation_refuses_non_additive_changes(tmp_path, change):
    old_private, old_spec = _key(tmp_path, "old")
    _, second_spec = _key(tmp_path, "second", operator="bob")
    path = tmp_path / "state" / "operator_trust.json"
    store = OperatorTrustStateStore(path)
    current = store.resolve_for_authority([old_spec, second_spec])
    assert current is not None
    if change == "removal":
        candidate = OperatorTrustPolicy.from_specs([old_spec])
    else:
        second_path = second_spec.split("=", 1)[1]
        candidate = OperatorTrustPolicy.from_specs([old_spec, f"alice={second_path}"])
    enrolled = store.get()
    assert enrolled is not None
    attestation = _transition(enrolled, candidate, old_private)
    before = path.read_bytes()

    with pytest.raises(OperatorTrustStateError, match="strictly additive"):
        store.rotate(current, candidate, attestation)

    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("operator", "mallory", "current generation"),
        ("note", "rewritten", "signature"),
        ("from_generation", 9, "generation"),
        ("to_bindings_hash", "sha256:" + "0" * 64, "does not match|bind"),
        ("signature", "base64:" + "A" * 88, "signature"),
    ],
)
def test_tampered_rotation_is_rejected_without_state_change(
    tmp_path, field, replacement, message
):
    old_private, old_spec = _key(tmp_path, "old")
    _, new_spec = _key(tmp_path, "new")
    path = tmp_path / "state" / "operator_trust.json"
    store = OperatorTrustStateStore(path)
    current = store.resolve_for_authority([old_spec])
    assert current is not None
    candidate = OperatorTrustPolicy.from_specs([old_spec, new_spec])
    enrolled = store.get()
    assert enrolled is not None
    attestation = _transition(enrolled, candidate, old_private)
    tampered = copy.deepcopy(attestation)
    tampered[field] = replacement
    before = path.read_bytes()

    with pytest.raises(OperatorTrustStateError, match=message):
        store.rotate(current, candidate, tampered)

    assert path.read_bytes() == before


def test_new_key_cannot_authorize_its_own_addition(tmp_path):
    _, old_spec = _key(tmp_path, "old")
    new_private, new_spec = _key(tmp_path, "new")
    store = OperatorTrustStateStore(tmp_path / "state" / "operator_trust.json")
    current = store.resolve_for_authority([old_spec])
    assert current is not None
    candidate = OperatorTrustPolicy.from_specs([old_spec, new_spec])
    enrolled = store.get()
    assert enrolled is not None
    attestation = _transition(enrolled, candidate, new_private)

    with pytest.raises(OperatorTrustStateError, match="current generation"):
        store.rotate(current, candidate, attestation)


def test_tampered_durable_chain_fails_authority_and_read_only_audit(tmp_path):
    old_private, old_spec = _key(tmp_path, "old")
    _, new_spec = _key(tmp_path, "new")
    path = tmp_path / "state" / "operator_trust.json"
    store = OperatorTrustStateStore(path)
    current = store.resolve_for_authority([old_spec])
    assert current is not None
    candidate = OperatorTrustPolicy.from_specs([old_spec, new_spec])
    enrolled = store.get()
    assert enrolled is not None
    store.rotate(current, candidate, _transition(enrolled, candidate, old_private))
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["transitions"][0]["attestation"]["signature"] = "base64:" + "A" * 88
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(OperatorTrustStateError, match="signature"):
        store.resolve_for_authority([old_spec, new_spec])
    report = StateIntegrityAuditor(tmp_path / "state", operator_trust=candidate).audit()
    assert not report.safe_to_execute
    assert any(issue.code == "operator_trust_mismatch" for issue in report.issues)


def test_present_trust_lock_is_critical(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "operator_trust.json.lock").write_text("pid=unknown\n", encoding="utf-8")
    (state / "operator_trust.json.lock").chmod(0o600)

    report = StateIntegrityAuditor(state).audit()

    assert not report.safe_to_execute
    assert any(
        issue.code == "state_lock_present" and issue.store == "operator_trust.json"
        for issue in report.issues
    )


def test_oversized_trust_state_fails_closed_without_json_parsing(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "operator_trust.json").write_bytes(b" " * (1024 * 1024 + 1))
    (state / "operator_trust.json").chmod(0o600)

    report = StateIntegrityAuditor(state).audit()

    assert not report.safe_to_execute
    assert any(issue.code == "operator_trust_invalid" for issue in report.issues)
    assert "too large" in report.issues[0].detail


def test_rotation_cli_requires_explicit_identity_note_and_old_signer(tmp_path, capsys):
    old_private, old_spec = _key(tmp_path, "old")
    _, new_spec = _key(tmp_path, "new")
    passphrase_file = tmp_path / "operator.passphrase"
    passphrase_file.write_bytes(PASSPHRASE)
    state = tmp_path / "state"
    OperatorTrustStateStore(state / "operator_trust.json").resolve_for_authority(
        [old_spec]
    )

    exit_code = main(
        [
            "--workdir",
            str(state),
            "operator-trust-rotate",
            "--trusted-operator-key",
            old_spec,
            "--new-trusted-operator-key",
            old_spec,
            "--new-trusted-operator-key",
            new_spec,
            "--operator-key",
            str(old_private),
            "--operator-passphrase-file",
            str(passphrase_file),
            "--operator",
            "alice",
            "--note",
            "stage replacement key",
        ]
    )

    assert exit_code == 0
    assert "generation 2" in capsys.readouterr().out
    assert OperatorTrustStateStore(state / "operator_trust.json").resolve_for_authority(
        [old_spec, new_spec]
    )


def test_native_hook_restart_without_enrolled_pins_fails_closed(tmp_path):
    _, spec = _key(tmp_path, "old")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    CopilotHookGate(workspace, state, trusted_operator_keys=[spec])

    with pytest.raises(OperatorTrustStateError, match="durably enrolled"):
        CopilotHookGate(workspace, state)


@pytest.mark.parametrize("command", ["pending", "budget", "policy"])
def test_harness_cli_views_accept_enrolled_trust_pins(tmp_path, command, capsys):
    _, spec = _key(tmp_path, "old")
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter(), trusted_operator_keys=[spec])

    missing_exit = main(["--workdir", str(state), command])
    missing_output = capsys.readouterr()
    pinned_exit = main(
        [
            "--workdir",
            str(state),
            command,
            "--trusted-operator-key",
            spec,
        ]
    )

    assert missing_exit == 1
    assert "durably enrolled" in missing_output.err
    assert pinned_exit == 0
