from __future__ import annotations

import copy
import json

import pytest

from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.authority_profile import (
    AuthorityProfileError,
    AuthorityProfileStore,
)
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import HarnessRequest, sha256_of
from defiant_agent_harness.evidence.signing import generate_key_pair
from defiant_agent_harness.operator_identity import (
    OperatorTrustPolicy,
    sign_authority_profile_transition,
)
from defiant_agent_harness.operator_trust_state import OperatorTrustStateError
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.state_integrity import StateIntegrityAuditor

PASSPHRASE = b"test-only authority profile passphrase"


def _hash(label: str) -> str:
    return sha256_of({"profile": label})


def _key(tmp_path, operator: str = "alice"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    private = tmp_path / "operator-private.pem"
    public = tmp_path / "operator-public.pem"
    generate_key_pair(private, public, PASSPHRASE)
    spec = f"{operator}={public}"
    return private, spec, OperatorTrustPolicy.from_specs([spec])


def _signed_rotation(store, target, private, trust, *, note="approved rollout"):
    state = store.get()
    assert state is not None
    attestation = sign_authority_profile_transition(
        private,
        PASSPHRASE,
        from_generation=state.generation,
        from_profile_hash=state.profile_hash,
        to_profile_hash=target,
        operator="alice",
        note=note,
    )
    return store.request_rotation(
        target,
        operator="alice",
        note=note,
        operator_trust=trust,
        attestation=attestation,
    )


def test_first_startup_enrolls_complete_profile_and_exact_restart_matches(tmp_path):
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"

    first = build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    second = build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    enrolled = AuthorityProfileStore(state / "authority_profile.json").get()

    assert enrolled is not None
    assert enrolled.generation == 1
    assert enrolled.profile_hash == first.policy.ruleset_hash
    assert second.policy.ruleset_hash == first.policy.ruleset_hash
    assert enrolled.pending_rotation is None


def test_unapproved_profile_drift_fails_before_other_state_changes(tmp_path):
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    before = {
        path.name: path.read_bytes()
        for path in state.iterdir()
        if path.is_file() and path.name != "authority.lock"
    }

    with pytest.raises(AuthorityProfileError, match="does not match"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            dry_run=True,
        )

    after = {
        path.name: path.read_bytes()
        for path in state.iterdir()
        if path.is_file() and path.name != "authority.lock"
    }
    assert after == before


def test_unsigned_rotation_is_staged_then_exact_candidate_activates(tmp_path):
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    current = build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    candidate_state = tmp_path / "candidate"
    candidate = build_harness(
        candidate_state,
        MockAgentAdapter(),
        workspace_root=workspace,
        dry_run=True,
    )
    store = AuthorityProfileStore(state / "authority_profile.json")

    staged = store.request_rotation(
        candidate.policy.ruleset_hash,
        operator="release-operator",
        note="enable tested dry-run posture",
        operator_trust=None,
    )
    assert staged.profile_hash == current.policy.ruleset_hash
    assert staged.pending_rotation["to_profile_hash"] == candidate.policy.ruleset_hash

    # The old generation remains valid during a staged cutover.
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    activated = build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        dry_run=True,
    )
    resolved = store.get()

    assert activated.policy.ruleset_hash == candidate.policy.ruleset_hash
    assert resolved is not None
    assert resolved.generation == 2
    assert resolved.pending_rotation is None
    assert resolved.transitions[-1]["operator"] == "release-operator"
    assert resolved.transitions[-1]["note"] == "enable tested dry-run posture"


def test_pending_rotation_does_not_authorize_a_third_profile(tmp_path):
    store = AuthorityProfileStore(tmp_path / "state" / "authority_profile.json")
    store.resolve_for_authority(_hash("one"), None)
    store.request_rotation(
        _hash("two"), operator="alice", note="roll forward", operator_trust=None
    )
    before = store.path.read_bytes()

    with pytest.raises(AuthorityProfileError, match="approved pending profile"):
        store.resolve_for_authority(_hash("three"), None)

    assert store.path.read_bytes() == before


def test_signed_rotation_is_bound_to_old_generation_identity_and_note(tmp_path):
    private, _, trust = _key(tmp_path)
    store = AuthorityProfileStore(tmp_path / "state" / "authority_profile.json")
    store.resolve_for_authority(_hash("one"), trust)
    staged = _signed_rotation(store, _hash("two"), private, trust)

    assert staged.pending_rotation["attestation"]["operator"] == "alice"
    assert staged.pending_rotation["attestation"]["note"] == "approved rollout"
    activated = store.resolve_for_authority(_hash("two"), trust)
    assert activated.generation == 2
    assert activated.projection(verification="verified")["signed_transition_count"] == 1


def test_enrolled_signed_mode_cannot_be_downgraded_by_direct_unsigned_rotation(
    tmp_path,
):
    _, spec, _ = _key(tmp_path)
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter(), trusted_operator_keys=[spec])
    store = AuthorityProfileStore(state / "authority_profile.json")

    with pytest.raises(AuthorityProfileError, match="durably enrolled"):
        store.request_rotation(
            _hash("unsigned-downgrade"),
            operator="mallory",
            note="remove signature requirement",
            operator_trust=None,
        )


def test_crash_between_signed_trust_and_profile_enrollment_cannot_downgrade(
    tmp_path, monkeypatch
):
    _, spec, _ = _key(tmp_path)
    state = tmp_path / "state"

    def crash_before_profile_write(*_args, **_kwargs):
        raise RuntimeError("simulated profile write crash")

    monkeypatch.setattr(
        "defiant_agent_harness.authority_profile.atomic_write_json",
        crash_before_profile_write,
    )
    with pytest.raises(RuntimeError, match="simulated profile write crash"):
        build_harness(state, MockAgentAdapter(), trusted_operator_keys=[spec])

    assert (state / "operator_trust.json").exists()
    assert not (state / "authority_profile.json").exists()
    monkeypatch.undo()
    with pytest.raises(OperatorTrustStateError, match="durably enrolled"):
        build_harness(state, MockAgentAdapter())


def test_direct_profile_api_cannot_substitute_forged_operator_trust(tmp_path):
    _, enrolled_spec, _ = _key(tmp_path / "enrolled", operator="alice")
    attacker_private, _, attacker_trust = _key(
        tmp_path / "attacker", operator="mallory"
    )
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter(), trusted_operator_keys=[enrolled_spec])
    store = AuthorityProfileStore(state / "authority_profile.json")
    current = store.get()
    assert current is not None
    target = _hash("attacker-profile")
    forged = sign_authority_profile_transition(
        attacker_private,
        PASSPHRASE,
        from_generation=current.generation,
        from_profile_hash=current.profile_hash,
        to_profile_hash=target,
        operator="mallory",
        note="replace enrolled trust",
    )

    with pytest.raises(AuthorityProfileError, match="does not match durable"):
        store.request_rotation(
            target,
            operator="mallory",
            note="replace enrolled trust",
            operator_trust=attacker_trust,
            attestation=forged,
        )


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("operator", "mallory", "does not bind|does not match"),
        ("note", "rewritten", "does not bind|does not match"),
        ("to_profile_hash", _hash("three"), "does not bind|does not match"),
        ("signature", "base64:" + "A" * 88, "signature"),
    ],
)
def test_tampered_signed_pending_rotation_fails_closed(
    tmp_path, field, replacement, message
):
    private, _, trust = _key(tmp_path)
    store = AuthorityProfileStore(tmp_path / "state" / "authority_profile.json")
    store.resolve_for_authority(_hash("one"), trust)
    _signed_rotation(store, _hash("two"), private, trust)
    raw = json.loads(store.path.read_text(encoding="utf-8"))
    tampered = copy.deepcopy(raw)
    tampered["pending_rotation"]["attestation"][field] = replacement
    store.path.write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(AuthorityProfileError, match=message):
        store.resolve_for_authority(_hash("two"), trust)


def test_read_only_projection_exposes_rotation_without_operator_note_or_signature(
    tmp_path,
):
    state = tmp_path / "state"
    store = AuthorityProfileStore(state / "authority_profile.json")
    store.resolve_for_authority(_hash("one"), None)
    store.request_rotation(
        _hash("two"),
        operator="private-operator-name",
        note="sensitive deployment rationale",
        operator_trust=None,
    )
    before = store.path.read_bytes()

    report = StateIntegrityAuditor(state).audit()
    snapshot = CommandCore(state).snapshot()
    rendered = json.dumps(snapshot)

    assert report.safe_to_execute
    assert report.recovery_required
    assert snapshot["authority_profile"]["state"] == "rotation_required"
    assert snapshot["authority_profile"]["pending_assurance"] == "unsigned"
    assert "private-operator-name" not in rendered
    assert "sensitive deployment rationale" not in rendered
    assert "signature" not in rendered
    assert store.path.read_bytes() == before


def test_rotation_cli_requires_explicit_identity_note_and_stages_signed_target(
    tmp_path, capsys
):
    private, spec, _ = _key(tmp_path)
    passphrase = tmp_path / "operator.passphrase"
    passphrase.write_bytes(PASSPHRASE)
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        trusted_operator_keys=[spec],
    )
    target = _hash("candidate-runtime")

    exit_code = main(
        [
            "--workdir",
            str(state),
            "authority-profile-rotate",
            target,
            "--operator",
            "alice",
            "--note",
            "production rollout",
            "--trusted-operator-key",
            spec,
            "--operator-key",
            str(private),
            "--operator-passphrase-file",
            str(passphrase),
        ]
    )

    assert exit_code == 0
    assert "staged for generation 2" in capsys.readouterr().out
    pending = AuthorityProfileStore(state / "authority_profile.json").get()
    assert pending is not None
    assert pending.pending_rotation["to_profile_hash"] == target
    assert pending.pending_rotation["attestation"] is not None


def test_invalid_profile_state_and_lock_are_critical_read_only_findings(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "authority_profile.json").write_text("{}", encoding="utf-8")
    report = StateIntegrityAuditor(state).audit()
    assert not report.safe_to_execute
    assert any(issue.code == "authority_profile_invalid" for issue in report.issues)

    (state / "authority_profile.json.lock").write_text(
        "pid=unknown\n", encoding="utf-8"
    )
    locked = StateIntegrityAuditor(state).audit()
    assert any(
        issue.code == "state_lock_present" and issue.store == "authority_profile.json"
        for issue in locked.issues
    )


def test_operator_control_profile_verification_cannot_execute_or_authorize(tmp_path):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    operator_control = build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        _operator_control=True,
    )

    with pytest.raises(RuntimeError, match="cannot execute or authorize"):
        operator_control.run(
            HarnessRequest(task="send_email", user_id="alice", workspace_id="ws")
        )
