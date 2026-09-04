from __future__ import annotations

import json
import re
import threading

import pytest

import defiant_agent_harness.authority_publication_witness as witness_module
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.authority_profile import (
    AuthorityProfileError,
    AuthorityProfileStore,
)
from defiant_agent_harness.authority_publication import AuthorityPublicationStore
from defiant_agent_harness.authority_publication_witness import (
    AuthorityPublicationWitnessError,
    AuthorityPublicationWitnessPolicy,
    AuthorityPublicationWitnessPolicyState,
    AuthorityPublicationWitnessPolicyStore,
    WITNESS_MODE,
    assess_witness,
    build_witness_payload,
    create_current_witness,
    load_witness,
    sign_witness,
    validate_external_witness_paths,
    write_witness,
)
from defiant_agent_harness.evidence.signing import generate_key_pair
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.persistence import (
    AuthorityLockError,
    AuthorityTransactionLock,
    PersistenceError,
)
from defiant_agent_harness.state_integrity import StateIntegrityAuditor
from defiant_agent_harness.state_storage import StateStorageStateStore

PASSPHRASE = b"v0.80-publication-witness"


def _keys(tmp_path, name="publication"):
    private_key = tmp_path / f"{name}-private.pem"
    public_key = tmp_path / f"{name}-public.pem"
    generate_key_pair(private_key, public_key, PASSPHRASE)
    return private_key, public_key


def _context(state, public_key):
    profile = AuthorityProfileStore(state / "authority_profile.json").get()
    storage = StateStorageStateStore(state / "state_storage.json").get()
    publication_store = AuthorityPublicationStore(state / "authority_publication.json")
    publication = publication_store.get()
    continuity = publication_store.get_continuity()
    assert profile is not None
    assert storage is not None
    assert publication is not None
    assert continuity is not None
    return {
        "policy": AuthorityPublicationWitnessPolicy.from_paths([public_key]),
        "deployment_root_hash": storage.root_hash,
        "profile": profile,
        "publication": publication,
        "continuity": continuity,
    }


def _signed(state, private_key):
    return sign_witness(
        build_witness_payload(state),
        private_key,
        PASSPHRASE,
        signer="release-operator",
        note="retain publication head off box",
    )


def test_signed_publication_witness_verifies_exact_head_and_round_trips(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    private_key, public_key = _keys(tmp_path)
    document = _signed(state, private_key)
    destination = tmp_path / "publication-witness.json"
    write_witness(destination, document)

    assessment = assess_witness(
        load_witness(destination), **_context(state, public_key)
    )

    assert assessment.ok is True
    assert assessment.verification == "verified"
    assert assessment.unwitnessed_publication_count == 0
    assert assessment.signer == "release-operator"
    assert assessment.checkpoint_hash not in json.dumps(
        AuthorityPublicationWitnessPolicyState.from_dict(
            {
                "schema_name": "defiant.authority.publication_witness_policy",
                "schema_version": "0.1.0",
                "profile_hash": assessment.authority_profile_hash,
                "mode": WITNESS_MODE,
                "trusted_key_ids": [
                    _context(state, public_key)["policy"].trusted_key_ids[0]
                ],
                "recorded_at": document["observed_at"],
            }
        ).projection(verification=assessment.verification, assessment=assessment)
    )
    with pytest.raises(AuthorityPublicationWitnessError, match="overwrite"):
        write_witness(destination, document)


def test_witness_publication_syncs_directory_before_and_after_temp_cleanup(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    private_key, _ = _keys(tmp_path)
    destination = tmp_path / "durable-publication-witness.json"
    syncs = []

    def record_sync(path):
        syncs.append(path)

    monkeypatch.setattr(witness_module, "sync_storage_directory", record_sync)
    write_witness(destination, _signed(state, private_key))

    assert syncs == [destination.parent, destination.parent]
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))


def test_witness_publication_fails_if_directory_durability_is_uncertain(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    private_key, _ = _keys(tmp_path)
    destination = tmp_path / "uncertain-publication-witness.json"

    def refuse_sync(_path):
        raise PersistenceError("simulated directory sync failure")

    monkeypatch.setattr(witness_module, "sync_storage_directory", refuse_sync)
    with pytest.raises(
        AuthorityPublicationWitnessError,
        match="durable publication could not be confirmed",
    ):
        write_witness(destination, _signed(state, private_key))

    assert destination.exists()
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))


def test_witness_publication_fails_on_post_link_byte_substitution(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    private_key, _ = _keys(tmp_path)
    destination = tmp_path / "substituted-publication-witness.json"
    original_write = witness_module._write_new

    def substitute_after_write(path, content):
        original_write(path, content)
        path.write_bytes(b"{}\n")

    monkeypatch.setattr(witness_module, "_write_new", substitute_after_write)
    with pytest.raises(
        AuthorityPublicationWitnessError,
        match="bytes do not match the signed document",
    ):
        create_current_witness(
            state,
            private_key,
            PASSPHRASE,
            signer="release-operator",
            note="detect publication substitution",
            output_path=destination,
        )

    assert destination.read_bytes() == b"{}\n"


def test_witness_publication_fails_if_published_temp_cannot_be_removed(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    private_key, _ = _keys(tmp_path)
    destination = tmp_path / "cleanup-publication-witness.json"
    original_unlink = witness_module.Path.unlink

    def refuse_temp_cleanup(path, *args, **kwargs):
        if path.name.startswith(f".{destination.name}.") and path.name.endswith(".tmp"):
            raise PermissionError("simulated cleanup refusal")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(witness_module.Path, "unlink", refuse_temp_cleanup)
    with pytest.raises(
        AuthorityPublicationWitnessError,
        match="cannot remove published publication-witness temporary file",
    ):
        write_witness(destination, _signed(state, private_key))

    assert destination.exists()
    assert len(list(tmp_path.glob(f".{destination.name}.*.tmp"))) == 1


def test_witness_accepts_only_one_provable_forward_step(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    private_key, public_key = _keys(tmp_path)
    document = _signed(state, private_key)

    build_harness(state, MockAgentAdapter())
    one_step = assess_witness(document, **_context(state, public_key))
    assert one_step.ok is True
    assert one_step.verification == "forward"
    assert one_step.unwitnessed_publication_count == 1

    build_harness(state, MockAgentAdapter())
    stale = assess_witness(document, **_context(state, public_key))
    assert stale.ok is False
    assert stale.verification == "invalid"
    assert "compact continuity window" in stale.detail


def test_witness_detects_matched_local_rollback(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    store = AuthorityPublicationStore(state / "authority_publication.json")
    old_publication = store.path.read_bytes()
    old_continuity = store.continuity_store.path.read_bytes()
    build_harness(state, MockAgentAdapter())
    private_key, public_key = _keys(tmp_path)
    document = _signed(state, private_key)

    store.path.write_bytes(old_publication)
    store.continuity_store.path.write_bytes(old_continuity)
    assessment = assess_witness(document, **_context(state, public_key))

    assert assessment.ok is False
    assert assessment.verification == "invalid"
    assert "behind the external witness" in assessment.detail


def test_witness_rejects_tampering_wrong_root_and_untrusted_key(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    private_key, public_key = _keys(tmp_path)
    document = _signed(state, private_key)

    tampered = json.loads(json.dumps(document))
    tampered["continuity_sequence"] += 1
    assert assess_witness(tampered, **_context(state, public_key)).ok is False

    context = _context(state, public_key)
    context["deployment_root_hash"] = "sha256:" + "9" * 64
    assert assess_witness(document, **context).ok is False

    _, other_public = _keys(tmp_path, "other")
    context = _context(state, other_public)
    assert assess_witness(document, **context).ok is False


def test_policy_is_strict_bounded_and_immutable_within_profile(tmp_path):
    _, public_key = _keys(tmp_path)
    policy = AuthorityPublicationWitnessPolicy.from_paths([public_key])
    store = AuthorityPublicationWitnessPolicyStore(
        tmp_path / "state" / "authority_publication_witness_policy.json"
    )
    profile_hash = "sha256:" + "a" * 64
    recorded = store.record(profile_hash, policy)

    assert store.get() == recorded
    assert recorded.mode == WITNESS_MODE
    assert recorded.trusted_key_ids == policy.trusted_key_ids
    raw = recorded.to_dict()
    raw["unexpected"] = True
    with pytest.raises(AuthorityPublicationWitnessError, match="fields"):
        AuthorityPublicationWitnessPolicyState.from_dict(raw)
    with pytest.raises(AuthorityPublicationWitnessError, match="changed"):
        store.record(
            profile_hash,
            AuthorityPublicationWitnessPolicy(
                trusted_key_ids=("sha256:" + "b" * 64,),
                trusted_key_paths=(),
            ),
        )


def test_witness_material_must_be_outside_state(tmp_path):
    state = tmp_path / "state"
    witness = state / "witness.json"
    key = tmp_path / "public.pem"
    with pytest.raises(AuthorityPublicationWitnessError, match="outside"):
        validate_external_witness_paths(state, witness, [key])
    with pytest.raises(AuthorityPublicationWitnessError, match="outside"):
        validate_external_witness_paths(
            state, tmp_path / "witness.json", [state / "key"]
        )


def _enroll_required_witness(tmp_path):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    private_key, public_key = _keys(tmp_path)
    witness_path = tmp_path / "publication-witness.json"
    write_witness(witness_path, _signed(state, private_key))
    with pytest.raises(AuthorityProfileError, match="does not match") as mismatch:
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            authority_publication_witness=witness_path,
            trusted_authority_publication_witness_keys=[str(public_key)],
        )
    candidate = re.search(r"configured (sha256:[0-9a-f]{64})", str(mismatch.value))
    assert candidate is not None
    AuthorityProfileStore(state / "authority_profile.json").request_rotation(
        candidate.group(1),
        operator="release-operator",
        note="require external publication rollback witnessing",
        operator_trust=None,
    )
    harness = build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        authority_publication_witness=witness_path,
        trusted_authority_publication_witness_keys=[str(public_key)],
    )
    return state, workspace, harness, private_key, public_key, witness_path


def test_required_witness_is_authority_bound_visible_and_requires_refresh(tmp_path):
    state, workspace, harness, private_key, public_key, witness_path = (
        _enroll_required_witness(tmp_path)
    )
    policy = AuthorityPublicationWitnessPolicyStore(
        state / "authority_publication_witness_policy.json"
    ).get()
    assert policy is not None
    assert policy.mode == WITNESS_MODE

    report = harness.state_integrity.audit()
    snapshot = CommandCore(
        state,
        workspace_root=workspace,
        authority_publication_witness=witness_path,
        trusted_authority_publication_witness_keys=[str(public_key)],
    ).snapshot()
    projection = snapshot["authority_publication_witness"]
    assert report.safe_to_execute is True
    assert report.status == "recovery_required"
    assert projection["verification"] == "forward"
    assert projection["unwitnessed_publication_count"] == 1
    assert projection["signer"] == "release-operator"
    assert snapshot["authoritative"] is True
    assert build_witness_payload(state)["checkpoint_hash"] not in json.dumps(snapshot)

    with pytest.raises(AuthorityPublicationWitnessError, match="must be refreshed"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            authority_publication_witness=witness_path,
            trusted_authority_publication_witness_keys=[str(public_key)],
        )
    with pytest.raises(AuthorityPublicationWitnessError, match="requires"):
        build_harness(state, MockAgentAdapter(), workspace_root=workspace)

    refreshed = tmp_path / "publication-witness-refreshed.json"
    write_witness(refreshed, _signed(state, private_key))
    build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        authority_publication_witness=refreshed,
        trusted_authority_publication_witness_keys=[str(public_key)],
    )


def test_required_witness_blocks_matched_publication_and_anchor_rollback(tmp_path):
    state, workspace, _, private_key, public_key, _ = _enroll_required_witness(tmp_path)
    store = AuthorityPublicationStore(state / "authority_publication.json")
    old_publication = store.path.read_bytes()
    old_continuity = store.continuity_store.path.read_bytes()
    current = tmp_path / "current-witness.json"
    write_witness(current, _signed(state, private_key))
    build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        authority_publication_witness=current,
        trusted_authority_publication_witness_keys=[str(public_key)],
    )
    newer = tmp_path / "newer-witness.json"
    write_witness(newer, _signed(state, private_key))

    store.path.write_bytes(old_publication)
    store.continuity_store.path.write_bytes(old_continuity)
    report = StateIntegrityAuditor(
        state,
        workspace_root=workspace,
        authority_publication_witness=newer,
        trusted_authority_publication_witness_keys=[str(public_key)],
    ).audit()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["publication_continuity"] == (
        "verified"
    )
    assert report.stores["authority_publication_witness"]["verification"] == ("invalid")
    assert any(issue.code == "publication_witness_invalid" for issue in report.issues)


def test_valid_policy_downgrade_is_detected_by_publication_manifest(tmp_path, capsys):
    state, workspace, _, private_key, _, _ = _enroll_required_witness(tmp_path)
    policy_path = state / "authority_publication_witness_policy.json"
    substituted = json.loads(policy_path.read_text(encoding="utf-8"))
    substituted["mode"] = "not_configured"
    substituted["trusted_key_ids"] = []
    policy_path.write_text(json.dumps(substituted), encoding="utf-8")

    with pytest.raises(AuthorityPublicationWitnessError, match="manifest"):
        build_witness_payload(state)

    passphrase_file = tmp_path / "issuance-passphrase.txt"
    passphrase_file.write_bytes(PASSPHRASE)
    refused_output = tmp_path / "must-not-be-created.json"
    assert (
        main(
            [
                "--workdir",
                str(state),
                "witness-authority-publication",
                "--signing-key",
                str(private_key),
                "--passphrase-file",
                str(passphrase_file),
                "--signer",
                "release-operator",
                "--note",
                "must refuse substituted policy",
                "--output",
                str(refused_output),
            ]
        )
        == 1
    )
    assert "manifest" in capsys.readouterr().err
    assert not refused_output.exists()

    report = StateIntegrityAuditor(state, workspace_root=workspace).audit()

    assert report.safe_to_execute is False
    assert report.stores["authority_publication"]["verification"] == (
        "manifest_mismatch"
    )
    assert any(
        issue.code == "authority_publication_manifest_mismatch"
        for issue in report.issues
    )


def test_current_witness_issuance_is_serialized_with_authority(tmp_path):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    private_key, public_key = _keys(tmp_path)
    destination = tmp_path / "serialized-publication-witness.json"
    acquired = threading.Event()
    release = threading.Event()

    def hold_authority():
        with AuthorityTransactionLock(state / "authority.lock").acquire():
            acquired.set()
            assert release.wait(timeout=10)

    holder = threading.Thread(target=hold_authority)
    holder.start()
    assert acquired.wait(timeout=10)
    try:
        with pytest.raises(AuthorityLockError, match="authority transaction is busy"):
            create_current_witness(
                state,
                private_key,
                PASSPHRASE,
                signer="release-operator",
                note="serialize witness issuance",
                output_path=destination,
            )
        assert not destination.exists()
    finally:
        release.set()
        holder.join(timeout=10)

    document = create_current_witness(
        state,
        private_key,
        PASSPHRASE,
        signer="release-operator",
        note="serialize witness issuance",
        output_path=destination,
    )
    assert assess_witness(document, **_context(state, public_key)).ok is True


def test_cli_witness_and_verify_round_trip(tmp_path, capsys):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    private_key, public_key = _keys(tmp_path)
    passphrase_file = tmp_path / "passphrase.txt"
    passphrase_file.write_bytes(PASSPHRASE)
    witness_path = tmp_path / "cli-publication-witness.json"

    result = main(
        [
            "--workdir",
            str(state),
            "witness-authority-publication",
            "--signing-key",
            str(private_key),
            "--passphrase-file",
            str(passphrase_file),
            "--signer",
            "release-operator",
            "--note",
            "publish v0.80 checkpoint",
            "--output",
            str(witness_path),
        ]
    )
    assert result == 0
    assert "wrote authority-publication witness" in capsys.readouterr().out

    result = main(
        [
            "--workdir",
            str(state),
            "verify-authority-publication-witness",
            str(witness_path),
            "--trusted-key",
            str(public_key),
        ]
    )
    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert output["ok"] is True
    assert output["verification"] == "verified"
