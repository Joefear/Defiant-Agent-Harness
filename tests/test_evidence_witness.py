from __future__ import annotations

import json
import re
import threading

import pytest

import defiant_agent_harness.evidence_witness as witness_module
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.authority_profile import (
    AuthorityProfileError,
    AuthorityProfileStore,
)
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import Decision, EvidenceRecord, ResultStatus
from defiant_agent_harness.evidence.signing import generate_key_pair
from defiant_agent_harness.evidence_witness import (
    EvidenceWitnessError,
    EvidenceWitnessPolicy,
    EvidenceWitnessPolicyState,
    EvidenceWitnessPolicyStore,
    WITNESS_MODE,
    assess_witness,
    build_witness_payload,
    create_current_witness,
    load_witness,
    sign_witness,
    write_witness,
)
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.persistence import (
    AuthorityLockError,
    AuthorityTransactionLock,
    PersistenceError,
    atomic_write_json,
    read_json,
)
from defiant_agent_harness.state_integrity import StateIntegrityAuditor
from defiant_agent_harness.state_storage import StateStorageStateStore

PASSPHRASE = b"v0.22-test-passphrase"


def _record(index: int) -> EvidenceRecord:
    return EvidenceRecord(
        request_id=f"req_witness_{index}",
        action_id=f"act_witness_{index}",
        decision=Decision.BLOCK,
        result_status=ResultStatus.BLOCKED,
        tool_name="read_file",
        target=f"workspace/{index}.txt",
    )


def _keys(tmp_path, name: str = "witness"):
    private_key = tmp_path / f"{name}-private.pem"
    public_key = tmp_path / f"{name}-public.pem"
    generate_key_pair(private_key, public_key, PASSPHRASE)
    return private_key, public_key


def _write_signed_witness(state, private_key, destination, *, note="release head"):
    document = sign_witness(
        build_witness_payload(state),
        private_key,
        PASSPHRASE,
        signer="release-operator",
        note=note,
    )
    write_witness(destination, document)
    return document


def _enroll_required_witness(
    tmp_path,
    *,
    records=1,
    max_unwitnessed_records=None,
):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    harness = build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    for index in range(records):
        harness.evidence.append(_record(index + 1))
    private_key, public_key = _keys(tmp_path)
    witness_path = tmp_path / "head-witness.json"
    _write_signed_witness(state, private_key, witness_path)

    with pytest.raises(AuthorityProfileError, match="does not match") as mismatch:
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            evidence_head_witness=witness_path,
            trusted_evidence_witness_keys=[str(public_key)],
            max_unwitnessed_records=max_unwitnessed_records,
        )
    candidate = re.search(r"configured (sha256:[0-9a-f]{64})", str(mismatch.value))
    assert candidate is not None
    AuthorityProfileStore(state / "authority_profile.json").request_rotation(
        candidate.group(1),
        operator="release-operator",
        note="enable signed external evidence witnessing",
        operator_trust=None,
    )
    harness = build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        evidence_head_witness=witness_path,
        trusted_evidence_witness_keys=[str(public_key)],
        max_unwitnessed_records=max_unwitnessed_records,
    )
    return state, workspace, harness, private_key, public_key, witness_path


def _current_issuance_state(tmp_path):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    harness = build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    harness.evidence.append(_record(1))
    private_key, public_key = _keys(tmp_path)
    return state, harness, private_key, public_key


def test_current_evidence_witness_issuance_is_serialized_with_authority(tmp_path):
    state, harness, private_key, public_key = _current_issuance_state(tmp_path)
    destination = tmp_path / "serialized-evidence-witness.json"
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
                note="serialize evidence witness issuance",
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
        note="serialize evidence witness issuance",
        output_path=destination,
    )
    profile = AuthorityProfileStore(state / "authority_profile.json").get()
    storage = StateStorageStateStore(state / "state_storage.json").get()
    assert profile is not None and storage is not None
    assessment = assess_witness(
        document,
        EvidenceWitnessPolicy.from_paths([public_key]),
        deployment_root_hash=storage.root_hash,
        profile=profile,
        records=harness.evidence.records(),
    )
    assert assessment.ok is True
    assert not holder.is_alive()


def test_current_evidence_witness_missing_store_fails_without_recreation(tmp_path):
    state, _harness, private_key, _public_key = _current_issuance_state(tmp_path)
    evidence_path = state / "evidence.jsonl"
    evidence_path.unlink()
    destination = tmp_path / "must-not-exist.json"

    with pytest.raises(EvidenceWitnessError, match="evidence store must be enrolled"):
        create_current_witness(
            state,
            private_key,
            PASSPHRASE,
            signer="release-operator",
            note="do not recreate missing evidence",
            output_path=destination,
        )

    assert not evidence_path.exists()
    assert not destination.exists()


def test_evidence_witness_publication_syncs_and_verifies_exact_bytes(
    tmp_path, monkeypatch
):
    state, _harness, private_key, _public_key = _current_issuance_state(tmp_path)
    destination = tmp_path / "durable-evidence-witness.json"
    syncs = []

    def record_sync(path):
        syncs.append(path)

    monkeypatch.setattr(witness_module, "sync_storage_directory", record_sync)
    create_current_witness(
        state,
        private_key,
        PASSPHRASE,
        signer="release-operator",
        note="durably publish evidence witness",
        output_path=destination,
    )

    assert syncs == [destination.parent, destination.parent]
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))


def test_evidence_witness_publication_fails_on_directory_sync_uncertainty(
    tmp_path, monkeypatch
):
    state, _harness, private_key, _public_key = _current_issuance_state(tmp_path)
    destination = tmp_path / "uncertain-evidence-witness.json"

    def refuse_sync(_path):
        raise PersistenceError("simulated directory sync failure")

    monkeypatch.setattr(witness_module, "sync_storage_directory", refuse_sync)
    with pytest.raises(
        EvidenceWitnessError, match="durable publication could not be confirmed"
    ):
        create_current_witness(
            state,
            private_key,
            PASSPHRASE,
            signer="release-operator",
            note="detect durability uncertainty",
            output_path=destination,
        )

    assert destination.exists()
    assert not list(tmp_path.glob(f".{destination.name}.*.tmp"))


def test_evidence_witness_publication_fails_on_post_link_substitution(
    tmp_path, monkeypatch
):
    state, _harness, private_key, _public_key = _current_issuance_state(tmp_path)
    destination = tmp_path / "substituted-evidence-witness.json"
    original_write = witness_module._write_new

    def substitute_after_write(path, content, mode):
        original_write(path, content, mode)
        path.write_bytes(b"{}\n")

    monkeypatch.setattr(witness_module, "_write_new", substitute_after_write)
    with pytest.raises(
        EvidenceWitnessError, match="bytes do not match the signed document"
    ):
        create_current_witness(
            state,
            private_key,
            PASSPHRASE,
            signer="release-operator",
            note="detect evidence witness substitution",
            output_path=destination,
        )

    assert destination.read_bytes() == b"{}\n"


def test_evidence_witness_publication_fails_if_published_temp_cannot_be_removed(
    tmp_path, monkeypatch
):
    state, _harness, private_key, _public_key = _current_issuance_state(tmp_path)
    destination = tmp_path / "cleanup-evidence-witness.json"
    original_unlink = witness_module.Path.unlink

    def refuse_temp_cleanup(path, *args, **kwargs):
        if path.name.startswith(f".{destination.name}.") and path.name.endswith(".tmp"):
            raise PermissionError("simulated cleanup refusal")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(witness_module.Path, "unlink", refuse_temp_cleanup)
    with pytest.raises(
        EvidenceWitnessError,
        match="cannot remove published evidence-witness temporary file",
    ):
        create_current_witness(
            state,
            private_key,
            PASSPHRASE,
            signer="release-operator",
            note="detect temporary cleanup failure",
            output_path=destination,
        )

    assert destination.exists()
    assert len(list(tmp_path.glob(f".{destination.name}.*.tmp"))) == 1


class HostileText(str):
    def __str__(self):
        raise AssertionError("caller string rendering hook invoked")

    def __len__(self):
        raise AssertionError("caller string length hook invoked")

    def __eq__(self, other):
        raise AssertionError("caller string comparison hook invoked")

    def __lt__(self, other):
        raise AssertionError("caller string ordering hook invoked")

    def __hash__(self):
        raise AssertionError("caller string hash hook invoked")

    def startswith(self, *args, **kwargs):
        raise AssertionError("caller string prefix hook invoked")

    def replace(self, *args, **kwargs):
        raise AssertionError("caller string replacement hook invoked")

    def __deepcopy__(self, memo):
        raise AssertionError("caller string copy hook invoked")


class HostileList(list):
    def __iter__(self):
        raise AssertionError("caller list iterator hook invoked")

    def __len__(self):
        raise AssertionError("caller list length hook invoked")

    def __getitem__(self, key):
        raise AssertionError("caller list item hook invoked")

    def __deepcopy__(self, memo):
        raise AssertionError("caller list copy hook invoked")


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


def _hostile_policy_document(raw):
    return HostileDict(
        {
            key: (
                HostileList([HostileText(item) for item in value])
                if type(value) is list
                else HostileText(value)
                if type(value) is str
                else value
            )
            for key, value in raw.items()
        }
    )


def test_witness_policy_reader_captures_one_hostile_state_snapshot(
    tmp_path, monkeypatch
):
    path = tmp_path / "state" / "evidence_witness_policy.json"
    policy = EvidenceWitnessPolicy(
        trusted_key_ids=("sha256:" + "1" * 64,),
        trusted_key_paths=(),
        max_unwitnessed_records=3,
    )
    store = EvidenceWitnessPolicyStore(path)
    store.record("sha256:" + "a" * 64, policy)
    raw = read_json(path)
    supplied = _hostile_policy_document(raw)
    observed_limits = []

    def hostile_read(source, *, max_bytes=None):
        assert source == path
        observed_limits.append(max_bytes)
        return supplied

    monkeypatch.setattr(witness_module, "read_json", hostile_read)

    restored = store.get()

    assert restored is not None
    assert restored.to_dict() == raw
    assert type(restored.profile_hash) is str
    assert type(restored.trusted_key_ids) is tuple
    assert type(restored.trusted_key_ids[0]) is str
    assert observed_limits == [witness_module._MAX_POLICY_STATE_BYTES]
    supplied_ids = dict.__getitem__(supplied, "trusted_key_ids")
    list.__setitem__(supplied_ids, 0, "sha256:" + "f" * 64)
    assert restored.to_dict() == raw


def test_witness_policy_public_inputs_are_detached_before_comparison_and_write(
    tmp_path,
):
    path = tmp_path / "state" / "evidence_witness_policy.json"
    key_ids = HostileList([HostileText("sha256:" + "1" * 64)])
    policy = EvidenceWitnessPolicy(
        trusted_key_ids=key_ids,
        trusted_key_paths=(),
        max_unwitnessed_records=2,
    )

    stored = EvidenceWitnessPolicyStore(path).record(
        HostileText("sha256:" + "a" * 64),
        policy,
    )

    list.__setitem__(key_ids, 0, "sha256:" + "f" * 64)
    assert stored.profile_hash == "sha256:" + "a" * 64
    assert stored.trusted_key_ids == ("sha256:" + "1" * 64,)
    assert EvidenceWitnessPolicyStore(path).get() == stored


def test_witness_policy_rejects_noncanonical_input_without_secret_echo():
    class SecretValue:
        def __str__(self):
            raise AssertionError("secret rendered")

        def __repr__(self):
            raise AssertionError("secret represented")

        def __deepcopy__(self, memo):
            raise AssertionError("secret copied")

    with pytest.raises(
        EvidenceWitnessError, match="exceeds bounded canonical state"
    ) as failure:
        EvidenceWitnessPolicyState.from_dict(HostileDict({"secret": SecretValue()}))

    assert "SecretValue" not in str(failure.value)


def test_witness_policy_store_uses_one_explicit_read_write_ceiling(
    tmp_path, monkeypatch
):
    read_limits = []
    write_limits = []
    original_read = witness_module.read_json
    original_write = witness_module.atomic_write_json

    def observed_read(path, *, max_bytes=None):
        read_limits.append(max_bytes)
        return original_read(path, max_bytes=max_bytes)

    def observed_write(path, data, *, max_bytes=None):
        write_limits.append(max_bytes)
        return original_write(path, data, max_bytes=max_bytes)

    monkeypatch.setattr(witness_module, "read_json", observed_read)
    monkeypatch.setattr(witness_module, "atomic_write_json", observed_write)
    store = EvidenceWitnessPolicyStore(
        tmp_path / "state" / "evidence_witness_policy.json"
    )
    store.record("sha256:" + "a" * 64, None)
    assert store.get() is not None

    assert read_limits
    assert write_limits
    assert set(read_limits) == {witness_module._MAX_POLICY_STATE_BYTES}
    assert set(write_limits) == {witness_module._MAX_POLICY_STATE_BYTES}


def test_witness_policy_refuses_unrecoverable_publication_without_replacement(
    tmp_path, monkeypatch
):
    path = tmp_path / "state" / "evidence_witness_policy.json"
    store = EvidenceWitnessPolicyStore(path)
    current = store.record("sha256:" + "a" * 64, None)
    prior = path.read_bytes()
    original_limit = witness_module._MAX_POLICY_STATE_BYTES
    monkeypatch.setattr(witness_module, "_MAX_POLICY_STATE_BYTES", 1)

    with pytest.raises(EvidenceWitnessError, match="bounded canonical state"):
        store._write(current)

    assert path.read_bytes() == prior
    monkeypatch.setattr(
        witness_module,
        "_MAX_POLICY_STATE_BYTES",
        original_limit,
    )
    assert store.get() == current


def test_required_witness_is_profile_bound_and_visible_read_only(tmp_path):
    state, workspace, _harness, _private, public, witness = _enroll_required_witness(
        tmp_path
    )

    stored = EvidenceWitnessPolicyStore(state / "evidence_witness_policy.json").get()
    assert stored is not None
    assert stored.mode == WITNESS_MODE
    assert len(stored.trusted_key_ids) == 1

    snapshot = CommandCore(
        state,
        workspace_root=workspace,
        evidence_head_witness=witness,
        trusted_evidence_witness_keys=[str(public)],
    ).snapshot()
    projection = snapshot["evidence_witness"]
    serialized = json.dumps(projection)
    assert snapshot["authoritative"] is True
    assert projection["verification"] == "verified"
    assert projection["witnessed_record_count"] == 1
    assert projection["signer"] == "release-operator"
    assert "release head" not in serialized
    assert str(witness) not in serialized
    assert str(public) not in serialized


def test_live_chain_may_validly_extend_a_trusted_witness(tmp_path):
    state, workspace, harness, _private, public, witness = _enroll_required_witness(
        tmp_path
    )
    harness.evidence.append(_record(2))

    report = StateIntegrityAuditor(
        state,
        workspace_root=workspace,
        evidence_head_witness=witness,
        trusted_evidence_witness_keys=[str(public)],
    ).audit()

    assert report.safe_to_execute is True
    assert report.stores["evidence_witness"]["verification"] == "forward"
    reopened = build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        evidence_head_witness=witness,
        trusted_evidence_witness_keys=[str(public)],
    )
    assert len(reopened.evidence.records()) == 2


def test_profile_bound_witness_lag_blocks_authority_until_witness_refresh(tmp_path):
    state, workspace, harness, private, public, witness = _enroll_required_witness(
        tmp_path,
        max_unwitnessed_records=1,
    )
    harness.evidence.append(_record(2))

    at_limit = StateIntegrityAuditor(
        state,
        workspace_root=workspace,
        evidence_head_witness=witness,
        trusted_evidence_witness_keys=[str(public)],
    ).audit()
    projection = at_limit.stores["evidence_witness"]
    assert at_limit.safe_to_execute is True
    assert projection["verification"] == "forward"
    assert projection["max_unwitnessed_records"] == 1
    assert projection["unwitnessed_record_count"] == 1

    harness.evidence.append(_record(3))
    exceeded = StateIntegrityAuditor(
        state,
        workspace_root=workspace,
        evidence_head_witness=witness,
        trusted_evidence_witness_keys=[str(public)],
    ).audit()
    projection = exceeded.stores["evidence_witness"]
    assert exceeded.safe_to_execute is False
    assert projection["verification"] == "lag_exceeded"
    assert projection["unwitnessed_record_count"] == 2
    assert any(
        issue.code == "evidence_witness_lag_exceeded" for issue in exceeded.issues
    )
    with pytest.raises(EvidenceWitnessError, match="too far behind"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            evidence_head_witness=witness,
            trusted_evidence_witness_keys=[str(public)],
            max_unwitnessed_records=1,
        )

    refreshed = tmp_path / "refreshed-head-witness.json"
    _write_signed_witness(state, private, refreshed, note="refresh stale witness")
    reopened = build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        evidence_head_witness=refreshed,
        trusted_evidence_witness_keys=[str(public)],
        max_unwitnessed_records=1,
    )
    assert len(reopened.evidence.records()) == 3


def test_zero_lag_and_operator_control_cannot_weaken_enrolled_bound(tmp_path):
    state, workspace, harness, _private, public, witness = _enroll_required_witness(
        tmp_path,
        max_unwitnessed_records=0,
    )
    stored = EvidenceWitnessPolicyStore(state / "evidence_witness_policy.json").get()
    assert stored is not None
    assert stored.max_unwitnessed_records == 0

    with pytest.raises(EvidenceWitnessError, match="does not match the enrolled"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            evidence_head_witness=witness,
            trusted_evidence_witness_keys=[str(public)],
            _operator_control=True,
        )
    build_harness(
        state,
        MockAgentAdapter(),
        workspace_root=workspace,
        evidence_head_witness=witness,
        trusted_evidence_witness_keys=[str(public)],
        max_unwitnessed_records=0,
        _operator_control=True,
    )

    harness.evidence.append(_record(2))
    with pytest.raises(EvidenceWitnessError, match="too far behind"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            evidence_head_witness=witness,
            trusted_evidence_witness_keys=[str(public)],
            max_unwitnessed_records=0,
        )


@pytest.mark.parametrize("value", [True, -1, 1.5, "1"])
def test_witness_lag_policy_rejects_non_integer_or_negative_values(tmp_path, value):
    _private, public = _keys(tmp_path)
    with pytest.raises(EvidenceWitnessError, match="non-negative integer"):
        EvidenceWitnessPolicy.from_paths(
            [public],
            max_unwitnessed_records=value,
        )


def test_witness_policy_rejects_excess_keys_before_filesystem_access(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(witness_module, "MAX_TRUSTED_PUBLIC_KEYS", 1)

    with pytest.raises(EvidenceWitnessError, match="fixed limit of 1"):
        EvidenceWitnessPolicy.from_paths(
            [tmp_path / "missing-one.pem", tmp_path / "missing-two.pem"]
        )


def test_witness_policy_rejects_aggregate_key_bytes(tmp_path, monkeypatch):
    _first_private, first_public = _keys(tmp_path, "first")
    _second_private, second_public = _keys(tmp_path, "second")
    maximum = first_public.stat().st_size + second_public.stat().st_size - 1
    monkeypatch.setattr(
        witness_module,
        "MAX_TRUSTED_PUBLIC_KEY_SET_BYTES",
        maximum,
    )

    with pytest.raises(EvidenceWitnessError, match=f"{maximum}-byte ceiling"):
        EvidenceWitnessPolicy.from_paths([first_public, second_public])


def test_durable_witness_policy_rejects_excess_key_ids(monkeypatch):
    monkeypatch.setattr(witness_module, "MAX_TRUSTED_PUBLIC_KEYS", 1)
    raw = {
        "schema_name": "defiant.evidence.head_witness_policy",
        "schema_version": "0.2.0",
        "profile_hash": "sha256:" + "a" * 64,
        "mode": "signed_external_required",
        "trusted_key_ids": ["sha256:" + "1" * 64, "sha256:" + "2" * 64],
        "max_unwitnessed_records": None,
        "recorded_at": "2026-08-25T12:00:00Z",
    }

    with pytest.raises(EvidenceWitnessError, match="fixed limit of 1"):
        EvidenceWitnessPolicyState.from_dict(raw)


def test_v1_witness_policy_state_remains_readable_and_unbounded(tmp_path):
    state, _workspace, _harness, _private, _public, _witness = _enroll_required_witness(
        tmp_path
    )
    policy_path = state / "evidence_witness_policy.json"
    raw = read_json(policy_path)
    raw["schema_version"] = "0.1.0"
    raw.pop("max_unwitnessed_records")
    atomic_write_json(policy_path, raw)

    stored = EvidenceWitnessPolicyStore(policy_path).get()
    assert stored is not None
    assert stored.max_unwitnessed_records is None
    assert (
        "max_unwitnessed_records"
        not in EvidenceWitnessPolicy.from_paths([_public]).authority_dict()
    )


def test_external_witness_detects_matched_evidence_and_checkpoint_rollback(tmp_path):
    state, workspace, harness, private, public, _initial = _enroll_required_witness(
        tmp_path
    )
    harness.evidence.append(_record(2))
    old_evidence = (state / "evidence.jsonl").read_bytes()
    old_head = read_json(state / "evidence_head.json")
    harness.evidence.append(_record(3))
    latest = tmp_path / "latest-head-witness.json"
    _write_signed_witness(state, private, latest, note="latest retained head")

    (state / "evidence.jsonl").write_bytes(old_evidence)
    atomic_write_json(state / "evidence_head.json", old_head)

    local_only = StateIntegrityAuditor(state).audit()
    assert local_only.stores["evidence_head"]["verification"] == "verified"
    assert local_only.safe_to_execute is False
    assert any(
        issue.code == "external_evidence_witness_required"
        for issue in local_only.issues
    )

    witnessed = StateIntegrityAuditor(
        state,
        workspace_root=workspace,
        evidence_head_witness=latest,
        trusted_evidence_witness_keys=[str(public)],
    ).audit()
    assert witnessed.safe_to_execute is False
    assert any(issue.code == "evidence_witness_invalid" for issue in witnessed.issues)
    with pytest.raises(EvidenceWitnessError, match="behind the external witness"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            evidence_head_witness=latest,
            trusted_evidence_witness_keys=[str(public)],
        )


def test_required_witness_cannot_be_omitted_from_authority_or_operator_control(
    tmp_path,
):
    state, workspace, _harness, _private, _public, _witness = _enroll_required_witness(
        tmp_path
    )

    with pytest.raises(EvidenceWitnessError, match="requires an external"):
        build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    with pytest.raises(EvidenceWitnessError, match="requires an external"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            _operator_control=True,
        )

    report = StateIntegrityAuditor(state).audit()
    assert report.safe_to_execute is False
    assert (
        report.stores["evidence_witness"]["verification"] == "external_input_required"
    )


def test_missing_completed_publication_policy_is_read_only_unsafe(
    tmp_path,
):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    policy_path = state / "evidence_witness_policy.json"
    policy_path.unlink()

    report = StateIntegrityAuditor(state).audit()
    assert report.safe_to_execute is False
    assert report.status == "unsafe"
    assert any(
        issue.code == "authority_publication_dependency_invalid"
        for issue in report.issues
    )
    assert not policy_path.exists()
    with pytest.raises(EvidenceWitnessError, match="not initialized"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            _operator_control=True,
        )
    assert not policy_path.exists()


@pytest.mark.parametrize("tamper", ["payload", "signature", "time"])
def test_witness_payload_or_signature_tamper_fails_closed(tmp_path, tamper):
    state, workspace, _harness, _private, public, witness = _enroll_required_witness(
        tmp_path
    )
    document = load_witness(witness)
    if tamper == "payload":
        document["record_count"] += 1
    elif tamper == "signature":
        document["attestation"]["signature"] = "base64:" + "A" * 88
    else:
        document["attestation"]["signed_at"] = "2020-01-01T00:00:00Z"
    tampered = tmp_path / f"tampered-{tamper}.json"
    write_witness(tampered, document)

    with pytest.raises(EvidenceWitnessError, match="untrusted evidence-head witness"):
        build_harness(
            state,
            MockAgentAdapter(),
            workspace_root=workspace,
            evidence_head_witness=tampered,
            trusted_evidence_witness_keys=[str(public)],
        )


def test_untrusted_key_and_cross_deployment_replay_fail_closed(tmp_path):
    state, _workspace, harness, _private, public, witness = _enroll_required_witness(
        tmp_path / "first"
    )
    _other_private, other_public = _keys(tmp_path, "other")
    policy = EvidenceWitnessPolicy.from_paths([other_public])
    profile = AuthorityProfileStore(state / "authority_profile.json").get()
    storage = StateStorageStateStore(state / "state_storage.json").get()
    assert profile is not None and storage is not None

    untrusted = assess_witness(
        load_witness(witness),
        policy,
        deployment_root_hash=storage.root_hash,
        profile=profile,
        records=harness.evidence.records(),
    )
    assert untrusted.ok is False
    assert "not trusted" in untrusted.detail

    second_state = tmp_path / "second-state"
    second_workspace = tmp_path / "second-workspace"
    second = build_harness(
        second_state,
        MockAgentAdapter(),
        workspace_root=second_workspace,
    )
    second_profile = AuthorityProfileStore(
        second_state / "authority_profile.json"
    ).get()
    second_storage = StateStorageStateStore(second_state / "state_storage.json").get()
    assert second_profile is not None and second_storage is not None
    replay = assess_witness(
        load_witness(witness),
        EvidenceWitnessPolicy.from_paths([public]),
        deployment_root_hash=second_storage.root_hash,
        profile=second_profile,
        records=second.evidence.records(),
    )
    assert replay.ok is False
    assert "different state root" in replay.detail


def test_cli_witness_and_verify_round_trip_and_refuse_state_paths(tmp_path, capsys):
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    harness = build_harness(state, MockAgentAdapter(), workspace_root=workspace)
    harness.evidence.append(_record(1))
    private, public = _keys(tmp_path)
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_bytes(PASSPHRASE)
    witness = tmp_path / "head.json"

    assert (
        main(
            [
                "--workdir",
                str(state),
                "witness-evidence-head",
                "--signing-key",
                str(private),
                "--passphrase-file",
                str(passphrase),
                "--signer",
                "operator-7",
                "--note",
                "off-box retention",
                "--output",
                str(witness),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "--workdir",
                str(state),
                "verify-evidence-head-witness",
                str(witness),
                "--trusted-key",
                str(public),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["verification"] == "verified"

    harness.evidence.append(_record(2))
    assert (
        main(
            [
                "--workdir",
                str(state),
                "--max-unwitnessed-records",
                "0",
                "verify-evidence-head-witness",
                str(witness),
                "--trusted-key",
                str(public),
            ]
        )
        == 1
    )
    stale = json.loads(capsys.readouterr().out)
    assert stale["verification"] == "lag_exceeded"
    assert stale["unwitnessed_record_count"] == 1

    inside = state / "forbidden-witness.json"
    exit_code = main(
        [
            "--workdir",
            str(state),
            "witness-evidence-head",
            "--signing-key",
            str(private),
            "--passphrase-file",
            str(passphrase),
            "--signer",
            "operator-7",
            "--note",
            "must remain external",
            "--output",
            str(inside),
        ]
    )
    assert exit_code == 1
    assert "outside the workdir" in capsys.readouterr().err
    assert not inside.exists()
