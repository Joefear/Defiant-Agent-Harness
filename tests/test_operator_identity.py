from __future__ import annotations

import copy
import json

import pytest

from defiant_agent_harness.approvals.store import ApprovalError, ApprovalStore
from defiant_agent_harness.adapters.mock import MockAgentAdapter, SCRIPTS
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import (
    HarnessRequest,
    ProposedAction,
    ResultStatus,
    SideEffect,
)
from defiant_agent_harness.evidence.signing import generate_key_pair
from defiant_agent_harness.operator_identity import (
    DECISION_PURPOSE,
    RECONCILIATION_PURPOSE,
    OperatorTrustPolicy,
    OperatorIdentityError,
    sign_operator_action,
)
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.state_integrity import StateIntegrityAuditor

PASSPHRASE = b"test-only operator key passphrase"


def _keys(tmp_path, name: str, operator: str = "alice"):
    private = tmp_path / f"{name}-private.pem"
    public = tmp_path / f"{name}-public.pem"
    generate_key_pair(private, public, PASSPHRASE)
    spec = f"{operator}={public}"
    return private, public, spec, OperatorTrustPolicy.from_specs([spec])


def _action(target: str = "merchant@example.com") -> ProposedAction:
    return ProposedAction(
        tool_name="send_email",
        target=target,
        payload={"to": target, "body": "reviewed content"},
        side_effect_level=SideEffect.EXTERNAL_SEND,
        request_id="req_operator_identity",
    )


def _pending(store: ApprovalStore, target: str = "merchant@example.com"):
    return store.create(_action(target), "human review", "exact action", ["r1"])


def _decision(approval, private, *, operator="alice", note="reviewed"):
    return sign_operator_action(
        approval,
        private,
        PASSPHRASE,
        purpose=DECISION_PURPOSE,
        outcome="approved",
        operator=operator,
        note=note,
    )


def test_trusted_operator_decision_survives_restart_and_authorizes(tmp_path):
    private, _, _, trust = _keys(tmp_path, "alice")
    path = tmp_path / "state" / "approvals.json"
    store = ApprovalStore(path, operator_trust=trust)
    pending = _pending(store)
    attestation = _decision(pending, private)

    decided = store.decide(
        pending.approval_id,
        True,
        "alice",
        "reviewed",
        attestation=attestation,
    )
    reopened = ApprovalStore(path, operator_trust=trust)

    assert reopened.decision_identity(decided).assurance == "signed_trusted"
    assert reopened.begin_execution(
        pending.approval_id, pending.held_action()
    ).status == ("executing")


def test_strict_policy_refuses_unsigned_and_wrong_identity_keys(tmp_path):
    private, _, _, trust = _keys(tmp_path, "alice")
    store = ApprovalStore(tmp_path / "state" / "approvals.json", operator_trust=trust)
    pending = _pending(store)

    with pytest.raises(ApprovalError, match="signed operator attestation"):
        store.decide(pending.approval_id, True, "alice", "reviewed")

    forged_identity = _decision(pending, private, operator="mallory")
    with pytest.raises(ApprovalError, match="not trusted for operator"):
        store.decide(
            pending.approval_id,
            True,
            "mallory",
            "reviewed",
            attestation=forged_identity,
        )


def test_runtime_refuses_a_trust_root_inside_mutable_harness_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    private = tmp_path / "private.pem"
    public = state / "agent-writable-public.pem"
    generate_key_pair(private, public, PASSPHRASE)

    with pytest.raises(OperatorIdentityError, match="outside the workdir"):
        build_harness(
            state,
            MockAgentAdapter(),
            trusted_operator_keys=[f"alice={public}"],
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("outcome", "rejected", "invalid"),
        ("operator", "mallory", "not trusted"),
        ("note", "different rationale", "invalid"),
        ("action_id", "act_replayed", "action_id"),
        ("signature", "base64:" + "A" * 88, "signature"),
    ],
)
def test_tampered_operator_statements_are_rejected(tmp_path, field, value, message):
    private, _, _, trust = _keys(tmp_path, "alice")
    store = ApprovalStore(tmp_path / "state" / "approvals.json", operator_trust=trust)
    pending = _pending(store)
    attestation = _decision(pending, private)
    attestation[field] = value

    with pytest.raises(ApprovalError, match=message):
        store.decide(
            pending.approval_id,
            True,
            "alice",
            "reviewed",
            attestation=attestation,
        )


def test_attestation_replay_against_another_approval_is_rejected(tmp_path):
    private, _, _, trust = _keys(tmp_path, "alice")
    store = ApprovalStore(tmp_path / "state" / "approvals.json", operator_trust=trust)
    first = _pending(store, "first@example.com")
    second = _pending(store, "second@example.com")
    replay = _decision(first, private)

    with pytest.raises(ApprovalError, match="approval_id"):
        store.decide(
            second.approval_id,
            True,
            "alice",
            "reviewed",
            attestation=replay,
        )


@pytest.mark.parametrize(
    ("signed_at", "message"),
    [
        ("2000-01-01T00:00:00Z", "predates approval creation"),
        ("2999-01-01T00:00:00Z", "too far in the future"),
    ],
)
def test_operator_signature_time_must_match_approval_lifecycle(
    tmp_path, signed_at, message
):
    private, _, _, trust = _keys(tmp_path, "alice")
    store = ApprovalStore(tmp_path / "state" / "approvals.json", operator_trust=trust)
    pending = _pending(store)
    attestation = sign_operator_action(
        pending,
        private,
        PASSPHRASE,
        purpose=DECISION_PURPOSE,
        outcome="approved",
        operator="alice",
        note="reviewed",
        signed_at=signed_at,
    )

    with pytest.raises(ApprovalError, match=message):
        store.decide(
            pending.approval_id,
            True,
            "alice",
            "reviewed",
            attestation=attestation,
        )


def test_rotation_accepts_old_and_new_keys_for_the_same_operator(tmp_path):
    old_private, _, old_spec, _ = _keys(tmp_path, "old")
    new_private, _, new_spec, _ = _keys(tmp_path, "new")
    trust = OperatorTrustPolicy.from_specs([old_spec, new_spec])
    store = ApprovalStore(tmp_path / "state" / "approvals.json", operator_trust=trust)
    old = _pending(store, "old@example.com")
    new = _pending(store, "new@example.com")

    store.decide(
        old.approval_id,
        True,
        "alice",
        "old key still trusted",
        attestation=_decision(old, old_private, note="old key still trusted"),
    )
    store.decide(
        new.approval_id,
        True,
        "alice",
        "new key active",
        attestation=_decision(new, new_private, note="new key active"),
    )

    assert store.decision_identity(store.get(old.approval_id)).ok
    assert store.decision_identity(store.get(new.approval_id)).ok


def test_reconciliation_requires_a_distinct_bound_attestation(tmp_path):
    private, _, _, trust = _keys(tmp_path, "alice")
    store = ApprovalStore(tmp_path / "state" / "approvals.json", operator_trust=trust)
    pending = _pending(store)
    store.decide(
        pending.approval_id,
        True,
        "alice",
        "approved",
        attestation=_decision(pending, private, note="approved"),
    )
    executing = store.begin_execution(pending.approval_id, pending.held_action())

    wrong_purpose = _decision(executing, private, note="upstream checked")
    with pytest.raises(ApprovalError, match="purpose"):
        store.begin_reconciliation(
            pending.approval_id,
            "failed",
            "alice",
            "upstream checked",
            attestation=wrong_purpose,
        )

    reconciliation = sign_operator_action(
        executing,
        private,
        PASSPHRASE,
        purpose=RECONCILIATION_PURPOSE,
        outcome="failed",
        operator="alice",
        note="upstream checked",
    )
    started = store.begin_reconciliation(
        pending.approval_id,
        "failed",
        "alice",
        "upstream checked",
        attestation=reconciliation,
    )

    assert store.reconciliation_identity(started).assurance == "signed_trusted"


def test_integrity_audit_blocks_tampered_persisted_operator_identity(tmp_path):
    private, _, _, trust = _keys(tmp_path, "alice")
    state = tmp_path / "state"
    path = state / "approvals.json"
    store = ApprovalStore(path, operator_trust=trust)
    pending = _pending(store)
    store.decide(
        pending.approval_id,
        True,
        "alice",
        "reviewed",
        attestation=_decision(pending, private),
    )
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw[pending.approval_id]["note"] = "tampered after signing"
    path.write_text(json.dumps(raw), encoding="utf-8")

    report = StateIntegrityAuditor(state, operator_trust=trust).audit()

    assert not report.safe_to_execute
    assert any(
        issue.code == "operator_decision_identity_invalid" for issue in report.issues
    )


def test_command_core_exposes_assurance_without_signature_or_note(tmp_path):
    private, _, spec, trust = _keys(tmp_path, "alice")
    state = tmp_path / "state"
    store = ApprovalStore(state / "approvals.json", operator_trust=trust)
    pending = _pending(store)
    store.decide(
        pending.approval_id,
        True,
        "alice",
        "sensitive operator rationale",
        attestation=_decision(pending, private, note="sensitive operator rationale"),
    )

    snapshot = CommandCore(state, trusted_operator_keys=[spec]).snapshot()
    projected = snapshot["approvals"]["actionable"][0]["operator_identity"]

    assert projected["assurance"] == "signed_trusted"
    assert projected["operator"] == "alice"
    assert projected["key_id"].startswith("sha256:")
    assert "signature" not in projected
    assert "sensitive operator rationale" not in json.dumps(snapshot)


def test_attestation_copy_cannot_be_mutated_through_store_result(tmp_path):
    private, _, _, trust = _keys(tmp_path, "alice")
    store = ApprovalStore(tmp_path / "state" / "approvals.json", operator_trust=trust)
    pending = _pending(store)
    attestation = _decision(pending, private)
    original = copy.deepcopy(attestation)
    store.decide(
        pending.approval_id,
        True,
        "alice",
        "reviewed",
        attestation=attestation,
    )
    attestation["operator"] = "mallory"

    assert store.get(pending.approval_id).decision_attestation == original


def test_signed_cli_decision_executes_under_the_same_runtime_trust_pins(
    tmp_path, capsys
):
    private, public, spec, _ = _keys(tmp_path, "alice")
    passphrase_file = tmp_path / "operator.passphrase"
    passphrase_file.write_bytes(PASSPHRASE)
    state = tmp_path / "state"
    harness = build_harness(
        state,
        MockAgentAdapter(script=SCRIPTS["send_email"]),
        trusted_operator_keys=[spec],
    )
    request = HarnessRequest(task="send", user_id="user", workspace_id="ws")
    [held] = harness.run(request)

    exit_code = main(
        [
            "--workdir",
            str(state),
            "--user",
            "alice",
            "approve",
            held.approval_id,
            "--note",
            "reviewed exact action",
            "--operator-key",
            str(private),
            "--operator-passphrase-file",
            str(passphrase_file),
            "--trusted-operator-key",
            f"alice={public}",
        ]
    )

    assert exit_code == 0
    assert "succeeded" in capsys.readouterr().out
    stored = ApprovalStore(
        state / "approvals.json",
        operator_trust=OperatorTrustPolicy.from_specs([spec]),
    ).get(held.approval_id)
    assert stored.status == "consumed"
    assert stored.decision_attestation["operator"] == "alice"


def test_signed_reconciliation_charges_worst_case_only_after_verification(tmp_path):
    private, _, spec, trust = _keys(tmp_path, "alice")
    state = tmp_path / "state"
    harness = build_harness(
        state,
        MockAgentAdapter(script=SCRIPTS["overspend"]),
        starting_budget_usd="500",
        trusted_operator_keys=[spec],
    )
    request = HarnessRequest(task="spend", user_id="user", workspace_id="ws")
    [held] = harness.run(request)
    pending = harness.approvals.get(held.approval_id)
    harness.approvals.decide(
        held.approval_id,
        True,
        "alice",
        "approved exact spend",
        attestation=_decision(pending, private, note="approved exact spend"),
    )
    executing = harness.approvals.begin_execution(held.approval_id, held.action)
    reconciliation = sign_operator_action(
        executing,
        private,
        PASSPHRASE,
        purpose=RECONCILIATION_PURPOSE,
        outcome="failed",
        operator="alice",
        note="provider may have accepted the charge",
    )
    tampered = copy.deepcopy(reconciliation)
    tampered["note"] = "release the reservation"

    with pytest.raises(ApprovalError, match="invalid"):
        harness.reconcile_execution(
            held.approval_id,
            "failed",
            "alice",
            "release the reservation",
            attestation=tampered,
        )
    assert harness.budget.summary()["total_spent_usd"] == "0"
    assert harness.budget.reservation_for(held.action.action_id) == 250

    reconciled = harness.reconcile_execution(
        held.approval_id,
        "failed",
        "alice",
        "provider may have accepted the charge",
        attestation=reconciliation,
    )

    assert reconciled.status is ResultStatus.FAILED
    assert harness.budget.summary()["total_spent_usd"] == "250"
    assert harness.budget.reservation_for(held.action.action_id) == 0
    assert (
        ApprovalStore(state / "approvals.json", operator_trust=trust)
        .reconciliation_identity(harness.approvals.get(held.approval_id))
        .ok
    )
