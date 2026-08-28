from dataclasses import FrozenInstanceError

import pytest

import defiant_agent_harness.approvals.store as approval_store_module
from defiant_agent_harness.approvals.store import (
    ApprovalError,
    ApprovalStore,
    PendingApproval,
)
from defiant_agent_harness.contracts import (
    Decision,
    GuardrailDecision,
    HarnessRequest,
    ProposedAction,
    SideEffect,
)
from defiant_agent_harness.persistence import atomic_write_json


def _approval() -> PendingApproval:
    request = HarnessRequest(
        task="send the briefing",
        user_id="operator",
        workspace_id="workspace",
        request_id="req_approval_state",
    )
    action = ProposedAction(
        tool_name="send_email",
        target="recipient@example.test",
        payload={"body": "briefing", "options": ["signed"]},
        side_effect_level=SideEffect.EXTERNAL_SEND,
        request_id=request.request_id,
        action_id="act_approval_state",
    )
    decision = GuardrailDecision(
        Decision.APPROVAL_REQUIRED,
        "operator decision required",
        policy_ids=["external-send"],
        policy_version="1",
        ruleset_hash="sha256:rules",
        approval_scope="external_send",
        decision_inputs={"request_id": request.request_id},
    )
    return PendingApproval(
        action_id=action.action_id,
        request_id=request.request_id,
        tool_name=action.tool_name,
        target=action.target,
        payload_hash=action.payload_hash,
        authorization_hash=action.authorization_hash,
        payload_preview="briefing",
        approval_scope=decision.approval_scope,
        reason=decision.reason,
        policy_ids=decision.policy_ids,
        expires_at="2999-01-01T00:00:00Z",
        created_at="2026-08-28T12:00:00Z",
        approval_id="apr_approval_state",
        reserved_usd="3.5",
        action_snapshot=action.to_dict(),
        request_snapshot=request.to_dict(),
        decision_snapshot=decision.to_dict(),
    )


def test_approval_captures_hostile_input_without_caller_hooks():
    class HostileText(str):
        def __str__(self):
            raise AssertionError("caller string hook invoked")

        def __len__(self):
            raise AssertionError("caller string length hook invoked")

        def strip(self, *args, **kwargs):
            raise AssertionError("caller string strip hook invoked")

        def replace(self, *args, **kwargs):
            raise AssertionError("caller string replace hook invoked")

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

    raw = _approval().to_dict()
    raw["approval_id"] = HostileText(raw["approval_id"])
    raw["policy_ids"] = HostileList([HostileText("external-send")])
    raw["action_snapshot"] = HostileDict(raw["action_snapshot"])
    raw["action_snapshot"]["payload"] = HostileDict(raw["action_snapshot"]["payload"])
    raw["action_snapshot"]["payload"]["options"] = HostileList([HostileText("signed")])

    restored = PendingApproval.from_dict(HostileDict(raw))

    assert type(restored.approval_id) is str
    assert type(restored.policy_ids) is list
    assert type(restored.action_snapshot) is dict
    assert type(restored.action_snapshot["payload"]["options"][0]) is str


def test_approval_retains_sealed_state_and_defensive_projections():
    raw = _approval().to_dict()
    approval = PendingApproval.from_dict(raw)
    expected = approval.to_dict()

    raw["policy_ids"].append("caller-change")
    raw["action_snapshot"]["payload"]["body"] = "caller changed"
    raw["request_snapshot"]["task"] = "caller changed"
    raw["decision_snapshot"]["decision_inputs"]["request_id"] = "caller"
    policy_ids = approval.policy_ids
    action = approval.action_snapshot
    request = approval.request_snapshot
    decision = approval.decision_snapshot
    policy_ids.append("projection-change")
    action["payload"]["body"] = "projection changed"
    request["task"] = "projection changed"
    decision["decision_inputs"]["request_id"] = "projection"

    assert approval.to_dict() == expected
    with pytest.raises(FrozenInstanceError):
        approval.status = "approved"


def test_approval_rejects_noncanonical_state_without_secret_echo():
    class SecretValue:
        def __str__(self):
            raise AssertionError("secret rendered")

        def __repr__(self):
            raise AssertionError("secret represented")

        def __deepcopy__(self, memo):
            raise AssertionError("secret copied")

    raw = _approval().to_dict()
    raw["decision_attestation"] = {"secret": SecretValue()}

    with pytest.raises(
        ApprovalError, match="exceeds bounded canonical contract"
    ) as failure:
        PendingApproval.from_dict(raw)

    assert "SecretValue" not in str(failure.value)


def test_approval_rejects_stale_hashes_and_cross_request_snapshots():
    stale_hash = _approval().to_dict()
    stale_hash["action_snapshot"]["payload"]["body"] = "substituted"
    with pytest.raises(ApprovalError, match="action_snapshot is not canonical"):
        PendingApproval.from_dict(stale_hash)

    cross_request = _approval().to_dict()
    cross_request["request_snapshot"]["request_id"] = "req_other"
    with pytest.raises(ApprovalError, match="request snapshot binding is invalid"):
        PendingApproval.from_dict(cross_request)


def test_approval_store_transitions_are_copy_on_write_and_restart_safe(tmp_path):
    store = ApprovalStore(tmp_path / "approvals.json")
    pending = store.create_prepared(_approval())

    approved = store.decide(pending.approval_id, True, "operator-7", "reviewed")

    assert pending.status == "pending"
    assert pending.decided_by is None
    assert approved.status == "approved"
    assert approved.decided_by == "operator-7"
    assert ApprovalStore(store.path).get(pending.approval_id) == approved


def test_approval_store_loads_legacy_record_with_newer_optional_fields_absent(
    tmp_path,
):
    raw = _approval().to_dict()
    for name in (
        "execution_owner",
        "execution_key",
        "reconciliation_outcome",
        "reconciled_by",
        "reconciliation_note",
        "reconciliation_started_at",
        "reconciliation_completed_at",
        "reconciliation_attestation",
    ):
        raw.pop(name)
    path = tmp_path / "approvals.json"
    atomic_write_json(path, {raw["approval_id"]: raw})

    restored = ApprovalStore(path).get(raw["approval_id"])

    assert restored is not None
    assert restored.execution_owner == ""
    assert restored.reconciliation_outcome == ""
    assert set(restored.to_dict()) == approval_store_module._APPROVAL_FIELDS


def test_approval_store_rejects_record_key_mismatch(tmp_path):
    raw = _approval().to_dict()
    path = tmp_path / "approvals.json"
    atomic_write_json(path, {"apr_substituted": raw})

    with pytest.raises(ApprovalError, match="key mismatch"):
        ApprovalStore(path)


def test_approval_store_passes_one_explicit_ceiling_to_reads_and_writes(
    tmp_path, monkeypatch
):
    read_limits = []
    write_limits = []
    original_read = approval_store_module.read_json
    original_write = approval_store_module.atomic_write_json

    def observed_read(path, *, max_bytes=None):
        read_limits.append(max_bytes)
        return original_read(path, max_bytes=max_bytes)

    def observed_write(path, data, *, max_bytes=None):
        write_limits.append(max_bytes)
        return original_write(path, data, max_bytes=max_bytes)

    monkeypatch.setattr(approval_store_module, "read_json", observed_read)
    monkeypatch.setattr(approval_store_module, "atomic_write_json", observed_write)
    store = ApprovalStore(tmp_path / "approvals.json")
    store.create_prepared(_approval())

    assert read_limits
    assert write_limits
    assert set(read_limits) == {approval_store_module._MAX_STATE_BYTES}
    assert set(write_limits) == {approval_store_module._MAX_STATE_BYTES}


def test_approval_store_refuses_oversized_update_without_replacing_prior_state(
    tmp_path, monkeypatch
):
    path = tmp_path / "approvals.json"
    store = ApprovalStore(path)
    pending = store.create_prepared(_approval())
    prior = path.read_bytes()
    approved = pending.with_updates(
        status="approved",
        decided_by="operator-7",
        decided_at="2026-08-28T12:01:00Z",
    )
    original_limit = approval_store_module._MAX_STATE_BYTES
    monkeypatch.setattr(approval_store_module, "_MAX_STATE_BYTES", 1)

    with pytest.raises(ApprovalError, match="exceeds"):
        store._write_all({pending.approval_id: approved})

    assert path.read_bytes() == prior
    monkeypatch.setattr(approval_store_module, "_MAX_STATE_BYTES", original_limit)
    restored = ApprovalStore(path).get(pending.approval_id)
    assert restored is not None
    assert restored.status == "pending"
