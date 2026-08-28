from dataclasses import FrozenInstanceError

import pytest

import defiant_agent_harness.hooks.state as hook_state_module
from defiant_agent_harness.contracts import (
    Decision,
    GuardrailDecision,
    HarnessRequest,
    ProposedAction,
    SideEffect,
)
from defiant_agent_harness.hooks.state import (
    HookExecution,
    HookExecutionStore,
    HookStateError,
)


def _execution() -> HookExecution:
    request = HarnessRequest(
        task="read the briefing",
        user_id="operator",
        workspace_id="workspace",
    )
    action = ProposedAction(
        tool_name="read_file",
        target="workspace/briefing.txt",
        payload={"path": "briefing.txt", "options": ["text"]},
        side_effect_level=SideEffect.NONE,
        request_id=request.request_id,
    )
    decision = GuardrailDecision(
        Decision.ALLOW,
        "read is permitted",
        policy_ids=["baseline-read"],
        policy_version="1",
        ruleset_hash="sha256:rules",
        decision_inputs={"request_id": request.request_id},
    )
    return HookExecution(
        tool_use_id="hook-use-1",
        execution_key="sha256:execution",
        native_tool_name="Read",
        action_snapshot=action.to_dict(),
        request_snapshot=request.to_dict(),
        decision_snapshot=decision.to_dict(),
        authorization_record_id="evd_authorization",
    )


def test_hook_execution_captures_hostile_input_without_caller_hooks():
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

    raw = _execution().to_dict()
    raw["tool_use_id"] = HostileText(raw["tool_use_id"])
    raw["action_snapshot"] = HostileDict(raw["action_snapshot"])
    raw["action_snapshot"]["payload"] = HostileDict(raw["action_snapshot"]["payload"])
    raw["action_snapshot"]["payload"]["options"] = HostileList([HostileText("text")])

    restored = HookExecution.from_dict(HostileDict(raw))

    assert type(restored.tool_use_id) is str
    assert type(restored.action_snapshot) is dict
    assert type(restored.action_snapshot["payload"]["options"]) is list
    assert type(restored.action_snapshot["payload"]["options"][0]) is str


def test_hook_execution_retains_sealed_snapshots_and_defensive_projections():
    raw = _execution().to_dict()
    execution = HookExecution.from_dict(raw)
    expected = execution.to_dict()

    raw["action_snapshot"]["payload"]["path"] = "caller-change.txt"
    raw["request_snapshot"]["task"] = "caller changed task"
    raw["decision_snapshot"]["decision_inputs"]["request_id"] = "caller"
    action = execution.action_snapshot
    request = execution.request_snapshot
    decision = execution.decision_snapshot
    action["payload"]["path"] = "projection-change.txt"
    request["task"] = "projection changed task"
    decision["decision_inputs"]["request_id"] = "projection"

    assert execution.to_dict() == expected
    with pytest.raises(FrozenInstanceError):
        execution.status = "completed"


def test_hook_execution_rejects_noncanonical_state_without_secret_echo():
    class SecretValue:
        def __str__(self):
            raise AssertionError("secret rendered")

        def __repr__(self):
            raise AssertionError("secret represented")

        def __deepcopy__(self, memo):
            raise AssertionError("secret copied")

    raw = _execution().to_dict()
    raw["action_snapshot"]["payload"]["secret"] = SecretValue()

    with pytest.raises(
        HookStateError,
        match="hook execution exceeds bounded canonical contract",
    ) as failure:
        HookExecution.from_dict(raw)

    assert "SecretValue" not in str(failure.value)


def test_hook_execution_rejects_stale_hashes_and_cross_request_snapshots():
    stale_hash = _execution().to_dict()
    stale_hash["action_snapshot"]["payload"]["path"] = "substituted.txt"
    with pytest.raises(HookStateError, match="action_snapshot is not canonical"):
        HookExecution.from_dict(stale_hash)

    cross_request = _execution().to_dict()
    cross_request["request_snapshot"]["request_id"] = "req_other"
    with pytest.raises(HookStateError, match="action/request binding is invalid"):
        HookExecution.from_dict(cross_request)


def test_hook_store_completion_is_copy_on_write_and_restart_safe(tmp_path):
    store = HookExecutionStore(tmp_path / "hook_executions.json")
    authorized = store.create(_execution())

    completed = store.mark_completed(
        authorized.tool_use_id,
        "evd_completion",
    )

    assert authorized.status == "authorized"
    assert authorized.completion_record_id == ""
    assert completed.status == "completed"
    assert completed.completion_record_id == "evd_completion"
    assert completed.completed_at is not None
    assert HookExecutionStore(store.path).get(authorized.tool_use_id) == completed
    assert store.mark_completed(authorized.tool_use_id, "evd_completion") == completed


def test_hook_store_passes_one_explicit_ceiling_to_reads_and_writes(
    tmp_path, monkeypatch
):
    read_limits = []
    write_limits = []
    original_read = hook_state_module.read_json
    original_write = hook_state_module.atomic_write_json

    def observed_read(path, *, max_bytes=None):
        read_limits.append(max_bytes)
        return original_read(path, max_bytes=max_bytes)

    def observed_write(path, data, *, max_bytes=None):
        write_limits.append(max_bytes)
        return original_write(path, data, max_bytes=max_bytes)

    monkeypatch.setattr(hook_state_module, "read_json", observed_read)
    monkeypatch.setattr(hook_state_module, "atomic_write_json", observed_write)
    store = HookExecutionStore(tmp_path / "hook_executions.json")
    store.create(_execution())

    assert read_limits
    assert write_limits
    assert set(read_limits) == {hook_state_module._MAX_STATE_BYTES}
    assert set(write_limits) == {hook_state_module._MAX_STATE_BYTES}


def test_hook_store_refuses_oversized_completion_without_replacing_prior_state(
    tmp_path, monkeypatch
):
    path = tmp_path / "hook_executions.json"
    store = HookExecutionStore(path)
    authorized = store.create(_execution())
    prior = path.read_bytes()
    completed = authorized.complete(
        "evd_completion",
        completed_at="2026-08-28T12:00:00Z",
    )
    original_limit = hook_state_module._MAX_STATE_BYTES
    monkeypatch.setattr(hook_state_module, "_MAX_STATE_BYTES", 1)

    with pytest.raises(HookStateError, match="exceeds"):
        store._write_all({authorized.tool_use_id: completed})

    assert path.read_bytes() == prior
    monkeypatch.setattr(hook_state_module, "_MAX_STATE_BYTES", original_limit)
    restored = HookExecutionStore(path).get(authorized.tool_use_id)
    assert restored is not None
    assert restored.status == "authorized"
    assert restored.completion_record_id == ""
