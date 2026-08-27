from __future__ import annotations

import pytest

import defiant_agent_harness.adapters.base as adapter_module
import defiant_agent_harness.contracts as contracts_module
from defiant_agent_harness.adapters.base import (
    ToolCall,
    ToolCallContractError,
    ToolCallLimitError,
)
from defiant_agent_harness.contracts import HarnessRequest, canonical_json


def test_tool_call_requires_bounded_scalar_fields(monkeypatch):
    monkeypatch.setattr(adapter_module, "MAX_TOOL_CALL_NAME_CHARACTERS", 4)
    monkeypatch.setattr(adapter_module, "MAX_TOOL_CALL_IDENTIFIER_CHARACTERS", 4)

    ToolCall("name", call_id="1234", server="srv4")
    with pytest.raises(ToolCallLimitError) as name_error:
        ToolCall("name-secret")
    with pytest.raises(ToolCallLimitError) as identifier_error:
        ToolCall("name", call_id="12345-secret")

    assert name_error.value.limit_enforced == "tool_call_name_characters"
    assert identifier_error.value.limit_enforced == "tool_call_identifier_characters"
    assert "secret" not in str(name_error.value)
    assert "secret" not in str(identifier_error.value)


@pytest.mark.parametrize(
    ("field", "value", "limit_enforced"),
    [
        ("name", "", "tool_call_name_contract"),
        ("call_id", None, "tool_call_identifier_contract"),
        ("server", None, "tool_call_identifier_contract"),
        ("arguments", [], "tool_call_arguments_contract"),
        ("transport_params", [], "tool_call_transport_params_contract"),
    ],
)
def test_tool_call_rejects_invalid_field_shapes(field, value, limit_enforced):
    values = {"name": "tool", field: value}

    with pytest.raises(ToolCallContractError) as exc:
        ToolCall(**values)

    assert exc.value.limit_enforced == limit_enforced


@pytest.mark.parametrize(
    ("constant", "maximum", "exact", "beyond", "limit_enforced"),
    [
        (
            "MAX_ACTION_HASH_NESTING_DEPTH",
            2,
            {"v": []},
            {"v": [None]},
            "tool_call_nesting_depth",
        ),
        (
            "MAX_ACTION_HASH_NODES",
            11,
            {},
            {"v": None},
            "tool_call_nodes",
        ),
        (
            "MAX_ACTION_HASH_MAPPING_ENTRIES",
            5,
            {str(index): index for index in range(5)},
            {str(index): index for index in range(6)},
            "tool_call_mapping_entries",
        ),
        (
            "MAX_ACTION_HASH_SCALAR_CHARACTERS",
            16,
            {"v": "x" * 16},
            {"v": "x" * 17 + "secret"},
            "tool_call_scalar_characters",
        ),
    ],
)
def test_tool_call_accepts_exact_structural_bounds_and_maps_next_failure(
    monkeypatch,
    constant,
    maximum,
    exact,
    beyond,
    limit_enforced,
):
    monkeypatch.setattr(contracts_module, constant, maximum)

    ToolCall("tool", arguments=exact)
    with pytest.raises(ToolCallLimitError) as exc:
        ToolCall("tool", arguments=beyond)

    assert exc.value.limit_enforced == limit_enforced
    assert "secret" not in str(exc.value)


def test_tool_call_accepts_exact_canonical_byte_bound_and_maps_next(monkeypatch):
    call = ToolCall("x")
    exact_bytes = len(canonical_json(call._contract_surface()).encode("utf-8"))
    monkeypatch.setattr(
        contracts_module, "MAX_ACTION_HASH_CANONICAL_BYTES", exact_bytes
    )

    ToolCall("x")
    with pytest.raises(ToolCallLimitError) as exc:
        ToolCall("xx")

    assert exc.value.limit_enforced == "tool_call_canonical_bytes"


def test_tool_call_maps_canonical_mapping_sort_work_failure(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS", 0)

    with pytest.raises(ToolCallLimitError) as exc:
        ToolCall("tool")

    assert exc.value.limit_enforced == "tool_call_mapping_sort_work_units"


def test_tool_call_maps_invalid_mapping_key_contract():
    with pytest.raises(ToolCallContractError) as exc:
        ToolCall("tool", arguments={"text": 1, 2: "number"})

    assert not isinstance(exc.value, ToolCallLimitError)
    assert exc.value.limit_enforced == "tool_call_contract"


def test_tool_call_completes_mapping_key_preflight_before_values(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_NUMBER_CHARACTERS", 2)

    with pytest.raises(ToolCallLimitError) as exc:
        ToolCall("tool", arguments={1: object(), 100: "late invalid key"})

    assert exc.value.limit_enforced == "tool_call_number_characters"
    assert "late invalid key" not in str(exc.value)


def test_tool_call_maps_canonical_number_failure(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_NUMBER_CHARACTERS", 4)

    ToolCall("tool", arguments={"value": 9999})
    with pytest.raises(ToolCallLimitError) as exc:
        ToolCall("tool", arguments={"value": 10000})

    assert exc.value.limit_enforced == "tool_call_number_characters"


def test_tool_call_maps_canonical_string_token_failure(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_STRING_TOKEN_BYTES", 20)

    ToolCall("t", arguments={"value": "😀"})
    with pytest.raises(ToolCallLimitError) as exc:
        ToolCall("t", arguments={"value": "😀😀"})

    assert exc.value.limit_enforced == "tool_call_string_token_bytes"


def test_tool_call_rejects_cycles_without_echoing_content():
    arguments: dict = {}
    arguments["secret-key"] = arguments

    with pytest.raises(ToolCallContractError, match="not canonical") as exc:
        ToolCall("tool", arguments=arguments)

    assert exc.value.limit_enforced == "tool_call_contract"
    assert "secret-key" not in str(exc.value)


def test_tool_call_seal_revalidates_detaches_freezes_and_detects_nested_mutation(
    monkeypatch,
):
    arguments = {"nested": ["accepted"]}
    transport = {"meta": {"trace": "accepted"}}
    call = ToolCall("tool", arguments=arguments, transport_params=transport)
    call.arguments["nested"] = ["x" * 17 + "secret"]
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_SCALAR_CHARACTERS", 16)

    with pytest.raises(ToolCallLimitError):
        call.seal_contract()

    monkeypatch.setattr(
        contracts_module, "MAX_ACTION_HASH_SCALAR_CHARACTERS", 8 * 1024 * 1024
    )
    safe_arguments = {"nested": ["accepted"]}
    call.arguments = safe_arguments
    call.seal_contract()
    sealed_hash = call.contract_hash
    safe_arguments["nested"].append("caller mutation")
    transport["meta"]["trace"] = "caller mutation"

    assert call.arguments == {"nested": ["accepted"]}
    assert call.transport_params == {"meta": {"trace": "accepted"}}
    assert call.contract_hash == sealed_hash

    with pytest.raises(ValueError, match="sealed tool call"):
        call.name = "changed"
    with pytest.raises(ValueError, match="sealed tool call"):
        call._contract_sealed = False

    call.arguments["nested"].append("adapter mutation")
    with pytest.raises(ToolCallContractError) as exc:
        call.require_unchanged()
    assert exc.value.limit_enforced == "tool_call_mutation"


def test_tool_call_seal_adopts_validated_snapshot_without_deepcopy_hooks():
    class HostileArguments(dict):
        def __deepcopy__(self, memo):
            raise AssertionError("validated tool-call ownership must not use deepcopy")

    arguments = HostileArguments({"nested": ["accepted"]})
    call = ToolCall("tool", arguments=arguments)
    expected_hash = call.seal_contract()
    arguments["nested"].append("caller mutation")

    assert type(call.arguments) is dict
    assert call.arguments == {"nested": ["accepted"]}
    assert call.contract_hash == expected_hash


def test_pre_adapter_oversize_fails_before_translation_or_authority(
    tmp_path, monkeypatch
):
    from defiant_agent_harness.adapters.mock import MockAgentAdapter
    from defiant_agent_harness.orchestrator.harness import build_harness

    class ObservedAdapter(MockAgentAdapter):
        translated = False

        def to_action(self, call, request_id):
            self.translated = True
            return super().to_action(call, request_id)

    adapter = ObservedAdapter([])
    harness = build_harness(tmp_path, adapter, starting_budget_usd=25)
    request = HarnessRequest(task="bounded", user_id="tester", workspace_id="ws")
    call = ToolCall("summarize", {"text": "accepted"})
    call.seal_contract()
    call.arguments["text"] = "x" * 17 + "secret"
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_SCALAR_CHARACTERS", 16)

    with pytest.raises(ToolCallLimitError) as exc:
        harness.handle_call(call, request)

    assert exc.value.limit_enforced == "tool_call_scalar_characters"
    assert "secret" not in str(exc.value)
    assert adapter.translated is False
    assert harness.evidence.records() == []
    assert harness.approvals.list_pending() == []
    assert harness.budget.balance_usd == 25


@pytest.mark.parametrize("external", [False, True])
def test_adapter_nested_mutation_fails_before_authority_work(tmp_path, external):
    from defiant_agent_harness.adapters.mock import MockAgentAdapter
    from defiant_agent_harness.orchestrator.harness import build_harness

    class MutatingAdapter(MockAgentAdapter):
        def to_action(self, call, request_id):
            call.arguments["text"] = "substituted-secret"
            return super().to_action(call, request_id)

    adapter = MutatingAdapter([])
    harness = build_harness(tmp_path, adapter, starting_budget_usd=25)
    request = HarnessRequest(task="mutation", user_id="tester", workspace_id="ws")
    call = ToolCall("summarize", {"text": "accepted"})

    with pytest.raises(ToolCallContractError) as exc:
        if external:
            harness.preflight_external_call(
                call,
                request,
                execution_owner="worker",
                execution_key="call-1",
            )
        else:
            harness.handle_call(call, request)

    assert exc.value.limit_enforced == "tool_call_mutation"
    assert "substituted-secret" not in str(exc.value)
    assert harness.evidence.records() == []
    assert harness.approvals.list_pending() == []
    assert harness.budget.balance_usd == 25
