from __future__ import annotations

from decimal import Decimal
from enum import Enum, IntEnum

import pytest

import defiant_agent_harness.contracts as contracts_module

from defiant_agent_harness.contracts import (
    ActionHashLimitError,
    ContentRef,
    HarnessRequest,
    ProposedAction,
    RequestLimitError,
    SideEffect,
    Trust,
    action_sha256_of,
    canonical_json,
    sha256_of,
)


def test_request_rejects_negative_budget_limit():
    with pytest.raises(ValueError, match="must not be negative"):
        HarnessRequest(
            task="task",
            user_id="user",
            workspace_id="workspace",
            budget_limit_usd="-0.01",
        )


@pytest.mark.parametrize("field", ["allowed_tools", "inputs"])
def test_request_collections_must_be_lists(field):
    values = {
        "task": "task",
        "user_id": "user",
        "workspace_id": "workspace",
        "allowed_tools": [],
        "inputs": [],
    }
    values[field] = ()

    with pytest.raises(ValueError, match=f"{field} must be a list"):
        HarnessRequest(**values)


def test_request_accepts_exact_text_item_limits_and_rejects_next(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_REQUEST_TEXT_ITEM_CHARACTERS", 4)
    monkeypatch.setattr(contracts_module, "MAX_REQUEST_IDENTIFIER_CHARACTERS", 4)

    HarnessRequest(
        task="1234",
        user_id="1234",
        workspace_id="1234",
        request_id="1234",
        task_type="1234",
    )
    with pytest.raises(RequestLimitError, match="task exceeds") as task_error:
        HarnessRequest(task="12345", user_id="u", workspace_id="w")
    with pytest.raises(RequestLimitError, match="user_id exceeds") as id_error:
        HarnessRequest(task="task", user_id="12345", workspace_id="w")
    assert task_error.value.limit_enforced == "request_text_item"
    assert id_error.value.limit_enforced == "request_text_item"


def test_request_accepts_exact_allowlist_limits_and_rejects_next(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_REQUEST_ALLOWED_TOOLS", 2)
    monkeypatch.setattr(contracts_module, "MAX_REQUEST_ALLOWED_TOOL_CHARACTERS", 4)

    HarnessRequest(
        task="task",
        user_id="user",
        workspace_id="workspace",
        allowed_tools=["1234", "read"],
    )
    with pytest.raises(RequestLimitError, match="allowed tool count") as count_error:
        HarnessRequest(
            task="task",
            user_id="user",
            workspace_id="workspace",
            allowed_tools=["one", "two", "three"],
        )
    with pytest.raises(RequestLimitError, match="allowed tool exceeds") as item_error:
        HarnessRequest(
            task="task",
            user_id="user",
            workspace_id="workspace",
            allowed_tools=["12345"],
        )
    assert count_error.value.limit_enforced == "request_allowed_tools"
    assert item_error.value.limit_enforced == "request_text_item"


def test_request_rejects_empty_allowlist_entries():
    with pytest.raises(ValueError, match="non-empty strings"):
        HarnessRequest(
            task="task",
            user_id="user",
            workspace_id="workspace",
            allowed_tools=[" "],
        )


def test_request_accepts_exact_aggregate_text_limit_and_rejects_next(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_REQUEST_TEXT_CHARACTERS", 5)
    base = {
        "task": "t",
        "user_id": "u",
        "workspace_id": "w",
        "request_id": "r",
        "task_type": "g",
    }

    HarnessRequest(**base)
    with pytest.raises(RequestLimitError, match="request text exceeds") as exc:
        HarnessRequest(**base, allowed_tools=["x"])
    assert exc.value.limit_enforced == "request_text_characters"


def test_provenance_metadata_accepts_exact_item_limit_and_sanitizes_failure(
    monkeypatch,
):
    monkeypatch.setattr(contracts_module, "MAX_PROVENANCE_TEXT_ITEM_CHARACTERS", 4)

    ContentRef("1234", "web", Trust.UNTRUSTED, "hash", "")
    with pytest.raises(RequestLimitError, match="provenance metadata item") as exc:
        ContentRef("12345-secret", "web", Trust.UNTRUSTED, "hash", "")
    assert exc.value.limit_enforced == "provenance_text_item"
    assert "secret" not in str(exc.value)


def test_provenance_count_is_bounded_for_requests_and_actions(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_PROVENANCE_REFS", 2)
    ref = ContentRef("r", "web", Trust.UNTRUSTED, "hash")

    HarnessRequest(
        task="task",
        user_id="user",
        workspace_id="workspace",
        inputs=[ref, ref],
    )
    ProposedAction(
        tool_name="tool",
        target="target",
        payload={},
        side_effect_level=SideEffect.NONE,
        payload_sources=[ref, ref],
    )
    with pytest.raises(RequestLimitError) as request_error:
        HarnessRequest(
            task="task",
            user_id="user",
            workspace_id="workspace",
            inputs=[ref, ref, ref],
        )
    with pytest.raises(RequestLimitError) as action_error:
        ProposedAction(
            tool_name="tool",
            target="target",
            payload={},
            side_effect_level=SideEffect.NONE,
            payload_sources=[ref, ref, ref],
        )
    assert request_error.value.limit_enforced == "request_provenance_refs"
    assert action_error.value.limit_enforced == "action_provenance_refs"


def test_action_provenance_aggregate_text_is_bounded(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_PROVENANCE_TEXT_CHARACTERS", 3)
    ref = ContentRef("r", "o", Trust.DERIVED, "h")

    ProposedAction(
        tool_name="tool",
        target="target",
        payload={},
        side_effect_level=SideEffect.NONE,
        payload_sources=[ref],
    )
    with pytest.raises(RequestLimitError, match="action provenance text") as exc:
        ProposedAction(
            tool_name="tool",
            target="target",
            payload={},
            side_effect_level=SideEffect.NONE,
            payload_sources=[ref, ref],
        )
    assert exc.value.limit_enforced == "action_provenance_text_characters"


def test_request_seal_revalidates_mutation_and_sanitizes_failure(monkeypatch):
    request = HarnessRequest(task="task", user_id="user", workspace_id="workspace")
    request.task = "secret-over-limit"
    monkeypatch.setattr(contracts_module, "MAX_REQUEST_TEXT_ITEM_CHARACTERS", 4)

    with pytest.raises(RequestLimitError, match="task exceeds") as exc:
        request.seal_contract()
    assert exc.value.limit_enforced == "request_text_item"
    assert "secret-over-limit" not in str(exc.value)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("sensitivity", "invalid", "invalid"),
        ("budget_limit_usd", "-1", "budget_limit_usd"),
        ("created_at", "2026-01-01T00:00:00", "timezone-aware"),
    ],
)
def test_request_seal_revalidates_mutated_scalar_fields(field, value, message):
    request = HarnessRequest(task="task", user_id="user", workspace_id="workspace")
    setattr(request, field, value)

    with pytest.raises(ValueError, match=message):
        request.seal_contract()


def test_request_seal_detaches_collections_and_freezes_contract_fields():
    allowed_tools = ["read_file"]
    ref = ContentRef("ref", "operator", Trust.TRUSTED, "hash")
    inputs = [ref]
    request = HarnessRequest(
        task="task",
        user_id="user",
        workspace_id="workspace",
        allowed_tools=allowed_tools,
        inputs=inputs,
    )

    request.seal_contract()
    allowed_tools.append("delete_file")
    inputs.clear()

    assert request.allowed_tools == ("read_file",)
    assert request.inputs == (ref,)
    assert request.to_dict()["allowed_tools"] == ["read_file"]
    assert request.to_dict()["inputs"] == [
        {
            "ref_id": "ref",
            "origin": "operator",
            "trust": "trusted",
            "content_hash": "hash",
            "label": "",
        }
    ]
    with pytest.raises(ValueError, match="sealed request"):
        request.workspace_id = "changed"
    with pytest.raises(ValueError, match="sealed request"):
        request._contract_sealed = False


def test_action_rejects_negative_or_nonfinite_cost():
    for value in ("-1", float("nan"), float("inf")):
        with pytest.raises(ValueError):
            ProposedAction(
                tool_name="spend",
                target="vendor",
                payload={"amount_usd": value},
                side_effect_level=SideEffect.SPEND,
                estimated_cost_usd=value,
            )


def test_decimal_serialization_is_stable_and_string_safe():
    value = {"amount": Decimal("0.1000")}
    assert canonical_json(value) == '{"amount":"0.1"}'
    assert canonical_json(value) == canonical_json(value)


@pytest.mark.parametrize(
    "value",
    [
        {"text": "hello \u2603\n", "items": [1, True, None]},
        {"amount": Decimal("0.1000")},
        {"effect": SideEffect.EXTERNAL_SEND},
        ("tuple", {"nested": "value"}),
        {1: "integer key"},
        {False: "boolean key"},
        {None: "null key"},
        {1.25: "float key"},
    ],
)
def test_bounded_action_hash_preserves_canonical_hashes(value):
    assert action_sha256_of(value) == sha256_of(value)


def test_action_hash_accepts_exact_canonical_byte_limit(monkeypatch):
    value = {"x": "y"}
    exact = len(canonical_json(value).encode("utf-8"))
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_CANONICAL_BYTES", exact)

    assert action_sha256_of(value) == sha256_of(value)

    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_CANONICAL_BYTES", exact - 1)
    with pytest.raises(ActionHashLimitError, match="canonical hash input") as exc:
        action_sha256_of(value)
    assert exc.value.limit_enforced == "action_hash_canonical_bytes"


@pytest.mark.parametrize(
    "value",
    [
        [],
        {},
        [True, False, None, -12, 1.25],
        {"escaped": "\x00😀"},
        {1: "integer key"},
        {False: "boolean key"},
        {None: "null key"},
        {1.25: "float key"},
        {"amount": Decimal("0.1000")},
        {"nested": [{"x": "y"}, ()]},
    ],
)
def test_action_hash_preflight_matches_exact_encoder_size(value, monkeypatch):
    exact = len(canonical_json(value).encode("utf-8"))
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_CANONICAL_BYTES", exact)

    assert action_sha256_of(value) == sha256_of(value)

    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_CANONICAL_BYTES", exact - 1)
    with pytest.raises(ActionHashLimitError) as exc:
        action_sha256_of(value)
    assert exc.value.limit_enforced == "action_hash_canonical_bytes"


def test_action_hash_rejects_aggregate_bytes_before_encoder(monkeypatch):
    value = ["1234", "5678"]
    exact = len(canonical_json(value).encode("utf-8"))
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_CANONICAL_BYTES", exact - 1)

    def unexpected_encode(*args, **kwargs):
        raise AssertionError("JSON encoder must not receive oversized value")

    monkeypatch.setattr(
        contracts_module.json.JSONEncoder, "iterencode", unexpected_encode
    )
    with pytest.raises(ActionHashLimitError, match="canonical hash input") as exc:
        action_sha256_of(value)

    assert exc.value.limit_enforced == "action_hash_canonical_bytes"


def test_action_hash_rejects_next_depth_without_echoing_content(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_NESTING_DEPTH", 2)
    accepted = [["secret-at-limit"]]
    rejected = [[["secret-over-limit"]]]

    assert action_sha256_of(accepted) == sha256_of(accepted)
    with pytest.raises(ActionHashLimitError, match="maximum nesting depth") as exc:
        action_sha256_of(rejected)
    assert exc.value.limit_enforced == "action_hash_nesting_depth"
    assert "secret-over-limit" not in str(exc.value)


def test_action_hash_rejects_excess_nodes_before_encoding(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_NODES", 3)

    assert action_sha256_of({"x": "y"}) == sha256_of({"x": "y"})
    with pytest.raises(ActionHashLimitError, match="maximum node count") as exc:
        action_sha256_of({"x": "y", "z": "blocked"})
    assert exc.value.limit_enforced == "action_hash_nodes"


def test_action_hash_accepts_exact_mapping_entries_and_rejects_next(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_MAPPING_ENTRIES", 2)

    accepted = {"b": 2, "a": 1}
    assert action_sha256_of(accepted) == sha256_of(accepted)

    with pytest.raises(ActionHashLimitError, match="mapping exceeds") as exc:
        action_sha256_of({"a": 1, "b": 2, "secret": 3})

    assert exc.value.limit_enforced == "action_hash_mapping_entries"
    assert "secret" not in str(exc.value)


def test_action_hash_rejects_mapping_before_traversal_or_encoding(monkeypatch):
    class StrandedMapping(dict):
        def items(self):
            raise AssertionError("oversized mapping must not be traversed")

    value = StrandedMapping({"a": 1, "b": 2, "secret": 3})
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_MAPPING_ENTRIES", 2)

    def unexpected_encode(*args, **kwargs):
        raise AssertionError("JSON encoder must not receive oversized mapping")

    monkeypatch.setattr(
        contracts_module.json.JSONEncoder, "iterencode", unexpected_encode
    )
    with pytest.raises(ActionHashLimitError) as exc:
        action_sha256_of(value)

    assert exc.value.limit_enforced == "action_hash_mapping_entries"
    assert "secret" not in str(exc.value)


def test_action_hash_mapping_limit_applies_to_each_nested_mapping(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_MAPPING_ENTRIES", 2)

    assert action_sha256_of({"outer": {"a": 1, "b": 2}}) == sha256_of(
        {"outer": {"a": 1, "b": 2}}
    )
    with pytest.raises(ActionHashLimitError) as exc:
        action_sha256_of({"outer": {"a": 1, "b": 2, "c": 3}})

    assert exc.value.limit_enforced == "action_hash_mapping_entries"


def test_action_hash_accepts_exact_mapping_sort_work_and_rejects_next(monkeypatch):
    value = {"aa": 1, "bb": 2}
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS", 8)

    assert action_sha256_of(value) == sha256_of(value)

    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS", 7)
    with pytest.raises(ActionHashLimitError, match="mapping sort work") as exc:
        action_sha256_of(value)

    assert exc.value.limit_enforced == "action_hash_mapping_sort_work_units"


def test_action_hash_mapping_sort_work_scales_with_comparison_rounds(monkeypatch):
    value = {"a": 1, "b": 2, "c": 3, "d": 4}
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS", 24)

    assert action_sha256_of(value) == sha256_of(value)

    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS", 23)
    with pytest.raises(ActionHashLimitError) as exc:
        action_sha256_of(value)

    assert exc.value.limit_enforced == "action_hash_mapping_sort_work_units"


@pytest.mark.parametrize(
    ("value", "exact"),
    [
        ({1: "a", 22: "b"}, 7),
        ({False: "a", True: "b"}, 13),
        ({1.25: "a", 2.5: "b"}, 11),
        ({"é": "a", "😀": "b"}, 22),
    ],
)
def test_action_hash_mapping_sort_work_uses_exact_canonical_key_widths(
    value, exact, monkeypatch
):
    monkeypatch.setattr(
        contracts_module, "MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS", exact
    )
    assert action_sha256_of(value) == sha256_of(value)

    monkeypatch.setattr(
        contracts_module, "MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS", exact - 1
    )
    with pytest.raises(ActionHashLimitError) as exc:
        action_sha256_of(value)

    assert exc.value.limit_enforced == "action_hash_mapping_sort_work_units"


def test_action_hash_mapping_sort_work_is_aggregate_and_pre_encoder(monkeypatch):
    value = {"x": {"a": 1, "b": 2}, "y": {"c": 3, "d": 4}}
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS", 18)
    assert action_sha256_of(value) == sha256_of(value)

    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS", 17)

    def unexpected_encode(*args, **kwargs):
        raise AssertionError("JSON encoder must not receive over-budget mapping")

    monkeypatch.setattr(
        contracts_module.json.JSONEncoder, "iterencode", unexpected_encode
    )
    with pytest.raises(ActionHashLimitError) as exc:
        action_sha256_of(value)

    assert exc.value.limit_enforced == "action_hash_mapping_sort_work_units"


def test_action_hash_single_entry_mapping_requires_no_sort_work(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS", 0)
    value = {"only": "value"}

    assert action_sha256_of(value) == sha256_of(value)


def test_action_hash_accepts_existing_sortable_mapping_key_families():
    class NumericKey(IntEnum):
        THREE = 3

    class TextKey(str, Enum):
        BETA = "beta"

    values = [
        {"b": 1, "a": 2},
        {False: 1, 1.5: 2, 2: 3, NumericKey.THREE: 4},
        {TextKey.BETA: 1, "alpha": 2},
        {None: "single null key"},
    ]

    for value in values:
        assert action_sha256_of(value) == sha256_of(value)


def test_action_hash_rejects_mixed_key_families_before_values_or_encoder(
    monkeypatch,
):
    class GuardedMapping(dict):
        def items(self):
            raise AssertionError("invalid mapping values must not be traversed")

    value = GuardedMapping({"secret-text-key": object(), 2: object()})

    def unexpected_encode(*args, **kwargs):
        raise AssertionError("JSON encoder must not receive invalid mapping keys")

    monkeypatch.setattr(
        contracts_module.json.JSONEncoder, "iterencode", unexpected_encode
    )
    with pytest.raises(ValueError, match="not canonical JSON data") as exc:
        action_sha256_of(value)

    assert "secret-text-key" not in str(exc.value)


def test_action_hash_rejects_unsupported_keys_before_values_or_encoder(monkeypatch):
    class PlainKey(Enum):
        VALUE = "enum-secret"

    class GuardedMapping(dict):
        def items(self):
            raise AssertionError("unsupported mapping values must not be traversed")

    def unexpected_encode(*args, **kwargs):
        raise AssertionError("JSON encoder must not receive unsupported mapping keys")

    monkeypatch.setattr(
        contracts_module.json.JSONEncoder, "iterencode", unexpected_encode
    )
    for key in (Decimal("1"), PlainKey.VALUE, object()):
        with pytest.raises(ValueError, match="not canonical JSON data") as exc:
            action_sha256_of(GuardedMapping({key: object()}))
        assert "secret" not in str(exc.value)


@pytest.mark.parametrize(
    ("constant", "maximum", "entries", "limit_enforced"),
    [
        (
            "MAX_ACTION_HASH_SCALAR_CHARACTERS",
            4,
            [("safe", object()), ("secret-key", 1)],
            "action_hash_scalar_characters",
        ),
        (
            "MAX_ACTION_HASH_STRING_TOKEN_BYTES",
            8,
            [("a", object()), ("😀", 1)],
            "action_hash_string_token_bytes",
        ),
        (
            "MAX_ACTION_HASH_NUMBER_CHARACTERS",
            2,
            [(1, object()), (100, 1)],
            "action_hash_number_characters",
        ),
    ],
)
def test_action_hash_validates_every_key_token_before_mapping_values(
    monkeypatch, constant, maximum, entries, limit_enforced
):
    class GuardedMapping(dict):
        def items(self):
            raise AssertionError(
                "mapping values must not precede complete key preflight"
            )

    value = GuardedMapping(entries)
    monkeypatch.setattr(contracts_module, constant, maximum)

    def unexpected_encode(*args, **kwargs):
        raise AssertionError("JSON encoder must not receive an invalid mapping key")

    monkeypatch.setattr(
        contracts_module.json.JSONEncoder, "iterencode", unexpected_encode
    )
    with pytest.raises(ActionHashLimitError) as exc:
        action_sha256_of(value)

    assert exc.value.limit_enforced == limit_enforced
    assert "secret" not in str(exc.value)


def test_action_hash_validates_all_numeric_keys_before_mapping_values(monkeypatch):
    class GuardedMapping(dict):
        def items(self):
            raise AssertionError(
                "mapping values must not precede complete key preflight"
            )

    value = GuardedMapping([(1.0, object()), (float("inf"), 1)])

    def unexpected_encode(*args, **kwargs):
        raise AssertionError("JSON encoder must not receive a non-finite mapping key")

    monkeypatch.setattr(
        contracts_module.json.JSONEncoder, "iterencode", unexpected_encode
    )
    with pytest.raises(ValueError, match="non-finite number"):
        action_sha256_of(value)


def test_action_hash_accounts_all_key_sort_work_before_mapping_values(monkeypatch):
    class GuardedMapping(dict):
        def items(self):
            raise AssertionError(
                "mapping values must not precede complete key preflight"
            )

    value = GuardedMapping([("a", object()), ("bb", 1)])
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS", 6)

    def unexpected_encode(*args, **kwargs):
        raise AssertionError("JSON encoder must not receive an over-budget mapping")

    monkeypatch.setattr(
        contracts_module.json.JSONEncoder, "iterencode", unexpected_encode
    )
    with pytest.raises(ActionHashLimitError) as exc:
        action_sha256_of(value)

    assert exc.value.limit_enforced == "action_hash_mapping_sort_work_units"


def test_action_hash_encodes_the_validated_snapshot_when_caller_mutates(monkeypatch):
    value = {"safe": ["before"]}
    expected = sha256_of(value)
    original_iterencode = contracts_module.json.JSONEncoder.iterencode

    def mutate_caller_before_encoding(encoder, snapshot, *args, **kwargs):
        assert snapshot is not value
        assert type(snapshot) is dict
        assert type(snapshot["safe"]) is list
        value["late"] = {"unvalidated": "mutation"}
        value["safe"].append("mutation")
        return original_iterencode(encoder, snapshot, *args, **kwargs)

    monkeypatch.setattr(
        contracts_module.json.JSONEncoder,
        "iterencode",
        mutate_caller_before_encoding,
    )

    assert action_sha256_of(value) == expected


def test_action_hash_snapshots_builtin_container_storage_without_subclass_hooks():
    class HostileMapping(dict):
        def items(self):
            raise AssertionError("mapping subclass iteration must not run")

        def __iter__(self):
            raise AssertionError("mapping subclass iteration must not run")

    class HostileList(list):
        def __iter__(self):
            raise AssertionError("list subclass iteration must not run")

    class HostileTuple(tuple):
        def __iter__(self):
            raise AssertionError("tuple subclass iteration must not run")

    value = HostileMapping(
        {
            "list": HostileList([1, {"nested": "value"}]),
            "tuple": HostileTuple((True, None)),
        }
    )
    expected = {
        "list": [1, {"nested": "value"}],
        "tuple": (True, None),
    }

    assert action_sha256_of(value) == sha256_of(expected)


def test_action_hash_snapshots_enum_values_before_encoding(monkeypatch):
    class MutableValue(Enum):
        PAYLOAD = ["before"]

    value = {"enum": MutableValue.PAYLOAD}
    expected = sha256_of(value)
    original_iterencode = contracts_module.json.JSONEncoder.iterencode

    def mutate_enum_before_encoding(encoder, snapshot, *args, **kwargs):
        MutableValue.PAYLOAD.value.append("mutation")
        return original_iterencode(encoder, snapshot, *args, **kwargs)

    monkeypatch.setattr(
        contracts_module.json.JSONEncoder,
        "iterencode",
        mutate_enum_before_encoding,
    )

    assert action_sha256_of(value) == expected


def test_action_hash_sanitizes_mapping_mutation_during_snapshot():
    value = {}

    class MutatingKey(str):
        def __len__(self):
            value["secret-added-during-snapshot"] = 2
            return str.__len__(self)

    value[MutatingKey("key")] = 1

    with pytest.raises(ValueError, match="changed during canonical snapshot") as exc:
        action_sha256_of(value)

    assert "secret" not in str(exc.value)


def test_action_hash_rejects_oversized_scalar_before_encoding(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_SCALAR_CHARACTERS", 4)

    assert action_sha256_of("1234") == sha256_of("1234")
    with pytest.raises(ActionHashLimitError, match="scalar exceeds") as exc:
        action_sha256_of("secret")
    assert exc.value.limit_enforced == "action_hash_scalar_characters"
    assert "secret" not in str(exc.value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "plain ASCII",
        'quote " and backslash \\',
        "line\nbreak",
        "\x00\x1f\x7f",
        "café",
        "😀",
    ],
)
def test_action_hash_string_preflight_preserves_canonical_hashes(value, monkeypatch):
    exact = len(canonical_json(value).encode("utf-8"))
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_STRING_TOKEN_BYTES", exact)

    assert action_sha256_of(value) == sha256_of(value)

    monkeypatch.setattr(
        contracts_module, "MAX_ACTION_HASH_STRING_TOKEN_BYTES", exact - 1
    )
    with pytest.raises(ActionHashLimitError, match="canonical string token") as exc:
        action_sha256_of(value)
    assert exc.value.limit_enforced == "action_hash_string_token_bytes"


def test_action_hash_rejects_expanded_string_before_encoder(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_STRING_TOKEN_BYTES", 13)

    def unexpected_encode(*args, **kwargs):
        raise AssertionError("JSON encoder must not receive oversized string")

    monkeypatch.setattr(
        contracts_module.json.JSONEncoder, "iterencode", unexpected_encode
    )
    with pytest.raises(ActionHashLimitError) as exc:
        action_sha256_of("😀secret")

    assert exc.value.limit_enforced == "action_hash_string_token_bytes"
    assert "secret" not in str(exc.value)


def test_action_hash_accepts_exact_integer_tokens_and_rejects_next(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_NUMBER_CHARACTERS", 4)

    for value in (9999, -999):
        assert action_sha256_of(value) == sha256_of(value)

    for value in (10000, -1000):
        with pytest.raises(ActionHashLimitError, match="canonical number") as exc:
            action_sha256_of(value)
        assert exc.value.limit_enforced == "action_hash_number_characters"


def test_action_hash_bounds_decimal_before_large_exponent_rendering(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_NUMBER_CHARACTERS", 4)

    exact = Decimal("1E+3")
    assert action_sha256_of(exact) == sha256_of(exact)
    with pytest.raises(ActionHashLimitError, match="canonical number") as exc:
        action_sha256_of(Decimal("1E+1000000"))

    assert exc.value.limit_enforced == "action_hash_number_characters"
    assert "1000000" not in str(exc.value)


def test_action_hash_refuses_large_fractional_zero_tail_without_rendering():
    trailing_zeros = (0,) * 100_000
    value = Decimal((0, (1,) + trailing_zeros, -100_000))

    with pytest.raises(ActionHashLimitError) as exc:
        action_sha256_of(value)
    assert exc.value.limit_enforced == "action_hash_number_characters"


def test_action_hash_bounds_finite_float_tokens_and_refuses_nonfinite(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_NUMBER_CHARACTERS", 4)

    assert action_sha256_of(1.25) == sha256_of(1.25)
    with pytest.raises(ActionHashLimitError) as exc:
        action_sha256_of(10.25)
    assert exc.value.limit_enforced == "action_hash_number_characters"

    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError, match="non-finite"):
            action_sha256_of(value)


def test_action_hash_rejects_cyclic_payload_without_recursing_forever():
    payload = {}
    payload["self"] = payload

    with pytest.raises(ValueError, match="cyclic container"):
        action_sha256_of(payload)


def test_proposed_action_hashes_are_bounded(monkeypatch):
    action = ProposedAction(
        tool_name="custom_tool",
        target="target",
        payload={"body": "oversized"},
        side_effect_level=SideEffect.LOCAL_WRITE,
    )
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_SCALAR_CHARACTERS", 4)

    with pytest.raises(ActionHashLimitError) as payload_error:
        _ = action.payload_hash
    with pytest.raises(ActionHashLimitError) as authorization_error:
        _ = action.authorization_hash
    assert payload_error.value.limit_enforced == "action_hash_scalar_characters"
    assert authorization_error.value.limit_enforced == "action_hash_scalar_characters"


def test_governed_action_seals_one_detached_fingerprint_snapshot(monkeypatch):
    payload = {"nested": {"body": "original"}}
    action = ProposedAction(
        tool_name="custom_tool",
        target="target",
        payload=payload,
        side_effect_level=SideEffect.LOCAL_WRITE,
    )
    calls = 0
    original_hash = contracts_module.action_sha256_of

    def counted_hash(value):
        nonlocal calls
        calls += 1
        return original_hash(value)

    monkeypatch.setattr(contracts_module, "action_sha256_of", counted_hash)
    expected = action.seal_fingerprints()
    payload["nested"]["body"] = "caller mutation"

    assert calls == 2
    assert (action.payload_hash, action.authorization_hash) == expected
    assert calls == 2
    assert action.payload["nested"]["body"] == "original"
    with pytest.raises(ValueError, match="sealed action"):
        action.target = "changed"


def test_live_hash_detects_nested_mutation_after_action_seal():
    action = ProposedAction(
        tool_name="custom_tool",
        target="target",
        payload={"nested": {"body": "original"}},
        side_effect_level=SideEffect.LOCAL_WRITE,
    )
    _, sealed_authorization_hash = action.seal_fingerprints()
    action.payload["nested"]["body"] = "changed"

    assert action.authorization_hash == sealed_authorization_hash
    assert action.current_authorization_hash() != sealed_authorization_hash


def test_authorization_hash_binds_target_and_provenance():
    trusted = ContentRef.of("operator", Trust.TRUSTED, "hello")
    action = ProposedAction(
        tool_name="send_email",
        target="customer@example.com",
        payload={"body": "hello"},
        side_effect_level=SideEffect.EXTERNAL_SEND,
        request_id="req",
        payload_sources=[trusted],
    )
    original = action.authorization_hash
    action.target = "attacker@example.com"
    assert action.authorization_hash != original
    action.target = "customer@example.com"
    action.payload_sources = [ContentRef.of("web", Trust.UNTRUSTED, "hello")]
    assert action.authorization_hash != original


def test_underscore_prefixed_tool_arguments_are_not_omitted_from_hashes():
    action = ProposedAction(
        tool_name="custom_tool",
        target="target",
        payload={"_private_option": "one"},
        side_effect_level=SideEffect.LOCAL_WRITE,
    )
    original = action.authorization_hash
    action.payload["_private_option"] = "two"
    assert action.authorization_hash != original


@pytest.mark.parametrize("field", ["task", "user_id", "workspace_id"])
def test_request_rejects_empty_required_text(field):
    values = {"task": "task", "user_id": "user", "workspace_id": "workspace"}
    values[field] = " "
    with pytest.raises(ValueError, match=field):
        HarnessRequest(**values)


def test_naive_timestamps_are_rejected():
    with pytest.raises(ValueError, match="timezone-aware"):
        HarnessRequest(
            task="task",
            user_id="user",
            workspace_id="workspace",
            created_at="2026-07-25T12:00:00",
        )


def test_timestamps_are_normalized_to_utc():
    request = HarnessRequest(
        task="task",
        user_id="user",
        workspace_id="workspace",
        created_at="2026-07-25T07:00:00-05:00",
    )
    assert request.created_at == "2026-07-25T12:00:00Z"
