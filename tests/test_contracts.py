from __future__ import annotations

from decimal import Decimal

import pytest

import defiant_agent_harness.contracts as contracts_module

from defiant_agent_harness.contracts import (
    ActionHashLimitError,
    ContentRef,
    HarnessRequest,
    ProposedAction,
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


def test_action_hash_rejects_oversized_scalar_before_encoding(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_SCALAR_CHARACTERS", 4)

    assert action_sha256_of("1234") == sha256_of("1234")
    with pytest.raises(ActionHashLimitError, match="scalar exceeds") as exc:
        action_sha256_of("secret")
    assert exc.value.limit_enforced == "action_hash_scalar_characters"
    assert "secret" not in str(exc.value)


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
