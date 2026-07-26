from __future__ import annotations

from decimal import Decimal

import pytest

from defiant_agent_harness.contracts import (
    ContentRef,
    HarnessRequest,
    ProposedAction,
    SideEffect,
    Trust,
    canonical_json,
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
