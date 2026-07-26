from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from defiant_agent_harness.approvals.store import ApprovalError, ApprovalStore
from defiant_agent_harness.budgets.ledger import BudgetLedger
from defiant_agent_harness.contracts import ProposedAction, SideEffect


def action(payload=None):
    return ProposedAction(
        tool_name="send_email",
        target="a@example.com",
        payload=payload or {"body": "hello"},
        side_effect_level=SideEffect.EXTERNAL_SEND,
        request_id="req_test",
    )


# -- approvals --------------------------------------------------------------


def test_pending_survives_a_restart(tmp_path):
    p = tmp_path / "a.json"
    a = action()
    ApprovalStore(p).create(a, "needs review", "scope", ["r1"])
    reopened = ApprovalStore(p)
    assert len(reopened.list_pending()) == 1


def test_approval_is_single_use(tmp_path):
    s = ApprovalStore(tmp_path / "a.json")
    pending = s.create(action(), "needs review", "scope", ["r1"])
    s.decide(pending.approval_id, True, "sam")
    with pytest.raises(ApprovalError, match="single-use"):
        s.decide(pending.approval_id, True, "sam")


def test_approval_is_bound_to_the_payload(tmp_path):
    s = ApprovalStore(tmp_path / "a.json")
    a = action({"body": "Statement summary attached."})
    pending = s.create(a, "needs review", "scope", ["r1"])
    s.decide(pending.approval_id, True, "sam")

    swapped = action({"body": "Please wire funds to account 1234."})
    swapped.action_id = a.action_id
    with pytest.raises(ApprovalError, match="action changed after approval"):
        s.validate_for(pending.approval_id, swapped)

    # the original still validates
    assert s.validate_for(pending.approval_id, a)


def test_rejected_approval_does_not_authorize(tmp_path):
    s = ApprovalStore(tmp_path / "a.json")
    a = action()
    pending = s.create(a, "needs review", "scope", ["r1"])
    s.decide(pending.approval_id, False, "sam")
    with pytest.raises(ApprovalError, match="rejected, not approved"):
        s.validate_for(pending.approval_id, a)


def test_expired_approval_cannot_be_granted(tmp_path):
    s = ApprovalStore(tmp_path / "a.json", default_ttl_minutes=60)
    a = action()
    pending = s.create(a, "needs review", "scope", ["r1"])
    # force expiry
    p = s.get(pending.approval_id)
    p.expires_at = (
        (datetime.now(timezone.utc) - timedelta(minutes=1))
        .isoformat()
        .replace("+00:00", "Z")
    )
    s._save(p)
    with pytest.raises(ApprovalError, match="expired"):
        s.decide(pending.approval_id, True, "sam")


def test_expired_approvals_drop_out_of_pending(tmp_path):
    s = ApprovalStore(tmp_path / "a.json")
    pending = s.create(action(), "needs review", "scope", ["r1"])
    p = s.get(pending.approval_id)
    p.expires_at = (
        (datetime.now(timezone.utc) - timedelta(minutes=1))
        .isoformat()
        .replace("+00:00", "Z")
    )
    s._save(p)
    assert s.list_pending() == []


# -- budget -----------------------------------------------------------------


def test_preflight_refuses_when_worst_case_exceeds_balance(tmp_path):
    b = BudgetLedger(tmp_path / "b.json", starting_balance_usd=10.0)
    assert b.preflight(5.0).ok
    check = b.preflight(50.0)
    assert not check.ok
    assert "exceeds remaining budget" in check.reason


def test_preflight_respects_per_request_limit(tmp_path):
    b = BudgetLedger(tmp_path / "b.json", starting_balance_usd=100.0)
    check = b.preflight(20.0, request_limit_usd=5.0)
    assert not check.ok
    assert "request's limit" in check.reason


def test_reservation_reduces_available_immediately(tmp_path):
    b = BudgetLedger(tmp_path / "b.json", starting_balance_usd=10.0)
    b.reserve(6.0, "req", "act")
    assert b.balance_usd == pytest.approx(4.0)
    assert not b.preflight(5.0).ok


def test_settle_debits_actual_and_frees_the_reservation(tmp_path):
    b = BudgetLedger(tmp_path / "b.json", starting_balance_usd=10.0)
    b.reserve(6.0, "req", "act")
    remaining = b.settle(2.5, "req", "act")
    assert remaining == pytest.approx(7.5)
    assert b.summary()["total_spent_usd"] == "2.5"


def test_release_returns_money_when_the_action_never_ran(tmp_path):
    b = BudgetLedger(tmp_path / "b.json", starting_balance_usd=10.0)
    b.reserve(6.0, "req", "act")
    assert b.release("req", "act") == Decimal("10")


def test_drift_is_reported_not_hidden(tmp_path):
    b = BudgetLedger(tmp_path / "b.json", starting_balance_usd=100.0)
    b.reserve(1.0, "r", "a")
    b.settle(3.0, "r", "a")  # overran the estimate
    d = b.drift()
    assert d["drift_usd"] == "2"
    assert Decimal(d["drift_pct"]) > 0


def test_ledger_survives_a_restart(tmp_path):
    p = tmp_path / "b.json"
    BudgetLedger(p, starting_balance_usd=10.0).reserve(3.0, "r", "a")
    assert BudgetLedger(p).balance_usd == pytest.approx(7.0)


@pytest.mark.parametrize("value", [-1, "-0.01", float("nan"), float("inf")])
def test_budget_rejects_negative_and_nonfinite_values(tmp_path, value):
    b = BudgetLedger(tmp_path / "b.json", starting_balance_usd=10)
    with pytest.raises(ValueError):
        b.preflight(value)
    with pytest.raises(ValueError):
        b.grant(value)
    with pytest.raises(ValueError):
        b.reserve(value, "req", "act")


def test_reservation_is_bound_to_action_and_request(tmp_path):
    b = BudgetLedger(tmp_path / "b.json", starting_balance_usd=10)
    b.reserve("3.25", "req", "act")
    with pytest.raises(Exception, match="already has a reservation"):
        b.reserve("1", "req", "act")
    with pytest.raises(Exception, match="reservation/request mismatch"):
        b.settle("1", "other-request", "act")


def test_settlement_and_release_require_a_real_reservation(tmp_path):
    b = BudgetLedger(tmp_path / "b.json", starting_balance_usd=10)
    with pytest.raises(Exception, match="has no reservation"):
        b.settle("1", "req", "missing")
    with pytest.raises(Exception, match="has no reservation"):
        b.release("req", "missing")


def test_exact_decimal_arithmetic_avoids_binary_float_drift(tmp_path):
    b = BudgetLedger(tmp_path / "b.json", starting_balance_usd="0.30")
    b.reserve("0.10", "req", "a")
    assert b.balance_usd == Decimal("0.20")
    b.settle("0.10", "req", "a")
    assert b.balance_usd == Decimal("0.20")
