"""End-to-end control-loop tests, including the red-team scenarios.

Every scenario named in the S1 scope is here:
  agent wants to send an email / publish a post / read a customer statement /
  export a file / spend above budget / access a blocked folder.
"""

from __future__ import annotations

import re

import pytest

import defiant_agent_harness.policy.engine as policy_engine_module
import defiant_agent_harness.contracts as contracts_module
from defiant_agent_harness.adapters.mock import SCRIPTS, MockAgentAdapter
from defiant_agent_harness.adapters.base import ToolCall
from defiant_agent_harness.authority_profile import (
    AuthorityProfileError,
    AuthorityProfileStore,
)
from defiant_agent_harness.contracts import (
    ActionHashLimitError,
    Decision,
    HarnessRequest,
    ResultStatus,
    SideEffect,
    Trust,
)
from defiant_agent_harness.cli.main import build_parser, main
from defiant_agent_harness.orchestrator.harness import build_harness


def run(tmp_path, scenario, packs=None, budget=25.0, **req_kwargs):
    adapter = MockAgentAdapter(script=SCRIPTS[scenario])
    h = build_harness(
        tmp_path, adapter, policy_packs=packs or [], starting_budget_usd=budget
    )
    req = HarnessRequest(
        task=f"test {scenario}", user_id="tester", workspace_id="ws", **req_kwargs
    )
    return h, req, h.run(req)


# -- the six scoped scenarios ----------------------------------------------


def test_email_is_held_for_approval(tmp_path):
    _, _, [o] = run(tmp_path, "send_email")
    assert o.decision.decision is Decision.APPROVAL_REQUIRED
    assert o.status is ResultStatus.PENDING_APPROVAL
    assert o.approval_id
    assert o.as_tool_outcome().is_error is True


def test_publish_is_held_for_approval(tmp_path):
    _, _, [o] = run(tmp_path, "publish_post")
    assert o.status is ResultStatus.PENDING_APPROVAL


def test_reading_a_statement_runs_freely(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "statement.txt").write_text("Fees: $412.55 interchange")
    import os

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        _, _, [o] = run(tmp_path / "state", "read_statement")
    finally:
        os.chdir(cwd)
    assert o.decision.decision is Decision.ALLOW
    assert o.status is ResultStatus.SUCCEEDED


def test_export_is_held_for_approval(tmp_path):
    _, _, [o] = run(tmp_path, "export_file")
    assert o.status is ResultStatus.PENDING_APPROVAL


def test_spend_above_budget_is_blocked(tmp_path):
    _, _, [o] = run(tmp_path, "overspend", budget=25.0)  # script spends 250
    assert o.status is ResultStatus.BLOCKED
    assert "budget" in o.decision.reason


def test_blocked_folder_is_refused(tmp_path):
    _, _, [o] = run(tmp_path, "blocked_folder")
    assert o.status is ResultStatus.BLOCKED
    assert "outside the approved workspace" in o.decision.reason


def test_delete_is_blocked(tmp_path):
    _, _, [o] = run(tmp_path, "delete")
    assert o.status is ResultStatus.BLOCKED


# -- red team ---------------------------------------------------------------


def test_injected_exfiltration_is_blocked(tmp_path):
    _, _, [o] = run(tmp_path, "injected_exfiltration")
    assert o.status is ResultStatus.BLOCKED
    assert "block_untrusted_side_effect" in o.decision.policy_ids
    assert o.action.payload_trust is Trust.UNTRUSTED


def test_oversized_action_hash_input_fails_before_authority_or_execution(
    tmp_path, monkeypatch
):
    adapter = MockAgentAdapter(
        script=[
            ToolCall(
                name="send_email",
                arguments={"to": "a@example.com", "body": "x" * 33},
            )
        ]
    )
    harness = build_harness(tmp_path, adapter, starting_budget_usd=25)
    request = HarnessRequest(task="oversized", user_id="tester", workspace_id="ws")
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_SCALAR_CHARACTERS", 32)

    with pytest.raises(ActionHashLimitError, match="scalar exceeds") as exc:
        harness.run(request)

    assert exc.value.limit_enforced == "action_hash_scalar_characters"
    assert harness.evidence.records() == []
    assert harness.approvals.list_pending() == []
    assert harness.budget.balance_usd == 25


def test_injected_publish_is_blocked(tmp_path):
    _, _, [o] = run(tmp_path, "injected_publish")
    assert o.status is ResultStatus.BLOCKED


def test_prohibited_merchant_claim_is_blocked(tmp_path):
    _, _, [o] = run(tmp_path, "prohibited_claim", packs=["merchant_services"])
    assert o.status is ResultStatus.BLOCKED
    assert "ms_block_guaranteed_savings" in o.decision.policy_ids


def test_legal_advice_is_blocked(tmp_path):
    _, _, [o] = run(tmp_path, "legal_advice", packs=["legal_intake"])
    assert o.status is ResultStatus.BLOCKED


def test_request_scope_narrows_beyond_policy(tmp_path):
    _, _, [o] = run(tmp_path, "send_email", allowed_tools=["read_file"])
    assert o.status is ResultStatus.BLOCKED
    assert "allowed_tools" in o.decision.reason


# -- approve / reject resume ------------------------------------------------


def test_approving_completes_the_action(tmp_path):
    h, _, [o] = run(tmp_path, "send_email")
    resumed = h.resume(o.approval_id, True, "sam")
    assert resumed.status is ResultStatus.SUCCEEDED
    rec = h.evidence.get(resumed.evidence_record_id)
    assert rec["approved_by"] == "sam"
    assert rec["approved_at"]


def test_rejecting_stops_the_action(tmp_path):
    h, _, [o] = run(tmp_path, "send_email")
    resumed = h.resume(o.approval_id, False, "sam", note="wrong recipient")
    assert resumed.status is ResultStatus.REJECTED


def test_approval_cannot_be_replayed(tmp_path):
    h, _, [o] = run(tmp_path, "send_email")
    h.resume(o.approval_id, True, "sam")
    with pytest.raises(Exception):
        h.resume(o.approval_id, True, "sam")


def test_approved_action_resumes_after_process_restart(tmp_path):
    first, _, [pending] = run(tmp_path, "send_email")
    assert first.approvals.get(pending.approval_id).status == "pending"

    reopened = build_harness(tmp_path, MockAgentAdapter())
    resumed = reopened.resume(pending.approval_id, True, "sam")

    assert resumed.status is ResultStatus.SUCCEEDED
    stored = reopened.approvals.get(pending.approval_id)
    assert stored.status == "consumed"
    assert stored.execution_record_id == resumed.evidence_record_id


def test_changed_policy_ruleset_voids_stale_approval(tmp_path):
    _, _, [pending] = run(tmp_path, "send_email")
    with pytest.raises(AuthorityProfileError, match="does not match") as mismatch:
        build_harness(
            tmp_path,
            MockAgentAdapter(),
            policy_packs=["merchant_services"],
        )
    match = re.search(r"configured (sha256:[0-9a-f]{64})", str(mismatch.value))
    assert match is not None
    AuthorityProfileStore(tmp_path / "authority_profile.json").request_rotation(
        match.group(1),
        operator="test-operator",
        note="authorize policy pack test",
        operator_trust=None,
    )
    reopened = build_harness(
        tmp_path,
        MockAgentAdapter(),
        policy_packs=["merchant_services"],
    )
    resumed = reopened.resume(pending.approval_id, True, "sam")
    assert resumed.status is ResultStatus.BLOCKED
    assert resumed.decision.policy_ids == ["policy_changed"]


def test_rejected_action_releases_reservation_after_restart(tmp_path):
    first, _, [pending] = run(tmp_path, "overspend", budget=500)
    assert first.budget.reservation_for(pending.action.action_id) == 250
    reopened = build_harness(tmp_path, MockAgentAdapter())
    resumed = reopened.resume(pending.approval_id, False, "sam")
    assert resumed.status is ResultStatus.REJECTED
    assert reopened.budget.reservation_for(pending.action.action_id) == 0


def test_operator_reconciles_stranded_execution_with_structured_evidence(tmp_path):
    h, _, [pending] = run(tmp_path, "overspend", budget=500)
    h.approvals.decide(pending.approval_id, True, "reviewer", "approved")
    h.approvals.begin_execution(pending.approval_id, pending.action)

    reconciled = h.reconcile_execution(
        pending.approval_id,
        "failed",
        "operator-7",
        "provider accepted request but returned no result",
    )

    stored = h.approvals.get(pending.approval_id)
    evidence = h.evidence.get(reconciled.evidence_record_id)
    assert reconciled.status is ResultStatus.FAILED
    assert stored.status == "consumed"
    assert stored.reconciliation_outcome == "failed"
    assert stored.reconciled_by == "operator-7"
    assert stored.reconciliation_completed_at
    assert h.budget.reservation_for(pending.action.action_id) == 0
    assert h.budget.summary()["total_spent_usd"] == "250"
    assert evidence["reconciliation_outcome"] == "failed"
    assert evidence["reconciled_by"] == "operator-7"
    assert evidence["reconciliation_note"]


def test_not_executed_operator_outcome_releases_stranded_reservation(tmp_path):
    h, _, [pending] = run(tmp_path, "overspend", budget=500)
    h.approvals.decide(pending.approval_id, True, "reviewer")
    h.approvals.begin_execution(pending.approval_id, pending.action)

    reconciled = h.reconcile_execution(
        pending.approval_id,
        "not_executed",
        "operator-7",
        "worker crashed before dispatch",
    )

    assert reconciled.status is ResultStatus.NOT_EXECUTED
    assert h.budget.summary()["available_usd"] == "500"
    assert h.budget.summary()["total_spent_usd"] == "0"


def test_known_result_recovery_finishes_crash_after_evidence_without_replay(
    tmp_path,
):
    h, _, [pending] = run(tmp_path, "overspend", budget=500)

    def crash_before_consumption(*_args, **_kwargs):
        raise RuntimeError("simulated crash before approval consumption")

    h.approvals.ensure_consumed = crash_before_consumption
    with pytest.raises(RuntimeError, match="simulated crash"):
        h.resume(pending.approval_id, True, "reviewer", "approved")

    assert h.approvals.get(pending.approval_id).status == "executing"
    before_records = len(h.evidence.records())
    before_spend = h.budget.summary()["total_spent_usd"]
    reopened = build_harness(tmp_path, MockAgentAdapter())

    assert len(reopened.evidence.records()) == before_records
    assert reopened.budget.summary()["total_spent_usd"] == before_spend
    assert reopened.approvals.get(pending.approval_id).status == "consumed"
    with pytest.raises(Exception, match="consumed"):
        reopened.reconcile_execution(
            pending.approval_id, "succeeded", "operator-7", "checked provider logs"
        )


def test_reconciliation_retry_finishes_crash_after_budget_without_double_charge(
    tmp_path,
):
    h, _, [pending] = run(tmp_path, "overspend", budget=500)
    h.approvals.decide(pending.approval_id, True, "reviewer")
    h.approvals.begin_execution(pending.approval_id, pending.action)

    def crash_before_evidence(*_args, **_kwargs):
        raise RuntimeError("simulated crash before reconciliation evidence")

    h._record = crash_before_evidence
    with pytest.raises(RuntimeError, match="simulated crash"):
        h.reconcile_execution(
            pending.approval_id, "failed", "operator-7", "provider outcome unknown"
        )
    assert h.budget.summary()["total_spent_usd"] == "250"

    reopened = build_harness(tmp_path, MockAgentAdapter())
    reconciled = reopened.reconcile_execution(
        pending.approval_id, "failed", "operator-7", "provider outcome unknown"
    )

    assert reconciled.status is ResultStatus.FAILED
    assert reopened.budget.summary()["total_spent_usd"] == "250"
    assert reopened.approvals.get(pending.approval_id).status == "consumed"


def test_reconcile_cli_requires_and_records_explicit_operator_outcome_and_note(
    tmp_path, capsys
):
    h, _, [pending] = run(tmp_path, "overspend", budget=500)
    h.approvals.decide(pending.approval_id, True, "reviewer")
    h.approvals.begin_execution(pending.approval_id, pending.action)

    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["--workdir", str(tmp_path), "reconcile", pending.approval_id]
        )

    exit_code = main(
        [
            "--workdir",
            str(tmp_path),
            "reconcile",
            pending.approval_id,
            "--outcome",
            "not_executed",
            "--operator",
            "operator-7",
            "--note",
            "worker never dispatched",
        ]
    )

    assert exit_code == 0
    assert "reconciled by operator-7" in capsys.readouterr().out
    stored = h.approvals.get(pending.approval_id)
    assert stored.reconciliation_outcome == "not_executed"
    assert stored.reconciled_by == "operator-7"
    assert stored.reconciliation_note == "worker never dispatched"


def test_adapter_cannot_downgrade_send_email_to_no_side_effect(tmp_path):
    class LyingAdapter(MockAgentAdapter):
        tool_side_effects = dict(MockAgentAdapter.tool_side_effects)
        tool_side_effects["send_email"] = SideEffect.NONE

    adapter = LyingAdapter(script=SCRIPTS["send_email"])
    harness = build_harness(tmp_path, adapter)
    request = HarnessRequest(task="test", user_id="tester", workspace_id="ws")
    [outcome] = harness.run(request)
    assert outcome.status is ResultStatus.BLOCKED
    assert outcome.decision.policy_ids == ["tool_contract"]


@pytest.mark.parametrize(
    "target",
    [
        "workspace/../secret.txt",
        "../secret.txt",
        "workspace\\..\\secret.txt",
        "/etc/passwd",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:relative\\secret.txt",
        "\\\\server\\share\\secret.txt",
        "\\\\?\\C:\\Windows\\secret.txt",
    ],
)
def test_file_targets_cannot_escape_workspace(tmp_path, target):
    adapter = MockAgentAdapter(script=[ToolCall("read_file", {"path": target})])
    harness = build_harness(
        tmp_path / "state",
        adapter,
        workspace_root=tmp_path / "workspace",
    )
    request = HarnessRequest(task="read", user_id="tester", workspace_id="ws")
    [outcome] = harness.run(request)
    assert outcome.status is ResultStatus.BLOCKED
    assert outcome.decision.policy_ids == ["tool_contract"]


def test_v01_write_tool_is_simulated_and_does_not_touch_disk(tmp_path):
    adapter = MockAgentAdapter(
        script=[
            ToolCall(
                "write_file",
                {"path": "workspace/report.txt", "content": "sensitive"},
            )
        ]
    )
    workspace = tmp_path / "workspace"
    harness = build_harness(
        tmp_path / "state",
        adapter,
        workspace_root=workspace,
    )
    request = HarnessRequest(task="write", user_id="tester", workspace_id="ws")
    [outcome] = harness.run(request)
    assert outcome.status is ResultStatus.SUCCEEDED
    assert outcome.result.output["simulated"] is True
    assert not (workspace / "report.txt").exists()


# -- evidence properties ----------------------------------------------------


def test_every_outcome_produces_evidence(tmp_path):
    for scenario in ["send_email", "blocked_folder", "delete", "injected_exfiltration"]:
        h, req, outcomes = run(tmp_path / scenario, scenario)
        recs = h.evidence.by_request(req.request_id)
        assert recs, f"{scenario} produced no evidence"
        assert h.evidence.verify().ok


def test_blocked_actions_are_recorded_too(tmp_path):
    h, req, [o] = run(tmp_path, "blocked_folder")
    rec = h.evidence.get(o.evidence_record_id)
    assert rec["decision"] == "block"
    assert rec["result_status"] == "blocked"
    assert rec["decision_reason"]
    assert rec["ruleset_hash"]


def test_evidence_carries_replay_inputs(tmp_path):
    h, _, [o] = run(tmp_path, "send_email")
    rec = h.evidence.get(o.evidence_record_id)
    assert rec["decision_inputs"]["payload_hash"] == o.action.payload_hash
    assert rec["policy_version"]
    assert rec["ruleset_hash"].startswith("sha256:")


def test_evidence_contains_no_raw_payload(tmp_path):
    """Evidence is shareable: hashes and decisions, not client content."""
    h, _, [o] = run(tmp_path, "send_email")
    blob = str(h.evidence.get(o.evidence_record_id))
    assert "plain-English summary" not in blob


def test_policy_payload_match_limit_blocks_and_records_sanitized_evidence(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_MATCH_PAYLOAD_CHARACTERS", 10)
    policy = tmp_path / "bounded-payload.yaml"
    policy.write_text(
        """version: test
rules:
  - id: inspect_payload
    tools: [send_email]
    payload_contains: [not-present]
    effect: allow
""",
        encoding="utf-8",
    )
    state = tmp_path / "state"

    harness, _, [outcome] = run(
        state,
        "send_email",
        packs=[str(policy)],
    )

    assert outcome.status is ResultStatus.BLOCKED
    assert outcome.decision.policy_ids == ["policy_match_limit"]
    assert outcome.approval_id == ""
    record = harness.evidence.get(outcome.evidence_record_id)
    assert record["result_status"] == "blocked"
    assert record["decision_inputs"]["limit_enforced"] == "policy_payload_matching"
    assert "plain-English summary" not in repr(record)
    assert harness.evidence.verify().ok


def test_policy_glob_match_limit_blocks_and_records_sanitized_evidence(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_MATCH_TARGET_CHARACTERS", 5)
    policy = tmp_path / "bounded-glob.yaml"
    policy.write_text(
        """version: test
rules:
  - id: inspect_target
    tools: [send_email]
    targets: ['*']
    effect: allow
""",
        encoding="utf-8",
    )
    state = tmp_path / "state"

    harness, _, [outcome] = run(
        state,
        "send_email",
        packs=[str(policy)],
    )

    assert outcome.status is ResultStatus.BLOCKED
    assert outcome.decision.policy_ids == ["policy_match_limit"]
    assert outcome.approval_id == ""
    record = harness.evidence.get(outcome.evidence_record_id)
    assert record["result_status"] == "blocked"
    assert record["decision_inputs"]["limit_enforced"] == "policy_glob_matching"
    assert "merchant@example.com" not in outcome.decision.reason
    assert "merchant@example.com" not in repr(outcome.decision.decision_inputs)
    assert record["target"] == "merchant@example.com"
    assert harness.evidence.verify().ok


def test_chain_holds_across_a_mixed_session(tmp_path):
    h, req, _ = run(tmp_path, "send_email")
    for scenario in ["blocked_folder", "delete", "injected_exfiltration"]:
        h.adapter.script = SCRIPTS[scenario]
        h.run(HarnessRequest(task=scenario, user_id="t", workspace_id="ws"))
    status = h.evidence.verify()
    assert status.ok
    assert status.count >= 4


# -- dry run ----------------------------------------------------------------


def test_dry_run_executes_nothing(tmp_path):
    adapter = MockAgentAdapter(script=SCRIPTS["send_email"])
    h = build_harness(tmp_path, adapter, dry_run=True)
    req = HarnessRequest(task="dry", user_id="t", workspace_id="ws")
    [o] = h.run(req)
    resumed = h.resume(o.approval_id, True, "sam")
    assert resumed.result.dry_run
    assert "DRY RUN" in resumed.result.summary
    assert h.evidence.get(resumed.evidence_record_id)["dry_run"] is True


def test_dry_run_approval_cannot_be_reused_for_live_execution(tmp_path):
    adapter = MockAgentAdapter(script=SCRIPTS["send_email"])
    dry = build_harness(tmp_path, adapter, dry_run=True)
    request = HarnessRequest(task="dry", user_id="t", workspace_id="ws")
    [pending] = dry.run(request)

    with pytest.raises(RuntimeError, match="authority profile does not match"):
        build_harness(tmp_path, MockAgentAdapter(), dry_run=False)
