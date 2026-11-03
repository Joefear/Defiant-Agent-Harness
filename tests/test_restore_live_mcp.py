"""S7 opt-in restore across one actual write to the pinned real MCP server."""

import os
import json
import re

import pytest

from defiant_agent_harness.approvals.store import ApprovalStore
from defiant_agent_harness.backup import snapshot
from defiant_agent_harness.budgets.ledger import BudgetLedger
from defiant_agent_harness.state_integrity import StateIntegrityAuditor
from defiant_agent_harness.persistence import PersistenceError
from test_process_kill_recovery import Client, Run, real_package as real_package


@pytest.mark.skipif(
    os.environ.get("DAH_LIVE_MCP") != "1",
    reason="set DAH_LIVE_MCP=1 for real pinned MCP restore proof",
)
def test_real_write_across_restore(tmp_path, real_package):
    run = Run(tmp_path, real_package)
    original = run.state
    try:
        first = Client(run, instrument=False)
        first.initialize()
        pending = first.request("tools/call", run.params)["result"]["_defiant"]
        assert pending["status"] == "pending_approval"
        approval_id = pending["approval_id"]
        decision = run.cli(
            "approve", approval_id, "--note", "S7 approve exactly one synthetic write"
        )
        assert decision.returncode == 0, decision.stderr
        assert run.arrivals() == []
        with pytest.raises(PersistenceError, match="busy"):
            snapshot(
                original,
                tmp_path / "must-not-exist",
                workspace=run.workspace,
                operator="s7-operator",
                note="Attempted while real proxy is idle",
            )
        assert not (tmp_path / "must-not-exist").exists()
        first.close()
        run.clients.remove(first)
        run.drain_all(1)
        captured_command = run.cli(
            "--workspace-root",
            str(run.workspace),
            "snapshot",
            "--output",
            str(tmp_path / "snapshot"),
            "--operator",
            "s7-operator",
            "--note",
            "Proxy stopped; first real upstream EOF and exit observed",
        )
        assert captured_command.returncode == 0, captured_command.stderr
        captured = json.loads(captured_command.stdout)

        second = Client(run, instrument=False)
        second.initialize()
        executed = second.request("tools/call", run.params)["result"]["_defiant"]
        assert executed["status"] == "succeeded"
        second.close()
        run.clients.remove(second)
        run.drain_all(2)
        assert run.arrivals() == [run.params]
        target = run.workspace / "one-action.txt"
        assert target.read_text() == run.params["arguments"]["content"]
        original_bytes = {p.name: p.read_bytes() for p in original.iterdir()}
        restored_command = run.cli(
            "--workspace-root",
            str(run.workspace),
            "restore",
            "--snapshot",
            str(tmp_path / "snapshot"),
            "--target",
            str(tmp_path / "restored"),
            "--expect-manifest-sha256",
            captured["manifest_sha256"],
            "--operator",
            "s7-operator",
            "--note",
            "Both real upstreams exited; original runner retired; actual write retained",
        )
        assert restored_command.returncode == 0, restored_command.stderr
        restored = json.loads(restored_command.stdout)
        run.state = tmp_path / "restored"
        assert restored["uncertain_approval_ids"] == [approval_id]
        assert run.arrivals() == [run.params]
        assert {p.name: p.read_bytes() for p in original.iterdir()} == original_bytes
        assert (
            ApprovalStore(run.state / "approvals.json").get(approval_id).status
            == "executing"
        )
        assert BudgetLedger(run.state / "budget.json").summary()["reserved_usd"] == "5"

        candidate = run.cli(
            "--workspace-root",
            str(run.workspace),
            "mcp-proxy",
            "--config",
            str(run.config),
        )
        assert candidate.returncode != 0
        match = re.search(r"configured (sha256:[0-9a-f]{64})", candidate.stderr)
        assert match, candidate.stderr
        rotation = run.cli(
            "authority-profile-rotate",
            match.group(1),
            "--operator",
            "s7-operator",
            "--note",
            "Explicit S7 restored-root activation",
        )
        assert rotation.returncode == 0, rotation.stderr
        third = Client(run, instrument=False)
        third.initialize()
        refused = third.request("tools/call", run.params)["result"]
        assert refused["_defiant"]["status"] == "failed"
        assert "uncertain" in str(refused).lower()
        assert run.arrivals() == [run.params]
        reconciled = run.cli(
            "--workspace-root",
            str(run.workspace),
            "reconcile",
            approval_id,
            "--outcome",
            "succeeded",
            "--operator",
            "s7-operator",
            "--note",
            "Inspected exact actual file bytes and one real upstream receipt",
        )
        assert reconciled.returncode == 0, reconciled.stderr
        retry = third.request("tools/call", run.params)["result"]["_defiant"]
        assert retry["status"] == "pending_approval"
        assert retry["approval_id"] != approval_id
        third.close()
        run.clients.remove(third)
        run.drain_all(3)
        assert run.arrivals() == [run.params]
        assert target.read_text() == run.params["arguments"]["content"]
        assert (
            BudgetLedger(run.state / "budget.json").summary()["total_spent_usd"] == "5"
        )
        assert (
            StateIntegrityAuditor(run.state, workspace_root=run.workspace)
            .audit()
            .status
            == "healthy"
        )
        assert {p.name: p.read_bytes() for p in original.iterdir()} == original_bytes
    finally:
        for client in run.clients:
            client.close()
