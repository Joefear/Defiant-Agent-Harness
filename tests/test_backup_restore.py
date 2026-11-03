from __future__ import annotations

import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest

from defiant_agent_harness.adapters.mock import MockAgentAdapter, SCRIPTS
from defiant_agent_harness.approvals.store import ApprovalStore
from defiant_agent_harness.authority_profile import (
    AuthorityProfileError,
    AuthorityProfileStore,
)
from defiant_agent_harness.backup import BackupError, snapshot, restore
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import HarnessRequest
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.persistence import PersistenceError
from defiant_agent_harness.runtime_lease import runtime_session, INCOMPLETE_FILE
from defiant_agent_harness.state_integrity import StateIntegrityAuditor


def tree(root):
    return {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}


@pytest.fixture
def setup(tmp_path):
    root, workspace = tmp_path / "state", tmp_path / "workspace"
    workspace.mkdir()
    with runtime_session(root):
        harness = build_harness(
            root,
            MockAgentAdapter(script=SCRIPTS["send_email"]),
            workspace_root=workspace,
        )
    return root, workspace, harness


def capture(setup, tmp_path):
    root, workspace, _ = setup
    destination = tmp_path / "snapshot"
    result = snapshot(
        root,
        destination,
        workspace=workspace,
        operator="operator",
        note="All runners stopped; upstream drained",
    )
    return destination, result["manifest_sha256"]


def recover(setup, source, digest, target):
    root, workspace, _ = setup
    return restore(
        root,
        source,
        target,
        expected_manifest_sha256=digest,
        workspace=workspace,
        operator="operator",
        note="Stopped runners, retired original configuration, checked actual target",
    )


def activate(root, workspace):
    with pytest.raises(AuthorityProfileError, match="configured") as mismatch:
        build_harness(root, MockAgentAdapter(), workspace_root=workspace)
    candidate = re.search(
        r"configured (sha256:[0-9a-f]{64})", str(mismatch.value)
    ).group(1)
    AuthorityProfileStore(root / "authority_profile.json").request_rotation(
        candidate,
        operator="operator",
        note="Activate explicitly reviewed restored root",
        operator_trust=None,
    )
    return build_harness(root, MockAgentAdapter(), workspace_root=workspace)


def approve(harness):
    [outcome] = harness.run(
        HarnessRequest(
            task="synthetic approval", user_id="operator", workspace_id="test"
        )
    )
    assert outcome.approval_id
    harness.approvals.decide(outcome.approval_id, True, "operator", "approve fixture")
    return outcome.approval_id


def test_clean_restore_requires_explicit_activation_and_preserves_original(
    setup, tmp_path
):
    source, digest = capture(setup, tmp_path)
    original = tree(setup[0])
    target = tmp_path / "restored"
    result = recover(setup, source, digest, target)
    assert result["original_preserved"]
    assert tree(setup[0]) == original
    assert not StateIntegrityAuditor(target).audit().safe_to_execute
    restored = activate(target, setup[1])
    assert StateIntegrityAuditor(target).audit().status == "healthy"
    assert restored.evidence.verify().ok
    assert tree(setup[0]) == original


def test_expired_restored_approval_stays_uncertain_until_explicit_reconciliation(
    setup, tmp_path
):
    root, workspace, harness = setup
    approval_id = approve(harness)
    held = harness.approvals.get(approval_id)
    harness.approvals._save(
        held.with_updates(
            expires_at=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        )
    )
    source, digest = capture(setup, tmp_path)
    target = tmp_path / "restored"
    recover(setup, source, digest, target)
    restored = activate(target, workspace)
    uncertain = restored.approvals.get(approval_id)
    assert uncertain.status == "executing"
    assert uncertain.reconciliation_outcome == ""
    assert restored.budget.reservation_for(
        uncertain.action_id
    ) == harness.budget.reservation_for(uncertain.action_id)
    with pytest.raises(Exception, match="uncertain"):
        restored.resume(approval_id, True, "operator")
    for outcome, operator, note in (
        ("", "operator", "checked"),
        ("succeeded", "", "checked"),
        ("succeeded", "operator", ""),
    ):
        with pytest.raises(Exception):
            restored.reconcile_execution(approval_id, outcome, operator, note)
    assert restored.approvals.get(approval_id).status == "executing"
    restored.reconcile_execution(
        approval_id,
        "not_executed",
        "operator",
        "Positive fixture evidence: no tool was dispatched",
    )
    assert StateIntegrityAuditor(target).audit().status == "healthy"


@pytest.mark.parametrize("damage", ["missing", "torn", "digest", "extra", "hardlink"])
def test_invalid_snapshot_never_publishes_or_changes_original(setup, tmp_path, damage):
    source, digest = capture(setup, tmp_path)
    if damage == "missing":
        (source / "budget.json").unlink()
    elif damage == "torn":
        (source / "evidence.jsonl").write_bytes(b'{"torn":')
    elif damage == "digest":
        digest = "sha256:" + "0" * 64
    elif damage == "extra":
        (source / "unexpected").write_text("x")
    else:
        os.link(source / "budget.json", tmp_path / "alias")
    original = tree(setup[0])
    target = tmp_path / "restored"
    with pytest.raises(PersistenceError):
        recover(setup, source, digest, target)
    assert not target.exists()
    assert tree(setup[0]) == original


def test_post_snapshot_authorization_is_refused_without_dropping_it(setup, tmp_path):
    source, digest = capture(setup, tmp_path)
    approval_id = approve(setup[2])
    original = tree(setup[0])
    with pytest.raises(BackupError, match="post-snapshot"):
        recover(setup, source, digest, tmp_path / "restored")
    assert tree(setup[0]) == original
    assert setup[2].approvals.get(approval_id).status == "approved"


@pytest.mark.parametrize("damage", ["stale_lock", "torn_tail", "publication"])
def test_interrupted_original_is_retained_on_refusal(setup, tmp_path, damage):
    source, digest = capture(setup, tmp_path)
    root = setup[0]
    if damage == "stale_lock":
        (root / "approvals.json.lock").write_text("deadline killed writer")
    elif damage == "torn_tail":
        with (root / "evidence.jsonl").open("ab") as stream:
            stream.write(b'{"partial":')
    else:
        from defiant_agent_harness.authority_publication import (
            AuthorityPublicationStore,
            AUTHORITY_PUBLICATION_STORE_NAMES,
        )

        store = AuthorityPublicationStore(root / "authority_publication.json")
        completed = store.get().completed
        store.prepare(
            completed.profile_hash,
            completed.generation,
            completed.manifest_hash,
            {
                name: dict(completed.store_hashes).get(name)
                for name in AUTHORITY_PUBLICATION_STORE_NAMES
            },
        )
    original = tree(root)
    with pytest.raises(PersistenceError):
        recover(setup, source, digest, tmp_path / "restored")
    assert tree(root) == original


def test_process_lifetime_lease_blocks_snapshot_even_without_transaction(
    setup, tmp_path
):
    root = setup[0]
    code = "from defiant_agent_harness.runtime_lease import runtime_session\nimport sys\nwith runtime_session(sys.argv[1]):\n print('leased', flush=True)\n sys.stdin.readline()\n"
    process = subprocess.Popen(
        [sys.executable, "-c", code, str(root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert process.stdout.readline().strip() == "leased"
        with pytest.raises(PersistenceError, match="busy"):
            capture(setup, tmp_path)
    finally:
        process.communicate("stop\n", timeout=15)
    assert process.returncode == 0
    capture(setup, tmp_path)


def test_incomplete_candidate_blocks_startup_and_remains_visible(
    setup, tmp_path, monkeypatch
):
    import defiant_agent_harness.backup as module

    source, digest = capture(setup, tmp_path)
    original = tree(setup[0])

    def fail(_temporary):
        raise RuntimeError("injected interruption before publication")

    monkeypatch.setattr(module, "_finish", fail)
    target = tmp_path / "restored"
    with pytest.raises(RuntimeError, match="interruption"):
        recover(setup, source, digest, target)
    assert not target.exists()
    [candidate] = list(tmp_path.glob(".restored.restore-*"))
    assert (candidate / INCOMPLETE_FILE).exists()
    with pytest.raises(PersistenceError, match="incomplete restore"):
        build_harness(candidate, MockAgentAdapter(), workspace_root=setup[1])
    assert tree(setup[0]) == original
    assert not StateIntegrityAuditor(candidate).audit().safe_to_execute


def test_restore_does_not_open_or_modify_other_root(setup, tmp_path, monkeypatch):
    other = tmp_path / "hook-state"
    with runtime_session(other):
        build_harness(other, MockAgentAdapter(), workspace_root=setup[1])
    other_before = tree(other)
    source, digest = capture(setup, tmp_path)
    import builtins

    original_open = builtins.open

    def guarded(file, *args, **kwargs):
        assert str(other) not in str(file)
        return original_open(file, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", guarded)
        recover(setup, source, digest, tmp_path / "restored")
    assert tree(other) == other_before
    assert StateIntegrityAuditor(other).audit().status == "healthy"
    before = tree(setup[0])
    CommandCore(setup[0]).snapshot()
    assert tree(setup[0]) == before


def test_missing_original_or_unknown_legacy_runtime_is_refused(setup, tmp_path):
    source, digest = capture(setup, tmp_path)
    (setup[0] / "runtime.lease").unlink()
    original = tree(setup[0])
    with pytest.raises(PersistenceError, match="enrolled"):
        recover(setup, source, digest, tmp_path / "restored")
    assert tree(setup[0]) == original


def test_same_thread_runtime_cannot_reenter_as_maintenance(setup, tmp_path):
    with runtime_session(setup[0]):
        with pytest.raises(PersistenceError, match="busy"):
            capture(setup, tmp_path)
    capture(setup, tmp_path)


def test_real_restore_process_death_preserves_original_and_blocks_candidate(
    setup, tmp_path
):
    source, digest = capture(setup, tmp_path)
    original = tree(setup[0])
    target = tmp_path / "restored"
    code = """
import os, sys
import defiant_agent_harness.backup as backup
write = backup._write_new
def interrupted(path, data):
    write(path, data)
    print(os.getpid(), flush=True)
    sys.stdin.readline()
backup._write_new = interrupted
backup.restore(sys.argv[1], sys.argv[2], sys.argv[3], expected_manifest_sha256=sys.argv[4], workspace=sys.argv[5], operator="fixture", note="Stopped original and all external tools")
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(str(p) for p in sys.path if p)
    process = subprocess.Popen(
        [
            getattr(sys, "_base_executable", sys.executable),
            "-c",
            code,
            str(setup[0]),
            str(source),
            str(target),
            digest,
            str(setup[1]),
        ],
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert int(process.stdout.readline().strip()) == process.pid
        process.kill()
        assert process.wait(timeout=15) != 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=15)
        process.stdin.close()
        process.stdout.close()
    assert tree(setup[0]) == original
    assert not target.exists()
    [candidate] = list(tmp_path.glob(".restored.restore-*"))
    assert (candidate / INCOMPLETE_FILE).exists()
    with pytest.raises(PersistenceError, match="incomplete restore"):
        build_harness(candidate, MockAgentAdapter(), workspace_root=setup[1])
    # OS lease release on death permits a fresh attempt; nothing deletes or
    # repairs the abandoned candidate or the original as part of that retry.
    recover(setup, source, digest, target)
    assert candidate.exists()


def test_required_witness_snapshot_is_refused_without_changing_enrollment(tmp_path):
    from test_evidence_witness import _enroll_required_witness

    state, workspace, _, _, _, _ = _enroll_required_witness(tmp_path)
    with runtime_session(state):
        pass
    original = tree(state)
    with pytest.raises(PersistenceError, match="witness"):
        snapshot(
            state,
            tmp_path / "snapshot",
            workspace=workspace,
            operator="operator",
            note="All writers stopped",
        )
    assert tree(state) == original
    assert not (tmp_path / "snapshot").exists()


def test_signed_approval_keeps_signature_and_requires_trusted_keys(tmp_path):
    from test_operator_identity import _keys, _decision

    private, _, spec, trust = _keys(tmp_path, "operator")
    root, workspace = tmp_path / "state", tmp_path / "workspace"
    workspace.mkdir()
    with runtime_session(root):
        harness = build_harness(
            root,
            MockAgentAdapter(script=SCRIPTS["send_email"]),
            workspace_root=workspace,
            trusted_operator_keys=[spec],
        )
    [outcome] = harness.run(
        HarnessRequest(task="signed fixture", user_id="alice", workspace_id="test")
    )
    held = harness.approvals.get(outcome.approval_id)
    attestation = _decision(held, private)
    harness.approvals.decide(
        held.approval_id, True, "alice", "reviewed", attestation=attestation
    )
    with pytest.raises(PersistenceError, match="operator_trust_unverified"):
        snapshot(
            root,
            tmp_path / "refused",
            workspace=workspace,
            operator="alice",
            note="Stopped",
        )
    captured = snapshot(
        root,
        tmp_path / "snapshot",
        workspace=workspace,
        operator="alice",
        note="All writers stopped",
        trusted_operator_keys=[spec],
    )
    target = tmp_path / "restored"
    restore(
        root,
        tmp_path / "snapshot",
        target,
        expected_manifest_sha256=captured["manifest_sha256"],
        workspace=workspace,
        operator="alice",
        note="Stopped and retired original",
        trusted_operator_keys=[spec],
    )
    restored = ApprovalStore(target / "approvals.json", operator_trust=trust).get(
        held.approval_id
    )
    assert restored.status == "executing"
    assert restored.decision_attestation == attestation
    assert restored.reconciliation_outcome == ""


def test_real_hook_root_and_proxy_root_can_be_restored_independently(setup, tmp_path):
    from defiant_agent_harness.hooks.copilot import CopilotHookGate

    hook = tmp_path / "hooks"
    with runtime_session(hook):
        CopilotHookGate(setup[1], hook)
    assert (hook / "hook_executions.json").is_file()
    captured = snapshot(
        hook,
        tmp_path / "hook-snapshot",
        workspace=setup[1],
        operator="operator",
        note="Runner stopped; no outstanding tools",
    )
    proxy_before = tree(setup[0])
    hook_before = tree(hook)
    target = tmp_path / "hook-restored"
    restore(
        hook,
        tmp_path / "hook-snapshot",
        target,
        expected_manifest_sha256=captured["manifest_sha256"],
        workspace=setup[1],
        operator="operator",
        note="Stopped and retired hook root",
    )
    with pytest.raises(AuthorityProfileError, match="configured") as mismatch:
        CopilotHookGate(setup[1], target)
    candidate = re.search(
        r"configured (sha256:[0-9a-f]{64})", str(mismatch.value)
    ).group(1)
    AuthorityProfileStore(target / "authority_profile.json").request_rotation(
        candidate,
        operator="operator",
        note="Explicit restored hook activation",
        operator_trust=None,
    )
    CopilotHookGate(setup[1], target)
    assert (
        StateIntegrityAuditor(target, workspace_root=setup[1]).audit().status
        == "healthy"
    )
    assert tree(setup[0]) == proxy_before
    source, digest = capture(setup, tmp_path)
    recover(setup, source, digest, tmp_path / "proxy-restored")
    assert tree(hook) == hook_before


def test_new_approval_free_execution_after_snapshot_is_refused(setup, tmp_path):
    from defiant_agent_harness.adapters.base import ToolCall

    source, digest = capture(setup, tmp_path)
    target = setup[1] / "synthetic.txt"
    target.write_text("synthetic")
    outcome = setup[2].handle_call(
        ToolCall(name="read_file", arguments={"path": "workspace/synthetic.txt"}),
        HarnessRequest(task="new action", user_id="operator", workspace_id="test"),
    )
    assert outcome.status.value == "succeeded"
    original = tree(setup[0])
    with pytest.raises(PersistenceError, match="authorization"):
        recover(setup, source, digest, tmp_path / "restored")
    assert tree(setup[0]) == original


def test_changed_snapshot_during_copy_is_not_activated(setup, tmp_path, monkeypatch):
    import defiant_agent_harness.backup as module

    source, digest = capture(setup, tmp_path)
    write = module._write_new

    def change(path, data):
        write(path, data)
        (source / "evidence.jsonl").write_bytes(b'{"torn":')

    monkeypatch.setattr(module, "_write_new", change)
    with pytest.raises(PersistenceError, match="snapshot changed"):
        recover(setup, source, digest, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()


def test_restore_gate_requires_one_complete_non_skipped_test():
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "restore_gate",
        Path(__file__).resolve().parents[1] / "examples/filesystem/restore_ci.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    gate = module.RestoreGate()
    assert not gate.passed()
    gate.collected = [module.TEST]
    gate.reports = [
        (module.TEST, phase, "passed", False) for phase in ("setup", "call", "teardown")
    ]
    assert gate.passed()
    for outcome in ("skipped", "failed"):
        gate.reports[1] = (module.TEST, "call", outcome, False)
        assert not gate.passed()
    gate.reports[1] = (module.TEST, "call", "passed", True)
    assert not gate.passed()


def test_oversized_source_is_refused_before_audit(setup, tmp_path, monkeypatch):
    import defiant_agent_harness.backup as module

    monkeypatch.setattr(module, "MAX_FILE_BYTES", 8)

    def forbidden(*args, **kwargs):
        pytest.fail("oversized input reached the state audit")

    monkeypatch.setattr(module, "_assess", forbidden)
    original = tree(setup[0])
    with pytest.raises(PersistenceError, match="byte limit"):
        capture(setup, tmp_path)
    assert tree(setup[0]) == original


def test_non_object_manifest_with_matching_pin_is_refused(setup, tmp_path):
    import hashlib

    source, _ = capture(setup, tmp_path)
    document = b"[]"
    (source / "snapshot_manifest.json").write_bytes(document)
    digest = "sha256:" + hashlib.sha256(document).hexdigest()
    with pytest.raises(PersistenceError, match="JSON object"):
        recover(setup, source, digest, tmp_path / "restored")
