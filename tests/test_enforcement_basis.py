"""S6 labels are sealed provenance, not a claim of pilot readiness."""

import io
import json

import pytest

from defiant_agent_harness.cli.main import main
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import Decision, EvidenceRecord, ResultStatus
from defiant_agent_harness.evidence.store import EvidenceStore, GENESIS
from defiant_agent_harness.hooks import codex, copilot
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.orchestrator.harness import build_harness


def record(**kwargs):
    return EvidenceRecord(
        request_id="req",
        action_id="act",
        decision=Decision.ALLOW,
        result_status=ResultStatus.SKIPPED,
        **kwargs,
    )


def test_legacy_positional_constructor_keeps_model_identity():
    legacy = EvidenceRecord(
        "req",
        "act",
        Decision.ALLOW,
        ResultStatus.SKIPPED,
        "defiant.agent_harness.evidence_record",
        "0.1.0",
        "evd_fixture",
        "2026-10-04T00:00:00Z",
        "old-runner",
        "old-model",
    )
    assert legacy.model_id == "old-model"
    assert "enforcement_basis" not in legacy.to_dict()


@pytest.mark.parametrize(
    "basis", ["native_hook_preview", "mcp_proxy", "harness_control_loop"]
)
def test_basis_is_hashed_and_legacy_round_trip_is_unchanged(tmp_path, basis):
    legacy = record().seal(GENESIS).to_dict()
    assert "enforcement_basis" not in legacy
    assert EvidenceRecord(**legacy).to_dict() == legacy
    assert EvidenceRecord(**legacy).body() == {
        k: v for k, v in legacy.items() if k != "record_hash"
    }
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    prepared = record(enforcement_basis=basis)
    raw_prepared = prepared.to_dict()
    sealed = store.append_idempotent(prepared)
    assert (
        store.append_idempotent(EvidenceRecord(**raw_prepared)).to_dict()
        == sealed.to_dict()
    )
    assert store.verify().ok
    raw = sealed.to_dict()
    raw["enforcement_basis"] = (
        "mcp_proxy" if basis != "mcp_proxy" else "native_hook_preview"
    )
    store.path.write_text(json.dumps(raw) + "\n", encoding="utf-8")
    assert not store.verify().ok


def test_old_prepared_record_recognized_after_append(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    prepared = record().to_dict()
    assert "enforcement_basis" not in prepared
    sealed = store.append_idempotent(EvidenceRecord(**prepared)).to_dict()
    assert store.append_idempotent(EvidenceRecord(**prepared)).to_dict() == sealed
    assert len(store.records()) == 1


def test_legacy_authorization_reconciliation_does_not_invent_basis(tmp_path):
    harness = build_harness(tmp_path / "state", MockAgentAdapter())
    authority = record(authorization_hash="sha256:" + "1" * 64)
    harness.evidence.append(authority)
    harness.reconcile_authorization(
        authority.record_id, "not_executed", "sam", "synthetic observation"
    )
    assert len(harness.evidence.records()) == 2
    assert all("enforcement_basis" not in item for item in harness.evidence.records())


def test_operator_rejection_keeps_hook_action_basis(tmp_path, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    gate = codex.CodexHookGate(workspace, state)
    gate.pre_tool_use(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": "note.txt", "content": "synthetic"},
            "tool_use_id": "write",
        }
    )
    [pending] = gate.harness.approvals.list_pending()
    assert (
        main(
            [
                "--workdir",
                str(state),
                "--workspace-root",
                str(workspace),
                "--user",
                "sam",
                "reject",
                pending.approval_id,
                "--note",
                "fixture rejection",
            ]
        )
        == 0
    )
    capsys.readouterr()
    records = gate.harness.evidence.records()
    assert len(records) == 2
    assert {item["enforcement_basis"] for item in records} == {"native_hook_preview"}


@pytest.mark.parametrize("bad", [None, True, 1, {}, [], "authoritative", "MCP_PROXY"])
def test_invalid_basis_rejected(bad):
    with pytest.raises((ValueError, TypeError)):
        record(enforcement_basis=bad)


@pytest.mark.parametrize("gate_type", [codex.CodexHookGate, copilot.CopilotHookGate])
def test_hook_origin_cannot_be_promoted_by_event_or_delegated_tool(tmp_path, gate_type):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    gate = gate_type(workspace, state)
    event = {
        "session_id": "s6",
        "cwd": str(workspace),
        "tool_name": "Read",
        "tool_input": {"file_path": "note.txt", "enforcement_basis": "mcp_proxy"},
        "tool_use_id": "native-1",
        "enforcement_basis": "mcp_proxy",
        "agent_runner": "codex-mcp",
    }
    assert (
        gate.pre_tool_use(event)["hookSpecificOutput"]["permissionDecision"] == "allow"
    )
    gate.post_tool_use(event | {"tool_response": "reported completion"})
    gate.pre_tool_use(
        event
        | {
            "tool_name": "mcp__defiant_filesystem__read_text_file",
            "tool_use_id": "delegated",
        }
    )
    records = gate.harness.evidence.records()
    assert len(records) == 3
    assert records[-1]["tool_name"] == "proxied_mcp"
    assert {r["enforcement_basis"] for r in records} == {"native_hook_preview"}
    assert gate.harness.evidence.verify().ok


def test_operator_reconciliation_preserves_preview_basis(tmp_path, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    state = tmp_path / "state"
    gate = codex.CodexHookGate(workspace, state)
    event = {
        "session_id": "s6",
        "tool_name": "Read",
        "tool_input": {"file_path": "note.txt"},
        "tool_use_id": "lost-post",
    }
    gate.pre_tool_use(event)
    [authority] = gate.harness.evidence.records()
    assert (
        main(
            [
                "--workdir",
                str(state),
                "--workspace-root",
                str(workspace),
                "reconcile-authorization",
                authority["record_id"],
                "--outcome",
                "not_executed",
                "--operator",
                "sam",
                "--note",
                "synthetic fixture verified",
            ]
        )
        == 0
    )
    capsys.readouterr()
    records = EvidenceStore(state / "evidence.jsonl").records()
    assert len(records) == 2
    assert {r["enforcement_basis"] for r in records} == {"native_hook_preview"}


def test_read_only_surfaces_distinguish_legacy_and_preview(tmp_path, capsys):
    state = tmp_path / "state"
    store = EvidenceStore(state / "evidence.jsonl")
    store.append(record(agent_runner="codex-mcp"))
    preview = record(enforcement_basis="native_hook_preview")
    preview.action_id = "act2"
    store.append(preview)
    before = {p.name: p.read_bytes() for p in state.iterdir() if p.is_file()}
    snapshot = CommandCore(state).snapshot()
    assert [r["enforcement_basis"] for r in snapshot["recent_activity"]] == [
        "native_hook_preview",
        "legacy_unspecified",
    ]
    assert main(["--workdir", str(state), "history"]) == 0
    output = capsys.readouterr().out
    assert "native_hook_preview" in output and "legacy_unspecified" in output
    assert {p.name: p.read_bytes() for p in state.iterdir() if p.is_file()} == before


@pytest.mark.parametrize("module", [codex, copilot])
@pytest.mark.parametrize("phase", ["pre", "post"])
@pytest.mark.parametrize("failure", ["malformed", "exception", "missing_correlation"])
def test_hook_entrypoint_failure_is_explicitly_closed(
    tmp_path, monkeypatch, capsys, module, phase, failure
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DAH_HOOK_WORKDIR", str(tmp_path / "state"))
    monkeypatch.setenv("DAH_CODEX_HOOK_WORKDIR", str(tmp_path / "state"))
    event = {
        "tool_name": "Read",
        "tool_input": {"file_path": "note.txt"},
        "tool_use_id": "unmatched",
    }
    if failure == "missing_correlation" and phase == "pre":
        # An invalid event rather than a valid preflight in the pre branch.
        event = {"tool_name": []}
    monkeypatch.setattr(
        module.sys,
        "stdin",
        io.StringIO("{" if failure == "malformed" else json.dumps(event)),
    )
    if failure == "exception":

        def fail(*args, **kwargs):
            raise RuntimeError("injected entrypoint failure")

        monkeypatch.setattr(module, "run_hook", fail)
    assert module.main([phase]) == 0  # Hook dialect uses JSON, not exit status.
    captured = capsys.readouterr()
    response = json.loads(captured.out)
    assert "failed closed" in captured.err
    if phase == "pre":
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
    else:
        assert response["decision"] == "block"
        assert "failed closed" in response["reason"]
    path = tmp_path / "state" / "evidence.jsonl"
    assert not path.exists() or not EvidenceStore(path).records()
