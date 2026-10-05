"""Offline benchmark mechanics; no production hook subprocess or network needed."""

import importlib.util
from pathlib import Path

import pytest

from defiant_agent_harness.hooks.codex import CodexHookGate

spec = importlib.util.spec_from_file_location(
    "hook_latency", Path(__file__).resolve().parents[1] / "examples/hooks/latency.py"
)
latency = importlib.util.module_from_spec(spec)
spec.loader.exec_module(latency)


def test_bulk_history_is_valid_cross_store_state(tmp_path):
    gate = CodexHookGate(tmp_path, tmp_path / "state")
    latency.seed_history(gate, 60)
    assert len(gate.harness.evidence.records()) == 60
    assert gate.harness.evidence.verify().ok
    state = latency.inspect_state(tmp_path / "state")
    assert state["audit"]["safe_to_execute"]
    assert state["sentinel_lock_files"] == []


def test_deadline_kill_retains_fixture_and_audits_stale_lock(tmp_path, monkeypatch):
    calls = []

    def killed(kind, phase, document, workspace, environment, barrier):
        calls.append(True)
        (Path(environment["DAH_HOOK_WORKDIR"]) / "evidence.jsonl.lock").write_text(
            "stranded"
        )
        return {"seconds": 10.1, "outcome": "timeout"}

    monkeypatch.setattr(latency, "invoke", killed)
    case = latency.measure(
        "codex",
        rounds=3,
        workers=4,
        history_records=2,
        mode="serial",
        phase="pre",
        fixture_parent=tmp_path,
    )
    assert len(calls) == 1
    assert not case["within_budget"] and not case["responses_valid"]
    assert Path(case["fixture_root"]).is_dir()
    assert case["fixture_retained"]
    assert case["final_state"]["sentinel_lock_files"] == ["evidence.jsonl.lock"]
    assert not case["final_state"]["audit"]["safe_to_execute"]
    assert "authority.lock" not in case["final_state"]["sentinel_lock_files"]


def test_case_exception_still_preserves_audit(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("fixture failure")

    monkeypatch.setattr(latency, "seed_history", fail)
    case = latency.measure(
        "codex",
        rounds=1,
        workers=2,
        history_records=0,
        mode="serial",
        phase="pre",
        fixture_parent=tmp_path,
    )
    assert "fixture failure" in case["error"]
    assert "audit" in case["final_state"]
    assert Path(case["fixture_root"]).exists()


def test_cli_preserves_existing_report(tmp_path):
    report = tmp_path / "report.json"
    report.write_text("historical report")
    with pytest.raises(SystemExit):
        latency.main(["--output", str(report)])
    assert report.read_text() == "historical report"
