from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).parents[1]


def _load(relative):
    spec = importlib.util.spec_from_file_location("live_fixture", ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def live_ci():
    return _load("examples/filesystem/live_ci.py")


def _report(gate, node, phase, outcome="passed", xfail=False):
    report = SimpleNamespace(nodeid=node, when=phase, outcome=outcome)
    if xfail:
        report.wasxfail = "deliberate adversarial fixture"
    gate.pytest_runtest_logreport(report)


def test_live_gate_accepts_only_complete_exact_test(live_ci):
    gate = live_ci.LiveTestGate()
    gate.pytest_collection_finish(
        SimpleNamespace(items=[SimpleNamespace(nodeid=live_ci.LIVE_TEST)])
    )
    for phase in ("setup", "call", "teardown"):
        _report(gate, live_ci.LIVE_TEST, phase)
    assert gate.passed()


@pytest.mark.parametrize(
    "defect",
    [
        "uncollected",
        "extra_test",
        "wrong_test",
        "missing_call",
        "duplicate_call",
        "setup_skipped",
        "call_skipped",
        "call_failed",
        "teardown_failed",
        "xfail",
        "xpass",
    ],
)
def test_live_gate_refuses_apparent_success(live_ci, defect):
    gate = live_ci.LiveTestGate()
    node = "tests/fake.py::test_fake" if defect == "wrong_test" else live_ci.LIVE_TEST
    gate.collected = [node]
    if defect == "uncollected":
        gate.collected = []
    if defect == "extra_test":
        gate.collected.append("tests/extra.py::test_extra")
    for phase in ("setup", "call", "teardown"):
        if defect == "missing_call" and phase == "call":
            continue
        outcome = "passed"
        if defect == f"{phase}_skipped" or (defect == "xfail" and phase == "call"):
            outcome = "skipped"
        if defect == f"{phase}_failed":
            outcome = "failed"
        _report(gate, node, phase, outcome, defect in {"xfail", "xpass"})
        if defect == "duplicate_call" and phase == "call":
            _report(gate, node, phase)
    assert not gate.passed()


@pytest.mark.parametrize("value", [None, "", "0", "true"])
def test_live_entry_requires_opt_in_before_pytest(live_ci, monkeypatch, value):
    if value is None:
        monkeypatch.delenv("DAH_LIVE_MCP", raising=False)
    else:
        monkeypatch.setenv("DAH_LIVE_MCP", value)
    monkeypatch.setattr(
        live_ci.pytest, "main", lambda *a, **k: pytest.fail("ran pytest")
    )
    assert live_ci.main() == 1


@pytest.mark.parametrize("exit_code,complete", [(0, False), (1, True), (5, False)])
def test_live_entry_fails_even_if_pytest_reports_success(
    live_ci, monkeypatch, exit_code, complete
):
    monkeypatch.setenv("DAH_LIVE_MCP", "1")
    monkeypatch.setenv("PYTEST_ADDOPTS", "-k nonexistent")
    monkeypatch.chdir(ROOT)

    def fake_pytest(args, plugins):
        assert args[-1] == live_ci.LIVE_TEST
        assert "PYTEST_ADDOPTS" not in live_ci.os.environ
        gate = plugins[0]
        if complete:
            gate.collected = [live_ci.LIVE_TEST]
            for phase in ("setup", "call", "teardown"):
                _report(gate, live_ci.LIVE_TEST, phase)
        return exit_code

    monkeypatch.setattr(live_ci.pytest, "main", fake_pytest)
    assert live_ci.main() == 1


def test_live_example_and_config_use_same_exact_upstream_pin():
    demo = _load("examples/filesystem/live_demo.py")
    config = yaml.safe_load((ROOT / "examples/filesystem/mcp-proxy.yaml").read_text())
    assert demo.PACKAGE == "@modelcontextprotocol/server-filesystem@2026.7.10"
    assert config["server"]["command"] == ["npx", "-y", demo.PACKAGE, "workspace"]
    assert demo._upstream_command()[-4:] == config["server"]["command"]


def test_live_workflow_has_both_platforms_and_fail_closed_event_gate():
    # BaseLoader preserves YAML's `on` key rather than treating it as boolean True.
    workflow = yaml.load(
        (ROOT / ".github/workflows/ci.yml").read_text(), yaml.BaseLoader
    )
    assert set(workflow["on"]) == {
        "push",
        "pull_request",
        "workflow_dispatch",
        "schedule",
    }
    assert workflow["on"]["schedule"] == [{"cron": "23 6 * * *"}]
    live = workflow["jobs"]["live-mcp"]
    condition = (
        "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' "
        "|| startsWith(github.ref, 'refs/tags/v')"
    )
    assert live["if"] == condition
    assert live["strategy"]["matrix"]["os"] == ["ubuntu-latest", "windows-latest"]
    assert live["strategy"]["fail-fast"] == "false"
    assert live["env"]["DAH_LIVE_MCP"] == "1"
    assert live["steps"][-1]["run"] == "python examples/filesystem/live_ci.py"
    for step in live["steps"]:
        assert "if" not in step and "continue-on-error" not in step
    assert "continue-on-error" not in live
    gate = workflow["jobs"]["live-mcp-gate"]
    assert gate["if"] == f"always() && ({condition})"
    assert gate["needs"] == "live-mcp"
    assert gate["env"]["LIVE_MCP_RESULT"] == "${{ needs.live-mcp.result }}"
    assert '"$LIVE_MCP_RESULT" != "success"' in gate["steps"][0]["run"]
    assert "exit 1" in gate["steps"][0]["run"]
    assert "env" not in workflow["jobs"]["test"]
