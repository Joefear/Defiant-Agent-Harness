"""Offline adversarial verification that the S5 live gate cannot silently skip."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture
def gate_module():
    path = Path(__file__).parents[1] / "examples/filesystem/crash_ci.py"
    spec = importlib.util.spec_from_file_location("crash_gate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "defect",
    [
        "none",
        "no_collection",
        "missing_case",
        "extra_case",
        "missing_call",
        "duplicate",
        "skip",
        "xfail",
        "fail",
    ],
)
def test_gate_checks_exact_cases_and_phases(gate_module, defect):
    gate = gate_module.CrashGate()
    gate.collected = [f"{gate_module.TEST}[{p}]" for p in gate_module.POINTS]
    gate.reports = [
        (n, phase, "passed", False)
        for n in gate.collected
        for phase in ("setup", "call", "teardown")
    ]
    if defect == "no_collection":
        gate.collected = []
    elif defect == "missing_case":
        gate.collected.pop()
        del gate.reports[-3:]
    elif defect == "extra_case":
        gate.collected.append("fake")
    elif defect == "missing_call":
        del gate.reports[1]
    elif defect == "duplicate":
        gate.reports.append(gate.reports[-1])
    elif defect in {"skip", "xfail", "fail"}:
        node, phase, _, _ = gate.reports[1]
        gate.reports[1] = (
            node,
            phase,
            "skipped"
            if defect == "skip"
            else "failed"
            if defect == "fail"
            else "passed",
            defect == "xfail",
        )
    assert gate.passed() == (defect == "none")


@pytest.mark.parametrize("value", [None, "", "0", "true"])
def test_no_opt_in_never_invokes_pytest(gate_module, monkeypatch, value):
    monkeypatch.delenv("DAH_LIVE_MCP", raising=False)
    if value is not None:
        monkeypatch.setenv("DAH_LIVE_MCP", value)
    monkeypatch.setattr(
        gate_module.pytest, "main", lambda *a, **k: pytest.fail("invoked")
    )
    assert gate_module.main() == 1


@pytest.mark.parametrize(
    "status,complete", [(0, False), (1, True), (5, False), (0, True)]
)
def test_entry_requires_both_gate_and_pytest_success(
    gate_module, monkeypatch, status, complete
):
    monkeypatch.setenv("DAH_LIVE_MCP", "1")
    monkeypatch.setenv("PYTEST_ADDOPTS", "-k missing")
    monkeypatch.chdir(gate_module.ROOT)

    def execute(args, plugins):
        assert args[-1] == gate_module.TEST
        assert "PYTEST_ADDOPTS" not in gate_module.os.environ
        if complete:
            gate = plugins[0]
            gate.collected = [f"{gate_module.TEST}[{p}]" for p in gate_module.POINTS]
            gate.reports = [
                (n, phase, "passed", False)
                for n in gate.collected
                for phase in ("setup", "call", "teardown")
            ]
        return status

    monkeypatch.setattr(gate_module.pytest, "main", execute)
    assert gate_module.main() == (0 if status == 0 and complete else 1)
