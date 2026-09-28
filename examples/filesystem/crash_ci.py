"""Require all four real process-kill scenarios, with no skips or xfails."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEST = "tests/test_process_kill_recovery.py::test_real_proxy_process_kill"
POINTS = ("before_dispatch", "before_journal", "after_journal", "during_append")


class CrashGate:
    def __init__(self):
        self.collected = []
        self.reports = []

    def pytest_collection_finish(self, session):
        self.collected = [item.nodeid for item in session.items]

    def pytest_runtest_logreport(self, report):
        self.reports.append(
            (report.nodeid, report.when, report.outcome, hasattr(report, "wasxfail"))
        )

    def passed(self):
        nodes = [f"{TEST}[{point}]" for point in POINTS]
        expected = [
            (node, phase, "passed", False)
            for node in nodes
            for phase in ("setup", "call", "teardown")
        ]
        return self.collected == nodes and self.reports == expected


def main():
    if os.environ.get("DAH_LIVE_MCP") != "1":
        print("S5_CRASH_GATE: FAIL - DAH_LIVE_MCP must be exactly 1")
        return 1
    os.chdir(ROOT)
    os.environ.pop("PYTEST_ADDOPTS", None)
    gate = CrashGate()
    with tempfile.TemporaryDirectory(prefix="dah-s5-kill-") as temporary:
        status = pytest.main(
            [
                "-q",
                "-ra",
                "-s",
                "-o",
                "addopts=",
                "-p",
                "no:cacheprovider",
                "--basetemp",
                str(Path(temporary) / "pytest"),
                TEST,
            ],
            plugins=[gate],
        )
    if status != 0 or not gate.passed():
        print("S5_CRASH_GATE: FAIL - four complete real passes required")
        return 1
    print(
        "S5_CRASH_GATE: PASS - four actual proxy deaths; exact real upstream receipts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
