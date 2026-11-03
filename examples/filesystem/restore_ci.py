"""Require the actual S7 real-server restore test, without skips or xfails."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TEST = "tests/test_restore_live_mcp.py::test_real_write_across_restore"


class RestoreGate:
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
        return self.collected == [TEST] and self.reports == [
            (TEST, phase, "passed", False) for phase in ("setup", "call", "teardown")
        ]


def main():
    if os.environ.get("DAH_LIVE_MCP") != "1":
        print("S7_RESTORE_GATE: FAIL - DAH_LIVE_MCP must be exactly 1")
        return 1
    os.chdir(ROOT)
    os.environ.pop("PYTEST_ADDOPTS", None)
    gate = RestoreGate()
    with tempfile.TemporaryDirectory(prefix="dah-s7-restore-") as temporary:
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
        print("S7_RESTORE_GATE: FAIL - complete real restore pass required")
        return 1
    print(
        "S7_RESTORE_GATE: PASS - one real write; exact unchanged receipt through restore/reconciliation"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
