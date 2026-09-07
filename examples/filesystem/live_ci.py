"""CI entry point: an absent, skipped, xfailed, or incomplete live test fails."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LIVE_TEST = (
    "tests/test_filesystem_live_example.py::test_official_filesystem_server_end_to_end"
)


class LiveTestGate:
    def __init__(self):
        self.collected: list[str] = []
        self.reports: list[tuple[str, str, str, bool]] = []

    def pytest_collection_finish(self, session):
        self.collected = [item.nodeid for item in session.items]

    def pytest_runtest_logreport(self, report):
        self.reports.append(
            (report.nodeid, report.when, report.outcome, hasattr(report, "wasxfail"))
        )

    def passed(self) -> bool:
        expected = [
            (LIVE_TEST, phase, "passed", False)
            for phase in ("setup", "call", "teardown")
        ]
        return self.collected == [LIVE_TEST] and self.reports == expected


def main() -> int:
    if os.environ.get("DAH_LIVE_MCP") != "1":
        print("LIVE_MCP_GATE: FAIL - DAH_LIVE_MCP must be exactly 1", flush=True)
        return 1
    os.chdir(ROOT)
    gate = LiveTestGate()
    # Clear ambient selection overrides, and disable configured addopts below.
    # The only selected test must complete setup, call, AND teardown normally.
    os.environ.pop("PYTEST_ADDOPTS", None)
    with tempfile.TemporaryDirectory(prefix="dah-live-mcp-") as temporary:
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
                LIVE_TEST,
            ],
            plugins=[gate],
        )
    if status != 0 or not gate.passed():
        print("LIVE_MCP_GATE: FAIL - expected one real pass, zero skips/xfails")
        return 1
    print(f"LIVE_MCP_GATE: PASS - {LIVE_TEST}; setup/call/teardown passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
