"""Opt-in OS process death against the real, observed filesystem MCP server."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml

from defiant_agent_harness.approvals.store import ApprovalStore
from defiant_agent_harness.budgets.ledger import BudgetLedger
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.evidence.store import EvidenceStore
from defiant_agent_harness.operation_journal import OperationJournal
from defiant_agent_harness.state_integrity import StateIntegrityAuditor

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
PACKAGE = "@modelcontextprotocol/server-filesystem@2026.7.10"
POINTS = ("before_dispatch", "before_journal", "after_journal", "during_append")


def wait_for(predicate, description, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {description}")


def receipts(path):
    if not path.exists():
        return []
    # Only complete records are visible before an observed fsync/exit barrier.
    return [
        json.loads(line)
        for line in path.read_bytes().splitlines(keepends=True)
        if line.endswith(b"\n")
    ]


@pytest.fixture(scope="module")
def real_package(tmp_path_factory):
    directory = tmp_path_factory.mktemp("s5-real-package")
    npm = shutil.which("npm")
    node = shutil.which("node")
    assert npm and node, "live S5 requires Node/npm; missing dependencies must fail"
    command = [
        npm,
        "install",
        "--prefix",
        str(directory),
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--no-package-lock",
        PACKAGE,
    ]
    if os.name == "nt":
        npm_cli = Path(npm).parent / "node_modules/npm/bin/npm-cli.js"
        assert npm_cli.is_file(), "cannot resolve Windows npm CLI"
        command = [node, str(npm_cli), *command[1:]]
    subprocess.run(command, check=True, timeout=240)
    entry = (
        directory / "node_modules/@modelcontextprotocol/server-filesystem/dist/index.js"
    )
    original = hashlib.sha256(entry.read_bytes()).hexdigest()
    yield node, entry
    assert hashlib.sha256(entry.read_bytes()).hexdigest() == original


class Client:
    def __init__(self, run, point="none", instrument=True):
        self.run = run
        self.marker = run.root / f"barrier-{point}.json"
        arguments = [
            "--workdir",
            str(run.state),
            "--workspace-root",
            str(run.workspace),
            "--user",
            "s5-test-operator",
            "--workspace",
            "s5-synthetic",
            "mcp-proxy",
            "--config",
            str(run.config),
        ]
        command = (
            [run.python, str(FIXTURES / "crash_proxy.py"), point, str(self.marker)]
            if instrument
            else [run.python, "-m", "defiant_agent_harness.cli.main"]
        )
        self.stderr = (run.root / "proxy-stderr.log").open("a", encoding="utf-8")
        self.process = subprocess.Popen(
            [*command, *arguments],
            cwd=run.root,
            env=run.environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self.responses = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        self.next_id = 0
        run.clients.append(self)

    def _read(self):
        try:
            for line in self.process.stdout:
                self.responses.put(json.loads(line))
        finally:
            self.responses.put(None)

    def send(self, method, params=None, notification=False):
        self.next_id += 1
        message = {"jsonrpc": "2.0", "method": method}
        if not notification:
            message["id"] = self.next_id
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        return self.next_id

    def request(self, method, params=None):
        expected = self.send(method, params)
        while True:
            reply = self.responses.get(timeout=60)
            assert reply is not None, (self.run.root / "proxy-stderr.log").read_text()
            if reply.get("id") == expected:
                return reply
            assert "id" not in reply, reply

    def initialize(self):
        response = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "s5-real-kill", "version": "1"},
            },
        )
        assert response["result"]["serverInfo"]["name"] == "secure-filesystem-server"
        self.send("notifications/initialized", notification=True)
        assert self.request("ping")["result"] == {}

    def kill_at_barrier(self):
        wait_for(lambda: self.marker.exists(), "proxy crash barrier", timeout=60)
        marker = json.loads(self.marker.read_text())
        assert marker["pid"] == self.process.pid, "must kill interpreter, not launcher"
        self.process.kill()  # SIGKILL on POSIX; TerminateProcess on Windows.
        assert self.process.wait(timeout=20) != 0
        return marker

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=20)
        self.reader.join(timeout=5)
        self.process.stdout.close()
        if not self.process.stdin.closed:
            self.process.stdin.close()
        self.stderr.close()


class Run:
    def __init__(self, root, package):
        self.root = root
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        self.state = root / "state"
        self.receipt = root / "real-server-receipts.jsonl"
        self.config = root / "proxy.yaml"
        self.clients = []
        # Windows virtualenv launchers are separate processes. Kill the actual
        # interpreter and retain this test environment's import paths explicitly.
        self.python = getattr(sys, "_base_executable", sys.executable)
        self.environment = dict(os.environ)
        self.environment["PYTHONPATH"] = os.pathsep.join(
            [str(ROOT / "src"), *(str(Path(p).resolve()) for p in sys.path if p)]
        )
        node, entry = package
        command = [
            node,
            str(FIXTURES / "record_real_mcp.mjs"),
            str(entry),
            str(self.workspace),
            str(self.receipt),
        ]
        config = yaml.safe_load(
            (ROOT / "examples/filesystem/mcp-proxy.yaml").read_text()
        )
        config["server"]["command"] = command
        config["method_dispositions"]["reviewed_server"]["commands"] = [list(command)]
        config["tools"]["write_file"]["cost_estimate_usd"] = "5"
        self.config.write_text(yaml.safe_dump(config), encoding="utf-8")
        self.params = {
            "name": "write_file",
            "arguments": {
                "path": str(self.workspace / "one-action.txt"),
                "content": "Synthetic S5 operator-approved crash proof.\n",
            },
        }

    def cli(self, *args):
        return subprocess.run(
            [
                self.python,
                "-m",
                "defiant_agent_harness.cli.main",
                "--workdir",
                str(self.state),
                "--user",
                "s5-test-operator",
                *args,
            ],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=45,
        )

    def arrivals(self):
        return [
            r["message"]["params"]
            for r in receipts(self.receipt)
            if r["event"] == "arrival" and r["message"].get("method") == "tools/call"
        ]

    def drain(self, pid):
        wait_for(
            lambda: any(
                r["event"] == "exit" and r["pid"] == pid for r in receipts(self.receipt)
            ),
            "real upstream exit",
        )
        events = [r["event"] for r in receipts(self.receipt) if r["pid"] == pid]
        assert events[-2:] == ["eof", "exit"], events
        assert [
            r["code"]
            for r in receipts(self.receipt)
            if r["pid"] == pid and r["event"] == "exit"
        ] == [0]


@pytest.mark.skipif(
    os.environ.get("DAH_LIVE_MCP") != "1",
    reason="set DAH_LIVE_MCP=1 for real pinned MCP process-kill proof",
)
@pytest.mark.parametrize("point", POINTS)
def test_real_proxy_process_kill(tmp_path, real_package, point):
    run = Run(tmp_path, real_package)
    expected = [] if point == "before_dispatch" else [run.params]
    try:
        client = Client(run, point)
        client.initialize()
        upstream_pid = [r for r in receipts(run.receipt) if r["event"] == "boot"][-1][
            "pid"
        ]
        pending = client.request("tools/call", run.params)["result"]["_defiant"]
        assert pending["status"] == "pending_approval"
        approval_id = pending["approval_id"]
        assert client.request("ping")["result"] == {}
        assert run.arrivals() == []
        approved = run.cli(
            "approve", approval_id, "--note", "approve synthetic S5 action"
        )
        assert approved.returncode == 0, approved.stderr
        client.send("tools/call", run.params)
        marker = client.kill_at_barrier()
        run.drain(upstream_pid)
        assert run.arrivals() == expected
        observed_methods = [
            r["message"]["method"]
            for r in receipts(run.receipt)
            if r["pid"] == upstream_pid and r["event"] == "arrival"
        ]
        assert observed_methods == [
            "initialize",
            "notifications/initialized",
            "ping",
            "ping",
        ] + (["tools/call"] if expected else [])
        target = run.workspace / "one-action.txt"
        assert target.exists() == bool(expected)
        if expected:
            assert target.read_text() == run.params["arguments"]["content"]
        ledger = BudgetLedger(run.state / "budget.json")
        assert ledger.summary()["total_spent_usd"] == (
            "5" if point == "during_append" else "0"
        )
        assert ledger.summary()["reserved_usd"] == (
            "0" if point == "during_append" else "5"
        )

        if point == "during_append":
            # Do not delete stale locks, trim the torn log, or fabricate recovery.
            evidence = run.state / "evidence.jsonl"
            torn = evidence.read_bytes()
            assert not torn.endswith(b"\n")
            lock = run.state / "evidence.jsonl.lock"
            assert lock.read_text().strip() == f"pid={marker['pid']}"
            chain = EvidenceStore(evidence).verify()
            assert not chain.ok and chain.broken_at is not None
            assert StateIntegrityAuditor(run.state).audit().status == "unsafe"
            restarted = Client(run, instrument=False)
            assert restarted.process.wait(timeout=30) != 0
            attempt = run.cli(
                "reconcile",
                approval_id,
                "--outcome",
                "succeeded",
                "--operator",
                "s5-test-operator",
                "--note",
                "observed real write",
            )
            assert attempt.returncode != 0
            assert evidence.read_bytes() == torn and lock.exists()
            assert run.arrivals() == expected
            assert len([r for r in receipts(run.receipt) if r["event"] == "boot"]) == 1
        else:
            journal = OperationJournal(run.state / "operation_journal.json").active()
            assert (journal is not None) == (point == "after_journal")
            if journal is not None:
                assert journal.kind == "execution_complete"
                assert journal.payload["evidence"]["result_status"] == "succeeded"
            restarted = Client(run, instrument=False)
            restarted.initialize()
            if point != "after_journal":
                assert (
                    ApprovalStore(run.state / "approvals.json").get(approval_id).status
                    == "executing"
                )
                assert (
                    CommandCore(run.state).snapshot()["reconciliation_required"] is True
                )
                assert ledger.summary()["reserved_usd"] == "5"
                before_invalid = (run.state / "budget.json").read_bytes()
                assert (
                    restarted.request("tools/call", run.params)["result"]["_defiant"][
                        "status"
                    ]
                    == "failed"
                )
                valid = [
                    "reconcile",
                    approval_id,
                    "--outcome",
                    "not_executed" if point == "before_dispatch" else "succeeded",
                    "--operator",
                    "s5-test-operator",
                    "--note",
                    "real receipt and drain barrier checked",
                ]
                for option in ("--outcome", "--operator", "--note"):
                    incomplete = list(valid)
                    i = incomplete.index(option)
                    del incomplete[i : i + 2]
                    assert run.cli(*incomplete).returncode != 0
                    invalid = list(valid)
                    invalid[invalid.index(option) + 1] = " "
                    assert run.cli(*invalid).returncode != 0
                assert (run.state / "budget.json").read_bytes() == before_invalid
                assert ledger.summary()["reserved_usd"] == "5"
                for _ in range(2):
                    result = run.cli(*valid)
                    assert result.returncode == 0, result.stdout + result.stderr
            assert (
                OperationJournal(run.state / "operation_journal.json").active() is None
            )
            assert (
                ApprovalStore(run.state / "approvals.json").get(approval_id).status
                == "consumed"
            )
            assert ledger.summary()["reserved_usd"] == "0"
            assert ledger.summary()["total_spent_usd"] == ("0" if not expected else "5")
            budget_raw = json.loads((run.state / "budget.json").read_text())
            dispositions = [
                entry
                for entry in budget_raw["entries"]
                if entry["kind"] in {"debit", "reconcile"}
            ]
            assert len(dispositions) == 1
            assert dispositions[0]["kind"] == (
                "debit" if point == "after_journal" else "reconcile"
            )
            if point != "after_journal":
                [resolution] = budget_raw["reconciliations"].values()
                assert resolution["charged_usd"] == ("5" if expected else "0")
                assert resolution["released_usd"] == ("0" if expected else "5")
            assert EvidenceStore(run.state / "evidence.jsonl").verify().ok
            original_approval = ApprovalStore(run.state / "approvals.json").get(
                approval_id
            )
            terminals = [
                record
                for record in EvidenceStore(run.state / "evidence.jsonl").records()
                if record["action_id"] == original_approval.action_id
                and record["result_status"] in {"succeeded", "failed", "not_executed"}
            ]
            assert len(terminals) == 1
            assert terminals[0]["result_status"] == (
                "succeeded" if expected else "not_executed"
            )
            assert StateIntegrityAuditor(run.state).audit().status == "healthy"
            # A new identical write needs fresh approval, never an automatic replay.
            retry = restarted.request("tools/call", run.params)["result"]["_defiant"]
            assert retry["status"] == "pending_approval"
            assert retry["approval_id"] != approval_id
            assert restarted.request("ping")["result"] == {}
            assert run.arrivals() == expected
            restarted.close()
            pid = [r for r in receipts(run.receipt) if r["event"] == "boot"][-1]["pid"]
            run.drain(pid)
            assert run.arrivals() == expected
        print(
            f"S5_RECEIPTS: {point}: exact arrivals={len(expected)}; real proxy killed; no replay"
        )
    finally:
        for client in run.clients:
            if not client.stderr.closed:
                client.close()
