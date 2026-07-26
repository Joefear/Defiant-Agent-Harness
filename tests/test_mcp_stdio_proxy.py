from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path

from defiant_agent_harness.approvals.store import ApprovalStore
from defiant_agent_harness.budgets.ledger import BudgetLedger
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.evidence.store import EvidenceStore

ROOT = Path(__file__).parents[1]
SERVER = ROOT / "tests" / "fixtures" / "mcp_server.py"


class ProxyProcess:
    def __init__(self, config: Path, state: Path):
        environment = dict(os.environ)
        prior = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = str(ROOT / "src") + (
            os.pathsep + prior if prior else ""
        )
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "defiant_agent_harness.cli.main",
                "--workdir",
                str(state),
                "--workspace-root",
                str(state / "workspace"),
                "--user",
                "sam",
                "--workspace",
                "test",
                "mcp-proxy",
                "--config",
                str(config),
            ],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        assert self.process.stdin is not None
        assert self.process.stdout is not None
        self.responses: queue.Queue[dict] = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.responses.put(json.loads(line))

    def request(self, request_id: int, method: str, params=None) -> dict:
        assert self.process.stdin is not None
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        while True:
            response = self.responses.get(timeout=10)
            if response.get("id") == request_id:
                return response

    def notify(self, method: str, params=None) -> None:
        assert self.process.stdin is not None
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def raw(self, message) -> dict:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()
        return self.responses.get(timeout=10)

    def raw_text(self, message: str) -> dict:
        assert self.process.stdin is not None
        self.process.stdin.write(message + "\n")
        self.process.stdin.flush()
        return self.responses.get(timeout=10)

    def stop(self) -> None:
        if self.process.poll() is not None:
            return
        assert self.process.stdin is not None
        self.process.stdin.close()
        self.process.wait(timeout=10)
        if self.process.returncode:
            assert self.process.stderr is not None
            raise AssertionError(self.process.stderr.read())


def write_config(tmp_path: Path, marker: Path) -> Path:
    path = tmp_path / "proxy.yaml"
    path.write_text(
        f"""
server:
  name: fixture
  command:
    - {json.dumps(sys.executable)}
    - {json.dumps(str(SERVER))}
    - {json.dumps(str(marker))}
  timeout_seconds: 10
runner: pytest-mcp
tools:
  echo:
    side_effect: none
    target_arg: text
  send_email:
    side_effect: external_send
    target_arg: to
    cost_estimate_usd: "1.25"
  delete_record:
    side_effect: destructive
    target_arg: id
""",
        encoding="utf-8",
    )
    return path


def initialize(proxy: ProxyProcess, requested_version="2025-06-18") -> None:
    response = proxy.request(
        1,
        "initialize",
        {
            "protocolVersion": requested_version,
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1"},
        },
    )
    assert response["result"]["serverInfo"]["name"] == "fixture"
    assert response["result"]["protocolVersion"] == "2025-06-18"
    proxy.notify("notifications/initialized")


def calls(marker: Path) -> list[dict]:
    if not marker.exists():
        return []
    return [
        json.loads(line)
        for line in marker.read_text(encoding="utf-8").splitlines()
        if line
    ]


def test_proxy_preserves_protocol_and_governs_real_subprocess(tmp_path, capsys):
    state = tmp_path / "state"
    marker = tmp_path / "upstream-calls.jsonl"
    config = write_config(tmp_path, marker)
    proxy = ProxyProcess(config, state)
    try:
        initialize(proxy, requested_version="2025-11-25")
        bypass = proxy.raw(
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"text": "bypass"}},
            }
        )
        assert bypass["error"]["code"] == -32600
        batch = proxy.raw(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"text": "batch"}},
                }
            ]
        )
        assert batch["error"]["code"] == -32600
        nonfinite = proxy.raw_text(
            '{"jsonrpc":"2.0","id":98,"method":"tools/call",'
            '"params":{"name":"echo","arguments":{"value":NaN}}}'
        )
        assert nonfinite["error"]["code"] == -32700
        assert calls(marker) == []

        listed = proxy.request(2, "tools/list")
        assert {tool["name"] for tool in listed["result"]["tools"]} >= {
            "echo",
            "send_email",
            "unmapped_tool",
        }

        echoed = proxy.request(
            3,
            "tools/call",
            {"name": "echo", "arguments": {"text": "hello"}},
        )
        assert echoed["result"]["content"][0]["text"] == "hello"
        assert echoed["result"]["_defiant"]["status"] == "succeeded"

        email_params = {
            "name": "send_email",
            "arguments": {
                "to": "merchant@example.com",
                "subject": "Review",
                "body": "Attached.",
            },
            "_meta": {"progressToken": "email-progress"},
        }
        pending = proxy.request(4, "tools/call", email_params)
        metadata = pending["result"]["_defiant"]
        assert pending["result"]["isError"] is True
        assert metadata["status"] == "pending_approval"
        approval_id = metadata["approval_id"]
        assert [call["name"] for call in calls(marker)] == ["echo"]
    finally:
        proxy.stop()

    # Approval is durable and intentionally does not execute in the CLI
    # process, which has no authority over the upstream server connection.
    assert (
        main(
            [
                "--workdir",
                str(state),
                "--user",
                "sam",
                "approve",
                approval_id,
            ]
        )
        == 0
    )
    assert ApprovalStore(state / "approvals.json").get(approval_id).status == "approved"
    assert [call["name"] for call in calls(marker)] == ["echo"]
    capsys.readouterr()

    # A fresh proxy process recognizes the exact payload, consumes the approval,
    # and preserves the upstream MCP result rather than flattening it to text.
    restarted = ProxyProcess(config, state)
    try:
        initialize(restarted)
        completed = restarted.request(5, "tools/call", email_params)
        assert completed["result"]["_defiant"]["status"] == "succeeded"
        assert completed["result"]["_defiant"]["approval_id"] == approval_id
        assert completed["result"]["structuredContent"]["upstream_preserved"] is True

        blocked = restarted.request(
            6,
            "tools/call",
            {"name": "delete_record", "arguments": {"id": "customer-1"}},
        )
        assert blocked["result"]["isError"] is True
        assert blocked["result"]["_defiant"]["status"] == "blocked"

        unmapped = restarted.request(
            7,
            "tools/call",
            {"name": "unmapped_tool", "arguments": {}},
        )
        assert unmapped["result"]["isError"] is True
        assert unmapped["result"]["_defiant"]["status"] == "blocked"
    finally:
        restarted.stop()

    assert [call["name"] for call in calls(marker)] == ["echo", "send_email"]
    approval = ApprovalStore(state / "approvals.json").get(approval_id)
    assert approval.status == "consumed"
    assert BudgetLedger(state / "budget.json").summary()["total_spent_usd"] == "1.25"
    assert EvidenceStore(state / "evidence.jsonl").verify().ok


def test_repeated_pending_call_reuses_one_exact_action(tmp_path):
    state = tmp_path / "state"
    marker = tmp_path / "calls.jsonl"
    config = write_config(tmp_path, marker)
    proxy = ProxyProcess(config, state)
    params = {
        "name": "send_email",
        "arguments": {"to": "same@example.com", "body": "same"},
    }
    try:
        initialize(proxy)
        first = proxy.request(2, "tools/call", params)
        second = proxy.request(3, "tools/call", params)
    finally:
        proxy.stop()
    assert (
        first["result"]["_defiant"]["approval_id"]
        == second["result"]["_defiant"]["approval_id"]
    )
    assert len(ApprovalStore(state / "approvals.json").list_pending()) == 1
    assert calls(marker) == []


def test_rejected_proxy_call_cannot_be_spammed_into_a_new_approval(
    tmp_path,
    capsys,
):
    state = tmp_path / "state"
    marker = tmp_path / "calls.jsonl"
    config = write_config(tmp_path, marker)
    proxy = ProxyProcess(config, state)
    params = {
        "name": "send_email",
        "arguments": {"to": "wrong@example.com", "body": "do not send"},
    }
    try:
        initialize(proxy)
        pending = proxy.request(2, "tools/call", params)
        approval_id = pending["result"]["_defiant"]["approval_id"]
        assert (
            main(
                [
                    "--workdir",
                    str(state),
                    "--user",
                    "sam",
                    "reject",
                    approval_id,
                    "--note",
                    "wrong recipient",
                ]
            )
            == 0
        )
        capsys.readouterr()
        repeated = proxy.request(3, "tools/call", params)
    finally:
        proxy.stop()
    assert repeated["result"]["_defiant"]["status"] == "rejected"
    assert repeated["result"]["_defiant"]["approval_id"] == approval_id
    assert calls(marker) == []
