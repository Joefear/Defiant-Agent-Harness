from __future__ import annotations

import json
import queue
from io import StringIO

import pytest

import defiant_agent_harness.hooks.codex as codex_hook
import defiant_agent_harness.hooks.copilot as copilot_hook
from defiant_agent_harness.evidence.store import EvidenceStore
from defiant_agent_harness.mcp.http_session import McpTransportError, _json_object
from defiant_agent_harness.mcp.proxy import McpStdioProxy
from defiant_agent_harness.mcp.session import UpstreamSession
from defiant_agent_harness.persistence import (
    PersistenceError,
    open_state_file,
    prepare_storage_root,
    read_json,
)
from defiant_agent_harness.strict_json import StrictJsonError, loads_strict_json


@pytest.mark.parametrize(
    "document",
    [
        '{"decision":"allow","decision":"block"}',
        '{"outer":{"decision":"allow","decision":"block"}}',
    ],
)
def test_strict_json_rejects_duplicate_keys_at_every_depth_without_echo(document):
    with pytest.raises(StrictJsonError, match="duplicate JSON key") as failure:
        loads_strict_json(document, label="authority document")

    assert "decision" not in str(failure.value)
    assert "allow" not in str(failure.value)
    assert "block" not in str(failure.value)


def test_strict_json_requires_utf8_and_finite_numbers():
    with pytest.raises(StrictJsonError, match="not valid UTF-8 JSON"):
        loads_strict_json(b'{"value":"\xff"}', label="authority document")
    with pytest.raises(StrictJsonError, match="non-finite JSON number"):
        loads_strict_json('{"value":NaN}', label="authority document")


def test_durable_state_rejects_duplicate_keys_without_echo(tmp_path):
    root = prepare_storage_root(tmp_path / "state")
    path = root.path / "budget.json"
    with open_state_file(path, "xb") as handle:
        handle.write(b'{"balance_usd":"10","balance_usd":"sensitive"}')

    with pytest.raises(PersistenceError, match="duplicate JSON key") as failure:
        read_json(path)

    assert "balance_usd" not in str(failure.value)
    assert "sensitive" not in str(failure.value)
    assert str(root.path) not in str(failure.value)


def test_evidence_rejects_duplicate_keys_before_chain_interpretation(tmp_path):
    path = tmp_path / "evidence.jsonl"
    EvidenceStore(path)
    with open_state_file(path, "ab") as handle:
        handle.write(b'{"decision":"allow","decision":"sensitive"}\n')

    status = EvidenceStore(path).verify()

    assert status.ok is False
    assert status.detail == "record 0 contains a duplicate JSON key"
    assert "sensitive" not in status.detail


def test_mcp_client_duplicate_method_is_parse_error_and_never_forwarded():
    class CaptureSession:
        def __init__(self):
            self.messages = []
            self.forwarded = []

        def emit_message(self, message):
            self.messages.append(message)

        def forward_raw(self, message):
            self.forwarded.append(message)

    session = CaptureSession()
    proxy = object.__new__(McpStdioProxy)
    proxy.session = session

    proxy.accept_line(
        '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
        '"method":"tools/list","params":{}}'
    )

    assert session.messages == [
        {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": "Parse error"},
        }
    ]
    assert session.forwarded == []


def test_http_upstream_duplicate_keys_fail_transport_without_echo():
    with pytest.raises(McpTransportError, match="duplicate JSON key") as failure:
        _json_object('{"result":{"status":"safe","status":"sensitive"}}')

    assert "status" not in str(failure.value)
    assert "sensitive" not in str(failure.value)


def test_stdio_upstream_duplicate_keys_fail_pending_calls_without_forwarding():
    class Process:
        stdout = StringIO(
            '{"jsonrpc":"2.0","id":"defiant:test",'
            '"result":{"value":"safe","value":"sensitive"}}\n'
        )

        @staticmethod
        def poll():
            return 0

    output = StringIO()
    session = UpstreamSession(("unused",), output, start=False)
    session.process = Process()
    waiter = queue.Queue(maxsize=1)
    session._pending["defiant:test"] = waiter

    session._read_upstream()

    failure = waiter.get_nowait()["_transport_error"]
    assert "duplicate JSON key" in failure
    assert "value" not in failure
    assert "sensitive" not in failure
    assert output.getvalue() == ""


@pytest.mark.parametrize("hook_module", [copilot_hook, codex_hook])
def test_native_hook_duplicate_keys_fail_closed_before_state_creation(
    tmp_path,
    monkeypatch,
    hook_module,
):
    stdout = StringIO()
    stderr = StringIO()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        hook_module.sys,
        "stdin",
        StringIO('{"tool_name":"read_file","tool_name":"sensitive","tool_input":{}}'),
    )
    monkeypatch.setattr(hook_module.sys, "stdout", stdout)
    monkeypatch.setattr(hook_module.sys, "stderr", stderr)

    assert hook_module.main(["pre"]) == 0

    response = json.loads(stdout.getvalue())
    assert "deny" in json.dumps(response).lower()
    assert "duplicate JSON key" in stderr.getvalue()
    assert "sensitive" not in stderr.getvalue()
    assert not (tmp_path / ".dah-hooks").exists()
    assert not (tmp_path / ".dah-codex-hooks").exists()


@pytest.mark.parametrize("hook_module", [copilot_hook, codex_hook])
def test_native_hook_embedded_arguments_reject_duplicate_keys(
    tmp_path,
    monkeypatch,
    hook_module,
):
    stdout = StringIO()
    stderr = StringIO()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        hook_module.sys,
        "stdin",
        StringIO(
            '{"tool_name":"read_file",'
            '"tool_input":"{\\"path\\":\\"safe\\",'
            '\\"path\\":\\"sensitive\\"}"}'
        ),
    )
    monkeypatch.setattr(hook_module.sys, "stdout", stdout)
    monkeypatch.setattr(hook_module.sys, "stderr", stderr)

    assert hook_module.main(["pre"]) == 0

    response = json.loads(stdout.getvalue())
    assert "deny" in json.dumps(response).lower()
    assert "tool arguments must be valid JSON" in stderr.getvalue()
    assert "sensitive" not in stderr.getvalue()
