from __future__ import annotations

import json
import queue
from io import StringIO

import pytest

import defiant_agent_harness.hooks.codex as codex_hook
import defiant_agent_harness.hooks.copilot as copilot_hook
import defiant_agent_harness.evidence.store as evidence_store_module
import defiant_agent_harness.strict_json as strict_json_module
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


def test_strict_json_enforces_depth_before_decoder_without_echo(monkeypatch):
    monkeypatch.setattr(strict_json_module, "MAX_JSON_NESTING_DEPTH", 3)
    assert loads_strict_json('[[["within-limit"]]]') == [[["within-limit"]]]

    def unexpected_decode(*_args, **_kwargs):
        pytest.fail("over-depth JSON reached the decoder")

    monkeypatch.setattr(strict_json_module.json, "loads", unexpected_decode)
    with pytest.raises(StrictJsonError, match="nesting depth of 3") as failure:
        loads_strict_json('[[[["SENSITIVE-CONTENT"]]]]', label="authority document")

    assert "SENSITIVE-CONTENT" not in str(failure.value)


def test_strict_json_enforces_lexical_tokens_and_ignores_string_punctuation(
    monkeypatch,
):
    monkeypatch.setattr(strict_json_module, "MAX_JSON_LEXICAL_TOKENS", 4)
    document = '["{[,]}", "escaped \\" quote", 1]'
    assert loads_strict_json(document) == ["{[,]}", 'escaped " quote', 1]

    def unexpected_decode(*_args, **_kwargs):
        pytest.fail("over-token JSON reached the decoder")

    monkeypatch.setattr(strict_json_module.json, "loads", unexpected_decode)
    with pytest.raises(StrictJsonError, match="lexical token count of 4"):
        loads_strict_json("[0,1,2,3]", label="authority document")


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


def test_durable_state_rejects_over_depth_without_echo(tmp_path, monkeypatch):
    root = prepare_storage_root(tmp_path / "state")
    path = root.path / "budget.json"
    monkeypatch.setattr(strict_json_module, "MAX_JSON_NESTING_DEPTH", 2)
    with open_state_file(path, "xb") as handle:
        handle.write(b'{"outer":{"SENSITIVE-CONTENT":{}}}')

    with pytest.raises(PersistenceError, match="nesting depth of 2") as failure:
        read_json(path)

    assert "SENSITIVE-CONTENT" not in str(failure.value)
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


def test_evidence_rejects_over_token_record_before_chain_interpretation(
    tmp_path, monkeypatch
):
    path = tmp_path / "evidence.jsonl"
    EvidenceStore(path)
    monkeypatch.setattr(strict_json_module, "MAX_JSON_LEXICAL_TOKENS", 3)
    monkeypatch.setattr(evidence_store_module, "MAX_JSON_LEXICAL_TOKENS", 3)
    with open_state_file(path, "ab") as handle:
        handle.write(b'["SENSITIVE-CONTENT",0,1]\n')

    status = EvidenceStore(path).verify()

    assert status.ok is False
    assert status.detail == "record 0 exceeds maximum JSON lexical token count of 3"
    assert "SENSITIVE-CONTENT" not in status.detail


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


def test_mcp_client_over_depth_is_parse_error_and_never_forwarded(monkeypatch):
    class CaptureSession:
        def __init__(self):
            self.messages = []
            self.forwarded = []

        def emit_message(self, message):
            self.messages.append(message)

        def forward_raw(self, message):
            self.forwarded.append(message)

    monkeypatch.setattr(strict_json_module, "MAX_JSON_NESTING_DEPTH", 2)
    session = CaptureSession()
    proxy = object.__new__(McpStdioProxy)
    proxy.session = session

    proxy.accept_line(
        '{"jsonrpc":"2.0","id":1,"method":"tools/list",'
        '"params":{"SENSITIVE-CONTENT":{}}}'
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
def test_native_hook_over_depth_fails_closed_before_state_creation(
    tmp_path,
    monkeypatch,
    hook_module,
):
    stdout = StringIO()
    stderr = StringIO()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(strict_json_module, "MAX_JSON_NESTING_DEPTH", 2)
    monkeypatch.setattr(
        hook_module.sys,
        "stdin",
        StringIO(
            '{"tool_name":"read_file","tool_input":'
            '{"path":"safe","SENSITIVE-CONTENT":{}}}'
        ),
    )
    monkeypatch.setattr(hook_module.sys, "stdout", stdout)
    monkeypatch.setattr(hook_module.sys, "stderr", stderr)

    assert hook_module.main(["pre"]) == 0

    response = json.loads(stdout.getvalue())
    assert "deny" in json.dumps(response).lower()
    assert "nesting depth" in stderr.getvalue()
    assert "SENSITIVE-CONTENT" not in stderr.getvalue()
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
