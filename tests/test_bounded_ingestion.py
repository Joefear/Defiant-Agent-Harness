from __future__ import annotations

import json
from io import BytesIO, StringIO

import pytest

import defiant_agent_harness.evidence.store as evidence_store_module
import defiant_agent_harness.hooks.codex as codex_hook
import defiant_agent_harness.hooks.copilot as copilot_hook
import defiant_agent_harness.mcp.config as mcp_config_module
import defiant_agent_harness.mcp.proxy as mcp_proxy_module
import defiant_agent_harness.persistence as persistence_module
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.bounded_io import (
    InputLimitError,
    iter_bounded_text_lines,
    read_bounded_text,
)
from defiant_agent_harness.contracts import Decision, EvidenceRecord, ResultStatus
from defiant_agent_harness.evidence.store import EvidenceError, EvidenceStore
from defiant_agent_harness.mcp.config import McpConfigError, load_proxy_config
from defiant_agent_harness.mcp.proxy import McpStdioProxy
from defiant_agent_harness.mcp.session import McpTransportError
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.persistence import (
    PersistenceError,
    atomic_write_json,
    open_state_file,
    prepare_storage_root,
    read_json,
)
from defiant_agent_harness.state_integrity import StateIntegrityAuditor


def _record(summary: str = "") -> EvidenceRecord:
    return EvidenceRecord(
        request_id="req_bounded",
        action_id="act_bounded",
        decision=Decision.ALLOW,
        result_status=ResultStatus.SUCCEEDED,
        result_summary=summary,
    )


def test_text_limits_count_utf8_bytes_and_not_aggregate_lines():
    with pytest.raises(InputLimitError, match="exceeds 3 bytes"):
        read_bounded_text(StringIO("éé"), 3, "event")

    lines = list(iter_bounded_text_lines(StringIO("{}\n" * 100), 3, "message"))
    assert len(lines) == 100


def test_durable_json_is_bounded_before_decode(tmp_path):
    root = prepare_storage_root(tmp_path / "state")
    path = root.path / "oversized.json"
    with open_state_file(path, "xb") as handle:
        handle.write(b'{"value":"too large"}')

    with pytest.raises(PersistenceError, match="exceeds 8 bytes") as failure:
        read_json(path, max_bytes=8)
    assert str(root.path) not in str(failure.value)


def test_durable_json_rejects_non_finite_constants(tmp_path):
    root = prepare_storage_root(tmp_path / "state")
    path = root.path / "invalid.json"
    with open_state_file(path, "xb") as handle:
        handle.write(b'{"value":NaN}')

    with pytest.raises(PersistenceError, match="non-finite JSON number"):
        read_json(path)


def test_durable_json_write_refuses_unreadable_output_and_cleans_temp(
    tmp_path,
    monkeypatch,
):
    root = prepare_storage_root(tmp_path / "state")
    path = root.path / "bounded.json"
    monkeypatch.setattr(persistence_module, "MAX_DURABLE_JSON_BYTES", 32)

    with pytest.raises(PersistenceError, match="exceeds 32 bytes"):
        atomic_write_json(path, {"value": "x" * 64})

    assert not path.exists()
    assert not list(root.path.glob(".*.tmp"))


def test_durable_json_write_honors_a_store_specific_ceiling(tmp_path):
    root = prepare_storage_root(tmp_path / "state")
    path = root.path / "store-bounded.json"

    with pytest.raises(PersistenceError, match="exceeds 32 bytes"):
        atomic_write_json(path, {"value": "x" * 64}, max_bytes=32)

    assert not path.exists()
    assert not list(root.path.glob(".*.tmp"))


def test_evidence_rejects_oversized_existing_and_new_records(tmp_path, monkeypatch):
    path = tmp_path / "evidence.jsonl"
    store = EvidenceStore(path)
    monkeypatch.setattr(evidence_store_module, "MAX_EVIDENCE_RECORD_BYTES", 512)

    with pytest.raises(EvidenceError, match="evidence record exceeds 512 bytes"):
        store.append(_record("x" * 512))
    assert path.read_bytes() == b""

    with open_state_file(path, "ab") as handle:
        handle.write(b"x" * 513)
    status = store.verify()
    assert status.ok is False
    assert "record 0 exceeds 512 bytes" in status.detail


def test_evidence_line_limit_does_not_limit_total_history(monkeypatch):
    monkeypatch.setattr(evidence_store_module, "MAX_EVIDENCE_RECORD_BYTES", 3)
    lines = list(
        evidence_store_module.iter_bounded_evidence_lines(BytesIO(b"{}\n" * 100))
    )
    assert len(lines) == 100


def test_evidence_non_finite_constant_is_normalized(tmp_path):
    path = tmp_path / "evidence.jsonl"
    EvidenceStore(path)
    with open_state_file(path, "ab") as handle:
        handle.write(b'{"value":NaN}\n')

    status = EvidenceStore(path).verify()
    assert status.ok is False
    assert status.detail == "record 0 contains an invalid JSON value"


def test_oversized_evidence_is_a_sanitized_read_only_integrity_finding(
    tmp_path,
    monkeypatch,
):
    state = tmp_path / "state"
    build_harness(state, MockAgentAdapter())
    monkeypatch.setattr(evidence_store_module, "MAX_EVIDENCE_RECORD_BYTES", 64)
    with open_state_file(state / "evidence.jsonl", "ab") as handle:
        handle.write(b"sensitive" * 9)

    report = StateIntegrityAuditor(state).audit()
    rendered = json.dumps(report.to_dict())
    assert report.safe_to_execute is False
    assert any(issue.code == "evidence_invalid" for issue in report.issues)
    assert "exceeds 64 bytes" in rendered
    assert "sensitive" not in rendered
    assert str(state) not in rendered


def test_mcp_client_limit_fails_closed_before_json_parse(monkeypatch):
    monkeypatch.setattr(mcp_proxy_module, "MAX_MCP_MESSAGE_BYTES", 32)
    with pytest.raises(McpTransportError, match="exceeds 32 bytes"):
        list(mcp_proxy_module._client_lines(StringIO("x" * 33 + "\n")))

    class CaptureSession:
        def __init__(self):
            self.messages = []

        def emit_message(self, message):
            self.messages.append(message)

    session = CaptureSession()
    proxy = object.__new__(McpStdioProxy)
    proxy.session = session
    proxy.accept_line("x" * 33)
    assert session.messages[0]["error"] == {
        "code": -32600,
        "message": "MCP message exceeds size limit",
    }


def test_mcp_config_is_bounded_before_yaml_parse(tmp_path, monkeypatch):
    path = tmp_path / "proxy.yaml"
    path.write_text("x" * 33, encoding="utf-8")
    monkeypatch.setattr(mcp_config_module, "MAX_MCP_CONFIG_BYTES", 32)

    with pytest.raises(McpConfigError, match="exceeds 32 bytes"):
        load_proxy_config(path)


def test_mcp_config_rejects_yaml_alias_amplification(tmp_path):
    path = tmp_path / "proxy.yaml"
    path.write_text(
        "server: &server\n  name: local\n  command: [python]\ncopy: *server\n",
        encoding="utf-8",
    )

    with pytest.raises(McpConfigError, match="aliases are not supported"):
        load_proxy_config(path)


@pytest.mark.parametrize("hook_module", [copilot_hook, codex_hook])
def test_native_hook_event_limit_returns_fail_closed_response(monkeypatch, hook_module):
    stdin = StringIO("x" * 33)
    stdout = StringIO()
    stderr = StringIO()
    monkeypatch.setattr(hook_module, "MAX_HOOK_EVENT_BYTES", 32)
    monkeypatch.setattr(hook_module.sys, "stdin", stdin)
    monkeypatch.setattr(hook_module.sys, "stdout", stdout)
    monkeypatch.setattr(hook_module.sys, "stderr", stderr)

    assert hook_module.main(["pre"]) == 0
    response = json.loads(stdout.getvalue())
    assert "deny" in json.dumps(response).lower()
    assert "exceeds 32 bytes" in stderr.getvalue()
    assert "x" * 33 not in json.dumps(response)
