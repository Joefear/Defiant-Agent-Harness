from __future__ import annotations

import json
import sys
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest
import yaml

from defiant_agent_harness.authority_profile import AuthorityProfileError
from defiant_agent_harness.contracts import sha256_of
from defiant_agent_harness.evidence.store import EvidenceStore
from defiant_agent_harness.mcp.config import McpConfigError, load_proxy_config
from defiant_agent_harness.mcp.proxy import McpStdioProxy
from defiant_agent_harness.tools.registry import ToolResult
from test_mcp_stdio_proxy import ProxyProcess, SERVER, calls, initialize


class CaptureSession:
    def __init__(self):
        self.forwarded = []
        self.responses = []
        self.executed = []

    def forward_raw(self, line):
        self.forwarded.append(json.loads(line))

    def emit_message(self, message):
        self.responses.append(message)

    def call_tool(self, name, arguments, *, transport_params=None):
        self.executed.append((name, arguments))
        return ToolResult(
            status="succeeded", summary="real handler entered", output={"text": "ok"}
        )


def config_body(command=None):
    command = command or ["python", "reviewed-server.py"]
    return {
        "server": {"name": "fixture", "command": command},
        "tools": {"echo": {"side_effect": "none"}},
        "method_dispositions": {
            "protocol_version": "2025-06-18",
            "reviewed_server": {"name": "fixture", "commands": [command.copy()]},
            "requests": {
                "initialize": "allow",
                "tools/list": "allow",
                "ping": "allow",
                "tools/call": "governed",
                "resources/read": "deny",
            },
            "notifications": {
                "notifications/initialized": "allow",
                "notifications/roots/list_changed": "deny",
                "tools/call": "deny",
            },
        },
    }


def load_body(tmp_path, body):
    path = tmp_path / "methods.yaml"
    path.write_text(yaml.safe_dump(body), encoding="utf-8")
    return load_proxy_config(path)


def make_proxy(tmp_path, config=None):
    config = config or load_body(tmp_path, config_body())
    session = CaptureSession()
    proxy = McpStdioProxy(
        config,
        session,
        workdir=tmp_path / "state",
        user_id="operator",
        workspace_id="test",
        workspace_root=tmp_path / "workspace",
    )
    return proxy, session


def send(proxy, method, *, notification=False, **fields):
    message = {"jsonrpc": "2.0", "method": method, **fields}
    if not notification:
        message.setdefault("id", 42)
    proxy.accept_line(json.dumps(message))


@pytest.mark.parametrize("method", ["ping", "tools/list"])
def test_allowed_request_forwards_without_tool_authority(tmp_path, method):
    proxy, session = make_proxy(tmp_path)
    budget_before = proxy.harness.budget.summary()
    # A tool-shaped payload remains protocol data, never an adapter action.
    params = {"name": "echo", "arguments": {"text": "not a tool call"}}
    send(proxy, method, params=params)
    assert session.forwarded == [
        {"jsonrpc": "2.0", "method": method, "id": 42, "params": params}
    ]
    assert session.executed == []
    assert list(proxy.harness.evidence._raw()) == []
    assert proxy.harness.approvals.list_pending() == []
    assert proxy.harness.budget.summary() == budget_before


def test_allowed_notification_and_initialize_capabilities_are_reviewed(tmp_path):
    proxy, session = make_proxy(tmp_path)
    send(
        proxy,
        "initialize",
        params={
            "protocolVersion": "2025-11-25",
            "capabilities": {
                "roots": {"listChanged": True},
                "sampling": {},
                "elicitation": {},
            },
            "clientInfo": {"name": "test", "version": "1"},
        },
    )
    send(proxy, "notifications/initialized", notification=True)
    assert session.forwarded[0]["params"]["protocolVersion"] == "2025-06-18"
    assert session.forwarded[0]["params"]["capabilities"] == {}
    assert session.forwarded[1] == {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    }
    assert session.responses == []
    assert session.executed == []
    assert list(proxy.harness.evidence._raw()) == []


def test_tools_call_still_uses_governed_path(tmp_path):
    proxy, session = make_proxy(tmp_path)
    send(proxy, "tools/call", params={"name": "echo", "arguments": {}})
    assert session.forwarded == []
    assert session.executed == [("echo", {})]
    assert session.responses[0]["result"]["_defiant"]["status"] == "succeeded"
    records = list(proxy.harness.evidence._raw())
    assert [record["result_status"] for record in records] == ["skipped", "succeeded"]
    assert records[0]["authorization_hash"]
    assert proxy.harness.evidence.verify().ok


@pytest.mark.parametrize(
    "method, disposition",
    [
        ("future/doAnything", "unclassified"),
        ("resources/read", "deny"),
        ("Tools/call", "unclassified"),
        ("TOOLS/CALL", "unclassified"),
        ("tools/list/extra", "unclassified"),
    ],
)
def test_refused_request_has_durable_non_authorizing_evidence(
    tmp_path, method, disposition
):
    proxy, session = make_proxy(tmp_path)
    send(
        proxy,
        method,
        params={"name": "echo", "arguments": {"secret": "MUST-NOT-BE-LOGGED"}},
        id="PRIVATE-WIRE-ID",
    )
    assert session.forwarded == session.executed == []
    response = session.responses[0]
    assert response["id"] == "PRIVATE-WIRE-ID"
    assert response["error"]["code"] == -32601
    records = list(proxy.harness.evidence._raw())
    assert len(records) == 1
    record = records[0]
    assert (
        record["record_id"]
        == response["error"]["data"]["_defiant"]["evidence_record_id"]
    )
    inputs = record["decision_inputs"]
    assert inputs["method"] == method
    assert inputs["message_kind"] == "request"
    assert inputs["disposition"] == disposition
    assert inputs["server_name"] == "fixture"
    assert inputs["server_fingerprint"] == proxy.server_fingerprint
    assert inputs["proxy_fingerprint"] == proxy.proxy_fingerprint
    assert inputs["rpc_id_hash"] == sha256_of("PRIVATE-WIRE-ID")
    assert record["decision"] == "block" and record["result_status"] == "blocked"
    assert record["timestamp"] and record["decision_reason"]
    assert record["cost_usd"] == "0" and not record["authorization_hash"]
    assert record["request_id"].startswith("rpc_event_")
    assert "MUST-NOT-BE-LOGGED" not in json.dumps(record)
    assert "PRIVATE-WIRE-ID" not in json.dumps(record)
    assert proxy.harness.approvals.list_pending() == []
    assert proxy.harness.evidence.verify().ok


@pytest.mark.parametrize(
    "method",
    [
        "unknown/notification",
        "notifications/roots/list_changed",
        "tools/call",
        "initialize",
        "tools/list",
        "ping",
    ],
)
def test_refused_notification_is_silent_logged_and_never_forwarded(tmp_path, method):
    proxy, session = make_proxy(tmp_path)
    send(proxy, method, notification=True, params={"name": "echo", "arguments": {}})
    assert session.responses == session.forwarded == session.executed == []
    (record,) = list(proxy.harness.evidence._raw())
    assert record["decision_inputs"]["message_kind"] == "notification"
    assert record["decision_inputs"]["rpc_id_hash"] == ""
    assert not record["authorization_hash"]
    assert proxy.harness.evidence.verify().ok


@pytest.mark.parametrize(
    "method",
    [
        None,
        True,
        7,
        [],
        {},
        "",
        " tools/call",
        "tools/call\n",
        "tools/\u200bcall",
        "ｔools/call",
        "tools\\call",
        "tools/*",
        "rpc.internal",
        "x" * 129,
    ],
)
def test_malformed_method_cannot_be_forwarded(tmp_path, method):
    proxy, session = make_proxy(tmp_path)
    send(proxy, method)
    assert session.forwarded == session.executed == []
    assert session.responses[0]["error"]["code"] == -32600
    assert proxy.harness.evidence.verify().count == 1


@pytest.mark.parametrize(
    "extra",
    [
        {"jsonrpc": "1.0"},
        {"id": None},
        {"id": True},
        {"id": 1.5},
        {"id": {}},
        {"id": ""},
        {"result": {}},
        {"error": {}},
        {"unexpected": "tools/call"},
    ],
)
def test_ambiguous_envelopes_do_not_enter_allowed_or_tool_path(tmp_path, extra):
    proxy, session = make_proxy(tmp_path)
    send(proxy, "ping", **extra)
    assert session.forwarded == session.executed == []
    assert session.responses[0]["error"]["code"] == -32600


def test_client_response_and_batch_have_no_forwarding_path(tmp_path):
    proxy, session = make_proxy(tmp_path)
    proxy.accept_line(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "server-request",
                "result": {"roots": [{"uri": "file:///outside"}]},
            }
        )
    )
    assert session.responses == session.forwarded == []
    (record,) = list(proxy.harness.evidence._raw())
    assert record["decision_inputs"]["message_kind"] == "response"
    proxy.accept_line(
        json.dumps(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "echo"},
                }
            ]
        )
    )
    assert session.responses[-1]["error"]["code"] == -32600
    assert session.forwarded == session.executed == []


@pytest.mark.parametrize("params", [None, [], "tools/call", 42])
def test_malformed_non_tool_params_are_refused_with_evidence(tmp_path, params):
    proxy, session = make_proxy(tmp_path)
    send(proxy, "ping", params=params)
    assert session.responses[0]["error"]["code"] == -32602
    send(proxy, "notifications/initialized", notification=True, params=params)
    assert len(session.responses) == 1
    assert session.forwarded == session.executed == []
    assert proxy.harness.evidence.verify().count == 2


def test_escaped_ascii_method_is_still_governed(tmp_path):
    proxy, session = make_proxy(tmp_path)
    proxy.accept_line(
        r'{"jsonrpc":"2.0","id":1,"method":"\u0074ools/call","params":{"name":"echo","arguments":{}}}'
    )
    assert session.forwarded == []
    assert session.executed == [("echo", {})]
    assert session.responses[0]["result"]["_defiant"]["status"] == "succeeded"


@pytest.mark.parametrize(
    "form, name, value",
    [
        ("requests", "tools/call", "allow"),
        ("requests", "ping", "governed"),
        ("notifications", "tools/call", "governed"),
        ("requests", "ping", "ALLOW"),
        ("requests", "ping", True),
        ("requests", "", "allow"),
        ("requests", "*", "allow"),
        ("requests", "tools/*", "allow"),
        ("requests", "tools/\u200bcall", "allow"),
        ("requests", 42, "allow"),
    ],
)
def test_method_configuration_fails_closed(tmp_path, form, name, value):
    body = config_body()
    body["method_dispositions"][form][name] = value
    with pytest.raises(McpConfigError):
        load_body(tmp_path, body)


def test_duplicate_yaml_method_declaration_is_rejected(tmp_path):
    path = tmp_path / "duplicate.yaml"
    body = yaml.safe_dump(config_body())
    body = body.replace("    ping: allow", "    ping: allow\n    ping: deny")
    path.write_text(body, encoding="utf-8")
    with pytest.raises(McpConfigError, match="duplicate mapping key"):
        load_proxy_config(path)


@pytest.mark.parametrize(
    "change", ["name", "command", "protocol", "unknown", "missing", "null"]
)
def test_stale_or_ambiguous_review_is_rejected(tmp_path, change):
    body = config_body()
    if change == "name":
        body["server"]["name"] = "other"
    elif change == "command":
        body["server"]["command"] = ["python", "new-version.py"]
    elif change == "protocol":
        body["method_dispositions"]["protocol_version"] = "2025-11-25"
    elif change == "unknown":
        body["method_dispositions"]["default"] = "allow"
    elif change == "missing":
        del body["method_dispositions"]["notifications"]
    else:
        body["method_dispositions"] = None
    with pytest.raises(McpConfigError):
        load_body(tmp_path, body)


def test_command_override_and_pin_change_cannot_inherit_review():
    path = Path(__file__).parents[1] / "examples/filesystem/mcp-proxy.yaml"
    original = load_proxy_config(path)
    windows = load_proxy_config(path, ["cmd", "/d", "/s", "/c", *original.command])
    assert windows.method_dispositions == original.method_dispositions
    with pytest.raises(McpConfigError, match="binding mismatch"):
        load_proxy_config(
            path,
            [
                "npx",
                "-y",
                "@modelcontextprotocol/server-filesystem@latest",
                "workspace",
            ],
        )
    with pytest.raises(McpConfigError, match="binding mismatch"):
        replace(original, server_name="different")


@pytest.mark.parametrize(
    "form,name",
    [
        ("notifications", "initialize"),
        ("notifications", "tools/list"),
        ("notifications", "ping"),
        ("requests", "notifications/initialized"),
    ],
)
def test_known_protocol_forms_cannot_be_misdeclared(tmp_path, form, name):
    body = config_body()
    body["method_dispositions"][form][name] = "allow"
    with pytest.raises(McpConfigError, match="message form"):
        load_body(tmp_path, body)


def test_duplicate_in_memory_review_and_oversized_config_are_rejected(
    tmp_path, monkeypatch
):
    import defiant_agent_harness.mcp.config as config_module

    policy = load_body(tmp_path, config_body()).method_dispositions
    with pytest.raises(McpConfigError, match="duplicate"):
        replace(policy, requests=policy.requests + (("ping", "deny"),))
    monkeypatch.setattr(config_module, "MAX_MCP_CONFIG_COLLECTION_ITEMS", 4)
    with pytest.raises(McpConfigError, match="method requests item count"):
        load_body(tmp_path, config_body())


@pytest.mark.parametrize("field", ["commands", "requests"])
def test_review_rejects_callbacks_before_interpreting_values(tmp_path, field):
    class HostileValue:
        def __bool__(self):
            raise AssertionError("unvalidated truthiness callback executed")

        def __eq__(self, other):
            raise AssertionError("unvalidated equality callback executed")

    policy = load_body(tmp_path, config_body()).method_dispositions
    value = HostileValue()
    change = value if field == "commands" else (("ping", value),)
    with pytest.raises(McpConfigError):
        replace(policy, **{field: change})


@pytest.mark.parametrize("requested", ["2020-01-01", "2025-06-18", "2025-11-25"])
def test_initialize_offers_only_the_reviewed_revision(tmp_path, requested):
    proxy, session = make_proxy(tmp_path)
    send(proxy, "initialize", params={"protocolVersion": requested, "capabilities": {}})
    assert session.forwarded[0]["params"]["protocolVersion"] == "2025-06-18"


def test_absent_policy_never_inherits_non_tool_forwarding(tmp_path):
    body = config_body()
    del body["method_dispositions"]
    proxy, session = make_proxy(tmp_path, load_body(tmp_path, body))
    send(proxy, "initialize", params={"capabilities": {}})
    send(proxy, "future/method")
    assert session.forwarded == session.executed == []
    assert all(item["error"]["code"] == -32601 for item in session.responses)


def test_review_is_immutable_and_bound_to_existing_authority_profile(tmp_path):
    config = load_body(tmp_path, config_body())
    proxy, session = make_proxy(tmp_path, config)
    policy = config.method_dispositions
    projection = policy.authority_dict()
    projection["requests"]["ping"] = "deny"
    with pytest.raises(FrozenInstanceError):
        policy.requests = ()
    send(proxy, "ping")
    assert len(session.forwarded) == 1
    changed = replace(
        policy,
        requests=tuple(
            (name, "deny" if name == "ping" else value)
            for name, value in policy.requests
        ),
    )
    state = tmp_path / "state"
    before = {
        p.name: p.read_bytes()
        for p in state.iterdir()
        if p.suffix in {".json", ".jsonl"}
    }
    with pytest.raises(AuthorityProfileError):
        make_proxy(tmp_path, replace(config, method_dispositions=changed))
    assert before == {
        p.name: p.read_bytes()
        for p in state.iterdir()
        if p.suffix in {".json", ".jsonl"}
    }


def test_evidence_failure_never_forwards_or_claims_recorded_refusal(
    tmp_path, monkeypatch
):
    proxy, session = make_proxy(tmp_path)

    def fail(record):
        raise OSError("evidence unavailable")

    monkeypatch.setattr(proxy.harness.evidence, "append", fail)
    with pytest.raises(OSError, match="evidence unavailable"):
        send(proxy, "unknown/method")
    assert session.responses == session.forwarded == session.executed == []


def test_subprocess_wire_receipts_prove_refused_messages_never_arrive(tmp_path):
    executed = tmp_path / "executed.jsonl"
    traffic = tmp_path / "wire-receipts.jsonl"
    body = config_body([sys.executable, str(SERVER), str(executed), str(traffic)])
    path = tmp_path / "methods.yaml"
    path.write_text(yaml.safe_dump(body), encoding="utf-8")
    state = tmp_path / "state"
    process = ProxyProcess(path, state)
    try:
        initialize(process)
        response = process.request(
            2, "future/execute", {"name": "echo", "arguments": {"text": "never"}}
        )
        assert response["error"]["code"] == -32601
        response = process.request(3, "resources/read", {"uri": "file:///outside"})
        assert response["error"]["code"] == -32601
        process.notify("unknown/notification", {"name": "echo"})
        process.notify("notifications/roots/list_changed")
        process.notify("tools/call", {"name": "echo", "arguments": {"text": "never"}})
        barrier = process.raw({"jsonrpc": "2.0", "id": 4, "method": "ping"})
        assert barrier == {"jsonrpc": "2.0", "id": 4, "result": {}}
        response = process.request(
            5, "tools/call", {"name": "echo", "arguments": {"text": "governed"}}
        )
        assert response["result"]["_defiant"]["status"] == "succeeded"
    finally:
        process.stop()
    received = [
        json.loads(line) for line in traffic.read_text(encoding="utf-8").splitlines()
    ]
    assert [item["method"] for item in received] == [
        "initialize",
        "notifications/initialized",
        "ping",
        "tools/call",
    ]
    assert calls(executed) == [{"name": "echo", "arguments": {"text": "governed"}}]
    evidence = EvidenceStore(state / "evidence.jsonl")
    assert evidence.verify().ok
    refused = [
        record
        for record in evidence._raw()
        if record["decision_inputs"].get("event_type") == "mcp_method_refusal"
    ]
    assert len(refused) == 5
