from __future__ import annotations

import copy
import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from pathlib import Path

import pytest

from defiant_agent_harness.approvals.store import ApprovalStore
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.evidence.store import EvidenceStore
from defiant_agent_harness.mcp.config import load_proxy_config
from defiant_agent_harness.mcp.http_session import (
    HttpUpstreamSession,
    McpTransportError,
)
from defiant_agent_harness.mcp.proxy import McpStdioProxy
from defiant_agent_harness.mcp.session import MCP_RESULT

SESSION_ID = "test-session-2048"


class ServerState:
    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.deleted_sessions: list[str] = []


@contextmanager
def streamable_http_server():
    state = ServerState()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            message = json.loads(self.rfile.read(length))
            state.requests.append(
                {
                    "message": message,
                    "accept": self.headers.get("Accept"),
                    "content_type": self.headers.get("Content-Type"),
                    "protocol": self.headers.get("MCP-Protocol-Version"),
                    "session": self.headers.get("Mcp-Session-Id"),
                    "authorization": self.headers.get("Authorization"),
                }
            )
            if self.path == "/redirect":
                self.send_response(307)
                self.send_header("Location", "/mcp")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/plain":
                self._send(200, b"not MCP", "text/plain")
                return

            method = message.get("method")
            if method == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "http-fixture", "version": "1"},
                    },
                }
                self._send_json(response, session=SESSION_ID)
                return

            if (
                self.headers.get("Mcp-Session-Id") != SESSION_ID
                or self.headers.get("MCP-Protocol-Version") != "2025-06-18"
            ):
                self._send(400, b"missing MCP session headers", "text/plain")
                return
            if "id" not in message:
                self.send_response(202)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if method == "tools/list":
                self._send_json(
                    {
                        "jsonrpc": "2.0",
                        "id": message["id"],
                        "result": {
                            "tools": [
                                {"name": "echo", "inputSchema": {"type": "object"}},
                                {
                                    "name": "send_email",
                                    "inputSchema": {"type": "object"},
                                },
                            ]
                        },
                    }
                )
                return
            if method == "tools/call":
                params = message["params"]
                name = params["name"]
                if name == "unexpected_response":
                    self._send_json(
                        {
                            "jsonrpc": "2.0",
                            "id": "not-the-request-id",
                            "result": {"content": []},
                        }
                    )
                    return
                if name == "server_request":
                    self._send_sse(
                        [
                            {
                                "jsonrpc": "2.0",
                                "id": "upstream-question",
                                "method": "sampling/createMessage",
                                "params": {},
                            },
                            {
                                "jsonrpc": "2.0",
                                "id": message["id"],
                                "result": {"content": []},
                            },
                        ]
                    )
                    return
                text = (
                    params["arguments"].get("text")
                    or f"sent:{params['arguments'].get('to', '')}"
                )
                result = {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "result": {
                        "content": [{"type": "text", "text": text}],
                        "structuredContent": {"transport": "streamable-http"},
                    },
                }
                if name == "send_email":
                    self._send_sse(
                        [
                            {
                                "jsonrpc": "2.0",
                                "method": "notifications/progress",
                                "params": {"progress": 1},
                            },
                            result,
                        ]
                    )
                else:
                    self._send_json(result)
                return
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "id": message["id"],
                    "error": {"code": -32601, "message": "Method not found"},
                }
            )

        def do_DELETE(self) -> None:
            state.deleted_sessions.append(self.headers.get("Mcp-Session-Id", ""))
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _send_json(self, value: dict, *, session: str = "") -> None:
            body = json.dumps(value, separators=(",", ":")).encode()
            extra = {"Mcp-Session-Id": session} if session else {}
            self._send(200, body, "application/json", extra)

        def _send_sse(self, values: list[dict]) -> None:
            body = "".join(
                f"event: message\ndata: {json.dumps(value, separators=(',', ':'))}\n\n"
                for value in values
            ).encode()
            self._send(200, body, "text/event-stream")

        def _send(
            self,
            status: int,
            body: bytes,
            content_type: str,
            extra: dict[str, str] | None = None,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def initialize(proxy: McpStdioProxy) -> None:
    proxy.accept_line(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest", "version": "1"},
                },
            }
        )
    )
    proxy.accept_line(
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
    )


def send(proxy: McpStdioProxy, request_id: int, params: dict) -> None:
    proxy.accept_line(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": params,
            }
        )
    )


def messages(output: StringIO) -> list[dict]:
    return [json.loads(line) for line in output.getvalue().splitlines() if line.strip()]


def write_config(tmp_path: Path, endpoint: str) -> Path:
    path = tmp_path / "http-proxy.yaml"
    path.write_text(
        f"""
server:
  name: http-fixture
  url: {endpoint}/mcp
  header_env:
    Authorization: TEST_MCP_AUTH
  timeout_seconds: 5
runner: pytest-http
tools:
  echo:
    side_effect: none
    target_arg: text
  send_email:
    side_effect: external_send
    target_arg: to
  server_request:
    side_effect: none
""",
        encoding="utf-8",
    )
    return path


def build_proxy(
    config_path: Path,
    state: Path,
    output: StringIO,
) -> tuple[McpStdioProxy, HttpUpstreamSession]:
    config = load_proxy_config(config_path)
    session = HttpUpstreamSession(
        config.url,
        output,
        header_env=config.header_env,
        timeout_seconds=config.upstream_timeout_seconds,
    )
    proxy = McpStdioProxy(
        config,
        session,
        workdir=state,
        user_id="sam",
        workspace_id="http-test",
        workspace_root=state.parent / "workspace",
    )
    return proxy, session


def test_streamable_http_protocol_headers_sse_and_teardown(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("TEST_MCP_AUTH", "Bearer test-only")
    with streamable_http_server() as (endpoint, state):
        output = StringIO()
        session = HttpUpstreamSession(
            f"{endpoint}/mcp",
            output,
            header_env=(("Authorization", "TEST_MCP_AUTH"),),
        )
        session.forward_raw(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18"},
                }
            )
        )
        session.forward_raw(
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
        )
        result = session.call_tool(
            "send_email",
            {"to": "merchant@example.com"},
        )
        session.close()

    assert result.status == "succeeded"
    assert result.output[MCP_RESULT]["structuredContent"] == {
        "transport": "streamable-http"
    }
    assert messages(output)[-1]["method"] == "notifications/progress"
    initialize_request, notification, tool_call = state.requests
    assert initialize_request["protocol"] is None
    assert initialize_request["session"] is None
    assert initialize_request["authorization"] == "Bearer test-only"
    assert "application/json" in initialize_request["accept"]
    assert "text/event-stream" in initialize_request["accept"]
    assert notification["protocol"] == "2025-06-18"
    assert notification["session"] == SESSION_ID
    assert tool_call["protocol"] == "2025-06-18"
    assert tool_call["session"] == SESSION_ID
    assert state.deleted_sessions == [SESSION_ID]


def test_http_proxy_holds_then_consumes_exact_approved_retry(
    tmp_path,
    monkeypatch,
    capsys,
):
    monkeypatch.setenv("TEST_MCP_AUTH", "Bearer test-only")
    state_dir = tmp_path / "state"
    with streamable_http_server() as (endpoint, server_state):
        config = write_config(tmp_path, endpoint)
        first_output = StringIO()
        first, first_session = build_proxy(config, state_dir, first_output)
        params = {
            "name": "send_email",
            "arguments": {
                "to": "merchant@example.com",
                "subject": "Review",
                "body": "Attached.",
            },
            "_meta": {"progressToken": "first"},
        }
        try:
            initialize(first)
            send(first, 2, params)
        finally:
            first_session.close()

        pending = messages(first_output)[-1]
        approval_id = pending["result"]["_defiant"]["approval_id"]
        assert pending["result"]["_defiant"]["status"] == "pending_approval"
        assert not any(
            item["message"].get("method") == "tools/call"
            for item in server_state.requests
        )
        assert (
            main(
                [
                    "--workdir",
                    str(state_dir),
                    "--user",
                    "sam",
                    "approve",
                    approval_id,
                    "--note",
                    "reviewed exact HTTP MCP call",
                ]
            )
            == 0
        )
        capsys.readouterr()

        retry_output = StringIO()
        restarted, restarted_session = build_proxy(
            config,
            state_dir,
            retry_output,
        )
        try:
            initialize(restarted)
            retry = copy.deepcopy(params)
            retry["_meta"]["progressToken"] = "second"
            send(restarted, 3, retry)
        finally:
            restarted_session.close()

    completed = messages(retry_output)[-1]
    assert completed["result"]["_defiant"]["status"] == "succeeded"
    assert completed["result"]["_defiant"]["approval_id"] == approval_id
    assert completed["result"]["structuredContent"] == {"transport": "streamable-http"}
    assert ApprovalStore(state_dir / "approvals.json").get(approval_id).status == (
        "consumed"
    )
    assert EvidenceStore(state_dir / "evidence.jsonl").verify().ok
    calls = [
        item["message"]
        for item in server_state.requests
        if item["message"].get("method") == "tools/call"
    ]
    assert [call["params"]["name"] for call in calls] == ["send_email"]
    assert "_meta" not in calls[0]["params"]


def test_http_transport_refuses_redirects_and_unexpected_content_types():
    with streamable_http_server() as (endpoint, _):
        for path, expected in [
            ("/redirect", "status 307"),
            ("/plain", "Content-Type"),
        ]:
            session = HttpUpstreamSession(f"{endpoint}{path}", StringIO())
            with pytest.raises(McpTransportError, match=expected):
                session.forward_raw(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {"protocolVersion": "2025-06-18"},
                        }
                    )
                )


def test_missing_or_invalid_auth_environment_fails_before_network(
    tmp_path,
    monkeypatch,
    capsys,
):
    config = write_config(tmp_path, "https://mcp.example.com")
    monkeypatch.delenv("TEST_MCP_AUTH", raising=False)
    assert (
        main(
            [
                "--workdir",
                str(tmp_path / "state"),
                "mcp-http-proxy",
                "--config",
                str(config),
            ]
        )
        == 2
    )
    assert "TEST_MCP_AUTH" in capsys.readouterr().err

    monkeypatch.setenv("TEST_MCP_AUTH", "Bearer bad\r\nInjected: yes")
    with pytest.raises(McpTransportError, match="not a valid header value"):
        HttpUpstreamSession(
            "https://mcp.example.com",
            StringIO(),
            header_env=(("Authorization", "TEST_MCP_AUTH"),),
        )


def test_synchronous_tool_call_fails_closed_on_server_request(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("TEST_MCP_AUTH", "Bearer test-only")
    with streamable_http_server() as (endpoint, _):
        config = write_config(tmp_path, endpoint)
        output = StringIO()
        proxy, session = build_proxy(config, tmp_path / "state", output)
        try:
            initialize(proxy)
            send(
                proxy,
                2,
                {"name": "server_request", "arguments": {}},
            )
        finally:
            session.close()
    response = messages(output)[-1]
    assert response["error"]["data"]["_defiant"]["status"] == "failed"
    assert (
        "bidirectional request handling is not enabled"
        in (response["error"]["message"])
    )


def test_synchronous_tool_call_fails_closed_on_unexpected_response_id():
    with streamable_http_server() as (endpoint, _):
        output = StringIO()
        session = HttpUpstreamSession(f"{endpoint}/mcp", output)
        try:
            session.forward_raw(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"protocolVersion": "2025-06-18"},
                    }
                )
            )
            result = session.call_tool("unexpected_response", {})
        finally:
            session.close()
    assert result.status == "failed"
    assert "unexpected JSON-RPC id" in result.summary
    assert all(
        message.get("id") != "not-the-request-id" for message in messages(output)
    )
