"""Streamable HTTP client transport for a remote MCP upstream server."""

from __future__ import annotations

import json
import os
import threading
import uuid
from typing import Any, TextIO
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ..tools.registry import ToolResult
from .session import MCP_ERROR, MCP_RESULT, McpTransportError, _result_summary

MAX_HTTP_BODY_BYTES = 10 * 1024 * 1024
RESERVED_HEADERS = {
    "accept",
    "content-length",
    "content-type",
    "mcp-protocol-version",
    "mcp-session-id",
}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpUpstreamSession:
    """Send stdio-client messages to one remote Streamable HTTP endpoint."""

    def __init__(
        self,
        endpoint: str,
        client_output: TextIO,
        *,
        header_env: tuple[tuple[str, str], ...] = (),
        timeout_seconds: float = 60.0,
        protocol_version: str = "2025-06-18",
    ):
        self.endpoint = endpoint
        self.client_output = client_output
        self.timeout_seconds = timeout_seconds
        self.protocol_version = protocol_version
        self.session_id = ""
        self._closed = False
        self._client_lock = threading.Lock()
        self._opener = build_opener(_NoRedirect())
        self._configured_headers = self._load_headers(header_env)

    def forward_raw(self, line: str) -> None:
        message = _json_object(line)
        for response in self._post(message):
            self.emit_message(response)

    def emit_message(self, message: dict[str, Any]) -> None:
        with self._client_lock:
            self.client_output.write(
                json.dumps(message, separators=(",", ":"), allow_nan=False) + "\n"
            )
            self.client_output.flush()

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        transport_params: dict[str, Any] | None = None,
    ) -> ToolResult:
        internal_id = f"defiant:{uuid.uuid4().hex}"
        request = {
            "jsonrpc": "2.0",
            "id": internal_id,
            "method": "tools/call",
            "params": transport_params or {"name": name, "arguments": arguments},
        }
        try:
            messages = self._post(request)
        except Exception as exc:
            return _failed_result(str(exc))

        response = None
        for message in messages:
            if message.get("id") == internal_id:
                if response is not None:
                    return _failed_result(
                        "upstream HTTP response repeated the tools/call reply"
                    )
                response = message
                continue
            if "method" in message and "id" in message:
                return _failed_result(
                    "upstream issued a request during a synchronous HTTP tool call; "
                    "bidirectional request handling is not enabled"
                )
            if "id" in message:
                return _failed_result(
                    "upstream HTTP response used an unexpected JSON-RPC id"
                )
            if "method" not in message:
                return _failed_result(
                    "upstream HTTP response included an invalid JSON-RPC message"
                )
            self.emit_message(message)
        if response is None:
            return _failed_result("upstream HTTP response omitted the tools/call reply")
        return _tool_result(response)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if not self.session_id:
            return
        request = Request(
            self.endpoint,
            method="DELETE",
            headers=self._headers(include_session=True, include_content_type=False),
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds):
                pass
        except (HTTPError, URLError, OSError):
            pass
        self.session_id = ""

    def _post(self, message: dict[str, Any]) -> list[dict[str, Any]]:
        if self._closed:
            raise McpTransportError("upstream HTTP session is closed")
        body = json.dumps(
            message,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        request = Request(
            self.endpoint,
            data=body,
            method="POST",
            headers=self._headers(
                include_session=True,
                include_content_type=True,
                include_protocol=message.get("method") != "initialize",
            ),
        )
        try:
            response = self._opener.open(request, timeout=self.timeout_seconds)
        except HTTPError as exc:
            detail = _bounded_error_body(exc)
            if exc.code == 404 and self.session_id:
                self.session_id = ""
                raise McpTransportError(
                    "upstream MCP session expired; reinitialize before retrying"
                ) from exc
            suffix = f": {detail}" if detail else ""
            raise McpTransportError(f"upstream HTTP status {exc.code}{suffix}") from exc
        except (URLError, OSError) as exc:
            raise McpTransportError(f"upstream HTTP request failed: {exc}") from exc

        try:
            with response:
                self._capture_session(
                    message,
                    response.headers.get("Mcp-Session-Id", ""),
                )
                content_type = response.headers.get_content_type().lower()
                if response.status == 202:
                    if "id" in message:
                        raise McpTransportError(
                            "upstream returned 202 Accepted for a JSON-RPC request"
                        )
                    _read_bounded(response)
                    return []
                if content_type == "application/json":
                    payload = _read_bounded(response)
                    return [_json_object(payload.decode("utf-8", errors="strict"))]
                if content_type == "text/event-stream":
                    return _read_sse(response)
                raise McpTransportError(
                    f"unsupported upstream Content-Type: {content_type or 'missing'}"
                )
        except McpTransportError:
            raise
        except (OSError, UnicodeError) as exc:
            raise McpTransportError(
                f"upstream HTTP response could not be read: {exc}"
            ) from exc

    def _capture_session(self, message: dict[str, Any], candidate: str) -> None:
        if not candidate:
            return
        if any(not 0x21 <= ord(char) <= 0x7E for char in candidate):
            raise McpTransportError("upstream returned an invalid MCP session id")
        method = message.get("method")
        if not self.session_id:
            if method != "initialize":
                raise McpTransportError(
                    "upstream assigned an MCP session outside initialization"
                )
            self.session_id = candidate
        elif candidate != self.session_id:
            raise McpTransportError("upstream changed the MCP session id")

    def _headers(
        self,
        *,
        include_session: bool,
        include_content_type: bool,
        include_protocol: bool = True,
    ) -> dict[str, str]:
        headers = dict(self._configured_headers)
        headers["Accept"] = "application/json, text/event-stream"
        if include_protocol:
            headers["MCP-Protocol-Version"] = self.protocol_version
        if include_content_type:
            headers["Content-Type"] = "application/json; charset=utf-8"
        if include_session and self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        return headers

    @staticmethod
    def _load_headers(
        header_env: tuple[tuple[str, str], ...],
    ) -> dict[str, str]:
        headers: dict[str, str] = {}
        for header, env_name in header_env:
            if header.lower() in RESERVED_HEADERS:
                raise McpTransportError(
                    f"configured header {header!r} is transport-controlled"
                )
            value = os.environ.get(env_name)
            if value is None or not value:
                raise McpTransportError(
                    f"required environment variable {env_name!r} is not set"
                )
            if any(not 0x20 <= ord(char) <= 0x7E for char in value):
                raise McpTransportError(
                    f"environment variable {env_name!r} is not a valid header value"
                )
            headers[header] = value
        return headers


def _read_sse(response) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    data_lines: list[str] = []
    total = 0
    for raw_line in response:
        total += len(raw_line)
        if total > MAX_HTTP_BODY_BYTES:
            raise McpTransportError("upstream SSE response exceeded size limit")
        line = raw_line.decode("utf-8", errors="strict").rstrip("\r\n")
        if not line:
            if data_lines:
                messages.append(_json_object("\n".join(data_lines)))
                data_lines = []
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if field == "data":
            data_lines.append(
                value[1:] if separator and value.startswith(" ") else value
            )
    if data_lines:
        messages.append(_json_object("\n".join(data_lines)))
    if not messages:
        raise McpTransportError("upstream SSE response contained no JSON-RPC message")
    return messages


def _read_bounded(response) -> bytes:
    body = response.read(MAX_HTTP_BODY_BYTES + 1)
    if len(body) > MAX_HTTP_BODY_BYTES:
        raise McpTransportError("upstream HTTP response exceeded size limit")
    return body


def _bounded_error_body(error: HTTPError) -> str:
    try:
        body = error.read(2049)
    except OSError:
        return ""
    if len(body) > 2048:
        return "response body exceeded diagnostic limit"
    return body.decode("utf-8", errors="replace").strip()[:500]


def _json_object(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value, parse_constant=_reject_constant)
    except (json.JSONDecodeError, ValueError, UnicodeError) as exc:
        raise McpTransportError(f"upstream emitted invalid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise McpTransportError("upstream HTTP body must be one JSON-RPC object")
    return parsed


def _tool_result(response: dict[str, Any]) -> ToolResult:
    if "error" in response:
        error = response["error"]
        summary = (
            str(error.get("message", "upstream JSON-RPC error"))
            if isinstance(error, dict)
            else "upstream JSON-RPC error"
        )
        return ToolResult(
            status="failed",
            summary=summary,
            output={MCP_ERROR: error},
        )
    result = response.get("result")
    if not isinstance(result, dict):
        return _failed_result("upstream tools/call returned a non-object result")
    if not isinstance(result.get("content"), list) or (
        "isError" in result and not isinstance(result["isError"], bool)
    ):
        return _failed_result("upstream tools/call returned an invalid CallToolResult")
    failed = result.get("isError") is True
    return ToolResult(
        status="failed" if failed else "succeeded",
        summary=_result_summary(result, failed),
        output={MCP_RESULT: result},
    )


def _failed_result(message: str) -> ToolResult:
    return ToolResult(
        status="failed",
        summary=message,
        output={MCP_ERROR: {"code": -32000, "message": message}},
    )


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")
