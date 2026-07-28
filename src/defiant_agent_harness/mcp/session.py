"""One stdio subprocess session, with private request multiplexing."""

from __future__ import annotations

import json
import queue
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any, TextIO

from ..tools.registry import ToolResult

MCP_RESULT = "_defiant_mcp_result"
MCP_ERROR = "_defiant_mcp_error"


class McpTransportError(RuntimeError):
    """The upstream MCP server failed or violated its transport contract."""


class UpstreamSession:
    """Own an MCP server subprocess while preserving the proxy's stdout purity."""

    def __init__(
        self,
        command: tuple[str, ...],
        client_output: TextIO,
        *,
        cwd: Path | None = None,
        timeout_seconds: float = 60.0,
    ):
        self.command = command
        self.client_output = client_output
        self.timeout_seconds = timeout_seconds
        self._client_lock = threading.Lock()
        self._upstream_lock = threading.Lock()
        self._pending_lock = threading.Lock()
        self._pending: dict[str, queue.Queue[dict[str, Any]]] = {}
        self._private_ids: set[str] = set()
        self._closed = False
        self.process = subprocess.Popen(
            list(command),
            cwd=str(cwd) if cwd else None,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            encoding="utf-8",
            errors="strict",
            bufsize=1,
        )
        if self.process.stdin is None or self.process.stdout is None:
            raise McpTransportError("failed to open upstream stdio pipes")
        self._reader = threading.Thread(
            target=self._read_upstream,
            name="defiant-mcp-upstream-reader",
            daemon=True,
        )
        self._reader.start()

    def forward_raw(self, line: str) -> None:
        self._write_upstream(line if line.endswith("\n") else line + "\n")

    def emit_message(self, message: dict[str, Any]) -> None:
        self._emit_raw(json.dumps(message, separators=(",", ":")) + "\n")

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        transport_params: dict[str, Any] | None = None,
    ) -> ToolResult:
        internal_id = f"defiant:{uuid.uuid4().hex}"
        reply: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
        with self._pending_lock:
            self._pending[internal_id] = reply
            self._private_ids.add(internal_id)
        completed = False
        try:
            self._write_upstream(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": internal_id,
                        "method": "tools/call",
                        "params": transport_params
                        or {"name": name, "arguments": arguments},
                    },
                    separators=(",", ":"),
                )
                + "\n"
            )
            try:
                response = reply.get(timeout=self.timeout_seconds)
                completed = True
            except queue.Empty as exc:
                raise McpTransportError(
                    f"upstream timed out after {self.timeout_seconds:g}s"
                ) from exc
        except Exception as exc:
            return ToolResult(
                status="failed",
                summary=f"{type(exc).__name__}: {exc}",
                output={MCP_ERROR: {"code": -32000, "message": str(exc)}},
            )
        finally:
            with self._pending_lock:
                self._pending.pop(internal_id, None)
                if completed:
                    self._private_ids.discard(internal_id)

        if "_transport_error" in response:
            message = str(response["_transport_error"])
            return ToolResult(
                status="failed",
                summary=message,
                output={MCP_ERROR: {"code": -32000, "message": message}},
            )
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
            return ToolResult(
                status="failed",
                summary="upstream tools/call returned a non-object result",
                output={
                    MCP_ERROR: {
                        "code": -32603,
                        "message": "upstream tools/call returned a non-object result",
                    }
                },
            )
        if not isinstance(result.get("content"), list) or (
            "isError" in result and not isinstance(result["isError"], bool)
        ):
            return ToolResult(
                status="failed",
                summary="upstream tools/call returned an invalid CallToolResult",
                output={
                    MCP_ERROR: {
                        "code": -32603,
                        "message": (
                            "upstream tools/call returned an invalid CallToolResult"
                        ),
                    }
                },
            )
        failed = result.get("isError") is True
        return ToolResult(
            status="failed" if failed else "succeeded",
            summary=_result_summary(result, failed),
            output={MCP_RESULT: result},
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.process.stdin:
            try:
                self.process.stdin.close()
            except OSError:
                pass
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)

    def _read_upstream(self) -> None:
        assert self.process.stdout is not None
        failure = ""
        try:
            for line in self.process.stdout:
                try:
                    message = json.loads(line, parse_constant=_reject_constant)
                except (json.JSONDecodeError, ValueError) as exc:
                    failure = f"upstream emitted invalid JSON: {exc}"
                    break
                if isinstance(message, dict) and "id" in message:
                    key = message["id"]
                    with self._pending_lock:
                        waiter = (
                            self._pending.get(key) if isinstance(key, str) else None
                        )
                        private = isinstance(key, str) and key in self._private_ids
                    if waiter is not None:
                        waiter.put(message)
                        continue
                    if private:
                        with self._pending_lock:
                            self._private_ids.discard(key)
                        continue
                self._emit_raw(line if line.endswith("\n") else line + "\n")
        except (OSError, UnicodeError) as exc:
            failure = f"upstream read failed: {exc}"
        finally:
            if not failure and not self._closed:
                failure = (
                    f"upstream exited before client EOF (code {self.process.poll()})"
                )
            if failure:
                self._fail_pending(failure)

    def _write_upstream(self, line: str) -> None:
        if self._closed or self.process.poll() is not None:
            raise McpTransportError("upstream MCP process is not running")
        assert self.process.stdin is not None
        with self._upstream_lock:
            try:
                self.process.stdin.write(line)
                self.process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise McpTransportError(f"cannot write to upstream: {exc}") from exc

    def _emit_raw(self, line: str) -> None:
        with self._client_lock:
            self.client_output.write(line)
            self.client_output.flush()

    def _fail_pending(self, message: str) -> None:
        with self._pending_lock:
            waiters = list(self._pending.values())
        for waiter in waiters:
            try:
                waiter.put_nowait({"_transport_error": message})
            except queue.Full:
                pass


def _result_summary(result: dict[str, Any], failed: bool) -> str:
    texts = [
        item.get("text", "")
        for item in result.get("content", [])
        if isinstance(item, dict)
        and item.get("type") == "text"
        and isinstance(item.get("text"), str)
    ]
    summary = " ".join(text.strip() for text in texts if text.strip())
    if summary:
        return summary[:500]
    return "upstream tool reported an error" if failed else "upstream tool succeeded"


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")
