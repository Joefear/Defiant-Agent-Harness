"""Tiny dependency-free MCP stdio server for exercising the Defiant proxy.

This is a protocol fixture, not a production MCP SDK replacement. The
side-effecting tools are simulated so the repository demo remains harmless.
"""

from __future__ import annotations

import json
import sys
from typing import Any


TOOLS = [
    {
        "name": "echo",
        "description": "Echo text without side effects.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "send_email",
        "description": "Simulate sending an email.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "body"],
        },
    },
    {
        "name": "delete_record",
        "description": "Simulate deleting a record.",
        "inputSchema": {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        },
    },
]


def respond(request_id: Any, *, result=None, error=None) -> None:
    message = {"jsonrpc": "2.0", "id": request_id}
    message["error" if error is not None else "result"] = (
        error if error is not None else result
    )
    print(json.dumps(message, separators=(",", ":")), flush=True)


def handle(message: dict[str, Any]) -> None:
    if "id" not in message:
        return
    request_id = message["id"]
    method = message.get("method")
    if method == "initialize":
        respond(
            request_id,
            result={
                "protocolVersion": message.get("params", {}).get(
                    "protocolVersion", "2025-06-18"
                ),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "defiant-demo", "version": "0.2.0"},
            },
        )
        return
    if method == "tools/list":
        respond(request_id, result={"tools": TOOLS})
        return
    if method != "tools/call":
        respond(
            request_id,
            error={"code": -32601, "message": f"Method not found: {method}"},
        )
        return

    params = message.get("params", {})
    name = params.get("name")
    arguments = params.get("arguments", {})
    if name == "echo":
        text = str(arguments.get("text", ""))
        respond(
            request_id,
            result={"content": [{"type": "text", "text": text}], "isError": False},
        )
    elif name == "send_email":
        respond(
            request_id,
            result={
                "content": [
                    {
                        "type": "text",
                        "text": f"simulated email to {arguments.get('to', '')}",
                    }
                ],
                "structuredContent": {
                    "to": arguments.get("to", ""),
                    "simulated": True,
                },
                "isError": False,
            },
        )
    elif name == "delete_record":
        respond(
            request_id,
            result={
                "content": [
                    {
                        "type": "text",
                        "text": f"simulated deletion of {arguments.get('id', '')}",
                    }
                ],
                "isError": False,
            },
        )
    else:
        respond(
            request_id,
            error={"code": -32602, "message": f"Unknown tool: {name}"},
        )


for raw_line in sys.stdin:
    try:
        incoming = json.loads(raw_line)
    except json.JSONDecodeError:
        respond(None, error={"code": -32700, "message": "Parse error"})
        continue
    if isinstance(incoming, dict):
        handle(incoming)
