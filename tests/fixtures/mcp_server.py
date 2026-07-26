"""Subprocess fixture implementing enough MCP to test the stdio proxy."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

marker = Path(sys.argv[1])

tools = [
    {
        "name": "echo",
        "description": "Echo text.",
        "inputSchema": {"type": "object"},
    },
    {
        "name": "send_email",
        "description": "Send email.",
        "inputSchema": {"type": "object"},
    },
    {
        "name": "delete_record",
        "description": "Delete record.",
        "inputSchema": {"type": "object"},
    },
    {
        "name": "unmapped_tool",
        "description": "This remains advertised but must be blocked by Defiant.",
        "inputSchema": {"type": "object"},
    },
]


def send(request_id: Any, *, result=None, error=None) -> None:
    response = {"jsonrpc": "2.0", "id": request_id}
    response["error" if error is not None else "result"] = (
        error if error is not None else result
    )
    print(json.dumps(response, separators=(",", ":")), flush=True)


def execute(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    marker.parent.mkdir(parents=True, exist_ok=True)
    with marker.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"name": name, "arguments": arguments}) + "\n")
    if name == "echo":
        return {
            "content": [{"type": "text", "text": str(arguments.get("text", ""))}],
            "isError": False,
        }
    if name == "send_email":
        return {
            "content": [{"type": "text", "text": "sent"}],
            "structuredContent": {
                "recipient": arguments.get("to"),
                "upstream_preserved": True,
            },
            "isError": False,
        }
    if name == "delete_record":
        return {
            "content": [{"type": "text", "text": "deleted"}],
            "isError": False,
        }
    return {
        "content": [{"type": "text", "text": "unmapped executed"}],
        "isError": False,
    }


for line in sys.stdin:
    incoming = json.loads(line)
    if "id" not in incoming:
        continue
    request_id = incoming["id"]
    method = incoming.get("method")
    if method == "initialize":
        send(
            request_id,
            result={
                "protocolVersion": incoming.get("params", {}).get(
                    "protocolVersion", "2025-06-18"
                ),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fixture", "version": "1"},
            },
        )
    elif method == "tools/list":
        send(request_id, result={"tools": tools})
    elif method == "tools/call":
        params = incoming.get("params", {})
        send(
            request_id,
            result=execute(params.get("name", ""), params.get("arguments", {})),
        )
    else:
        send(
            request_id,
            error={"code": -32601, "message": f"unknown method {method}"},
        )
