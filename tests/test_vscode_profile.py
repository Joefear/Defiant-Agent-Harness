from __future__ import annotations

import json
from pathlib import Path

from defiant_agent_harness.adapters.base import ToolCall
from defiant_agent_harness.mcp.config import load_proxy_config
from defiant_agent_harness.mcp.proxy import McpProxyAdapter

ROOT = Path(__file__).parents[1]


def test_vscode_profile_routes_the_runner_through_defiant():
    profile = json.loads((ROOT / ".vscode" / "mcp.json").read_text(encoding="utf-8"))
    server = profile["servers"]["defiant-filesystem"]
    args = server["args"]

    assert server["type"] == "stdio"
    assert server["command"] == "python"
    assert server["cwd"] == "${workspaceFolder}"
    assert server["env"]["PYTHONPATH"] == "${workspaceFolder}/src"
    assert args[:2] == ["-m", "defiant_agent_harness.cli.main"]
    assert args[args.index("--runner") + 1] == "vscode-copilot"
    assert args[args.index("--workspace") + 1] == "vscode-agent-proof"
    assert "mcp-proxy" in args
    assert "@modelcontextprotocol/server-filesystem@2026.7.10" in args
    assert not any("TOKEN" in key or "KEY" in key for key in server["env"])


def test_vscode_absolute_path_is_canonicalized_inside_workspace(tmp_path):
    config = load_proxy_config(
        ROOT / "examples" / "filesystem" / "mcp-proxy.yaml",
        runner_override="vscode-copilot",
    )
    adapter = McpProxyAdapter(config, tmp_path)
    inside = tmp_path / "generated" / "agent-note.txt"

    assert (
        adapter.target_of(
            ToolCall(
                name="write_file",
                arguments={"path": str(inside), "content": "approved"},
            )
        )
        == "workspace/generated/agent-note.txt"
    )

    outside = tmp_path.parent / "outside.txt"
    assert adapter.target_of(
        ToolCall(
            name="write_file",
            arguments={"path": str(outside), "content": "blocked"},
        )
    ) == str(outside)
