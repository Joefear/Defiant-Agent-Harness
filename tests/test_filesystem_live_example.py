from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from defiant_agent_harness.contracts import SideEffect
from defiant_agent_harness.mcp.config import load_proxy_config

ROOT = Path(__file__).parents[1]
EXAMPLE = ROOT / "examples" / "filesystem"


def test_official_filesystem_tool_map_is_strict_and_pinned():
    config = load_proxy_config(EXAMPLE / "mcp-proxy.yaml")

    assert config.server_name == "official-filesystem"
    assert config.command == (
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem@2026.7.10",
        "workspace",
    )
    assert config.tools["read_text_file"].side_effect_level is SideEffect.NONE
    assert config.tools["write_file"].side_effect_level is SideEffect.LOCAL_WRITE
    assert config.tools["write_file"].target_scope == "workspace"
    assert config.tools["list_directory"].target_scope == "workspace_path"
    assert config.tools["edit_file"].side_effect_level is SideEffect.DESTRUCTIVE
    assert "read_multiple_files" not in config.tools
    assert "move_file" not in config.tools


@pytest.mark.skipif(
    os.environ.get("DAH_LIVE_MCP") != "1",
    reason="set DAH_LIVE_MCP=1 to download and exercise the official MCP server",
)
def test_official_filesystem_server_end_to_end(tmp_path):
    subprocess.run(
        [
            sys.executable,
            str(EXAMPLE / "live_demo.py"),
            "--yes",
            "--run-root",
            str(tmp_path / "run"),
            "--npm-cache",
            str(tmp_path / "npm-cache"),
        ],
        cwd=ROOT,
        check=True,
        timeout=180,
    )
