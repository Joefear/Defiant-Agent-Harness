from __future__ import annotations

from decimal import Decimal

import pytest

import defiant_agent_harness.strict_yaml as strict_yaml_module
from defiant_agent_harness.contracts import SideEffect, Trust
from defiant_agent_harness.mcp.config import McpConfigError, load_proxy_config


def test_proxy_config_is_strict_and_typed(tmp_path):
    path = tmp_path / "proxy.yaml"
    path.write_text(
        """
server:
  name: test
  command: [python, server.py]
  timeout_seconds: 12
tools:
  charge:
    side_effect: spend
    target_arg: payee
    cost_arg: price
    cost_estimate_usd: "4.25"
    argument_trust: untrusted
    supports_dry_run: false
""",
        encoding="utf-8",
    )
    config = load_proxy_config(path)
    tool = config.tools["charge"]
    assert config.command == ("python", "server.py")
    assert config.upstream_timeout_seconds == 12
    assert tool.side_effect_level is SideEffect.SPEND
    assert tool.argument_trust is Trust.UNTRUSTED
    assert tool.cost_estimate_usd == Decimal("4.25")
    assert tool.supports_dry_run is False


@pytest.mark.parametrize(
    "body, message",
    [
        ("server: {name: x, command: python}\ntools: {}", "command"),
        (
            "server: {name: x, command: [python]}\ntools: {x: {side_effect: nope}}",
            "invalid tools.x",
        ),
        (
            "server: {name: x, command: [python]}\ntools: {x: {side_effect: none, typo: true}}",
            "unknown fields",
        ),
        ("server: {name: x, command: [python]}\ntools: {}", "at least one"),
    ],
)
def test_proxy_config_fails_closed(tmp_path, body, message):
    path = tmp_path / "bad.yaml"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(McpConfigError, match=message):
        load_proxy_config(path)


def test_command_override_is_an_argument_vector_not_a_shell_string(tmp_path):
    path = tmp_path / "proxy.yaml"
    path.write_text(
        """
server: {name: x, command: [old]}
tools:
  echo: {side_effect: none}
""",
        encoding="utf-8",
    )
    config = load_proxy_config(path, ["python", "server.py", "--safe"])
    assert config.command == ("python", "server.py", "--safe")


def test_runner_override_is_bound_as_the_effective_runner(tmp_path):
    path = tmp_path / "proxy.yaml"
    path.write_text(
        """
server: {name: x, command: [python]}
runner: configured-runner
tools:
  echo: {side_effect: none}
""",
        encoding="utf-8",
    )
    config = load_proxy_config(path, runner_override="vscode-copilot")
    assert config.runner_name == "vscode-copilot"

    with pytest.raises(McpConfigError, match="runner"):
        load_proxy_config(path, runner_override=" ")


def test_streamable_http_config_uses_environment_header_references(tmp_path):
    path = tmp_path / "proxy.yaml"
    path.write_text(
        """
server:
  name: remote
  url: https://mcp.example.com/v1
  header_env:
    Authorization: REMOTE_MCP_AUTH
  timeout_seconds: 15
tools:
  lookup: {side_effect: none}
""",
        encoding="utf-8",
    )
    config = load_proxy_config(path)
    assert config.command == ()
    assert config.url == "https://mcp.example.com/v1"
    assert config.header_env == (("Authorization", "REMOTE_MCP_AUTH"),)
    assert config.upstream_timeout_seconds == 15


@pytest.mark.parametrize(
    "server, message",
    [
        (
            "{name: remote, command: [python], url: https://mcp.example.com}",
            "exactly one",
        ),
        ("{name: remote, url: http://mcp.example.com}", "https"),
        ("{name: remote, url: file:///tmp/mcp}", "http or https"),
        (
            "{name: remote, url: https://user:secret@mcp.example.com}",
            "userinfo",
        ),
        (
            "{name: remote, url: https://mcp.example.com, cwd: elsewhere}",
            "only valid",
        ),
        (
            "{name: remote, url: https://mcp.example.com, "
            "header_env: {Mcp-Session-Id: SESSION}}",
            "transport header",
        ),
    ],
)
def test_streamable_http_config_fails_closed(tmp_path, server, message):
    path = tmp_path / "bad-http.yaml"
    path.write_text(
        f"server: {server}\ntools:\n  lookup: {{side_effect: none}}\n",
        encoding="utf-8",
    )
    with pytest.raises(McpConfigError, match=message):
        load_proxy_config(path)


def test_plain_http_is_allowed_only_for_loopback(tmp_path):
    path = tmp_path / "local-http.yaml"
    path.write_text(
        """
server: {name: local, url: "http://127.0.0.1:8765/mcp"}
tools:
  lookup: {side_effect: none}
""",
        encoding="utf-8",
    )
    assert load_proxy_config(path).url == "http://127.0.0.1:8765/mcp"


@pytest.mark.parametrize(
    "body",
    [
        "server: {name: first, name: second, command: [python]}\ntools: {}\n",
        "server: {name: local, command: [python]}\ntools:\n  echo:\n    side_effect: none\n    side_effect: destructive\n",
    ],
)
def test_proxy_config_rejects_duplicate_yaml_keys(tmp_path, body):
    path = tmp_path / "duplicate.yaml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(McpConfigError, match="duplicate mapping key"):
        load_proxy_config(path)


def test_malformed_proxy_yaml_has_sanitized_error(tmp_path):
    path = tmp_path / "malformed.yaml"
    path.write_text("server: [sensitive-value", encoding="utf-8")

    with pytest.raises(McpConfigError, match="not valid YAML") as failure:
        load_proxy_config(path)

    assert "sensitive-value" not in str(failure.value)
    assert str(tmp_path) not in str(failure.value)


def test_unreadable_proxy_config_has_sanitized_error(tmp_path):
    path = tmp_path / "private" / "missing.yaml"

    with pytest.raises(McpConfigError, match="missing.yaml") as failure:
        load_proxy_config(path)

    assert str(tmp_path) not in str(failure.value)


def test_proxy_config_rejects_structural_complexity_before_validation(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(strict_yaml_module, "MAX_YAML_NESTING_DEPTH", 2)
    path = tmp_path / "nested.yaml"
    path.write_text(
        "server: {name: local, command: [[python]]}\n"
        "tools: {echo: {side_effect: none}}\n",
        encoding="utf-8",
    )

    with pytest.raises(McpConfigError, match="nesting exceeds maximum depth of 2"):
        load_proxy_config(path)
