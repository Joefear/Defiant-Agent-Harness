from __future__ import annotations

from decimal import Decimal

import pytest

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
