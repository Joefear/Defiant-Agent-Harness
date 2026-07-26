"""Strict configuration for the generic MCP stdio proxy."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..contracts import SideEffect, Trust
from ..money import ZERO, money
from ..tools.registry import ToolSpec


class McpConfigError(ValueError):
    """The proxy configuration is unsafe or malformed."""


@dataclass(frozen=True)
class McpToolConfig:
    name: str
    side_effect_level: SideEffect
    description: str = ""
    target_arg: str = ""
    cost_arg: str = ""
    cost_estimate_usd: Any = ZERO
    argument_trust: Trust = Trust.DERIVED
    argument_origin: str = ""
    supports_dry_run: bool = True
    target_scope: str = "any"

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise McpConfigError("tool names must be non-empty")
        try:
            object.__setattr__(
                self,
                "side_effect_level",
                SideEffect(self.side_effect_level),
            )
            object.__setattr__(
                self,
                "argument_trust",
                Trust(self.argument_trust),
            )
            object.__setattr__(
                self,
                "cost_estimate_usd",
                money(
                    self.cost_estimate_usd,
                    field_name=f"{self.name}.cost_estimate_usd",
                ),
            )
        except (TypeError, ValueError) as exc:
            raise McpConfigError(
                f"invalid configuration for tool '{self.name}'"
            ) from exc
        for field_name in ("target_arg", "cost_arg", "argument_origin"):
            value = getattr(self, field_name)
            if not isinstance(value, str):
                raise McpConfigError(f"{self.name}.{field_name} must be a string")
        if not isinstance(self.supports_dry_run, bool):
            raise McpConfigError(f"{self.name}.supports_dry_run must be boolean")
        if self.target_scope not in {"any", "workspace", "workspace_path"}:
            raise McpConfigError(
                f"{self.name}.target_scope must be 'any', 'workspace', "
                "or 'workspace_path'"
            )

    def tool_spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.name,
            side_effect_level=self.side_effect_level,
            description=self.description or f"Proxied MCP tool {self.name}.",
            cost_estimate_usd=self.cost_estimate_usd,
            supports_dry_run=self.supports_dry_run,
            target_scope=self.target_scope,
        )

    def authority_dict(self) -> dict[str, Any]:
        return self.tool_spec().authority_dict() | {
            "target_arg": self.target_arg,
            "cost_arg": self.cost_arg,
            "argument_trust": self.argument_trust.value,
            "argument_origin": self.argument_origin,
        }


@dataclass(frozen=True)
class McpProxyConfig:
    server_name: str
    command: tuple[str, ...]
    tools: dict[str, McpToolConfig]
    runner_name: str = "mcp"
    model_id: str = ""
    cwd: Path | None = None
    upstream_timeout_seconds: float = 60.0

    def __post_init__(self) -> None:
        if not isinstance(self.server_name, str) or not self.server_name.strip():
            raise McpConfigError("server.name must be non-empty")
        if not self.command or any(
            not isinstance(arg, str) or not arg for arg in self.command
        ):
            raise McpConfigError("server.command must contain at least one string")
        if not isinstance(self.tools, dict) or not self.tools:
            raise McpConfigError("tools must classify at least one upstream tool")
        if any(name != tool.name for name, tool in self.tools.items()):
            raise McpConfigError("tool map keys must match their configured names")
        if not isinstance(self.runner_name, str) or not self.runner_name.strip():
            raise McpConfigError("runner must be a non-empty string")
        if not isinstance(self.model_id, str):
            raise McpConfigError("model must be a string")
        if isinstance(self.upstream_timeout_seconds, bool) or not isinstance(
            self.upstream_timeout_seconds, (int, float)
        ):
            raise McpConfigError("server.timeout_seconds must be a positive number")
        if self.upstream_timeout_seconds <= 0:
            raise McpConfigError("server.timeout_seconds must be positive")


_ROOT_KEYS = {"server", "runner", "model", "tools"}
_SERVER_KEYS = {"name", "command", "cwd", "timeout_seconds"}
_TOOL_KEYS = {
    "side_effect",
    "description",
    "target_arg",
    "cost_arg",
    "cost_estimate_usd",
    "argument_trust",
    "argument_origin",
    "supports_dry_run",
    "target_scope",
}


def load_proxy_config(
    path: str | Path,
    command_override: list[str] | None = None,
) -> McpProxyConfig:
    source = Path(path)
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise McpConfigError(f"cannot load MCP proxy config {source}: {exc}") from exc
    root = _mapping(raw, "config")
    _reject_unknown(root, _ROOT_KEYS, "config")

    server = _mapping(root.get("server"), "server")
    _reject_unknown(server, _SERVER_KEYS, "server")
    command_raw = command_override or server.get("command")
    if not isinstance(command_raw, (list, tuple)) or any(
        not isinstance(arg, str) or not arg for arg in command_raw
    ):
        raise McpConfigError("server.command must be a list of non-empty strings")

    tools_raw = _mapping(root.get("tools"), "tools")
    tools: dict[str, McpToolConfig] = {}
    for name, value in tools_raw.items():
        if not isinstance(name, str) or not name.strip():
            raise McpConfigError("tool names must be non-empty strings")
        item = _mapping(value, f"tools.{name}")
        _reject_unknown(item, _TOOL_KEYS, f"tools.{name}")
        if "side_effect" not in item:
            raise McpConfigError(f"tools.{name}.side_effect is required")
        try:
            tools[name] = McpToolConfig(
                name=name,
                side_effect_level=SideEffect(item["side_effect"]),
                description=str(item.get("description", "")),
                target_arg=item.get("target_arg", ""),
                cost_arg=item.get("cost_arg", ""),
                cost_estimate_usd=item.get("cost_estimate_usd", ZERO),
                argument_trust=Trust(item.get("argument_trust", "derived")),
                argument_origin=item.get("argument_origin", ""),
                supports_dry_run=item.get("supports_dry_run", True),
                target_scope=item.get("target_scope", "any"),
            )
        except (TypeError, ValueError) as exc:
            raise McpConfigError(f"invalid tools.{name}: {exc}") from exc

    cwd_raw = server.get("cwd")
    cwd = None
    if cwd_raw is not None:
        if not isinstance(cwd_raw, str) or not cwd_raw.strip():
            raise McpConfigError("server.cwd must be a non-empty string")
        candidate = Path(cwd_raw)
        cwd = candidate if candidate.is_absolute() else (source.parent / candidate)
        cwd = cwd.resolve(strict=False)

    timeout = server.get("timeout_seconds", 60)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise McpConfigError("server.timeout_seconds must be a positive number")

    return McpProxyConfig(
        server_name=str(server.get("name", "")).strip(),
        command=tuple(command_raw),
        tools=tools,
        runner_name=str(root.get("runner", "mcp")).strip() or "mcp",
        model_id=str(root.get("model", "")).strip(),
        cwd=cwd,
        upstream_timeout_seconds=float(timeout),
    )


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise McpConfigError(f"{label} must be a mapping")
    return value


def _reject_unknown(raw: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise McpConfigError(f"{label} has unknown fields: {', '.join(unknown)}")
