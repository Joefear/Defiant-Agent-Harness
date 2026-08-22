"""Strict configuration for local and remote MCP upstream transports."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from ..contracts import SideEffect, Trust
from ..launch_envelope import LaunchEnvironmentConfig, LaunchEnvelopeError
from ..money import ZERO, money
from ..runtime_artifacts import (
    RuntimeArtifactError,
    RuntimeArtifactPin,
    RuntimeDependencyFilePin,
    RuntimeDependencyRoot,
)
from ..tools.registry import ToolSpec


class McpConfigError(ValueError):
    """The proxy configuration is unsafe or malformed."""


_RESERVED_HTTP_HEADERS = {
    "accept",
    "content-length",
    "content-type",
    "mcp-protocol-version",
    "mcp-session-id",
}


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
class McpArtifactIntegrityConfig:
    required: bool = False
    artifacts: tuple[RuntimeArtifactPin, ...] = ()
    dependency_roots: tuple[RuntimeDependencyRoot, ...] = ()

    def __post_init__(self) -> None:
        if type(self.required) is not bool:
            raise McpConfigError("server.artifact_integrity.required must be boolean")
        if self.required and not self.artifacts:
            raise McpConfigError(
                "required artifact integrity needs at least one artifact"
            )
        if not self.required and self.artifacts:
            raise McpConfigError(
                "artifact pins require server.artifact_integrity.required: true"
            )
        if not self.required and self.dependency_roots:
            raise McpConfigError(
                "dependency roots require server.artifact_integrity.required: true"
            )
        roles = [item.role for item in self.artifacts]
        if len(set(roles)) != len(roles):
            raise McpConfigError("server artifact roles must be unique")
        if self.required and roles.count("executable") != 1:
            raise McpConfigError(
                "required artifact integrity needs exactly one executable role"
            )


@dataclass(frozen=True)
class McpProxyConfig:
    server_name: str
    command: tuple[str, ...]
    tools: dict[str, McpToolConfig]
    url: str = ""
    header_env: tuple[tuple[str, str], ...] = ()
    runner_name: str = "mcp"
    model_id: str = ""
    cwd: Path | None = None
    upstream_timeout_seconds: float = 60.0
    artifact_integrity: McpArtifactIntegrityConfig = McpArtifactIntegrityConfig()
    launch_environment: LaunchEnvironmentConfig | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.server_name, str) or not self.server_name.strip():
            raise McpConfigError("server.name must be non-empty")
        has_command = bool(self.command)
        has_url = bool(self.url)
        if has_command == has_url:
            raise McpConfigError("server must configure exactly one of command or url")
        if has_command and any(
            not isinstance(arg, str) or not arg for arg in self.command
        ):
            raise McpConfigError("server.command must contain non-empty strings")
        if has_url:
            _validate_http_url(self.url)
            if self.cwd is not None:
                raise McpConfigError("server.cwd is only valid with server.command")
            if self.artifact_integrity.required:
                raise McpConfigError(
                    "server.artifact_integrity is only valid with server.command"
                )
            if self.launch_environment is not None:
                raise McpConfigError(
                    "server.launch_environment is only valid with server.command"
                )
        seen_headers: set[str] = set()
        for header, env_name in self.header_env:
            if not _valid_header_name(header):
                raise McpConfigError(f"invalid HTTP header name: {header!r}")
            normalized = header.lower()
            if normalized in _RESERVED_HTTP_HEADERS:
                raise McpConfigError(
                    f"server.header_env cannot override transport header {header!r}"
                )
            if normalized in seen_headers:
                raise McpConfigError(f"duplicate HTTP header name: {header!r}")
            seen_headers.add(normalized)
            if not isinstance(env_name, str) or not env_name.strip():
                raise McpConfigError(
                    f"environment variable for header {header!r} must be non-empty"
                )
        if self.header_env and not has_url:
            raise McpConfigError("server.header_env requires server.url")
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
_SERVER_KEYS = {
    "name",
    "command",
    "url",
    "header_env",
    "cwd",
    "timeout_seconds",
    "artifact_integrity",
    "launch_environment",
}
_ARTIFACT_INTEGRITY_KEYS = {"required", "artifacts", "dependency_roots"}
_ARTIFACT_KEYS = {"role", "path", "sha256"}
_DEPENDENCY_ROOT_KEYS = {"path", "files"}
_DEPENDENCY_FILE_KEYS = {"path", "sha256"}
_LAUNCH_ENVIRONMENT_KEYS = {"inherit", "secret_env", "set", "allow_unsafe"}
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


def _load_dependency_roots(
    raw: Any,
    *,
    source: Path,
) -> tuple[RuntimeDependencyRoot, ...]:
    if not isinstance(raw, list):
        raise McpConfigError(
            "server.artifact_integrity.dependency_roots must be a list"
        )
    roots: list[RuntimeDependencyRoot] = []
    for root_index, value in enumerate(raw):
        label = f"server.artifact_integrity.dependency_roots[{root_index}]"
        item = _mapping(value, label)
        _reject_unknown(item, _DEPENDENCY_ROOT_KEYS, label)
        if set(item) != _DEPENDENCY_ROOT_KEYS:
            raise McpConfigError(f"{label} requires path and files")
        if not isinstance(item["path"], str) or not item["path"].strip():
            raise McpConfigError(f"{label}.path must be non-empty")
        files_raw = item["files"]
        if not isinstance(files_raw, list):
            raise McpConfigError(f"{label}.files must be a list")
        files: list[RuntimeDependencyFilePin] = []
        for file_index, file_value in enumerate(files_raw):
            file_label = f"{label}.files[{file_index}]"
            file_item = _mapping(file_value, file_label)
            _reject_unknown(file_item, _DEPENDENCY_FILE_KEYS, file_label)
            if set(file_item) != _DEPENDENCY_FILE_KEYS:
                raise McpConfigError(f"{file_label} requires path and sha256")
            try:
                files.append(
                    RuntimeDependencyFilePin(
                        path=file_item["path"],
                        sha256=file_item["sha256"],
                    )
                )
            except RuntimeArtifactError as exc:
                raise McpConfigError(f"invalid {file_label}: {exc}") from exc
        root_path = Path(item["path"])
        if not root_path.is_absolute():
            root_path = source.parent / root_path
        try:
            roots.append(RuntimeDependencyRoot(root_path, tuple(files)))
        except RuntimeArtifactError as exc:
            raise McpConfigError(f"invalid {label}: {exc}") from exc
    return tuple(roots)


def load_proxy_config(
    path: str | Path,
    command_override: list[str] | None = None,
    runner_override: str | None = None,
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
    command_raw = (
        command_override if command_override is not None else server.get("command")
    )
    url_raw = server.get("url", "")
    if command_override is not None and url_raw:
        raise McpConfigError("command override cannot be used with server.url")
    if command_raw is None:
        command_raw = ()
    if not isinstance(command_raw, (list, tuple)) or any(
        not isinstance(arg, str) or not arg for arg in command_raw
    ):
        raise McpConfigError("server.command must be a list of non-empty strings")
    if not isinstance(url_raw, str):
        raise McpConfigError("server.url must be a string")

    header_env_raw = server.get("header_env", {})
    if not isinstance(header_env_raw, dict):
        raise McpConfigError("server.header_env must be a mapping")
    header_env: list[tuple[str, str]] = []
    for header, env_name in header_env_raw.items():
        if not isinstance(header, str) or not isinstance(env_name, str):
            raise McpConfigError("server.header_env keys and values must be strings")
        header_env.append((header, env_name))

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

    artifact_raw = server.get("artifact_integrity")
    artifact_integrity = McpArtifactIntegrityConfig()
    if artifact_raw is not None:
        artifact_mapping = _mapping(artifact_raw, "server.artifact_integrity")
        _reject_unknown(
            artifact_mapping,
            _ARTIFACT_INTEGRITY_KEYS,
            "server.artifact_integrity",
        )
        required = artifact_mapping.get("required")
        if type(required) is not bool:
            raise McpConfigError("server.artifact_integrity.required must be boolean")
        artifacts_raw = artifact_mapping.get("artifacts", [])
        if not isinstance(artifacts_raw, list):
            raise McpConfigError("server.artifact_integrity.artifacts must be a list")
        pins: list[RuntimeArtifactPin] = []
        for index, value in enumerate(artifacts_raw):
            label = f"server.artifact_integrity.artifacts[{index}]"
            item = _mapping(value, label)
            _reject_unknown(item, _ARTIFACT_KEYS, label)
            if set(item) != _ARTIFACT_KEYS:
                raise McpConfigError(f"{label} requires role, path, and sha256")
            if not isinstance(item["path"], str) or not item["path"].strip():
                raise McpConfigError(f"{label}.path must be non-empty")
            artifact_path = Path(item["path"])
            if not artifact_path.is_absolute():
                artifact_path = source.parent / artifact_path
            try:
                pins.append(
                    RuntimeArtifactPin(
                        role=item["role"],
                        path=artifact_path,
                        sha256=item["sha256"],
                    )
                )
            except RuntimeArtifactError as exc:
                raise McpConfigError(f"invalid {label}: {exc}") from exc
        artifact_integrity = McpArtifactIntegrityConfig(
            required=required,
            artifacts=tuple(pins),
            dependency_roots=_load_dependency_roots(
                artifact_mapping.get("dependency_roots", []),
                source=source,
            ),
        )

    launch_raw = server.get("launch_environment")
    launch_environment = None
    if launch_raw is not None:
        launch_mapping = _mapping(launch_raw, "server.launch_environment")
        _reject_unknown(
            launch_mapping, _LAUNCH_ENVIRONMENT_KEYS, "server.launch_environment"
        )
        values_raw = launch_mapping.get("set", {})
        if not isinstance(values_raw, dict) or any(
            not isinstance(name, str) or not isinstance(value, str)
            for name, value in values_raw.items()
        ):
            raise McpConfigError("server.launch_environment.set must map strings")
        try:
            launch_environment = LaunchEnvironmentConfig(
                inherit=_string_list(
                    launch_mapping.get("inherit", []),
                    "server.launch_environment.inherit",
                ),
                secret_env=_string_list(
                    launch_mapping.get("secret_env", []),
                    "server.launch_environment.secret_env",
                ),
                values=tuple(values_raw.items()),
                allow_unsafe=_string_list(
                    launch_mapping.get("allow_unsafe", []),
                    "server.launch_environment.allow_unsafe",
                ),
            )
        except LaunchEnvelopeError as exc:
            raise McpConfigError(f"invalid server.launch_environment: {exc}") from exc

    return McpProxyConfig(
        server_name=str(server.get("name", "")).strip(),
        command=tuple(command_raw),
        tools=tools,
        url=url_raw.strip(),
        header_env=tuple(sorted(header_env)),
        runner_name=(
            str(runner_override).strip()
            if runner_override is not None
            else str(root.get("runner", "mcp")).strip() or "mcp"
        ),
        model_id=str(root.get("model", "")).strip(),
        cwd=cwd,
        upstream_timeout_seconds=float(timeout),
        artifact_integrity=artifact_integrity,
        launch_environment=launch_environment,
    )


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise McpConfigError(f"{label} must be a mapping")
    return value


def _string_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise McpConfigError(f"{label} must be a list of strings")
    return tuple(value)


def _reject_unknown(raw: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise McpConfigError(f"{label} has unknown fields: {', '.join(unknown)}")


def _validate_http_url(value: str) -> None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise McpConfigError(f"invalid server.url: {exc}") from exc
    if parsed.scheme not in {"http", "https"}:
        raise McpConfigError("server.url must use http or https")
    if not parsed.hostname or parsed.username or parsed.password:
        raise McpConfigError("server.url needs a host and must not contain userinfo")
    if parsed.fragment:
        raise McpConfigError("server.url must not contain a fragment")
    if port is not None and not 1 <= port <= 65535:
        raise McpConfigError("server.url port is out of range")
    if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname):
        raise McpConfigError("server.url must use https unless the host is loopback")


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


def _valid_header_name(value: str) -> bool:
    token = "!#$%&'*+-.^_`|~"
    return bool(value) and all(char.isalnum() or char in token for char in value)
