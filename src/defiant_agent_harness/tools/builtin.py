"""Built-in v0.1 reference tools.

Only ``read_file`` performs real I/O, and it is confined to one configured
workspace root at the tool boundary. Every side-effecting handler is simulated
even when the registry is not in dry-run mode.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path

from ..contracts import ProposedAction, SideEffect, Trust
from ..money import ZERO, money, money_text
from .registry import (
    ToolRegistry,
    ToolResult,
    ToolSpec,
    resolve_workspace_target,
)

UNTRUSTED_MARKERS = ("inbound", "external", "web", "email", "downloads", "shared")


def trust_for_path(path: str) -> Trust:
    parts = {part.lower() for part in Path(path).parts}
    return Trust.UNTRUSTED if parts & set(UNTRUSTED_MARKERS) else Trust.TRUSTED


def _read_file(workspace_root: Path, action: ProposedAction) -> ToolResult:
    path = resolve_workspace_target(action.target, workspace_root)
    if not path.is_file():
        return ToolResult(status="failed", summary=f"no such workspace file: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    trust = trust_for_path(action.target)
    return ToolResult(
        status="succeeded",
        summary=f"read {len(text)} chars from {path} ({trust.value})",
        output={"text": text, "trust": trust.value, "path": str(path)},
        cost_usd=ZERO,
    )


def _write_file(action: ProposedAction) -> ToolResult:
    content = str(action.payload.get("content", ""))
    return ToolResult(
        status="succeeded",
        summary=f"simulated write of {len(content)} chars to {action.target}",
        output={
            "path": action.target,
            "bytes": len(content.encode()),
            "simulated": True,
        },
        cost_usd=ZERO,
    )


def _send_email(action: ProposedAction) -> ToolResult:
    return ToolResult(
        status="succeeded",
        summary=f"simulated email to {action.target}",
        output={
            "to": action.target,
            "subject": action.payload.get("subject", ""),
            "body_chars": len(str(action.payload.get("body", ""))),
            "simulated": True,
        },
        cost_usd=ZERO,
    )


def _publish_post(action: ProposedAction) -> ToolResult:
    return ToolResult(
        status="succeeded",
        summary=f"simulated publish to {action.target}",
        output={
            "destination": action.target,
            "title": action.payload.get("title", ""),
            "simulated": True,
        },
        cost_usd=ZERO,
    )


def _export_file(action: ProposedAction) -> ToolResult:
    return ToolResult(
        status="succeeded",
        summary=f"simulated export to {action.target}",
        output={"destination": action.target, "simulated": True},
        cost_usd=ZERO,
    )


def _delete_file(action: ProposedAction) -> ToolResult:
    return ToolResult(
        status="succeeded",
        summary=f"simulated deletion of {action.target}",
        output={"deleted": action.target, "simulated": True},
        cost_usd=ZERO,
    )


def _spend(action: ProposedAction) -> ToolResult:
    amount = money(action.payload.get("amount_usd", "0"), field_name="spend.amount_usd")
    return ToolResult(
        status="succeeded",
        summary=f"simulated charge of ${money_text(amount)} to {action.target}",
        output={
            "payee": action.target,
            "amount_usd": money_text(amount),
            "simulated": True,
        },
        cost_usd=amount,
    )


BUILTIN_SPECS: list[tuple[ToolSpec, object]] = [
    (
        ToolSpec(
            "read_file",
            SideEffect.NONE,
            "Read one file inside the configured workspace.",
            target_scope="workspace",
        ),
        "read",
    ),
    (
        ToolSpec(
            "write_file",
            SideEffect.LOCAL_WRITE,
            "Simulate writing a workspace file.",
            target_scope="workspace",
        ),
        _write_file,
    ),
    (
        ToolSpec("send_email", SideEffect.EXTERNAL_SEND, "Simulate sending email."),
        _send_email,
    ),
    (
        ToolSpec(
            "publish_post",
            SideEffect.EXTERNAL_PUBLISH,
            "Simulate publishing content.",
        ),
        _publish_post,
    ),
    (
        ToolSpec("export_file", SideEffect.EXTERNAL_SEND, "Simulate exporting data."),
        _export_file,
    ),
    (
        ToolSpec(
            "delete_file",
            SideEffect.DESTRUCTIVE,
            "Simulate deleting a workspace file.",
            target_scope="workspace",
        ),
        _delete_file,
    ),
    (
        ToolSpec("spend", SideEffect.SPEND, "Simulate spending money."),
        _spend,
    ),
]


def default_registry(
    dry_run: bool = False,
    workspace_root: str | Path = "workspace",
) -> ToolRegistry:
    root = Path(workspace_root).resolve(strict=False)
    registry = ToolRegistry(dry_run=dry_run, workspace_root=root)
    for spec, handler in BUILTIN_SPECS:
        fn = partial(_read_file, root) if handler == "read" else handler
        registry.register(spec, fn)  # type: ignore[arg-type]
    return registry
