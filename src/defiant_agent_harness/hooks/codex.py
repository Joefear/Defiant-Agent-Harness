"""Govern Codex local tool calls through the native lifecycle hook protocol."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from .copilot import (
    CopilotHookGate,
    _evidence_witness_from_env,
    _max_unwitnessed_records_from_env,
    _trusted_operator_keys_from_env,
)

CODEX_HOOK_MAPPING_VERSION = "codex-hook-v1"


class CodexHookGate(CopilotHookGate):
    """Codex-specific identity and strict output dialect over the shared gate."""

    def __init__(
        self,
        workspace_root: str | Path,
        state_root: str | Path,
        *,
        user_id: str = "codex-operator",
        workspace_id: str = "defiant-agent-harness",
        trusted_operator_keys: list[str] | None = None,
        evidence_head_witness: str | Path | None = None,
        trusted_evidence_witness_keys: list[str] | None = None,
        max_unwitnessed_records: int | None = None,
    ):
        super().__init__(
            workspace_root,
            state_root,
            user_id=user_id,
            workspace_id=workspace_id,
            runner_name="codex-hook",
            integration_id="codex",
            mapping_version=CODEX_HOOK_MAPPING_VERSION,
            policy_pack="codex_hook",
            server_name="codex-native-hook",
            trusted_operator_keys=trusted_operator_keys,
            evidence_head_witness=evidence_head_witness,
            trusted_evidence_witness_keys=trusted_evidence_witness_keys,
            max_unwitnessed_records=max_unwitnessed_records,
        )

    def pre_tool_use(self, event: dict[str, Any]) -> dict[str, Any]:
        return _codex_pre_output(super().pre_tool_use(event))

    def post_tool_use(self, event: dict[str, Any]) -> dict[str, Any]:
        return _codex_post_output(super().post_tool_use(event))


def run_hook(
    phase: str,
    event: dict[str, Any],
    *,
    workspace_root: str | Path,
    state_root: str | Path,
    user_id: str = "codex-operator",
    trusted_operator_keys: list[str] | None = None,
    evidence_head_witness: str | Path | None = None,
    trusted_evidence_witness_keys: list[str] | None = None,
    max_unwitnessed_records: int | None = None,
) -> dict[str, Any]:
    gate = CodexHookGate(
        workspace_root,
        state_root,
        user_id=user_id,
        trusted_operator_keys=trusted_operator_keys,
        evidence_head_witness=evidence_head_witness,
        trusted_evidence_witness_keys=trusted_evidence_witness_keys,
        max_unwitnessed_records=max_unwitnessed_records,
    )
    if phase == "pre":
        return gate.pre_tool_use(event)
    if phase == "post":
        return gate.post_tool_use(event)
    raise ValueError("hook phase must be 'pre' or 'post'")


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    phase = args[0] if len(args) == 1 else ""
    try:
        event = json.load(sys.stdin, parse_constant=_reject_constant)
        event_cwd = event.get("cwd") if isinstance(event, dict) else ""
        start = (
            Path(event_cwd) if isinstance(event_cwd, str) and event_cwd else Path.cwd()
        )
        workspace_root = _repository_root(start)
        configured_state = Path(
            os.environ.get(
                "DAH_CODEX_HOOK_WORKDIR",
                os.environ.get("DAH_HOOK_WORKDIR", ".dah-codex-hooks"),
            )
        )
        state_root = (
            configured_state
            if configured_state.is_absolute()
            else workspace_root / configured_state
        )
        witness_path, witness_keys = _evidence_witness_from_env()
        max_unwitnessed_records = _max_unwitnessed_records_from_env()
        response = run_hook(
            phase,
            event,
            workspace_root=workspace_root,
            state_root=state_root,
            user_id=os.environ.get("DAH_CODEX_USER", "codex-operator"),
            trusted_operator_keys=_trusted_operator_keys_from_env(),
            evidence_head_witness=witness_path,
            trusted_evidence_witness_keys=witness_keys,
            max_unwitnessed_records=max_unwitnessed_records,
        )
    except Exception as exc:
        reason = f"Defiant Codex hook failed closed: {type(exc).__name__}: {exc}"
        print(reason, file=sys.stderr)
        response = (
            _codex_deny_output(reason)
            if phase == "pre"
            else {"decision": "block", "reason": reason}
        )
    json.dump(response, sys.stdout, sort_keys=True, allow_nan=False)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0


def _repository_root(start: Path) -> Path:
    candidate = start.resolve(strict=False)
    if candidate.is_file():
        candidate = candidate.parent
    for directory in (candidate, *candidate.parents):
        if (directory / ".git").exists():
            return directory
    return candidate


def _codex_pre_output(response: dict[str, Any]) -> dict[str, Any]:
    specific = response.get("hookSpecificOutput")
    if not isinstance(specific, dict):
        raise ValueError("shared hook did not return hookSpecificOutput")
    return {"hookSpecificOutput": specific}


def _codex_post_output(response: dict[str, Any]) -> dict[str, Any]:
    if response.get("decision") == "block":
        return {
            "decision": "block",
            "reason": str(response.get("reason", "Defiant blocked the tool result.")),
        }
    specific = response.get("hookSpecificOutput")
    if not isinstance(specific, dict):
        raise ValueError("shared hook did not return hookSpecificOutput")
    return {"hookSpecificOutput": specific}


def _codex_deny_output(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


if __name__ == "__main__":
    raise SystemExit(main())
