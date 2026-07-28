"""Govern native VS Code and Copilot CLI tools through lifecycle hooks."""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

from ..adapters.base import AgentAdapter, ToolCall
from ..approvals.store import ApprovalError, PendingApproval
from ..contracts import (
    ContentRef,
    GuardrailDecision,
    HarnessRequest,
    ProposedAction,
    ResultStatus,
    Sensitivity,
    SideEffect,
    Trust,
    sha256_of,
)
from ..orchestrator.harness import ActionOutcome, build_harness
from ..tools.registry import (
    ToolContractError,
    ToolRegistry,
    ToolResult,
    ToolSpec,
    canonical_workspace_target,
)
from .state import HookExecution, HookExecutionStore, HookStateError

HOOK_MAPPING_VERSION = "copilot-hook-v3"

_READ_TOOLS = {
    "read",
    "view",
    "readfile",
    "read_file",
    "read_file_code",
}
_WRITE_TOOLS = {
    "write",
    "edit",
    "create",
    "apply_patch",
    "editfiles",
    "create_file",
    "replace_string_in_file",
    "multi_replace_string_in_file",
    "insert_edit_into_file",
    "notebookedit",
    "str_replace_editor",
}
_SEARCH_TOOLS = {
    "grep",
    "glob",
    "rg",
    "search",
    "filesearch",
    "file_search",
    "semanticsearch",
    "semantic_search",
    "listdirectory",
    "list_dir",
    "codebase",
}
_WEB_TOOLS = {"webfetch", "web_fetch", "websearch", "web_search", "fetch"}
_CONTROL_TOOLS = {
    "askuserquestion",
    "ask_user",
    "todowrite",
    "update_todo",
    "thinking",
}
_TERMINAL_TOOLS = {
    "bash",
    "powershell",
    "runinterminal",
    "run_in_terminal",
    "terminal",
    "execute",
    "runcommand",
    "runcommands",
}
_AGENT_TOOLS = {"agent", "task", "subagent", "runsubagent", "run_subagent"}

# Copilot prefixes MCP tool names with the configured server name. These exact
# tools belong to the operator-controlled defiant-filesystem profile and are
# already governed at the inner MCP proxy boundary. The outer native hook only
# delegates them; unknown or differently-prefixed tools still fail closed.
_DEFIANT_MCP_PREFIX = "defiant_filesystem_"
_DEFIANT_MCP_TOOLS = {
    "read_text_file",
    "read_media_file",
    "list_directory",
    "list_directory_with_sizes",
    "directory_tree",
    "search_files",
    "get_file_info",
    "list_allowed_directories",
    "write_file",
    "create_directory",
    "edit_file",
}

_PATH_KEYS = {
    "file",
    "file_path",
    "filepath",
    "notebook_path",
    "notebookpath",
    "path",
    "paths",
    "target",
}
_PATH_CONTAINER_KEYS = {"edits", "files", "items", "replacements"}


def _normalized_tool_name(name: str) -> str:
    return name.strip().replace("-", "_").replace(" ", "").lower()


def classify_native_tool(name: str) -> tuple[str, SideEffect, str]:
    """Return canonical policy name, side effect, and target scope."""
    normalized = _normalized_tool_name(name)
    if normalized.startswith(_DEFIANT_MCP_PREFIX):
        proxied_name = normalized.removeprefix(_DEFIANT_MCP_PREFIX)
        if proxied_name in _DEFIANT_MCP_TOOLS:
            return "proxied_mcp", SideEffect.NONE, "any"
    if normalized in _READ_TOOLS:
        return "read_file", SideEffect.NONE, "workspace"
    if normalized in _WRITE_TOOLS:
        return "write_file", SideEffect.LOCAL_WRITE, "workspace"
    if normalized in _SEARCH_TOOLS:
        return "search_native", SideEffect.NONE, "workspace_path"
    if normalized in _WEB_TOOLS:
        return "search_web", SideEffect.NONE, "any"
    if normalized in _CONTROL_TOOLS:
        return "agent_control", SideEffect.NONE, "any"
    if normalized in _TERMINAL_TOOLS:
        return "native_terminal", SideEffect.DESTRUCTIVE, "any"
    if normalized in _AGENT_TOOLS:
        return "native_agent", SideEffect.DESTRUCTIVE, "any"
    return "native_unknown", SideEffect.DESTRUCTIVE, "any"


class CopilotHookAdapter(AgentAdapter):
    runner_name = "copilot-cli-hook"

    def __init__(self, workspace_root: str | Path):
        self.workspace_root = Path(workspace_root).resolve(strict=False)
        self.tool_side_effects = {
            name: side_effect
            for name, side_effect, _ in {
                classify_native_tool(alias)
                for alias in (
                    *_READ_TOOLS,
                    *_WRITE_TOOLS,
                    *_SEARCH_TOOLS,
                    *_WEB_TOOLS,
                    *_CONTROL_TOOLS,
                    *_TERMINAL_TOOLS,
                    *_AGENT_TOOLS,
                    "__unknown__",
                )
            }
        }
        self.tool_side_effects["proxied_mcp"] = SideEffect.NONE

    def propose(self, task: str) -> Iterable[ToolCall]:
        return ()

    def call_from_event(self, event: dict[str, Any]) -> ToolCall:
        native_name, tool_input, tool_use_id = _tool_fields(event)
        canonical_name, _, target_scope = classify_native_tool(native_name)
        target = _target_for(
            native_name,
            tool_input,
            self.workspace_root,
            allow_root=target_scope == "workspace_path",
        )
        return ToolCall(
            name=canonical_name,
            arguments={
                "_native_tool_name": native_name,
                "_defiant_target": target,
                "tool_input": copy.deepcopy(tool_input),
            },
            call_id=tool_use_id,
            server="vscode-agent-hook",
        )

    def target_of(self, call: ToolCall) -> str:
        return str(call.arguments.get("_defiant_target", call.name))

    def payload_for(self, call: ToolCall) -> dict[str, Any]:
        return {
            "native_tool_name": call.arguments.get("_native_tool_name", ""),
            "tool_input": copy.deepcopy(call.arguments.get("tool_input", {})),
        }

    def provenance_for(self, call: ToolCall) -> list[ContentRef]:
        payload = self.payload_for(call)
        digest = sha256_of(
            {
                "runner": self.runner_name,
                "call_id": call.call_id,
                "payload": payload,
            }
        )
        return [
            ContentRef(
                ref_id="ref_hook_" + digest.split(":", 1)[-1][:24],
                origin=f"agent:{self.runner_name}",
                trust=Trust.DERIVED,
                content_hash=sha256_of(payload),
                label=f"native arguments for {payload['native_tool_name']}",
            )
        ]


class CopilotHookGate:
    def __init__(
        self,
        workspace_root: str | Path,
        state_root: str | Path,
        *,
        user_id: str = "vscode-operator",
        workspace_id: str = "defiant-agent-harness",
    ):
        self.workspace_root = Path(workspace_root).resolve(strict=False)
        self.state_root = Path(state_root)
        self.user_id = user_id
        self.workspace_id = workspace_id
        self.adapter = CopilotHookAdapter(self.workspace_root)
        self.registry = _hook_registry(self.workspace_root)
        self.execution_owner = (
            "agent_hook:copilot:"
            + sha256_of(
                {
                    "mapping_version": HOOK_MAPPING_VERSION,
                    "workspace_root": str(self.workspace_root),
                    "tools": [
                        spec.authority_dict()
                        for spec in sorted(
                            self.registry.specs(),
                            key=lambda item: item.name,
                        )
                    ],
                }
            ).split(":", 1)[-1]
        )
        self.harness = build_harness(
            self.state_root,
            self.adapter,
            policy_packs=["copilot_hook"],
            tools=self.registry,
            workspace_root=self.workspace_root,
            authority_context={
                "hook_mapping_version": HOOK_MAPPING_VERSION,
                "hook_execution_owner": self.execution_owner,
            },
        )
        self.executions = HookExecutionStore(self.state_root / "hook_executions.json")

    def pre_tool_use(self, event: dict[str, Any]) -> dict[str, Any]:
        native_name, tool_input, tool_use_id = _tool_fields(event)
        execution_key = self._execution_key(event, native_name, tool_input)
        existing = self.harness.approvals.find_execution(
            self.execution_owner,
            execution_key,
        )
        if existing is not None:
            return self._pre_existing(existing, event, execution_key)

        request = HarnessRequest(
            task=f"PreToolUse {native_name}",
            user_id=self.user_id,
            workspace_id=self.workspace_id,
            task_type="agent_hook",
            sensitivity=Sensitivity.INTERNAL,
            allowed_tools=self.registry.names(),
        )
        outcome = self.harness.preflight_external_call(
            self.adapter.call_from_event(event),
            request,
            execution_owner=self.execution_owner,
            execution_key=execution_key,
        )
        if (
            outcome.status is ResultStatus.SKIPPED
            and outcome.action.tool_name != "proxied_mcp"
        ):
            self._remember_authorization(
                tool_use_id,
                execution_key,
                native_name,
                outcome,
                request,
            )
        return _pre_output(outcome)

    def post_tool_use(self, event: dict[str, Any]) -> dict[str, Any]:
        native_name, tool_input, tool_use_id = _tool_fields(event)
        canonical_name, _, _ = classify_native_tool(native_name)
        if canonical_name == "proxied_mcp":
            return _delegated_mcp_post_output()
        execution = self.executions.get(tool_use_id)
        if execution is None:
            raise HookStateError(
                f"PostToolUse {tool_use_id} has no Defiant authorization"
            )
        execution_key = self._execution_key(event, native_name, tool_input)
        if execution.execution_key != execution_key:
            raise HookStateError(
                "PostToolUse input differs from the authorized PreToolUse input"
            )
        if execution.native_tool_name != native_name:
            raise HookStateError("PostToolUse tool name differs from authorization")
        if execution.status == "completed":
            return _post_output(execution.completion_record_id)

        outcome = self.harness.complete_external_call(
            ProposedAction.from_dict(execution.action_snapshot),
            HarnessRequest.from_dict(execution.request_snapshot),
            GuardrailDecision.from_dict(execution.decision_snapshot),
            tool_response=_tool_response(event),
            approval_id=execution.approval_id,
        )
        self.executions.mark_completed(tool_use_id, outcome.evidence_record_id)
        return _post_output(outcome.evidence_record_id)

    def _pre_existing(
        self,
        approval: PendingApproval,
        event: dict[str, Any],
        execution_key: str,
    ) -> dict[str, Any]:
        if approval.status == "pending":
            return _approval_output(approval, ResultStatus.PENDING_APPROVAL)
        if approval.status == "rejected":
            return _approval_output(approval, ResultStatus.REJECTED)
        if approval.status == "executing":
            return _deny_output(
                "Prior external execution outcome is uncertain; retry refused."
            )
        try:
            outcome = self.harness.resume_external(approval.approval_id)
        except ApprovalError as exc:
            return _deny_output(str(exc))
        if outcome.status is ResultStatus.SKIPPED:
            native_name, _, tool_use_id = _tool_fields(event)
            self._remember_authorization(
                tool_use_id,
                execution_key,
                native_name,
                outcome,
                approval.held_request(),
            )
        return _pre_output(outcome)

    def _remember_authorization(
        self,
        tool_use_id: str,
        execution_key: str,
        native_name: str,
        outcome: ActionOutcome,
        request: HarnessRequest,
    ) -> None:
        self.executions.create(
            HookExecution(
                tool_use_id=tool_use_id,
                execution_key=execution_key,
                native_tool_name=native_name,
                action_snapshot=outcome.action.to_dict(),
                request_snapshot=request.to_dict(),
                decision_snapshot=outcome.decision.to_dict(),
                authorization_record_id=outcome.evidence_record_id,
                approval_id=outcome.approval_id,
            )
        )

    def _execution_key(
        self,
        event: dict[str, Any],
        native_name: str,
        tool_input: dict[str, Any],
    ) -> str:
        return sha256_of(
            {
                "mapping_version": HOOK_MAPPING_VERSION,
                "execution_owner": self.execution_owner,
                "session_id": _string_field(event, "session_id", "sessionId"),
                "cwd": str(self.workspace_root),
                "tool_name": native_name,
                "tool_input": tool_input,
            }
        )


def _hook_registry(workspace_root: Path) -> ToolRegistry:
    registry = ToolRegistry(workspace_root=workspace_root)
    specs = (
        ToolSpec(
            "read_file",
            SideEffect.NONE,
            "Read a workspace file through a native agent tool.",
            target_scope="workspace",
        ),
        ToolSpec(
            "write_file",
            SideEffect.LOCAL_WRITE,
            "Write a workspace file through a native agent tool.",
            target_scope="workspace",
        ),
        ToolSpec(
            "search_native",
            SideEffect.NONE,
            "Search inside the workspace through a native agent tool.",
            target_scope="workspace_path",
        ),
        ToolSpec(
            "search_web",
            SideEffect.NONE,
            "Read external web information through a native agent tool.",
        ),
        ToolSpec(
            "agent_control",
            SideEffect.NONE,
            "Update non-executing agent control state.",
        ),
        ToolSpec(
            "proxied_mcp",
            SideEffect.NONE,
            "Delegate an operator-configured Defiant MCP tool to its inner proxy.",
        ),
        ToolSpec(
            "native_terminal",
            SideEffect.DESTRUCTIVE,
            "Run an arbitrary native terminal command.",
        ),
        ToolSpec(
            "native_agent",
            SideEffect.DESTRUCTIVE,
            "Spawn another agent with independent tools.",
        ),
        ToolSpec(
            "native_unknown",
            SideEffect.DESTRUCTIVE,
            "Unclassified native agent capability.",
        ),
    )
    for spec in specs:
        registry.register(spec, _never_execute)
    return registry


def _never_execute(action: ProposedAction) -> ToolResult:
    raise RuntimeError(
        f"native tool {action.tool_name} belongs to an external executor"
    )


def _tool_fields(event: dict[str, Any]) -> tuple[str, dict[str, Any], str]:
    if not isinstance(event, dict):
        raise ValueError("hook input must be a JSON object")
    name = _string_field(event, "tool_name", "toolName")
    use_id = _string_field(event, "tool_use_id", "toolUseId")
    tool_input = _first_field(
        event,
        "tool_input",
        "toolInput",
        "tool_args",
        "toolArgs",
    )
    if not name:
        raise ValueError("hook input tool_name must be non-empty")
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input, parse_constant=_reject_constant)
        except json.JSONDecodeError as exc:
            raise ValueError("hook input tool arguments must be valid JSON") from exc
    if not isinstance(tool_input, dict):
        raise ValueError("hook input tool_input must be an object")
    if not use_id:
        use_id = _synthetic_tool_use_id(event, name, tool_input)
    return name, copy.deepcopy(tool_input), use_id


def _first_field(event: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in event:
            return event[name]
    return None


def _string_field(event: dict[str, Any], *names: str) -> str:
    for name in names:
        value = event.get(name)
        if isinstance(value, str):
            return value
    return ""


def _synthetic_tool_use_id(
    event: dict[str, Any],
    native_name: str,
    tool_input: dict[str, Any],
) -> str:
    digest = sha256_of(
        {
            "session_id": _string_field(event, "session_id", "sessionId"),
            "cwd": _string_field(event, "cwd"),
            "tool_name": native_name,
            "tool_input": tool_input,
        }
    ).split(":", 1)[-1]
    return f"hook_{digest}"


def _tool_response(event: dict[str, Any]) -> Any:
    return copy.deepcopy(
        _first_field(
            event,
            "tool_response",
            "toolResponse",
            "tool_result",
            "toolResult",
        )
    )


def _target_for(
    native_name: str,
    tool_input: dict[str, Any],
    workspace_root: Path,
    *,
    allow_root: bool,
) -> str:
    canonical_name, _, target_scope = classify_native_tool(native_name)
    if target_scope == "any":
        for key in ("url", "query", "command", "prompt"):
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                return value
        return canonical_name

    candidates = _path_candidates(tool_input)
    if not candidates:
        return "workspace" if allow_root else native_name
    canonical: list[str] = []
    unsafe: list[str] = []
    for candidate in candidates:
        try:
            canonical.append(
                canonical_workspace_target(
                    candidate,
                    workspace_root,
                    allow_root=allow_root,
                )
            )
        except ToolContractError:
            unsafe.append(candidate)
    return unsafe[0] if unsafe else canonical[0]


def _path_candidates(value: Any, parent_key: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = key.replace("-", "_").lower()
            if normalized in _PATH_KEYS:
                if isinstance(child, str) and child.strip():
                    found.append(child)
                elif isinstance(child, list):
                    found.extend(
                        item for item in child if isinstance(item, str) and item.strip()
                    )
            if normalized in _PATH_CONTAINER_KEYS:
                found.extend(_path_candidates(child, normalized))
    elif isinstance(value, list) and parent_key in _PATH_CONTAINER_KEYS:
        for child in value:
            if isinstance(child, str) and child.strip():
                found.append(child)
            else:
                found.extend(_path_candidates(child, parent_key))
    return found


def _pre_output(outcome: ActionOutcome) -> dict[str, Any]:
    if outcome.status is ResultStatus.SKIPPED:
        reason = (
            "Allowed by Defiant policy; external result will be sealed "
            f"after execution ({outcome.evidence_record_id})."
        )
        return _decision_output("allow", reason)
    if outcome.status is ResultStatus.PENDING_APPROVAL:
        return _decision_output(
            "deny",
            (
                "Defiant held this exact call for approval "
                f"({outcome.approval_id}). Approve it, then retry the exact "
                "same tool input."
            ),
            additional_context=outcome.decision.reason,
        )
    return _deny_output(outcome.decision.reason)


def _approval_output(
    approval: PendingApproval,
    status: ResultStatus,
) -> dict[str, Any]:
    if status is ResultStatus.PENDING_APPROVAL:
        detail = (
            f"Defiant approval {approval.approval_id} is still pending. "
            "Retry only after the operator approves it."
        )
    else:
        detail = (
            f"Defiant approval {approval.approval_id} was rejected. "
            "This exact call remains denied."
        )
    return _deny_output(detail)


def _deny_output(reason: str) -> dict[str, Any]:
    return _decision_output("deny", reason)


def _decision_output(
    decision: str,
    reason: str,
    *,
    additional_context: str = "",
) -> dict[str, Any]:
    compatible = {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }
    output: dict[str, Any] = {
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
        "hookSpecificOutput": compatible,
    }
    if additional_context:
        output["additionalContext"] = additional_context
        compatible["additionalContext"] = additional_context
    return output


def _post_output(evidence_record_id: str) -> dict[str, Any]:
    context = (
        f"Defiant sealed the external result in evidence record {evidence_record_id}."
    )
    return {
        "additionalContext": context,
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": context,
        },
    }


def _delegated_mcp_post_output() -> dict[str, Any]:
    context = (
        "Defiant delegated lifecycle evidence to the inner MCP proxy, which "
        "governs and seals this tool result."
    )
    return {
        "additionalContext": context,
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": context,
        },
    }


def _post_failure(reason: str) -> dict[str, Any]:
    return {
        "decision": "block",
        "reason": reason,
        "additionalContext": reason,
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": reason,
        },
    }


def run_hook(
    phase: str,
    event: dict[str, Any],
    *,
    workspace_root: str | Path,
    state_root: str | Path,
) -> dict[str, Any]:
    gate = CopilotHookGate(workspace_root, state_root)
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
        workspace_root = Path.cwd()
        state_root = Path(os.environ.get("DAH_HOOK_WORKDIR", ".dah-hooks"))
        response = run_hook(
            phase,
            event,
            workspace_root=workspace_root,
            state_root=state_root,
        )
    except Exception as exc:
        reason = f"Defiant hook failed closed: {type(exc).__name__}: {exc}"
        print(reason, file=sys.stderr)
        response = _deny_output(reason) if phase == "pre" else _post_failure(reason)
    json.dump(response, sys.stdout, sort_keys=True, allow_nan=False)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return 0


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


if __name__ == "__main__":
    raise SystemExit(main())
