"""Generic MCP proxy at the ``tools/call`` authority boundary."""

from __future__ import annotations

import copy
import json
import sys
from dataclasses import replace
from decimal import Decimal
from functools import partial
from pathlib import Path
from typing import Any, Iterable, Protocol, TextIO

from ..adapters.base import AgentAdapter, ToolCall
from ..approvals.store import ApprovalError, PendingApproval
from ..contracts import (
    ContentRef,
    HarnessRequest,
    ResultStatus,
    Sensitivity,
    Trust,
    sha256_of,
)
from ..money import money
from ..orchestrator.harness import ActionOutcome, build_harness
from ..launch_envelope import (
    LaunchEnvelopeAssurance,
    build_launch_envelope,
    remote_launch_envelope,
    require_launch_target_unchanged,
)
from ..runtime_artifacts import (
    RuntimeArtifactAssurance,
    remote_artifacts,
    require_same_artifact_bundle,
    unverified_artifacts,
    verify_runtime_artifacts,
)
from ..tools.registry import (
    ToolContractError,
    ToolResult,
    ToolRegistry,
    canonical_workspace_target,
)
from .config import McpConfigError, McpProxyConfig, McpToolConfig
from .http_session import HttpUpstreamSession
from .session import MCP_ERROR, MCP_RESULT, UpstreamSession

MCP_PROTOCOL_VERSION = "2025-06-18"


class McpUpstream(Protocol):
    """Transport-neutral operations required by the governing proxy."""

    def forward_raw(self, line: str) -> None: ...

    def emit_message(self, message: dict[str, Any]) -> None: ...

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        transport_params: dict[str, Any] | None = None,
    ) -> ToolResult: ...

    def close(self) -> None: ...


class McpProxyAdapter(AgentAdapter):
    """Translate intercepted MCP calls without claiming knowledge we do not have."""

    def __init__(
        self,
        config: McpProxyConfig,
        workspace_root: str | Path,
    ):
        self.config = config
        self.workspace_root = Path(workspace_root).resolve(strict=False)
        self.runner_name = config.runner_name
        self.model_id = config.model_id
        self.tool_side_effects = {
            name: tool.side_effect_level for name, tool in config.tools.items()
        }

    def propose(self, task: str) -> Iterable[ToolCall]:
        return ()

    def provenance_for(self, call: ToolCall) -> list[ContentRef]:
        config = self.config.tools.get(call.name)
        trust = config.argument_trust if config else Trust.DERIVED
        origin = (
            config.argument_origin
            if config and config.argument_origin
            else f"mcp-client:{self.runner_name}"
        )
        return [
            ContentRef.of(
                origin=origin,
                trust=trust,
                content=call.arguments,
                label=f"arguments for {call.name} via {self.config.server_name}",
            )
        ]

    def payload_for(self, call: ToolCall) -> dict[str, Any]:
        # Bind every policy-bearing MCP parameter to policy, approval, and
        # evidence. The progress token is transport correlation chosen by the
        # client and can change on an otherwise exact retry.
        return copy.deepcopy(
            call.transport_params or {"name": call.name, "arguments": call.arguments}
        )

    def target_of(self, call: ToolCall) -> str:
        config = self.config.tools.get(call.name)
        if config and config.target_arg and config.target_arg in call.arguments:
            target = str(call.arguments[config.target_arg])
            if config.target_scope in {"workspace", "workspace_path"}:
                try:
                    return canonical_workspace_target(
                        target,
                        self.workspace_root,
                        allow_root=config.target_scope == "workspace_path",
                    )
                except ToolContractError:
                    # Preserve the unsafe target so the normal mechanical gate
                    # blocks it and writes evidence. Adapter translation must
                    # never turn a refusal into an unrecorded transport crash.
                    return target
            return target
        return super().target_of(call)

    def estimate_cost(self, call: ToolCall) -> Decimal:
        config = self.config.tools.get(call.name)
        if config and config.cost_arg and config.cost_arg in call.arguments:
            return money(
                call.arguments[config.cost_arg],
                field_name=f"{call.name}.{config.cost_arg}",
            )
        return super().estimate_cost(call)


class McpStdioProxy:
    def __init__(
        self,
        config: McpProxyConfig,
        session: McpUpstream,
        *,
        workdir: str | Path,
        user_id: str,
        workspace_id: str,
        workspace_root: str | Path,
        policy_packs: list[str] | None = None,
        sensitivity: Sensitivity = Sensitivity.INTERNAL,
        dry_run: bool = False,
        trusted_operator_keys: list[str] | None = None,
        evidence_head_witness: str | Path | None = None,
        trusted_evidence_witness_keys: list[str] | None = None,
        runtime_artifact_assurance: RuntimeArtifactAssurance | None = None,
        launch_envelope_assurance: LaunchEnvelopeAssurance | None = None,
    ):
        self.config = config
        self.session = session
        self.user_id = user_id
        self.workspace_id = workspace_id
        self.sensitivity = sensitivity
        artifact_assurance = runtime_artifact_assurance or (
            remote_artifacts() if config.url else unverified_artifacts(config.command)
        )
        launch_assurance = launch_envelope_assurance or (
            remote_launch_envelope()
            if config.url
            else build_launch_envelope(
                config.launch_environment, cwd=config.cwd, workdir=workdir
            )
        )
        self.server_fingerprint = sha256_of(
            {
                "name": config.server_name,
                "transport": "streamable_http" if config.url else "stdio",
                "command": config.command,
                "url": config.url,
                "header_env": config.header_env,
                "cwd": str(config.cwd) if config.cwd else "",
                "runtime_artifacts": artifact_assurance.authority_dict(),
                "launch_envelope": launch_assurance.authority_dict(),
            }
        )
        self.proxy_fingerprint = sha256_of(
            {
                "server_fingerprint": self.server_fingerprint,
                "runner": config.runner_name,
                "model": config.model_id,
                "timeout_seconds": config.upstream_timeout_seconds,
                "tools": [
                    tool.authority_dict()
                    for tool in sorted(
                        config.tools.values(),
                        key=lambda item: item.name,
                    )
                ],
                "dry_run": dry_run,
            }
        )
        owner_kind = "mcp_http" if config.url else "mcp_stdio"
        self.execution_owner = (
            f"{owner_kind}:{config.server_name}:{self.proxy_fingerprint}"
        )
        self.adapter = McpProxyAdapter(config, workspace_root)
        registry = ToolRegistry(dry_run=dry_run, workspace_root=workspace_root)
        for tool in config.tools.values():
            registry.register(
                tool.tool_spec(),
                partial(_call_upstream, session, tool),
            )
        self.harness = build_harness(
            workdir,
            self.adapter,
            policy_packs=policy_packs,
            dry_run=dry_run,
            tools=registry,
            workspace_root=workspace_root,
            authority_context={
                "mcp_server_fingerprint": self.server_fingerprint,
                "mcp_proxy_fingerprint": self.proxy_fingerprint,
                "runtime_artifacts": artifact_assurance.authority_dict(),
                "launch_envelope": launch_assurance.authority_dict(),
            },
            runtime_artifact_assurance=artifact_assurance,
            launch_envelope_assurance=launch_assurance,
            trusted_operator_keys=trusted_operator_keys,
            evidence_head_witness=evidence_head_witness,
            trusted_evidence_witness_keys=trusted_evidence_witness_keys,
        )

    def accept_line(self, line: str) -> None:
        try:
            message = json.loads(line, parse_constant=_reject_constant)
        except (json.JSONDecodeError, ValueError):
            self.session.emit_message(_rpc_error(None, -32700, "Parse error"))
            return
        if not isinstance(message, dict):
            # MCP stdio carries one JSON-RPC message per line. Forwarding a
            # JSON-RPC batch would let a nested tools/call bypass interception.
            self.session.emit_message(_rpc_error(None, -32600, "Invalid Request"))
            return
        if message.get("method") == "initialize" and "id" in message:
            self.session.forward_raw(_bounded_initialize(message))
            return
        if not _is_tool_request(message):
            self.session.forward_raw(line)
            return
        response = self._handle_tool_request(message)
        self.session.emit_message(response)

    def _handle_tool_request(self, message: dict[str, Any]) -> dict[str, Any]:
        if "id" not in message:
            return _rpc_error(
                None,
                -32600,
                "tools/call must be a request, not a notification",
            )
        request_id = message.get("id")
        params = message.get("params")
        if not isinstance(params, dict):
            return _rpc_error(request_id, -32602, "tools/call params must be an object")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not name:
            return _rpc_error(request_id, -32602, "tools/call name must be non-empty")
        if not isinstance(arguments, dict):
            return _rpc_error(
                request_id,
                -32602,
                "tools/call arguments must be an object",
            )

        authority_params = _authority_params(params)
        execution_key = sha256_of(
            {
                "server": self.config.server_name,
                "runner": self.config.runner_name,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "proxy_fingerprint": self.proxy_fingerprint,
                "params": authority_params,
            }
        )
        self.harness.reconcile_expired_approvals()
        existing = self.harness.approvals.find_execution(
            self.execution_owner,
            execution_key,
        )
        if existing is None:
            existing = self._find_legacy_progress_execution(authority_params)
        if existing:
            return self._handle_existing(
                request_id,
                existing,
                execution_key,
                authority_params,
            )

        request = HarnessRequest(
            task=f"MCP tools/call {self.config.server_name}:{name}",
            user_id=self.user_id,
            workspace_id=self.workspace_id,
            sensitivity=self.sensitivity,
            allowed_tools=list(self.config.tools),
        )
        outcome = self.harness.handle_call(
            ToolCall(
                name=name,
                arguments=arguments,
                call_id=str(request_id),
                server=self.config.server_name,
                transport_params=authority_params,
            ),
            request,
            execution_owner=self.execution_owner,
            execution_key=execution_key,
        )
        return _outcome_response(request_id, outcome, execution_key)

    def _handle_existing(
        self,
        request_id: Any,
        approval: PendingApproval,
        execution_key: str,
        authority_params: dict[str, Any],
    ) -> dict[str, Any]:
        evidence_id = _latest_evidence_id(self.harness, approval.action_id)
        if approval.status == "pending":
            return _approval_response(
                request_id,
                approval,
                ResultStatus.PENDING_APPROVAL.value,
                evidence_id,
                execution_key,
            )
        if approval.status == "rejected":
            return _approval_response(
                request_id,
                approval,
                ResultStatus.REJECTED.value,
                evidence_id,
                execution_key,
            )
        if approval.status == "executing":
            return _approval_response(
                request_id,
                approval,
                ResultStatus.FAILED.value,
                evidence_id,
                execution_key,
                detail=(
                    "Prior execution outcome is uncertain; automatic replay refused."
                ),
            )
        try:
            outcome = self.harness.resume(
                approval.approval_id,
                True,
                approval.decided_by or self.user_id,
                approval.note,
            )
        except ApprovalError as exc:
            return _approval_response(
                request_id,
                approval,
                ResultStatus.FAILED.value,
                evidence_id,
                execution_key,
                detail=str(exc),
            )
        self._reject_duplicate_pending(authority_params, approval.approval_id)
        return _outcome_response(request_id, outcome, execution_key)

    def _find_legacy_progress_execution(
        self,
        authority_params: dict[str, Any],
    ) -> PendingApproval | None:
        """Recognize approvals created before progress tokens were normalized."""
        compatible = []
        for approval in self.harness.approvals.list_actionable():
            if approval.execution_owner != self.execution_owner:
                continue
            try:
                held_params = approval.held_action().payload
            except ApprovalError:
                continue
            if _authority_params(held_params) == authority_params:
                compatible.append(approval)
        priority = {"executing": 3, "approved": 2, "pending": 1}
        return max(
            compatible,
            key=lambda item: (priority[item.status], item.created_at),
            default=None,
        )

    def _reject_duplicate_pending(
        self,
        authority_params: dict[str, Any],
        consumed_approval_id: str,
    ) -> None:
        for approval in self.harness.approvals.list_pending():
            if (
                approval.approval_id == consumed_approval_id
                or approval.execution_owner != self.execution_owner
            ):
                continue
            try:
                held_params = approval.held_action().payload
            except ApprovalError:
                continue
            if _authority_params(held_params) == authority_params:
                self.harness.approvals.decide(
                    approval.approval_id,
                    False,
                    "defiant-dedup",
                    "Superseded by an approved retry differing only by progressToken.",
                )


def run_stdio_proxy(
    config: McpProxyConfig,
    *,
    workdir: str | Path,
    user_id: str,
    workspace_id: str,
    workspace_root: str | Path,
    policy_packs: list[str] | None = None,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    dry_run: bool = False,
    trusted_operator_keys: list[str] | None = None,
    evidence_head_witness: str | Path | None = None,
    trusted_evidence_witness_keys: list[str] | None = None,
    client_input: TextIO | None = None,
    client_output: TextIO | None = None,
) -> int:
    if not config.command:
        raise McpConfigError("mcp-proxy requires server.command")
    input_stream = client_input or sys.stdin
    output_stream = client_output or sys.stdout
    assurance = verify_runtime_artifacts(
        config.command,
        config.artifact_integrity.artifacts,
        workdir=workdir,
        cwd=config.cwd,
    )
    launch_assurance = build_launch_envelope(
        config.launch_environment,
        cwd=config.cwd,
        workdir=workdir,
    )
    effective_config = replace(
        config, command=assurance.command, cwd=launch_assurance.cwd
    )
    session = UpstreamSession(
        effective_config.command,
        output_stream,
        cwd=effective_config.cwd,
        timeout_seconds=effective_config.upstream_timeout_seconds,
        environment=launch_assurance.environment,
        start=False,
    )
    try:
        proxy = McpStdioProxy(
            effective_config,
            session,
            workdir=workdir,
            user_id=user_id,
            workspace_id=workspace_id,
            workspace_root=workspace_root,
            policy_packs=policy_packs,
            sensitivity=sensitivity,
            dry_run=dry_run,
            trusted_operator_keys=trusted_operator_keys,
            evidence_head_witness=evidence_head_witness,
            trusted_evidence_witness_keys=trusted_evidence_witness_keys,
            runtime_artifact_assurance=assurance,
            launch_envelope_assurance=launch_assurance,
        )
        reverified = verify_runtime_artifacts(
            effective_config.command,
            effective_config.artifact_integrity.artifacts,
            workdir=workdir,
            cwd=effective_config.cwd,
        )
        require_same_artifact_bundle(assurance, reverified)
        require_launch_target_unchanged(launch_assurance)
        session.start()
        for line in input_stream:
            if line.strip():
                proxy.accept_line(line)
    finally:
        session.close()
    return 0


def run_http_upstream_proxy(
    config: McpProxyConfig,
    *,
    workdir: str | Path,
    user_id: str,
    workspace_id: str,
    workspace_root: str | Path,
    policy_packs: list[str] | None = None,
    sensitivity: Sensitivity = Sensitivity.INTERNAL,
    dry_run: bool = False,
    trusted_operator_keys: list[str] | None = None,
    evidence_head_witness: str | Path | None = None,
    trusted_evidence_witness_keys: list[str] | None = None,
    client_input: TextIO | None = None,
    client_output: TextIO | None = None,
) -> int:
    """Expose a local stdio MCP server backed by remote Streamable HTTP."""
    if not config.url:
        raise McpConfigError("mcp-http-proxy requires server.url")
    input_stream = client_input or sys.stdin
    output_stream = client_output or sys.stdout
    session = HttpUpstreamSession(
        config.url,
        output_stream,
        header_env=config.header_env,
        timeout_seconds=config.upstream_timeout_seconds,
        protocol_version=MCP_PROTOCOL_VERSION,
    )
    try:
        proxy = McpStdioProxy(
            config,
            session,
            workdir=workdir,
            user_id=user_id,
            workspace_id=workspace_id,
            workspace_root=workspace_root,
            policy_packs=policy_packs,
            sensitivity=sensitivity,
            dry_run=dry_run,
            trusted_operator_keys=trusted_operator_keys,
            evidence_head_witness=evidence_head_witness,
            trusted_evidence_witness_keys=trusted_evidence_witness_keys,
            runtime_artifact_assurance=remote_artifacts(),
            launch_envelope_assurance=remote_launch_envelope(),
        )
        for line in input_stream:
            if line.strip():
                proxy.accept_line(line)
    finally:
        session.close()
    return 0


def _call_upstream(
    session: McpUpstream,
    config: McpToolConfig,
    action,
):
    arguments = action.payload.get("arguments", {})
    result = session.call_tool(
        config.name,
        arguments,
        transport_params=action.payload,
    )
    if result.status == "succeeded":
        # MCP has no standard actual-cost field. Until an adapter supplies one,
        # settle at the conservative estimate rather than silently claiming $0.
        result.cost_usd = max(
            action.estimated_cost_usd,
            config.cost_estimate_usd,
        )
    return result


def _is_tool_request(message: Any) -> bool:
    return isinstance(message, dict) and message.get("method") == "tools/call"


def _authority_params(params: dict[str, Any]) -> dict[str, Any]:
    """Remove only non-authority MCP retry correlation metadata."""
    normalized = copy.deepcopy(params)
    metadata = normalized.get("_meta")
    if isinstance(metadata, dict):
        metadata.pop("progressToken", None)
        if not metadata:
            normalized.pop("_meta", None)
    return normalized


def _bounded_initialize(message: dict[str, Any]) -> str:
    forwarded = copy.deepcopy(message)
    params = forwarded.get("params")
    if isinstance(params, dict):
        requested = params.get("protocolVersion")
        if not isinstance(requested, str) or requested > MCP_PROTOCOL_VERSION:
            params["protocolVersion"] = MCP_PROTOCOL_VERSION
    return json.dumps(forwarded, separators=(",", ":")) + "\n"


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _metadata(
    outcome: ActionOutcome,
    execution_key: str,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "status": outcome.status.value,
        "evidence_record_id": outcome.evidence_record_id,
        "approval_id": outcome.approval_id,
    }
    if outcome.status is ResultStatus.PENDING_APPROVAL:
        data["retry"] = "After approval, repeat this exact tools/call."
        data["execution_key"] = execution_key
    return data


def _outcome_response(
    request_id: Any,
    outcome: ActionOutcome,
    execution_key: str,
) -> dict[str, Any]:
    metadata = _metadata(outcome, execution_key)
    output = outcome.result.output if outcome.result else None
    if isinstance(output, dict) and MCP_ERROR in output:
        upstream_error = output[MCP_ERROR]
        error = (
            copy.deepcopy(upstream_error)
            if isinstance(upstream_error, dict)
            else {"code": -32000, "message": str(upstream_error)}
        )
        data = error.get("data")
        error["data"] = (
            {"upstream": data, "_defiant": metadata}
            if data is not None
            else {"_defiant": metadata}
        )
        return {"jsonrpc": "2.0", "id": request_id, "error": error}
    if isinstance(output, dict) and MCP_RESULT in output:
        result = copy.deepcopy(output[MCP_RESULT])
        if "_defiant" in result:
            result["_defiant_upstream"] = result["_defiant"]
        result["_defiant"] = metadata
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    result = outcome.as_tool_outcome().as_mcp_result()
    result["_defiant"].update(metadata)
    if outcome.status is ResultStatus.PENDING_APPROVAL:
        result["_defiant"]["retry"] = "After approval, repeat this exact tools/call."
        result["_defiant"]["execution_key"] = execution_key
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _approval_response(
    request_id: Any,
    approval: PendingApproval,
    status: str,
    evidence_id: str,
    execution_key: str,
    detail: str = "",
) -> dict[str, Any]:
    if not detail:
        if status == ResultStatus.PENDING_APPROVAL.value:
            detail = (
                f"Action held for human approval ({approval.approval_id}). "
                "After approval, repeat this exact tools/call."
            )
        else:
            detail = f"Action {status} by human reviewer."
    metadata = {
        "status": status,
        "evidence_record_id": evidence_id,
        "approval_id": approval.approval_id,
    }
    if status == ResultStatus.PENDING_APPROVAL.value:
        metadata.update(
            {
                "retry": "After approval, repeat this exact tools/call.",
                "execution_key": execution_key,
            }
        )
    else:
        metadata["terminal"] = True
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "isError": True,
            "content": [{"type": "text", "text": detail}],
            "_defiant": metadata,
        },
    }


def _latest_evidence_id(harness, action_id: str) -> str:
    records = harness.evidence.by_action(action_id)
    return records[-1]["record_id"] if records else ""


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")
