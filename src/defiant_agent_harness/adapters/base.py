"""Adapter contract, defined at the tool-call boundary.

WHY THIS SHAPE
--------------
The obvious adapter design is "ask the agent for a plan, inspect the plan, then
run it." That design only governs agents that agree to be governed, which is
not the population we are worried about. Hermes, OpenClaw, NanoClaw, Claude
Code, and Codex all run their own loop and call their own tools; none of them
will hand you a plan and wait.

What they all DO have in common is that their tools reach the outside world
through a call boundary -- overwhelmingly MCP `tools/call`. So the adapter
contract here is not "produce a plan." It is:

    intercept a tool call, hand it to the harness as a ProposedAction,
    and return the harness's outcome to the agent as the tool's result.

An adapter is therefore a proxy, and the harness is a decision service sitting
behind it. That has three consequences worth stating plainly:

  * Vendor-neutrality is structural, not aspirational. Any runner that speaks
    MCP is governable without bespoke integration work.
  * A blocked action returns a normal tool error to the agent. The agent sees
    "permission denied," reasons about it, and continues. It is not killed.
  * An approval-required action returns a pending handle. The agent can wait,
    or abandon the call and be told later. Either way the harness holds the
    authority, not the agent.

`ToolCall` deliberately mirrors the MCP `tools/call` shape so an MCP proxy
adapter is a thin translation rather than a rewrite.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Iterable

from ..contracts import (
    ActionHashLimitError,
    ContentRef,
    ProposedAction,
    SideEffect,
    Trust,
    action_snapshot_and_sha256_of,
)
from ..limits import (
    MAX_TOOL_CALL_IDENTIFIER_CHARACTERS,
    MAX_TOOL_CALL_NAME_CHARACTERS,
)
from ..money import money


class ToolCallContractError(ValueError):
    """A pre-adapter tool call cannot enter the authority path safely."""

    def __init__(self, message: str, *, limit_enforced: str):
        super().__init__(message)
        self.limit_enforced = limit_enforced


class ToolCallLimitError(ToolCallContractError):
    """A pre-adapter tool call exceeded a fixed resource ceiling."""


@dataclass
class ToolCall:
    """One tool invocation as seen at the transport boundary (MCP-shaped)."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""
    server: str = ""  # originating MCP server, when proxying
    transport_params: dict[str, Any] = field(default_factory=dict)
    _sealed_contract_hash: str = field(default="", init=False, repr=False)
    _contract_sealed: bool = field(default=False, init=False, repr=False)

    _CONTRACT_FIELDS = frozenset(
        {"name", "arguments", "call_id", "server", "transport_params"}
    )

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_contract_sealed", False) and (
            name in self._CONTRACT_FIELDS
            or name in {"_sealed_contract_hash", "_contract_sealed"}
        ):
            raise ValueError("sealed tool call contract fields cannot be changed")
        object.__setattr__(self, name, value)

    def __post_init__(self) -> None:
        self._validate_contract()

    def seal_contract(self) -> str:
        """Revalidate, detach, hash, and freeze one pre-adapter call."""
        if self._contract_sealed:
            self.require_unchanged()
            return self._sealed_contract_hash
        self._validate_fields()
        snapshot, contract_hash = _tool_call_contract_snapshot(self._contract_surface())
        object.__setattr__(self, "arguments", snapshot["arguments"])
        object.__setattr__(self, "transport_params", snapshot["transport_params"])
        object.__setattr__(self, "_sealed_contract_hash", contract_hash)
        object.__setattr__(self, "_contract_sealed", True)
        return contract_hash

    def require_unchanged(self) -> None:
        """Refuse nested mutation performed during adapter translation."""
        if not self._contract_sealed:
            raise ToolCallContractError(
                "tool call contract is not sealed",
                limit_enforced="tool_call_contract",
            )
        current_hash = _tool_call_contract_hash(self._contract_surface())
        if current_hash != self._sealed_contract_hash:
            raise ToolCallContractError(
                "tool call contract changed during adapter translation",
                limit_enforced="tool_call_mutation",
            )

    @property
    def contract_hash(self) -> str:
        if self._contract_sealed:
            return self._sealed_contract_hash
        return _tool_call_contract_hash(self._contract_surface())

    def _validate_contract(self) -> None:
        self._validate_fields()
        _tool_call_contract_hash(self._contract_surface())

    def _validate_fields(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ToolCallContractError(
                "tool call name must be a non-empty string",
                limit_enforced="tool_call_name_contract",
            )
        if len(self.name) > MAX_TOOL_CALL_NAME_CHARACTERS:
            raise ToolCallLimitError(
                "tool call name exceeds maximum of "
                f"{MAX_TOOL_CALL_NAME_CHARACTERS} characters",
                limit_enforced="tool_call_name_characters",
            )
        for field_name in ("call_id", "server"):
            value = getattr(self, field_name)
            if not isinstance(value, str):
                raise ToolCallContractError(
                    f"tool call {field_name} must be a string",
                    limit_enforced="tool_call_identifier_contract",
                )
            if len(value) > MAX_TOOL_CALL_IDENTIFIER_CHARACTERS:
                raise ToolCallLimitError(
                    "tool call identifier exceeds maximum of "
                    f"{MAX_TOOL_CALL_IDENTIFIER_CHARACTERS} characters",
                    limit_enforced="tool_call_identifier_characters",
                )
        if not isinstance(self.arguments, dict):
            raise ToolCallContractError(
                "tool call arguments must be a dictionary",
                limit_enforced="tool_call_arguments_contract",
            )
        if not isinstance(self.transport_params, dict):
            raise ToolCallContractError(
                "tool call transport_params must be a dictionary",
                limit_enforced="tool_call_transport_params_contract",
            )

    def _contract_surface(
        self,
        *,
        arguments: dict[str, Any] | None = None,
        transport_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "name": self.name,
            "arguments": self.arguments if arguments is None else arguments,
            "call_id": self.call_id,
            "server": self.server,
            "transport_params": (
                self.transport_params if transport_params is None else transport_params
            ),
        }


def _tool_call_contract_hash(surface: dict[str, Any]) -> str:
    return _tool_call_contract_snapshot(surface)[1]


def _tool_call_contract_snapshot(surface: dict[str, Any]) -> tuple[dict[str, Any], str]:
    try:
        snapshot, digest = action_snapshot_and_sha256_of(surface)
        return snapshot, digest
    except ActionHashLimitError as exc:
        suffix = exc.limit_enforced.removeprefix("action_hash_")
        raise ToolCallLimitError(
            "tool call exceeds a fixed canonical-value ceiling",
            limit_enforced=f"tool_call_{suffix}",
        ) from exc
    except (TypeError, ValueError) as exc:
        raise ToolCallContractError(
            "tool call is not canonical JSON data",
            limit_enforced="tool_call_contract",
        ) from exc


@dataclass
class ToolCallOutcome:
    """What the adapter hands back to the agent in place of the tool result."""

    is_error: bool
    content: Any
    harness_status: str  # succeeded | blocked | pending_approval | failed | rejected
    evidence_record_id: str = ""
    approval_id: str = ""

    def as_mcp_result(self) -> dict:
        """Shape an MCP client will accept without special-casing."""
        return {
            "isError": self.is_error,
            "content": [{"type": "text", "text": _as_text(self.content)}],
            "_defiant": {
                "status": self.harness_status,
                "evidence_record_id": self.evidence_record_id,
                "approval_id": self.approval_id,
            },
        }


class AgentAdapter(abc.ABC):
    """Base class for anything that feeds tool calls into the harness.

    Implementations in scope after v0.1: an MCP stdio proxy, an MCP HTTP proxy,
    and thin config shims per runner (hermes/, claude-code/, codex/) that supply
    tool-name -> side-effect mappings and trust defaults. The mock adapter in
    this package is the reference implementation used by the tests and demos.
    """

    #: Identifier written into every evidence record this adapter produces.
    runner_name: str = "unknown"
    model_id: str = ""

    #: Tool name -> side effect. Anything absent is treated as DESTRUCTIVE,
    #: because an unclassified tool is the most dangerous kind.
    tool_side_effects: dict[str, SideEffect] = {}

    def classify(self, call: ToolCall) -> SideEffect:
        return self.tool_side_effects.get(call.name, SideEffect.DESTRUCTIVE)

    def provenance_for(self, call: ToolCall) -> list[ContentRef]:
        """Provenance of the material this call's arguments were built from.

        Default is conservative: if the adapter cannot prove where the content
        came from, it is DERIVED, not TRUSTED. Runner-specific adapters override
        this using whatever the runner knows about its own context sources.
        """
        return [
            ContentRef.of(
                origin=f"agent:{self.runner_name}",
                trust=Trust.DERIVED,
                content=call.arguments,
                label=f"arguments for {call.name}",
            )
        ]

    def to_action(self, call: ToolCall, request_id: str) -> ProposedAction:
        return ProposedAction(
            tool_name=call.name,
            target=self.target_of(call),
            payload=self.payload_for(call),
            side_effect_level=self.classify(call),
            agent_reason=str(call.arguments.get("_reason", "")),
            request_id=request_id,
            payload_sources=self.provenance_for(call),
            estimated_cost_usd=self.estimate_cost(call),
        )

    def payload_for(self, call: ToolCall) -> dict[str, Any]:
        """Arguments that will be authorized and forwarded to the tool."""
        return dict(call.arguments)

    def target_of(self, call: ToolCall) -> str:
        for key in ("path", "to", "url", "destination", "target", "recipient", "payee"):
            if key in call.arguments:
                return str(call.arguments[key])
        return call.name

    def estimate_cost(self, call: ToolCall) -> Decimal:
        """Worst-case cost estimate. Overestimating is the safe direction."""
        return money(
            call.arguments.get("amount_usd", "0"),
            field_name=f"{call.name}.amount_usd",
        )

    @abc.abstractmethod
    def propose(self, task: str) -> Iterable[ToolCall]:
        """Produce the tool calls the agent wants to make for this task."""
        raise NotImplementedError


def _as_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    import json

    return json.dumps(content, indent=2, sort_keys=True, default=str)
