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

from ..contracts import ContentRef, ProposedAction, SideEffect, Trust
from ..money import money


@dataclass
class ToolCall:
    """One tool invocation as seen at the transport boundary (MCP-shaped)."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""
    server: str = ""  # originating MCP server, when proxying


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
