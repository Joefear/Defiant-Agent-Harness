"""Deterministic policy engine.

Properties this engine guarantees, and which the tests enforce:

1. Deterministic. Same action + same ruleset -> same decision, always. No model
   call, no network, no clock-dependent branch except explicit expiry windows.
2. Default-deny for side effects. An action whose tool matches no rule is
   blocked if it has any side effect, allowed if it does not.
3. Strictest-wins. Every matching rule is evaluated; the most restrictive
   outcome is returned. Rule order cannot be used to sneak an allow past a block.
4. Trust-aware. A rule may refuse actions whose payload derives from untrusted
   content, regardless of what the agent claims about it.
5. Attributable. The ruleset is hashed and the decision inputs are snapshotted,
   so any decision can be replayed later against the exact rules that produced it.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..contracts import (
    Decision,
    GuardrailDecision,
    ProposedAction,
    SideEffect,
    Trust,
    sha256_of,
    side_effect_rank,
)

# Strictest wins.
_SEVERITY = {Decision.ALLOW: 0, Decision.APPROVAL_REQUIRED: 1, Decision.BLOCK: 2}


@dataclass
class Rule:
    id: str
    description: str = ""
    # match conditions (all present conditions must match)
    tools: list[str] = field(default_factory=list)  # glob patterns
    side_effect_at_least: str | None = None
    targets: list[str] = field(default_factory=list)  # glob patterns
    payload_contains: list[str] = field(default_factory=list)  # case-insensitive
    max_payload_trust: str | None = None  # deny if payload trust is worse
    sensitivities: list[str] = field(default_factory=list)
    # outcome
    effect: str = "block"  # allow | block | approval_required
    reason: str = ""
    approval_scope: str = ""
    redactions: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValueError("policy rule id must be a non-empty string")
        Decision(self.effect)
        if self.side_effect_at_least is not None:
            SideEffect(self.side_effect_at_least)
        if self.max_payload_trust is not None:
            Trust(self.max_payload_trust)
        for field_name in (
            "tools",
            "targets",
            "payload_contains",
            "sensitivities",
            "redactions",
        ):
            values = getattr(self, field_name)
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value for value in values
            ):
                raise ValueError(f"policy rule {self.id}: {field_name} must be strings")

    def matches(self, action: ProposedAction, context: dict) -> bool:
        if self.tools and not any(
            fnmatch.fnmatch(action.tool_name, p) for p in self.tools
        ):
            return False
        if self.side_effect_at_least is not None:
            threshold = SideEffect(self.side_effect_at_least)
            if side_effect_rank(action.side_effect_level) < side_effect_rank(threshold):
                return False
        if self.targets and not any(
            fnmatch.fnmatch(action.target, p) for p in self.targets
        ):
            return False
        if self.payload_contains:
            blob = _payload_text(action.payload).lower()
            if not any(term.lower() in blob for term in self.payload_contains):
                return False
        if self.max_payload_trust is not None:
            allowed = Trust(self.max_payload_trust)
            if not _trust_satisfies(action.payload_trust, allowed):
                return False
        if self.sensitivities:
            if str(context.get("sensitivity", "")) not in self.sensitivities:
                return False
        return True


_TRUST_RANK = {Trust.TRUSTED: 0, Trust.DERIVED: 1, Trust.UNTRUSTED: 2}


def _trust_satisfies(actual: Trust, required_max: Trust) -> bool:
    """True when `actual` is *worse* than the rule's ceiling, i.e. rule fires."""
    return _TRUST_RANK[actual] > _TRUST_RANK[required_max]


def _payload_text(payload: Any) -> str:
    if isinstance(payload, dict):
        return " ".join(_payload_text(v) for v in payload.values())
    if isinstance(payload, (list, tuple)):
        return " ".join(_payload_text(v) for v in payload)
    return str(payload)


class PolicyEngine:
    def __init__(self, packs: list[dict], name: str = "custom"):
        self.name = name
        self.version = "0"
        self.rules: list[Rule] = []
        self.known_tools: list[str] = []
        versions: list[str] = []
        seen_rule_ids: set[str] = set()
        for pack in packs:
            if not isinstance(pack, dict):
                raise ValueError("each policy pack must be a mapping")
            versions.append(str(pack.get("version", "0")))
            known_tools = pack.get("known_tools", []) or []
            if not isinstance(known_tools, list) or any(
                not isinstance(name, str) or not name for name in known_tools
            ):
                raise ValueError("known_tools must be a list of non-empty strings")
            self.known_tools.extend(known_tools)
            rules = pack.get("rules", []) or []
            if not isinstance(rules, list):
                raise ValueError("rules must be a list")
            for raw in rules:
                if not isinstance(raw, dict):
                    raise ValueError("each policy rule must be a mapping")
                rule = Rule(**raw)
                if rule.id in seen_rule_ids:
                    raise ValueError(f"duplicate policy rule id: {rule.id}")
                seen_rule_ids.add(rule.id)
                self.rules.append(rule)
        self.version = "+".join(versions)
        self.ruleset_hash = sha256_of(
            {
                "known_tools": sorted(self.known_tools),
                "rules": [
                    {k: v for k, v in vars(r).items()}
                    for r in sorted(self.rules, key=lambda r: r.id)
                ],
            }
        )

    def is_known_tool(self, tool_name: str) -> bool:
        """A tool nobody classified is the most dangerous kind of tool.

        If a pack declares `known_tools`, anything outside that list is refused
        outright rather than falling through to generic rules. Otherwise a new
        tool could inherit a permissive rule written for a different one.
        """
        if not self.known_tools:
            return True
        return any(fnmatch.fnmatch(tool_name, p) for p in self.known_tools)

    # -- loading ---------------------------------------------------------

    @classmethod
    def from_files(cls, paths: list[str | Path]) -> "PolicyEngine":
        packs = []
        names = []
        for p in paths:
            p = Path(p)
            with open(p, "r", encoding="utf-8") as fh:
                packs.append(yaml.safe_load(fh) or {})
            names.append(p.stem)
        return cls(packs, name="+".join(names))

    @classmethod
    def default(cls, extra_packs: list[str] | None = None) -> "PolicyEngine":
        base = Path(__file__).parent / "rules"
        paths: list[str | Path] = [base / "default.yaml"]
        for name in extra_packs or []:
            candidate = base / f"{name}.yaml"
            paths.append(candidate if candidate.exists() else Path(name))
        return cls.from_files(paths)

    # -- evaluation ------------------------------------------------------

    def evaluate(
        self, action: ProposedAction, context: dict | None = None
    ) -> GuardrailDecision:
        context = context or {}

        # Unclassified tools never reach the rule set.
        if not self.is_known_tool(action.tool_name):
            return GuardrailDecision(
                decision=Decision.BLOCK,
                reason=(
                    f"tool '{action.tool_name}' is not declared in any loaded policy "
                    "pack's known_tools; unclassified tools are refused"
                ),
                policy_ids=["unknown_tool"],
                policy_version=self.version,
                ruleset_hash=self.ruleset_hash,
                decision_inputs={
                    "tool_name": action.tool_name,
                    "known_tools": sorted(self.known_tools),
                    "policy_name": self.name,
                },
            )

        matched = [r for r in self.rules if r.matches(action, context)]

        if matched:
            worst = max(matched, key=lambda r: _SEVERITY[Decision(r.effect)])
            decision = Decision(worst.effect)
            # Collect every rule that agrees with the winning severity, so the
            # evidence shows all reasons, not just the first one found.
            agreeing = [r for r in matched if Decision(r.effect) is decision]
            reason = worst.reason or worst.description or f"matched {worst.id}"
            policy_ids = [r.id for r in agreeing]
            approval_scope = worst.approval_scope
            redactions = sorted({red for r in agreeing for red in r.redactions})
        else:
            # Default-deny for anything with a side effect.
            if action.side_effect_level is SideEffect.NONE:
                decision = Decision.ALLOW
                reason = "no rule matched; action has no side effect"
            else:
                decision = Decision.BLOCK
                reason = (
                    f"no rule permits tool '{action.tool_name}' at side-effect level "
                    f"'{action.side_effect_level.value}' (default deny)"
                )
            policy_ids = ["default_deny"]
            approval_scope = ""
            redactions = []

        return GuardrailDecision(
            decision=decision,
            reason=reason,
            policy_ids=policy_ids,
            policy_version=self.version,
            ruleset_hash=self.ruleset_hash,
            approval_scope=approval_scope
            or (
                f"execute {action.tool_name} on {action.target}"
                if decision is Decision.APPROVAL_REQUIRED
                else ""
            ),
            redactions=redactions,
            decision_inputs={
                "tool_name": action.tool_name,
                "target": action.target,
                "side_effect_level": action.side_effect_level.value,
                "payload_hash": action.payload_hash,
                "authorization_hash": action.authorization_hash,
                "payload_trust": action.payload_trust.value,
                "context": {k: str(v) for k, v in context.items()},
                "matched_rules": [r.id for r in matched],
                "policy_name": self.name,
            },
        )
