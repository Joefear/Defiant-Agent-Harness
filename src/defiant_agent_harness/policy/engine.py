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

from ..bounded_io import InputLimitError
from ..contracts import (
    Decision,
    GuardrailDecision,
    ProposedAction,
    SideEffect,
    Trust,
    sha256_of,
    side_effect_rank,
)
from ..limits import (
    MAX_POLICY_KNOWN_TOOLS,
    MAX_POLICY_MATCH_PAYLOAD_CHARACTERS,
    MAX_POLICY_MATCH_PAYLOAD_NESTING_DEPTH,
    MAX_POLICY_MATCH_PAYLOAD_NODES,
    MAX_POLICY_PACK_BYTES,
    MAX_POLICY_PACKS,
    MAX_POLICY_PAYLOAD_MATCH_WORK_UNITS,
    MAX_POLICY_RULE_FIELD_ITEMS,
    MAX_POLICY_RULE_LIST_ITEMS,
    MAX_POLICY_RULES,
    MAX_POLICY_TEXT_CHARACTERS,
    MAX_POLICY_TEXT_ITEM_CHARACTERS,
)
from ..strict_yaml import StrictYamlError, load_bounded_yaml

# Strictest wins.
_SEVERITY = {Decision.ALLOW: 0, Decision.APPROVAL_REQUIRED: 1, Decision.BLOCK: 2}
_PACK_FIELDS = {"version", "name", "description", "known_tools", "rules"}
_RULE_LIST_FIELDS = (
    "tools",
    "targets",
    "payload_contains",
    "sensitivities",
    "redactions",
)
_PACK_TEXT_FIELDS = ("version", "name", "description")
_RULE_TEXT_FIELDS = (
    "id",
    "description",
    "side_effect_at_least",
    "max_payload_trust",
    "effect",
    "reason",
    "approval_scope",
)


class PolicyError(ValueError):
    """Policy configuration is unreadable, ambiguous, or invalid."""


class PolicyMatchLimitError(RuntimeError):
    """A governed action exceeded deterministic policy-matching ceilings."""


@dataclass(frozen=True)
class LoadedPolicyPacks:
    """Strictly parsed policy documents awaiting authority-context binding."""

    packs: tuple[dict, ...]
    name: str


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

    def matches(
        self,
        action: ProposedAction,
        context: dict,
        *,
        payload_text: str = "",
        payload_match_budget: _PayloadMatchBudget | None = None,
    ) -> bool:
        if not self.matches_payload_prefix(action):
            return False
        if self.payload_contains:
            if payload_match_budget is None:
                raise PolicyMatchLimitError(
                    "payload substring matching requires bounded evaluation state"
                )
            found = False
            for term in self.payload_contains:
                lowered_term = term.lower()
                payload_match_budget.charge(len(payload_text) + len(lowered_term))
                if lowered_term in payload_text:
                    found = True
                    break
            if not found:
                return False
        if self.max_payload_trust is not None:
            allowed = Trust(self.max_payload_trust)
            if not _trust_satisfies(action.payload_trust, allowed):
                return False
        if self.sensitivities:
            if str(context.get("sensitivity", "")) not in self.sensitivities:
                return False
        return True

    def matches_payload_prefix(self, action: ProposedAction) -> bool:
        """Whether evaluation reaches this rule's payload condition."""
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
        return True


_TRUST_RANK = {Trust.TRUSTED: 0, Trust.DERIVED: 1, Trust.UNTRUSTED: 2}


def _trust_satisfies(actual: Trust, required_max: Trust) -> bool:
    """True when `actual` is *worse* than the rule's ceiling, i.e. rule fires."""
    return _TRUST_RANK[actual] > _TRUST_RANK[required_max]


@dataclass
class _PayloadMatchBudget:
    used: int = 0

    def charge(self, units: int) -> None:
        if units > MAX_POLICY_PAYLOAD_MATCH_WORK_UNITS - self.used:
            raise PolicyMatchLimitError(
                "policy payload substring work exceeds maximum of "
                f"{MAX_POLICY_PAYLOAD_MATCH_WORK_UNITS} units"
            )
        self.used += units


def _bounded_payload_text(payload: Any) -> str:
    """Flatten payload values once while preserving legacy join semantics."""

    parts: list[str] = []
    character_count = 0
    node_count = 0

    def append(value: str) -> None:
        nonlocal character_count
        if len(value) > MAX_POLICY_MATCH_PAYLOAD_CHARACTERS - character_count:
            raise PolicyMatchLimitError(
                "policy match payload text exceeds maximum of "
                f"{MAX_POLICY_MATCH_PAYLOAD_CHARACTERS} characters"
            )
        parts.append(value)
        character_count += len(value)

    def visit(value: Any, depth: int) -> None:
        nonlocal node_count
        if depth > MAX_POLICY_MATCH_PAYLOAD_NESTING_DEPTH:
            raise PolicyMatchLimitError(
                "policy match payload nesting exceeds maximum depth of "
                f"{MAX_POLICY_MATCH_PAYLOAD_NESTING_DEPTH}"
            )
        node_count += 1
        if node_count > MAX_POLICY_MATCH_PAYLOAD_NODES:
            raise PolicyMatchLimitError(
                "policy match payload node count exceeds maximum of "
                f"{MAX_POLICY_MATCH_PAYLOAD_NODES}"
            )
        if isinstance(value, dict):
            for index, child in enumerate(value.values()):
                if index:
                    append(" ")
                visit(child, depth + 1)
            return
        if isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                if index:
                    append(" ")
                visit(child, depth + 1)
            return
        append(str(value))

    visit(payload, 1)
    lowered = "".join(parts).lower()
    if len(lowered) > MAX_POLICY_MATCH_PAYLOAD_CHARACTERS:
        raise PolicyMatchLimitError(
            "normalized policy match payload text exceeds maximum of "
            f"{MAX_POLICY_MATCH_PAYLOAD_CHARACTERS} characters"
        )
    return lowered


def _policy_match_limit_decision(
    error: PolicyMatchLimitError,
    engine: PolicyEngine,
    action: ProposedAction,
) -> GuardrailDecision:
    return GuardrailDecision(
        decision=Decision.BLOCK,
        reason=str(error),
        policy_ids=["policy_match_limit"],
        policy_version=engine.version,
        ruleset_hash=engine.ruleset_hash,
        decision_inputs={
            "tool_name": action.tool_name,
            "side_effect_level": action.side_effect_level.value,
            "policy_name": engine.name,
            "limit_enforced": "policy_payload_matching",
        },
    )


def _validate_policy_complexity(packs: list[dict]) -> None:
    """Reject oversized rulesets before Rule construction or ruleset hashing."""

    if len(packs) > MAX_POLICY_PACKS:
        raise ValueError(f"policy pack count exceeds maximum of {MAX_POLICY_PACKS}")

    known_tool_count = 0
    rule_count = 0
    rule_list_item_count = 0
    text_character_count = 0
    for pack in packs:
        if not isinstance(pack, dict):
            raise ValueError("each policy pack must be a mapping")

        for field_name in _PACK_TEXT_FIELDS:
            text_character_count = _count_policy_text(
                pack.get(field_name), text_character_count
            )

        known_tools = pack.get("known_tools", []) or []
        if isinstance(known_tools, list):
            known_tool_count += len(known_tools)
            if known_tool_count > MAX_POLICY_KNOWN_TOOLS:
                raise ValueError(
                    "known tool pattern count exceeds maximum of "
                    f"{MAX_POLICY_KNOWN_TOOLS}"
                )
            for value in known_tools:
                text_character_count = _count_policy_text(value, text_character_count)

        rules = pack.get("rules", []) or []
        if not isinstance(rules, list):
            continue
        rule_count += len(rules)
        if rule_count > MAX_POLICY_RULES:
            raise ValueError(f"policy rule count exceeds maximum of {MAX_POLICY_RULES}")

        for raw in rules:
            if not isinstance(raw, dict):
                continue
            for field_name in _RULE_TEXT_FIELDS:
                text_character_count = _count_policy_text(
                    raw.get(field_name), text_character_count
                )
            for field_name in _RULE_LIST_FIELDS:
                values = raw.get(field_name, [])
                if not isinstance(values, list):
                    continue
                if len(values) > MAX_POLICY_RULE_FIELD_ITEMS:
                    raise ValueError(
                        f"policy rule {field_name} count exceeds maximum of "
                        f"{MAX_POLICY_RULE_FIELD_ITEMS}"
                    )
                rule_list_item_count += len(values)
                if rule_list_item_count > MAX_POLICY_RULE_LIST_ITEMS:
                    raise ValueError(
                        "policy rule list item count exceeds maximum of "
                        f"{MAX_POLICY_RULE_LIST_ITEMS}"
                    )
                for value in values:
                    text_character_count = _count_policy_text(
                        value, text_character_count
                    )


def _count_policy_text(value: Any, current: int) -> int:
    """Count one recognized policy string without echoing its contents."""
    if not isinstance(value, str):
        return current
    if len(value) > MAX_POLICY_TEXT_ITEM_CHARACTERS:
        raise ValueError(
            "policy text item exceeds maximum of "
            f"{MAX_POLICY_TEXT_ITEM_CHARACTERS} characters"
        )
    total = current + len(value)
    if total > MAX_POLICY_TEXT_CHARACTERS:
        raise ValueError(
            "policy text character count exceeds maximum of "
            f"{MAX_POLICY_TEXT_CHARACTERS}"
        )
    return total


def _validate_policy_pack_input_count(count: int) -> None:
    if count > MAX_POLICY_PACKS:
        raise PolicyError(f"policy pack count exceeds maximum of {MAX_POLICY_PACKS}")


class PolicyEngine:
    def __init__(
        self,
        packs: list[dict],
        name: str = "custom",
        authority_inputs: dict[str, Any] | None = None,
    ):
        _validate_policy_complexity(packs)
        self.name = name
        self.version = "0"
        self.rules: list[Rule] = []
        self.known_tools: list[str] = []
        self.authority_inputs = authority_inputs or {}
        versions: list[str] = []
        seen_rule_ids: set[str] = set()
        for pack in packs:
            if not isinstance(pack, dict):
                raise ValueError("each policy pack must be a mapping")
            if set(pack) - _PACK_FIELDS:
                raise ValueError("policy pack contains unknown fields")
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
                "authority_inputs": self.authority_inputs,
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
    def from_files(
        cls,
        paths: list[str | Path],
        additional_known_tools: list[str] | None = None,
        authority_inputs: dict[str, Any] | None = None,
    ) -> "PolicyEngine":
        _validate_policy_pack_input_count(
            len(paths) + (1 if additional_known_tools else 0)
        )
        return cls.from_loaded(
            cls.load_files(paths),
            additional_known_tools=additional_known_tools,
            authority_inputs=authority_inputs,
        )

    @classmethod
    def load_files(cls, paths: list[str | Path]) -> LoadedPolicyPacks:
        _validate_policy_pack_input_count(len(paths))
        packs: list[dict] = []
        names = []
        for p in paths:
            p = Path(p)
            try:
                packs.append(
                    load_bounded_yaml(
                        p,
                        MAX_POLICY_PACK_BYTES,
                        "policy pack",
                    )
                    or {}
                )
            except OSError as exc:
                detail = exc.strerror or exc.__class__.__name__
                raise PolicyError(
                    f"cannot read policy pack {p.name}: {detail}"
                ) from exc
            except (InputLimitError, StrictYamlError) as exc:
                raise PolicyError(f"cannot load policy pack {p.name}: {exc}") from exc
            names.append(p.stem)
        return LoadedPolicyPacks(tuple(packs), "+".join(names))

    @classmethod
    def from_loaded(
        cls,
        loaded: LoadedPolicyPacks,
        additional_known_tools: list[str] | None = None,
        authority_inputs: dict[str, Any] | None = None,
    ) -> "PolicyEngine":
        packs = list(loaded.packs)
        if additional_known_tools:
            packs.append(
                {
                    "version": "registry-v1",
                    "known_tools": sorted(additional_known_tools),
                    "rules": [],
                }
            )
        try:
            return cls(
                packs,
                name=loaded.name,
                authority_inputs=authority_inputs,
            )
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"invalid policy configuration: {exc}") from exc

    @classmethod
    def default(
        cls,
        extra_packs: list[str] | None = None,
        additional_known_tools: list[str] | None = None,
        authority_inputs: dict[str, Any] | None = None,
    ) -> "PolicyEngine":
        _validate_policy_pack_input_count(
            1 + len(extra_packs or []) + (1 if additional_known_tools else 0)
        )
        return cls.from_loaded(
            cls.load_default(extra_packs),
            additional_known_tools=additional_known_tools,
            authority_inputs=authority_inputs,
        )

    @classmethod
    def load_default(
        cls,
        extra_packs: list[str] | None = None,
    ) -> LoadedPolicyPacks:
        _validate_policy_pack_input_count(1 + len(extra_packs or []))
        base = Path(__file__).parent / "rules"
        paths: list[str | Path] = [base / "default.yaml"]
        for name in extra_packs or []:
            candidate = base / f"{name}.yaml"
            paths.append(candidate if candidate.exists() else Path(name))
        return cls.load_files(paths)

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
                    "authority_inputs": self.authority_inputs,
                },
            )

        try:
            payload_rules_present = any(
                rule.payload_contains and rule.matches_payload_prefix(action)
                for rule in self.rules
            )
            payload_text = (
                _bounded_payload_text(action.payload) if payload_rules_present else ""
            )
            payload_match_budget = _PayloadMatchBudget()
            matched = [
                rule
                for rule in self.rules
                if rule.matches(
                    action,
                    context,
                    payload_text=payload_text,
                    payload_match_budget=payload_match_budget,
                )
            ]
        except PolicyMatchLimitError as exc:
            return _policy_match_limit_decision(exc, self, action)

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
                "authority_inputs": self.authority_inputs,
            },
        )
