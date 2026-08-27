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
import os
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Sequence

from ..bounded_io import InputLimitError
from ..contracts import (
    Decision,
    GuardrailDecision,
    ProposedAction,
    SideEffect,
    Trust,
    authority_snapshot_of,
    sha256_of,
    side_effect_rank,
)
from ..limits import (
    MAX_POLICY_CONTEXT_CHARACTERS,
    MAX_POLICY_CONTEXT_ENTRIES,
    MAX_POLICY_CONTEXT_KEY_CHARACTERS,
    MAX_POLICY_CONTEXT_VALUE_CHARACTERS,
    MAX_POLICY_KNOWN_TOOLS,
    MAX_POLICY_GLOB_MATCH_WORK_UNITS,
    MAX_POLICY_MATCH_PAYLOAD_CHARACTERS,
    MAX_POLICY_MATCH_PAYLOAD_NESTING_DEPTH,
    MAX_POLICY_MATCH_PAYLOAD_NODES,
    MAX_POLICY_MATCH_TARGET_CHARACTERS,
    MAX_POLICY_MATCH_TOOL_NAME_CHARACTERS,
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

    def __init__(self, message: str, *, limit_enforced: str):
        super().__init__(message)
        self.limit_enforced = limit_enforced


class PolicyContextError(ValueError):
    """Caller-supplied policy context violated its bounded metadata contract."""

    def __init__(self, message: str, *, limit_enforced: str):
        super().__init__(message)
        self.limit_enforced = limit_enforced


@dataclass(frozen=True)
class LoadedPolicyPacks:
    """Strictly parsed policy documents awaiting authority-context binding."""

    packs: tuple[dict, ...]
    name: str


@dataclass(frozen=True)
class Rule:
    id: str
    description: str = ""
    # match conditions (all present conditions must match)
    tools: tuple[str, ...] = ()  # glob patterns
    side_effect_at_least: str | None = None
    targets: tuple[str, ...] = ()  # glob patterns
    payload_contains: tuple[str, ...] = ()  # case-insensitive
    max_payload_trust: str | None = None  # deny if payload trust is worse
    sensitivities: tuple[str, ...] = ()
    # outcome
    effect: str = "block"  # allow | block | approval_required
    reason: str = ""
    approval_scope: str = ""
    redactions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in ("id", "description", "effect", "reason", "approval_scope"):
            value = getattr(self, field_name)
            if not isinstance(value, str):
                raise ValueError(f"policy rule {field_name} must be a string")
            object.__setattr__(self, field_name, str.__str__(value))
        if not self.id.strip():
            raise ValueError("policy rule id must be a non-empty string")
        for field_name in ("side_effect_at_least", "max_payload_trust"):
            value = getattr(self, field_name)
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"policy rule {field_name} must be a string")
                object.__setattr__(self, field_name, str.__str__(value))
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
            if not isinstance(values, (list, tuple)):
                raise ValueError(f"policy rule {self.id}: {field_name} must be strings")
            snapshot = _snapshot_policy_configuration(
                values,
                f"policy rule {field_name}",
            )
            if not isinstance(snapshot, (list, tuple)) or any(
                type(value) is not str or not value for value in snapshot
            ):
                raise ValueError(f"policy rule {self.id}: {field_name} must be strings")
            object.__setattr__(self, field_name, tuple(snapshot))

    def matches(
        self,
        action: ProposedAction,
        context: dict[str, str],
        *,
        match_state: _PolicyMatchState | None = None,
    ) -> bool:
        state = match_state or _PolicyMatchState()
        if self.tools and not state.matches_any_glob(
            action.tool_name,
            self.tools,
            subject_label="tool name",
            maximum_characters=MAX_POLICY_MATCH_TOOL_NAME_CHARACTERS,
        ):
            return False
        if self.side_effect_at_least is not None:
            threshold = SideEffect(self.side_effect_at_least)
            if side_effect_rank(action.side_effect_level) < side_effect_rank(threshold):
                return False
        if self.targets and not state.matches_any_glob(
            action.target,
            self.targets,
            subject_label="target",
            maximum_characters=MAX_POLICY_MATCH_TARGET_CHARACTERS,
        ):
            return False
        if self.payload_contains:
            payload_text = state.payload_text_for(action.payload)
            found = False
            for term in self.payload_contains:
                lowered_term = term.lower()
                state.charge_payload_work(len(payload_text) + len(lowered_term))
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
            if context.get("sensitivity", "") not in self.sensitivities:
                return False
        return True


_TRUST_RANK = {Trust.TRUSTED: 0, Trust.DERIVED: 1, Trust.UNTRUSTED: 2}


def _trust_satisfies(actual: Trust, required_max: Trust) -> bool:
    """True when `actual` is *worse* than the rule's ceiling, i.e. rule fires."""
    return _TRUST_RANK[actual] > _TRUST_RANK[required_max]


@dataclass
class _PolicyMatchState:
    payload_work_used: int = 0
    glob_work_used: int = 0
    _payload_text: str | None = None

    def charge_payload_work(self, units: int) -> None:
        if units > MAX_POLICY_PAYLOAD_MATCH_WORK_UNITS - self.payload_work_used:
            raise PolicyMatchLimitError(
                "policy payload substring work exceeds maximum of "
                f"{MAX_POLICY_PAYLOAD_MATCH_WORK_UNITS} units",
                limit_enforced="policy_payload_matching",
            )
        self.payload_work_used += units

    def matches_any_glob(
        self,
        subject: str,
        patterns: Sequence[str],
        *,
        subject_label: str,
        maximum_characters: int,
    ) -> bool:
        if len(subject) > maximum_characters:
            raise PolicyMatchLimitError(
                f"policy glob {subject_label} exceeds maximum of "
                f"{maximum_characters} characters",
                limit_enforced="policy_glob_matching",
            )
        normalized_subject = os.path.normcase(subject)
        if len(normalized_subject) > maximum_characters:
            raise PolicyMatchLimitError(
                f"normalized policy glob {subject_label} exceeds maximum of "
                f"{maximum_characters} characters",
                limit_enforced="policy_glob_matching",
            )
        for pattern in patterns:
            normalized_pattern = os.path.normcase(pattern)
            units = len(normalized_subject) + len(normalized_pattern)
            if units > MAX_POLICY_GLOB_MATCH_WORK_UNITS - self.glob_work_used:
                raise PolicyMatchLimitError(
                    "policy glob match work exceeds maximum of "
                    f"{MAX_POLICY_GLOB_MATCH_WORK_UNITS} units",
                    limit_enforced="policy_glob_matching",
                )
            self.glob_work_used += units
            if fnmatch.fnmatchcase(normalized_subject, normalized_pattern):
                return True
        return False

    def payload_text_for(self, payload: Any) -> str:
        if self._payload_text is None:
            self._payload_text = _bounded_payload_text(payload)
        return self._payload_text


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
                f"{MAX_POLICY_MATCH_PAYLOAD_CHARACTERS} characters",
                limit_enforced="policy_payload_matching",
            )
        parts.append(value)
        character_count += len(value)

    def visit(value: Any, depth: int) -> None:
        nonlocal node_count
        if depth > MAX_POLICY_MATCH_PAYLOAD_NESTING_DEPTH:
            raise PolicyMatchLimitError(
                "policy match payload nesting exceeds maximum depth of "
                f"{MAX_POLICY_MATCH_PAYLOAD_NESTING_DEPTH}",
                limit_enforced="policy_payload_matching",
            )
        node_count += 1
        if node_count > MAX_POLICY_MATCH_PAYLOAD_NODES:
            raise PolicyMatchLimitError(
                "policy match payload node count exceeds maximum of "
                f"{MAX_POLICY_MATCH_PAYLOAD_NODES}",
                limit_enforced="policy_payload_matching",
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
            f"{MAX_POLICY_MATCH_PAYLOAD_CHARACTERS} characters",
            limit_enforced="policy_payload_matching",
        )
    return lowered


def _policy_match_limit_decision(
    error: PolicyMatchLimitError,
    engine: PolicyEngine,
    action: ProposedAction,
) -> GuardrailDecision:
    decision_inputs = {
        "side_effect_level": action.side_effect_level.value,
        "policy_name": engine.name,
        "limit_enforced": error.limit_enforced,
    }
    if error.limit_enforced != "policy_glob_matching":
        decision_inputs["tool_name"] = action.tool_name
    return GuardrailDecision(
        decision=Decision.BLOCK,
        reason=str(error),
        policy_ids=["policy_match_limit"],
        policy_version=engine.version,
        ruleset_hash=engine.ruleset_hash,
        decision_inputs=decision_inputs,
    )


def _policy_context_snapshot(context: dict | None) -> dict[str, str]:
    """Capture one bounded exact observation without invoking mapping hooks."""

    if context is None:
        return {}
    if not isinstance(context, dict):
        raise PolicyContextError(
            "policy context must be a mapping",
            limit_enforced="policy_context_type",
        )

    entry_count = dict.__len__(context)
    if entry_count > MAX_POLICY_CONTEXT_ENTRIES:
        raise PolicyContextError(
            "policy context exceeds maximum entry count of "
            f"{MAX_POLICY_CONTEXT_ENTRIES}",
            limit_enforced="policy_context_entries",
        )

    keys = list(dict.keys(context))
    if len(keys) != entry_count:
        raise PolicyContextError(
            "policy context changed during snapshot",
            limit_enforced="policy_context_snapshot",
        )

    normalized_keys: list[str] = []
    normalized_key_set: set[str] = set()
    characters = 0
    for key in keys:
        if not isinstance(key, str):
            raise PolicyContextError(
                "policy context keys and values must be strings",
                limit_enforced="policy_context_type",
            )
        normalized_key = str.__str__(key)
        key_characters = str.__len__(normalized_key)
        if key_characters > MAX_POLICY_CONTEXT_KEY_CHARACTERS:
            raise PolicyContextError(
                "policy context key exceeds maximum of "
                f"{MAX_POLICY_CONTEXT_KEY_CHARACTERS} characters",
                limit_enforced="policy_context_key_characters",
            )
        if key_characters > MAX_POLICY_CONTEXT_CHARACTERS - characters:
            raise PolicyContextError(
                "policy context text exceeds maximum of "
                f"{MAX_POLICY_CONTEXT_CHARACTERS} characters",
                limit_enforced="policy_context_characters",
            )
        if normalized_key in normalized_key_set:
            raise PolicyContextError(
                "policy context keys are ambiguous after normalization",
                limit_enforced="policy_context_type",
            )
        characters += key_characters
        normalized_keys.append(normalized_key)
        normalized_key_set.add(normalized_key)

    items = list(dict.items(context))
    if len(items) != entry_count or any(
        item_key is not key for key, (item_key, _) in zip(keys, items, strict=True)
    ):
        raise PolicyContextError(
            "policy context changed during snapshot",
            limit_enforced="policy_context_snapshot",
        )

    snapshot: dict[str, str] = {}
    for (_, value), normalized_key in zip(items, normalized_keys, strict=True):
        if not isinstance(value, str):
            raise PolicyContextError(
                "policy context keys and values must be strings",
                limit_enforced="policy_context_type",
            )
        normalized_value = str.__str__(value)
        value_characters = str.__len__(normalized_value)
        if value_characters > MAX_POLICY_CONTEXT_VALUE_CHARACTERS:
            raise PolicyContextError(
                "policy context value exceeds maximum of "
                f"{MAX_POLICY_CONTEXT_VALUE_CHARACTERS} characters",
                limit_enforced="policy_context_value_characters",
            )
        if value_characters > MAX_POLICY_CONTEXT_CHARACTERS - characters:
            raise PolicyContextError(
                "policy context text exceeds maximum of "
                f"{MAX_POLICY_CONTEXT_CHARACTERS} characters",
                limit_enforced="policy_context_characters",
            )
        characters += value_characters
        snapshot[normalized_key] = normalized_value

    if dict.__len__(context) != entry_count:
        raise PolicyContextError(
            "policy context changed during snapshot",
            limit_enforced="policy_context_snapshot",
        )
    return snapshot


def _policy_context_error_decision(
    error: PolicyContextError,
    engine: PolicyEngine,
    action: ProposedAction,
) -> GuardrailDecision:
    return GuardrailDecision(
        decision=Decision.BLOCK,
        reason=str(error),
        policy_ids=["policy_context_contract"],
        policy_version=engine.version,
        ruleset_hash=engine.ruleset_hash,
        decision_inputs={
            "tool_name": action.tool_name,
            "side_effect_level": action.side_effect_level.value,
            "policy_name": engine.name,
            "limit_enforced": error.limit_enforced,
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


def _snapshot_policy_configuration(value: Any, label: str) -> Any:
    """Capture policy authority without retaining caller-owned containers."""

    try:
        return authority_snapshot_of(value)
    except ValueError as exc:
        raise ValueError(f"{label} must contain bounded canonical data") from exc


def _freeze_policy_authority(value: Any) -> Any:
    """Recursively freeze an already validated canonical authority tree."""

    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_policy_authority(child) for key, child in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_policy_authority(child) for child in value)
    return value


def _thaw_policy_authority(value: Any) -> Any:
    """Return a detached built-in projection of frozen policy authority."""

    if isinstance(value, MappingProxyType):
        return {key: _thaw_policy_authority(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_policy_authority(child) for child in value]
    return value


class PolicyEngine:
    def __init__(
        self,
        packs: list[dict],
        name: str = "custom",
        authority_inputs: dict[str, Any] | None = None,
    ):
        if not isinstance(packs, (list, tuple)):
            raise ValueError("policy packs must be a sequence")
        observed_packs = _snapshot_policy_configuration(packs, "policy packs")
        if not isinstance(observed_packs, (list, tuple)):
            raise ValueError("policy packs must be a sequence")
        packs_snapshot = list(observed_packs)
        authority_snapshot = _snapshot_policy_configuration(
            {} if authority_inputs is None else authority_inputs,
            "policy authority inputs",
        )
        if not isinstance(authority_snapshot, dict):
            raise ValueError("policy authority inputs must be a mapping")
        if not isinstance(name, str):
            raise ValueError("policy name must be a string")

        _validate_policy_complexity(packs_snapshot)
        normalized_name = str.__str__(name)
        sealed_rules: list[Rule] = []
        known_tool_patterns: list[str] = []
        versions: list[str] = []
        seen_rule_ids: set[str] = set()
        for pack in packs_snapshot:
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
            known_tool_patterns.extend(known_tools)
            raw_rules = pack.get("rules", []) or []
            if not isinstance(raw_rules, list):
                raise ValueError("rules must be a list")
            for raw in raw_rules:
                if not isinstance(raw, dict):
                    raise ValueError("each policy rule must be a mapping")
                rule = Rule(**raw)
                if rule.id in seen_rule_ids:
                    raise ValueError(f"duplicate policy rule id: {rule.id}")
                seen_rule_ids.add(rule.id)
                sealed_rules.append(rule)
        version = "+".join(versions)
        ruleset_hash = sha256_of(
            {
                "known_tools": sorted(known_tool_patterns),
                "authority_inputs": authority_snapshot,
                "rules": [
                    {k: v for k, v in vars(r).items()}
                    for r in sorted(sealed_rules, key=lambda r: r.id)
                ],
            }
        )
        self._name = normalized_name
        self._version = version
        self._rules = tuple(sealed_rules)
        self._known_tools = tuple(known_tool_patterns)
        self._authority_inputs = _freeze_policy_authority(authority_snapshot)
        self._ruleset_hash = ruleset_hash

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return self._version

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self._rules

    @property
    def known_tools(self) -> tuple[str, ...]:
        return self._known_tools

    @property
    def authority_inputs(self) -> dict[str, Any]:
        snapshot = _thaw_policy_authority(self._authority_inputs)
        if not isinstance(snapshot, dict):
            raise RuntimeError("sealed policy authority root is invalid")
        return snapshot

    @property
    def ruleset_hash(self) -> str:
        return self._ruleset_hash

    def is_known_tool(
        self,
        tool_name: str,
        match_state: _PolicyMatchState | None = None,
    ) -> bool:
        """A tool nobody classified is the most dangerous kind of tool.

        If a pack declares `known_tools`, anything outside that list is refused
        outright rather than falling through to generic rules. Otherwise a new
        tool could inherit a permissive rule written for a different one.
        """
        if not self.known_tools:
            return True
        state = match_state or _PolicyMatchState()
        return state.matches_any_glob(
            tool_name,
            self.known_tools,
            subject_label="tool name",
            maximum_characters=MAX_POLICY_MATCH_TOOL_NAME_CHARACTERS,
        )

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
        try:
            loaded_packs = _snapshot_policy_configuration(
                loaded.packs,
                "loaded policy packs",
            )
            additional_tools = _snapshot_policy_configuration(
                [] if additional_known_tools is None else additional_known_tools,
                "additional known tools",
            )
        except ValueError as exc:
            raise PolicyError(f"invalid policy configuration: {exc}") from exc
        if not isinstance(loaded_packs, (list, tuple)):
            raise PolicyError(
                "invalid policy configuration: loaded packs must be a sequence"
            )
        if not isinstance(additional_tools, list):
            raise PolicyError(
                "invalid policy configuration: additional known tools must be a list"
            )
        packs = list(loaded_packs)
        if additional_tools:
            packs.append(
                {
                    "version": "registry-v1",
                    "known_tools": sorted(additional_tools),
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
        try:
            context_snapshot = _policy_context_snapshot(context)
        except PolicyContextError as exc:
            return _policy_context_error_decision(exc, self, action)

        match_state = _PolicyMatchState()
        try:
            # Unclassified tools never reach the rule set.
            if not self.is_known_tool(action.tool_name, match_state):
                return GuardrailDecision(
                    decision=Decision.BLOCK,
                    reason=(
                        f"tool '{action.tool_name}' is not declared in any loaded "
                        "policy pack's known_tools; unclassified tools are refused"
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
            matched = [
                rule
                for rule in self.rules
                if rule.matches(
                    action,
                    context_snapshot,
                    match_state=match_state,
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
                "context": context_snapshot,
                "matched_rules": [r.id for r in matched],
                "policy_name": self.name,
                "authority_inputs": self.authority_inputs,
            },
        )
