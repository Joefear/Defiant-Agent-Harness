from __future__ import annotations

import pytest

import defiant_agent_harness.policy.engine as policy_engine_module
import defiant_agent_harness.strict_yaml as strict_yaml_module
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.contracts import (
    ContentRef,
    Decision,
    ProposedAction,
    SideEffect,
    Trust,
)
from defiant_agent_harness.policy.engine import PolicyEngine, PolicyError
from defiant_agent_harness.orchestrator.harness import build_harness


@pytest.fixture
def engine():
    return PolicyEngine.default()


def act(tool, target, payload=None, level=SideEffect.NONE, trust=Trust.TRUSTED):
    return ProposedAction(
        tool_name=tool,
        target=target,
        payload=payload or {},
        side_effect_level=level,
        payload_sources=[ContentRef.of("test", trust, payload or {})],
    )


# -- allow ------------------------------------------------------------------


def test_reading_workspace_file_is_allowed(engine):
    d = engine.evaluate(act("read_file", "workspace/statement.txt"))
    assert d.decision is Decision.ALLOW


def test_drafting_is_allowed(engine):
    d = engine.evaluate(act("draft_email", "draft"))
    assert d.decision is Decision.ALLOW


# -- approval ---------------------------------------------------------------


def test_sending_email_requires_approval(engine):
    d = engine.evaluate(
        act("send_email", "a@example.com", {"body": "hi"}, SideEffect.EXTERNAL_SEND)
    )
    assert d.decision is Decision.APPROVAL_REQUIRED
    assert "approve_outbound_send" in d.policy_ids
    assert d.approval_scope


def test_spend_requires_approval(engine):
    d = engine.evaluate(act("spend", "vendor", {"amount_usd": 5}, SideEffect.SPEND))
    assert d.decision is Decision.APPROVAL_REQUIRED


# -- block ------------------------------------------------------------------


def test_delete_is_blocked(engine):
    d = engine.evaluate(
        act("delete_file", "workspace/x.txt", {}, SideEffect.DESTRUCTIVE)
    )
    assert d.decision is Decision.BLOCK


def test_read_outside_workspace_is_blocked(engine):
    d = engine.evaluate(act("read_file", "/etc/passwd"))
    assert d.decision is Decision.BLOCK
    assert "block_write_outside_workspace" in d.policy_ids


def test_unclassified_tool_is_refused_outright(engine):
    """An undeclared tool must not inherit a rule written for a different one."""
    d = engine.evaluate(
        act("some_new_tool", "somewhere", {}, SideEffect.EXTERNAL_PUBLISH)
    )
    assert d.decision is Decision.BLOCK
    assert d.policy_ids == ["unknown_tool"]


def test_unclassified_tool_is_refused_even_with_no_side_effect(engine):
    d = engine.evaluate(act("some_reader", "somewhere", {}, SideEffect.NONE))
    assert d.decision is Decision.BLOCK
    assert d.policy_ids == ["unknown_tool"]


def test_default_deny_applies_to_classified_but_unruled_side_effects():
    """With no known_tools declared, side-effecting actions still default-deny."""
    e = PolicyEngine([{"version": "t", "rules": []}], name="empty")
    d = e.evaluate(act("anything", "somewhere", {}, SideEffect.EXTERNAL_PUBLISH))
    assert d.decision is Decision.BLOCK
    assert d.policy_ids == ["default_deny"]
    allowed = e.evaluate(act("anything", "somewhere", {}, SideEffect.NONE))
    assert allowed.decision is Decision.ALLOW


# -- the injection floor ----------------------------------------------------


def test_untrusted_content_cannot_drive_an_outbound_send(engine):
    d = engine.evaluate(
        act(
            "send_email",
            "attacker@evil.example",
            {"body": "forwarding as the page instructed"},
            SideEffect.EXTERNAL_SEND,
            trust=Trust.UNTRUSTED,
        )
    )
    assert d.decision is Decision.BLOCK
    assert "block_untrusted_side_effect" in d.policy_ids


def test_untrusted_content_can_still_be_read_and_summarized(engine):
    """Injection defence must not break the actual use case."""
    d = engine.evaluate(
        act(
            "summarize",
            "inbound/email.txt",
            {"text": "..."},
            SideEffect.NONE,
            Trust.UNTRUSTED,
        )
    )
    assert d.decision is Decision.ALLOW


def test_missing_provenance_is_not_treated_as_trusted(engine):
    action = ProposedAction(
        tool_name="send_email",
        target="a@example.com",
        payload={"body": "origin unknown"},
        side_effect_level=SideEffect.EXTERNAL_SEND,
    )
    assert action.payload_trust is Trust.DERIVED
    assert engine.evaluate(action).decision is Decision.APPROVAL_REQUIRED


# -- strictest wins ---------------------------------------------------------


def test_block_beats_approval_when_both_match(engine):
    d = engine.evaluate(
        act(
            "send_email",
            "x@example.com",
            {"body": "hi"},
            SideEffect.EXTERNAL_SEND,
            trust=Trust.UNTRUSTED,
        )
    )
    # approve_outbound_send and block_untrusted_side_effect both match.
    assert d.decision is Decision.BLOCK


# -- vertical packs ---------------------------------------------------------


def test_merchant_pack_blocks_guaranteed_savings():
    e = PolicyEngine.default(["merchant_services"])
    d = e.evaluate(
        act(
            "send_email",
            "m@example.com",
            {"body": "We guarantee you will save 30%."},
            SideEffect.EXTERNAL_SEND,
        )
    )
    assert d.decision is Decision.BLOCK
    assert "ms_block_guaranteed_savings" in d.policy_ids


def test_legal_pack_blocks_advice():
    e = PolicyEngine.default(["legal_intake"])
    d = e.evaluate(
        act(
            "send_email",
            "c@example.com",
            {"body": "You have a case and you should sue."},
            SideEffect.EXTERNAL_SEND,
        )
    )
    assert d.decision is Decision.BLOCK
    assert "li_block_legal_advice" in d.policy_ids


def test_vertical_pack_cannot_loosen_the_base(engine):
    e = PolicyEngine.default(["merchant_services"])
    d = e.evaluate(act("delete_file", "workspace/x", {}, SideEffect.DESTRUCTIVE))
    assert d.decision is Decision.BLOCK


# -- attributability --------------------------------------------------------


def test_decision_is_attributable_and_replayable(engine):
    a = act("send_email", "a@example.com", {"body": "hi"}, SideEffect.EXTERNAL_SEND)
    d = engine.evaluate(a)
    assert d.ruleset_hash.startswith("sha256:")
    assert d.policy_version
    assert d.decision_inputs["payload_hash"] == a.payload_hash
    assert d.decision_inputs["matched_rules"]


def test_engine_is_deterministic(engine):
    a = act("send_email", "a@example.com", {"body": "hi"}, SideEffect.EXTERNAL_SEND)
    first = engine.evaluate(a)
    for _ in range(50):
        again = engine.evaluate(a)
        assert again.decision is first.decision
        assert again.policy_ids == first.policy_ids
        assert again.ruleset_hash == first.ruleset_hash


def test_ruleset_hash_changes_when_rules_change(engine):
    other = PolicyEngine.default(["merchant_services"])
    assert other.ruleset_hash != engine.ruleset_hash


def test_ruleset_hash_includes_authoritative_tool_contract():
    first = PolicyEngine.default(
        additional_known_tools=["paid_lookup"],
        authority_inputs={
            "tool_registry": [
                {
                    "name": "paid_lookup",
                    "side_effect_level": "spend",
                    "cost_estimate_usd": "1",
                }
            ]
        },
    )
    changed = PolicyEngine.default(
        additional_known_tools=["paid_lookup"],
        authority_inputs={
            "tool_registry": [
                {
                    "name": "paid_lookup",
                    "side_effect_level": "spend",
                    "cost_estimate_usd": "2",
                }
            ]
        },
    )
    assert first.ruleset_hash != changed.ruleset_hash


def test_policy_engine_owns_the_configuration_observation_it_hashes():
    rule = {
        "id": "allow_inspection",
        "tools": ["inspect"],
        "side_effect_at_least": "local_write",
        "effect": "allow",
    }
    pack = {
        "version": "ownership-test",
        "known_tools": ["inspect"],
        "rules": [rule],
    }
    authority_inputs = {
        "tool_registry": [{"name": "inspect", "contract": ["read-only"]}]
    }
    engine = PolicyEngine([pack], authority_inputs=authority_inputs)
    action = act("inspect", "workspace/item", {}, SideEffect.LOCAL_WRITE)
    original_hash = engine.ruleset_hash

    rule["effect"] = "block"
    rule["tools"].clear()
    pack["known_tools"][0] = "different_tool"
    pack["rules"].clear()
    authority_inputs["tool_registry"][0]["name"] = "different_tool"
    authority_inputs["tool_registry"][0]["contract"].append("mutated")

    decision = engine.evaluate(action)
    assert decision.decision is Decision.ALLOW
    assert decision.policy_ids == ["allow_inspection"]
    assert decision.ruleset_hash == original_hash
    assert engine.known_tools == ["inspect"]
    assert engine.authority_inputs == {
        "tool_registry": [{"name": "inspect", "contract": ["read-only"]}]
    }


def test_policy_engine_snapshots_hostile_builtin_subclasses_without_hooks():
    class HostileString(str):
        def __str__(self):
            raise AssertionError("policy snapshot invoked string hook")

        def strip(self, *args, **kwargs):
            raise AssertionError("policy snapshot invoked strip hook")

    class HostileList(list):
        def __iter__(self):
            raise AssertionError("policy snapshot invoked list iterator hook")

        def __len__(self):
            raise AssertionError("policy snapshot invoked list length hook")

        def __deepcopy__(self, memo):
            raise AssertionError("policy snapshot invoked deepcopy hook")

    class HostileDict(dict):
        def __iter__(self):
            raise AssertionError("policy snapshot invoked mapping iterator hook")

        def __len__(self):
            raise AssertionError("policy snapshot invoked mapping length hook")

        def keys(self):
            raise AssertionError("policy snapshot invoked mapping keys hook")

        def items(self):
            raise AssertionError("policy snapshot invoked mapping items hook")

        def get(self, *args, **kwargs):
            raise AssertionError("policy snapshot invoked mapping get hook")

        def __deepcopy__(self, memo):
            raise AssertionError("policy snapshot invoked deepcopy hook")

    packs = HostileList(
        [
            HostileDict(
                {
                    HostileString("version"): HostileString("hostile-test"),
                    HostileString("known_tools"): HostileList(
                        [HostileString("inspect")]
                    ),
                    HostileString("rules"): HostileList(
                        [
                            HostileDict(
                                {
                                    HostileString("id"): HostileString("allow"),
                                    HostileString("tools"): HostileList(
                                        [HostileString("inspect")]
                                    ),
                                    HostileString("effect"): HostileString("allow"),
                                }
                            )
                        ]
                    ),
                }
            )
        ]
    )
    authority_inputs = HostileDict(
        {
            HostileString("adapter"): HostileDict(
                {HostileString("mode"): HostileString("local")}
            )
        }
    )

    engine = PolicyEngine(
        packs,
        name=HostileString("hostile"),
        authority_inputs=authority_inputs,
    )

    assert type(engine.name) is str
    assert type(engine.known_tools) is list
    assert type(engine.known_tools[0]) is str
    assert type(engine.rules[0].tools) is list
    assert type(engine.rules[0].tools[0]) is str
    assert type(engine.authority_inputs) is dict
    assert type(engine.authority_inputs["adapter"]) is dict
    assert type(engine.authority_inputs["adapter"]["mode"]) is str
    assert engine.evaluate(act("inspect", "record")).decision is Decision.ALLOW


def test_policy_engine_rejects_noncanonical_authority_inputs_without_leaking_data():
    class SecretValue:
        def __repr__(self):
            return "private-policy-value"

    with pytest.raises(
        ValueError,
        match="policy authority inputs must contain bounded canonical data",
    ) as failure:
        PolicyEngine(
            [{"version": "test", "rules": []}],
            authority_inputs={"adapter": SecretValue()},
        )

    assert "private-policy-value" not in str(failure.value)


# -- policy glob matching limits -------------------------------------------


def test_glob_conditions_are_evaluated_once_per_rule(monkeypatch):
    engine = PolicyEngine(
        [
            {
                "version": "glob-test",
                "known_tools": ["inspect"],
                "rules": [
                    {
                        "id": "match",
                        "tools": ["inspect"],
                        "targets": ["record*"],
                        "payload_contains": ["needle"],
                        "effect": "block",
                    }
                ],
            }
        ]
    )
    original = policy_engine_module.fnmatch.fnmatchcase
    calls = []

    def counted(subject, pattern):
        calls.append((subject, pattern))
        return original(subject, pattern)

    monkeypatch.setattr(policy_engine_module.fnmatch, "fnmatchcase", counted)

    decision = engine.evaluate(act("inspect", "record-1", {"value": "needle"}))

    assert decision.decision is Decision.BLOCK
    assert calls == [
        ("inspect", "inspect"),
        ("inspect", "inspect"),
        ("record-1", "record*"),
    ]


def test_glob_tool_name_exact_character_boundary_is_accepted(monkeypatch):
    monkeypatch.setattr(
        policy_engine_module, "MAX_POLICY_MATCH_TOOL_NAME_CHARACTERS", 7
    )
    engine = PolicyEngine(
        [{"version": "test", "known_tools": ["inspect"], "rules": []}]
    )

    decision = engine.evaluate(act("inspect", "record"))

    assert decision.decision is Decision.ALLOW


def test_oversized_glob_tool_name_fails_closed_without_disclosure(monkeypatch):
    monkeypatch.setattr(
        policy_engine_module, "MAX_POLICY_MATCH_TOOL_NAME_CHARACTERS", 6
    )
    engine = PolicyEngine([{"version": "test", "known_tools": ["*"], "rules": []}])

    decision = engine.evaluate(act("SECRETS", "record"))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["policy_match_limit"]
    assert "tool name exceeds maximum of 6 characters" in decision.reason
    assert "SECRETS" not in repr(decision.to_dict())
    assert decision.decision_inputs["limit_enforced"] == "policy_glob_matching"


def test_normalized_glob_subject_expansion_fails_closed(monkeypatch):
    monkeypatch.setattr(
        policy_engine_module, "MAX_POLICY_MATCH_TOOL_NAME_CHARACTERS", 1
    )
    monkeypatch.setattr(
        policy_engine_module.os.path,
        "normcase",
        lambda value: "xx" if value == "X" else value,
    )
    engine = PolicyEngine([{"version": "test", "known_tools": ["*"], "rules": []}])

    decision = engine.evaluate(act("X", "record"))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["policy_match_limit"]
    assert "normalized policy glob tool name" in decision.reason
    assert "X" not in repr(decision.to_dict())


def test_glob_target_exact_character_boundary_is_accepted(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_MATCH_TARGET_CHARACTERS", 6)
    engine = PolicyEngine(
        [
            {
                "version": "test",
                "rules": [{"id": "target", "targets": ["record"], "effect": "block"}],
            }
        ]
    )

    decision = engine.evaluate(act("inspect", "record"))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["target"]


def test_oversized_glob_target_fails_closed_without_disclosure(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_MATCH_TARGET_CHARACTERS", 6)
    engine = PolicyEngine(
        [
            {
                "version": "test",
                "rules": [{"id": "target", "targets": ["*"], "effect": "allow"}],
            }
        ]
    )

    decision = engine.evaluate(act("inspect", "PRIVATE"))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["policy_match_limit"]
    assert "target exceeds maximum of 6 characters" in decision.reason
    assert "PRIVATE" not in repr(decision.to_dict())


def test_glob_work_exact_boundary_is_accepted(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_GLOB_MATCH_WORK_UNITS", 10)
    engine = PolicyEngine(
        [
            {
                "version": "test",
                "rules": [
                    {"id": "first", "targets": ["x"], "effect": "block"},
                    {"id": "second", "targets": ["y"], "effect": "block"},
                ],
            }
        ]
    )

    decision = engine.evaluate(act("inspect", "abcd"))

    assert decision.decision is Decision.ALLOW
    assert decision.policy_ids == ["default_deny"]


def test_glob_work_stops_at_first_matching_pattern(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_GLOB_MATCH_WORK_UNITS", 12)
    engine = PolicyEngine(
        [
            {
                "version": "test",
                "rules": [
                    {
                        "id": "first-match",
                        "targets": ["record", "never-reached"],
                        "effect": "block",
                    }
                ],
            }
        ]
    )

    decision = engine.evaluate(act("inspect", "record"))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["first-match"]


def test_glob_work_is_bounded_across_rules(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_GLOB_MATCH_WORK_UNITS", 9)
    engine = PolicyEngine(
        [
            {
                "version": "test",
                "rules": [
                    {"id": "first", "targets": ["x"], "effect": "allow"},
                    {"id": "second", "targets": ["y"], "effect": "allow"},
                ],
            }
        ]
    )

    decision = engine.evaluate(act("inspect", "abcd"))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["policy_match_limit"]
    assert "glob match work exceeds maximum of 9 units" in decision.reason


def test_glob_work_is_shared_by_classification_and_rules(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_GLOB_MATCH_WORK_UNITS", 27)
    engine = PolicyEngine(
        [
            {
                "version": "test",
                "known_tools": ["inspect"],
                "rules": [{"id": "allow", "tools": ["inspect"], "effect": "allow"}],
            }
        ]
    )

    decision = engine.evaluate(act("inspect", "record"))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["policy_match_limit"]


def test_glob_target_is_not_validated_without_target_patterns(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_MATCH_TARGET_CHARACTERS", 1)
    engine = PolicyEngine(
        [{"version": "test", "rules": [{"id": "allow", "effect": "allow"}]}]
    )

    decision = engine.evaluate(act("inspect", "ordinary-long-target"))

    assert decision.decision is Decision.ALLOW


def test_glob_tool_name_is_not_validated_without_tool_patterns(monkeypatch):
    monkeypatch.setattr(
        policy_engine_module, "MAX_POLICY_MATCH_TOOL_NAME_CHARACTERS", 1
    )
    engine = PolicyEngine(
        [{"version": "test", "rules": [{"id": "allow", "effect": "allow"}]}]
    )

    decision = engine.evaluate(act("ordinary-long-tool", "record"))

    assert decision.decision is Decision.ALLOW


# -- governed payload matching limits ---------------------------------------


def payload_engine(*rules):
    return PolicyEngine(
        [
            {
                "version": "payload-test",
                "known_tools": ["inspect"],
                "rules": list(rules),
            }
        ]
    )


def test_payload_text_is_materialized_once_for_all_matching_rules(monkeypatch):
    engine = payload_engine(
        {"id": "first", "payload_contains": ["absent"], "effect": "allow"},
        {"id": "second", "payload_contains": ["needle"], "effect": "block"},
    )
    original = policy_engine_module._bounded_payload_text
    calls = 0

    def counted(payload):
        nonlocal calls
        calls += 1
        return original(payload)

    monkeypatch.setattr(policy_engine_module, "_bounded_payload_text", counted)

    decision = engine.evaluate(act("inspect", "record", {"value": "needle"}))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["second"]
    assert calls == 1


def test_payload_text_exact_character_boundary_preserves_matching(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_MATCH_PAYLOAD_CHARACTERS", 5)
    engine = payload_engine(
        {"id": "contains", "payload_contains": ["bcd"], "effect": "block"}
    )

    decision = engine.evaluate(act("inspect", "record", {"value": "ABCDE"}))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["contains"]


def test_oversized_payload_text_fails_closed_without_disclosure(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_MATCH_PAYLOAD_CHARACTERS", 5)
    engine = payload_engine(
        {"id": "contains", "payload_contains": ["never"], "effect": "allow"}
    )

    decision = engine.evaluate(act("inspect", "private-target", {"value": "SECRET"}))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["policy_match_limit"]
    assert "maximum of 5 characters" in decision.reason
    assert "SECRET" not in decision.reason
    assert "SECRET" not in repr(decision.decision_inputs)
    assert "private-target" not in repr(decision.decision_inputs)
    assert decision.decision_inputs["limit_enforced"] == "policy_payload_matching"


def test_payload_node_limit_fails_closed_before_scalar_conversion(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_MATCH_PAYLOAD_NODES", 2)
    engine = payload_engine(
        {"id": "contains", "payload_contains": ["never"], "effect": "allow"}
    )

    decision = engine.evaluate(act("inspect", "record", {"outer": ["PRIVATE-SCALAR"]}))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["policy_match_limit"]
    assert "node count exceeds maximum of 2" in decision.reason
    assert "PRIVATE-SCALAR" not in repr(decision.to_dict())


def test_payload_nesting_limit_fails_closed(monkeypatch):
    monkeypatch.setattr(
        policy_engine_module, "MAX_POLICY_MATCH_PAYLOAD_NESTING_DEPTH", 2
    )
    engine = payload_engine(
        {"id": "contains", "payload_contains": ["never"], "effect": "allow"}
    )

    decision = engine.evaluate(act("inspect", "record", {"outer": ["PRIVATE"]}))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["policy_match_limit"]
    assert "nesting exceeds maximum depth of 2" in decision.reason
    assert "PRIVATE" not in repr(decision.to_dict())


def test_payload_structural_exact_boundaries_are_accepted(monkeypatch):
    monkeypatch.setattr(
        policy_engine_module, "MAX_POLICY_MATCH_PAYLOAD_NESTING_DEPTH", 3
    )
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_MATCH_PAYLOAD_NODES", 3)
    engine = payload_engine(
        {"id": "contains", "payload_contains": ["needle"], "effect": "block"}
    )

    decision = engine.evaluate(act("inspect", "record", {"outer": ["needle"]}))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["contains"]


def test_payload_substring_work_is_bounded_across_rules(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_PAYLOAD_MATCH_WORK_UNITS", 9)
    engine = payload_engine(
        {"id": "first", "payload_contains": ["x"], "effect": "allow"},
        {"id": "second", "payload_contains": ["y"], "effect": "allow"},
    )

    decision = engine.evaluate(act("inspect", "record", {"value": "abcd"}))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["policy_match_limit"]
    assert "substring work exceeds maximum of 9 units" in decision.reason


def test_payload_substring_work_exact_boundary_is_accepted(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_PAYLOAD_MATCH_WORK_UNITS", 10)
    engine = payload_engine(
        {"id": "first", "payload_contains": ["x"], "effect": "block"},
        {"id": "second", "payload_contains": ["y"], "effect": "block"},
    )

    decision = engine.evaluate(act("inspect", "record", {"value": "abcd"}))

    assert decision.decision is Decision.ALLOW
    assert decision.policy_ids == ["default_deny"]


def test_payload_without_substring_rules_is_not_materialized(monkeypatch):
    engine = payload_engine({"id": "allow", "tools": ["inspect"], "effect": "allow"})

    def unexpected_materialization(_payload):
        raise AssertionError("payload was materialized without substring rules")

    monkeypatch.setattr(
        policy_engine_module, "_bounded_payload_text", unexpected_materialization
    )

    assert (
        engine.evaluate(act("inspect", "record", {"value": "anything"})).decision
        is Decision.ALLOW
    )


def test_payload_for_unrelated_substring_rule_is_not_materialized(monkeypatch):
    engine = payload_engine(
        {
            "id": "other-tool",
            "tools": ["other"],
            "payload_contains": ["needle"],
            "effect": "block",
        },
        {"id": "allow", "tools": ["inspect"], "effect": "allow"},
    )

    def unexpected_materialization(_payload):
        raise AssertionError("payload was materialized for an inapplicable rule")

    monkeypatch.setattr(
        policy_engine_module, "_bounded_payload_text", unexpected_materialization
    )

    decision = engine.evaluate(act("inspect", "record", {"value": "ordinary payload"}))

    assert decision.decision is Decision.ALLOW


def test_unknown_tool_is_refused_before_payload_materialization(monkeypatch):
    engine = payload_engine(
        {"id": "contains", "payload_contains": ["needle"], "effect": "block"}
    )

    def unexpected_materialization(_payload):
        raise AssertionError("unknown-tool refusal traversed the payload")

    monkeypatch.setattr(
        policy_engine_module, "_bounded_payload_text", unexpected_materialization
    )

    decision = engine.evaluate(act("unclassified", "record", {"value": "anything"}))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["unknown_tool"]


def test_payload_flattening_preserves_nested_empty_separator_semantics():
    engine = payload_engine(
        {
            "id": "separator",
            "payload_contains": [" needle"],
            "effect": "block",
        }
    )

    decision = engine.evaluate(
        act("inspect", "record", {"empty": [], "value": "needle"})
    )

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["separator"]


def test_case_normalization_expansion_is_included_in_character_limit(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_MATCH_PAYLOAD_CHARACTERS", 1)
    engine = payload_engine(
        {"id": "contains", "payload_contains": ["i"], "effect": "allow"}
    )

    decision = engine.evaluate(act("inspect", "record", {"value": "\u0130"}))

    assert decision.decision is Decision.BLOCK
    assert decision.policy_ids == ["policy_match_limit"]
    assert "normalized policy match payload text" in decision.reason


def test_duplicate_rule_ids_are_rejected():
    pack = {
        "version": "test",
        "rules": [
            {"id": "duplicate", "effect": "allow"},
            {"id": "duplicate", "effect": "block"},
        ],
    }
    with pytest.raises(ValueError, match="duplicate policy rule id"):
        PolicyEngine([pack])


def test_invalid_rule_effect_is_rejected_at_load_time():
    with pytest.raises(ValueError):
        PolicyEngine([{"version": "test", "rules": [{"id": "bad", "effect": "maybe"}]}])


def test_policy_pack_is_bounded_before_yaml_parse(tmp_path, monkeypatch):
    path = tmp_path / "oversized.yaml"
    path.write_text("sensitive" * 5, encoding="utf-8")
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_PACK_BYTES", 32)

    with pytest.raises(PolicyError, match="policy pack exceeds 32 bytes") as failure:
        PolicyEngine.from_files([path])

    assert "sensitive" not in str(failure.value)
    assert str(tmp_path) not in str(failure.value)


def test_policy_pack_count_is_bounded_before_file_access(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_PACKS", 1)

    with pytest.raises(PolicyError, match="pack count exceeds maximum of 1"):
        PolicyEngine.load_files(
            [tmp_path / "does-not-exist.yaml", tmp_path / "also-missing.yaml"]
        )


def test_registry_pack_is_counted_before_policy_file_access(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_PACKS", 1)

    with pytest.raises(PolicyError, match="pack count exceeds maximum of 1"):
        PolicyEngine.from_files(
            [tmp_path / "does-not-exist.yaml"],
            additional_known_tools=["registry_tool"],
        )


def test_default_pack_count_precedes_extra_pack_path_probes(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_PACKS", 1)

    def unexpected_path_probe(_path):
        raise AssertionError("extra policy path was probed before count preflight")

    monkeypatch.setattr(policy_engine_module.Path, "exists", unexpected_path_probe)

    with pytest.raises(PolicyError, match="pack count exceeds maximum of 1"):
        PolicyEngine.load_default(["extra"])


def test_policy_rule_count_is_bounded_before_rule_construction(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_RULES", 1)
    pack = {
        "version": "test",
        "rules": [
            {"id": "first", "effect": "allow"},
            {"id": "second", "effect": "not-a-valid-effect"},
        ],
    }

    with pytest.raises(ValueError, match="rule count exceeds maximum of 1"):
        PolicyEngine([pack])


def test_known_tool_patterns_are_bounded_across_packs(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_KNOWN_TOOLS", 2)
    packs = [
        {"version": "one", "known_tools": ["read_*", "write_*"]},
        {"version": "two", "known_tools": ["send_*"]},
    ]

    with pytest.raises(ValueError, match="tool pattern count exceeds maximum of 2"):
        PolicyEngine(packs)


def test_policy_rule_field_items_are_bounded_before_matching(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_RULE_FIELD_ITEMS", 2)
    pack = {
        "version": "test",
        "rules": [
            {
                "id": "too-many-targets",
                "targets": ["one", "two", "three"],
                "effect": "block",
            }
        ],
    }

    with pytest.raises(ValueError, match="targets count exceeds maximum of 2"):
        PolicyEngine([pack])


def test_policy_rule_list_items_are_bounded_across_rules(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_RULE_LIST_ITEMS", 3)
    pack = {
        "version": "test",
        "rules": [
            {"id": "first", "tools": ["a", "b"], "effect": "block"},
            {"id": "second", "targets": ["c", "d"], "effect": "block"},
        ],
    }

    with pytest.raises(ValueError, match="list item count exceeds maximum of 3"):
        PolicyEngine([pack])


def test_policy_text_item_is_bounded_before_rule_construction(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_TEXT_ITEM_CHARACTERS", 4)
    pack = {
        "version": "test",
        "rules": [
            {
                "id": "private-rule-name",
                "effect": "not-a-valid-effect",
            }
        ],
    }

    with pytest.raises(ValueError, match="text item exceeds maximum of 4") as failure:
        PolicyEngine([pack])

    assert "private-rule-name" not in str(failure.value)


def test_policy_text_limit_from_file_has_sanitized_error(tmp_path, monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_TEXT_ITEM_CHARACTERS", 4)
    path = tmp_path / "oversized-text.yaml"
    path.write_text(
        "version: test\ndescription: private-policy-content\nrules: []\n",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="text item exceeds maximum of 4") as failure:
        PolicyEngine.from_files([path])

    assert "private-policy-content" not in str(failure.value)
    assert str(tmp_path) not in str(failure.value)


def test_policy_text_characters_are_bounded_across_packs(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_TEXT_ITEM_CHARACTERS", 3)
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_TEXT_CHARACTERS", 4)
    packs = [
        {"version": "aa", "rules": []},
        {"version": "bbb", "rules": []},
    ]

    with pytest.raises(ValueError, match="text character count exceeds maximum of 4"):
        PolicyEngine(packs)


def test_duplicate_policy_text_counts_as_supplied(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_TEXT_ITEM_CHARACTERS", 4)
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_TEXT_CHARACTERS", 4)
    pack = {
        "version": "t",
        "known_tools": ["aa", "aa"],
        "rules": [],
    }

    with pytest.raises(ValueError, match="text character count exceeds maximum of 4"):
        PolicyEngine([pack])


def test_additional_registry_tool_text_participates_in_policy_bounds(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_TEXT_ITEM_CHARACTERS", 20)
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_TEXT_CHARACTERS", 12)
    loaded = policy_engine_module.LoadedPolicyPacks(
        ({"version": "a", "rules": []},),
        "test",
    )

    with pytest.raises(PolicyError, match="text character count exceeds maximum of 12"):
        PolicyEngine.from_loaded(loaded, additional_known_tools=["x"])


def test_policy_text_exact_boundaries_are_accepted(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_TEXT_ITEM_CHARACTERS", 4)
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_TEXT_CHARACTERS", 8)
    pack = {
        "version": "a",
        "description": "dd",
        "known_tools": ["bb"],
        "rules": [{"id": "ccc"}],
    }

    engine = PolicyEngine([pack])

    assert engine.known_tools == ["bb"]
    assert [rule.id for rule in engine.rules] == ["ccc"]


def test_additional_registry_tools_cannot_bypass_policy_bounds(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_KNOWN_TOOLS", 1)
    loaded = policy_engine_module.LoadedPolicyPacks(
        ({"version": "test", "known_tools": ["existing"], "rules": []},),
        "test",
    )

    with pytest.raises(PolicyError, match="tool pattern count exceeds maximum of 1"):
        PolicyEngine.from_loaded(loaded, additional_known_tools=["registry_tool"])


def test_duplicate_registry_tools_count_as_supplied(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_KNOWN_TOOLS", 1)
    loaded = policy_engine_module.LoadedPolicyPacks(
        ({"version": "test", "rules": []},),
        "test",
    )

    with pytest.raises(PolicyError, match="tool pattern count exceeds maximum of 1"):
        PolicyEngine.from_loaded(
            loaded,
            additional_known_tools=["same_tool", "same_tool"],
        )


def test_policy_complexity_exact_boundaries_are_accepted(monkeypatch):
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_PACKS", 2)
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_RULES", 2)
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_KNOWN_TOOLS", 2)
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_RULE_FIELD_ITEMS", 2)
    monkeypatch.setattr(policy_engine_module, "MAX_POLICY_RULE_LIST_ITEMS", 4)
    packs = [
        {
            "version": "one",
            "known_tools": ["read_*"],
            "rules": [
                {
                    "id": "first",
                    "tools": ["read_*", "list_*"],
                    "effect": "allow",
                }
            ],
        },
        {
            "version": "two",
            "known_tools": ["write_*"],
            "rules": [
                {
                    "id": "second",
                    "targets": ["workspace/*", "scratch/*"],
                    "effect": "block",
                }
            ],
        },
    ]

    engine = PolicyEngine(packs)

    assert len(engine.rules) == 2
    assert len(engine.known_tools) == 2


@pytest.mark.parametrize(
    "body",
    [
        "version: first\nversion: second\nrules: []\n",
        "version: test\nrules:\n  - id: duplicate\n    effect: allow\n    effect: block\n",
    ],
)
def test_policy_pack_rejects_duplicate_yaml_keys(tmp_path, body):
    path = tmp_path / "duplicate.yaml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(PolicyError, match="duplicate mapping key"):
        PolicyEngine.from_files([path])


def test_policy_pack_rejects_yaml_aliases(tmp_path):
    path = tmp_path / "alias.yaml"
    path.write_text(
        "version: test\nknown_tools: &tools [read_file]\ncopy: *tools\nrules: []\n",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="aliases are not supported"):
        PolicyEngine.from_files([path])


def test_policy_pack_rejects_unsafe_yaml_tags(tmp_path):
    path = tmp_path / "tagged.yaml"
    path.write_text(
        "version: test\nrules: !!python/object/apply:builtins.list []\n",
        encoding="utf-8",
    )

    with pytest.raises(PolicyError, match="not valid YAML"):
        PolicyEngine.from_files([path])


def test_policy_pack_rejects_unknown_top_level_fields():
    with pytest.raises(ValueError, match="unknown fields"):
        PolicyEngine([{"version": "test", "rules": [], "typo": True}])


def test_malformed_policy_yaml_has_sanitized_error(tmp_path):
    path = tmp_path / "malformed.yaml"
    path.write_text("known_tools: [sensitive-value", encoding="utf-8")

    with pytest.raises(PolicyError, match="not valid YAML") as failure:
        PolicyEngine.from_files([path])

    assert "sensitive-value" not in str(failure.value)
    assert str(tmp_path) not in str(failure.value)


def test_invalid_policy_preflight_creates_no_state_or_workspace(tmp_path):
    policy = tmp_path / "duplicate.yaml"
    policy.write_text("version: first\nversion: second\nrules: []\n", encoding="utf-8")
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"

    with pytest.raises(PolicyError, match="duplicate mapping key"):
        build_harness(
            state,
            MockAgentAdapter(),
            policy_packs=[str(policy)],
            workspace_root=workspace,
        )

    assert not state.exists()
    assert not workspace.exists()


def test_structurally_complex_policy_creates_no_state_or_workspace(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(strict_yaml_module, "MAX_YAML_NESTING_DEPTH", 2)
    policy = tmp_path / "nested.yaml"
    policy.write_text(
        "version: test\nrules:\n  - id: nested\n    tools: [[read_file]]\n",
        encoding="utf-8",
    )
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"

    with pytest.raises(PolicyError, match="nesting exceeds maximum depth of 2"):
        build_harness(
            state,
            MockAgentAdapter(),
            policy_packs=[str(policy)],
            workspace_root=workspace,
        )

    assert not state.exists()
    assert not workspace.exists()


def test_cli_policy_failure_is_sanitized_and_fail_closed(tmp_path, capsys):
    policy = tmp_path / "private" / "alias.yaml"
    policy.parent.mkdir()
    policy.write_text(
        "version: test\nknown_tools: &sensitive [read_file]\ncopy: *sensitive\n",
        encoding="utf-8",
    )
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"

    exit_code = main(
        [
            "--workdir",
            str(state),
            "--workspace-root",
            str(workspace),
            "--policy",
            str(policy),
            "policy",
        ]
    )

    error = capsys.readouterr().err
    assert exit_code == 1
    assert "aliases are not supported" in error
    assert "sensitive" not in error
    assert str(tmp_path) not in error
    assert not state.exists()
    assert not workspace.exists()
