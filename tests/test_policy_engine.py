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
