"""The tool layer must be unreachable without action-bound signed authority."""

from __future__ import annotations

import pytest

from defiant_agent_harness.contracts import (
    CapabilityGrant,
    Decision,
    EvidenceRecord,
    GrantError,
    ProposedAction,
    ResultStatus,
    SideEffect,
)
from defiant_agent_harness.evidence.store import GENESIS
from defiant_agent_harness.tools.builtin import default_registry
from defiant_agent_harness.tools.registry import (
    ToolContractError,
    ToolRegistry,
    ToolResult,
    ToolSpec,
    canonical_workspace_target,
)


def _action(payload=None, tool="send_email", target="a@example.com"):
    return ProposedAction(
        tool_name=tool,
        target=target,
        payload=payload if payload is not None else {"subject": "hi", "body": "hello"},
        side_effect_level=SideEffect.EXTERNAL_SEND,
        request_id="req_test",
    )


def _authorization(action: ProposedAction) -> EvidenceRecord:
    record = EvidenceRecord(
        request_id=action.request_id,
        action_id=action.action_id,
        decision=Decision.ALLOW,
        result_status=ResultStatus.SKIPPED,
        tool_name=action.tool_name,
        target=action.target,
        side_effect_level=action.side_effect_level.value,
        payload_hash=action.payload_hash,
        authorization_hash=action.authorization_hash,
    )
    return record.seal(GENESIS)


def _grant_for(registry, action: ProposedAction) -> CapabilityGrant:
    return registry.authorize(action, _authorization(action))


def test_execution_without_grant_is_refused():
    registry = default_registry()
    with pytest.raises(GrantError, match="no capability grant"):
        registry.execute(_action(), grant=None)


def test_unsigned_forged_grant_is_refused():
    registry = default_registry()
    action = _action()
    forged = CapabilityGrant(
        action_id=action.action_id,
        tool_name=action.tool_name,
        authorization_hash=action.authorization_hash,
        evidence_record_id="evd_forged",
        evidence_record_hash="sha256:" + "1" * 64,
    )
    with pytest.raises(GrantError, match="signature is invalid"):
        registry.execute(action, forged)


def test_grant_from_another_registry_is_refused():
    first = default_registry()
    second = default_registry()
    action = _action()
    with pytest.raises(GrantError, match="signature is invalid"):
        second.execute(action, _grant_for(first, action))


def test_grant_is_single_use():
    registry = default_registry()
    action = _action()
    grant = _grant_for(registry, action)
    registry.execute(action, grant)
    with pytest.raises(GrantError, match="already spent"):
        registry.execute(action, grant)


def test_payload_substitution_voids_the_grant():
    registry = default_registry()
    benign = _action({"subject": "Statement summary", "body": "All good."})
    grant = _grant_for(registry, benign)
    malicious = _action({"subject": "Wire instructions", "body": "Send funds to 1234."})
    malicious.action_id = benign.action_id
    with pytest.raises(GrantError, match="action changed after authorization"):
        registry.execute(malicious, grant)


def test_target_substitution_voids_the_grant():
    registry = default_registry()
    action = _action(target="customer@example.com")
    grant = _grant_for(registry, action)
    action.target = "attacker@example.com"
    with pytest.raises(GrantError, match="action changed after authorization"):
        registry.execute(action, grant)


def test_grant_for_a_different_tool_is_refused():
    registry = default_registry()
    action = _action()
    grant = _grant_for(registry, action)
    other = _action(tool="publish_post", target="https://example.com")
    other.action_id = action.action_id
    other.payload = action.payload
    other.side_effect_level = SideEffect.EXTERNAL_PUBLISH
    with pytest.raises(GrantError, match="tool mismatch|action changed"):
        registry.execute(other, grant)


def test_grant_for_a_different_action_is_refused():
    registry = default_registry()
    first, second = _action(), _action()
    with pytest.raises(GrantError, match="id mismatch"):
        registry.execute(second, _grant_for(registry, first))


def test_adapter_cannot_downgrade_registered_side_effect():
    registry = default_registry()
    downgraded = _action()
    downgraded.side_effect_level = SideEffect.NONE
    with pytest.raises(ToolContractError, match="registry declares"):
        registry.validate_action(downgraded)


def test_workspace_path_scope_allows_root_but_refuses_escape(tmp_path):
    registry = ToolRegistry(workspace_root=tmp_path)
    registry.register(
        ToolSpec(
            "list_directory",
            SideEffect.NONE,
            "List a directory, including the workspace root.",
            target_scope="workspace_path",
        ),
        lambda action: ToolResult(status="succeeded", summary=action.target),
    )
    root = ProposedAction(
        tool_name="list_directory",
        target=".",
        payload={"path": "."},
        side_effect_level=SideEffect.NONE,
        request_id="req_root",
    )
    registry.validate_action(root)

    escaped = ProposedAction(
        tool_name="list_directory",
        target="../outside",
        payload={"path": "../outside"},
        side_effect_level=SideEffect.NONE,
        request_id="req_escape",
    )
    with pytest.raises(ToolContractError, match="workspace file target"):
        registry.validate_action(escaped)


def test_absolute_workspace_target_has_stable_policy_identity(tmp_path):
    child = tmp_path / "folder" / "note.txt"
    assert (
        canonical_workspace_target(str(child), tmp_path) == "workspace/folder/note.txt"
    )
    assert (
        canonical_workspace_target(str(tmp_path), tmp_path, allow_root=True)
        == "workspace"
    )

    with pytest.raises(ToolContractError, match="outside"):
        canonical_workspace_target(str(tmp_path.parent / "outside.txt"), tmp_path)


def test_blocked_evidence_cannot_authorize():
    registry = default_registry()
    action = _action()
    blocked = _authorization(action)
    blocked.record_hash = ""
    blocked.decision = Decision.BLOCK
    blocked.seal(GENESIS)
    with pytest.raises(GrantError, match="blocked evidence"):
        registry.authorize(action, blocked)


def test_mutating_sealed_evidence_cannot_turn_a_block_into_authority():
    registry = default_registry()
    action = _action()
    record = _authorization(action)
    record.decision = Decision.BLOCK
    with pytest.raises(GrantError, match="does not match its seal"):
        registry.authorize(action, record)


def test_registry_holds_raw_callables_privately():
    registry = default_registry()
    public = [name for name in dir(registry) if not name.startswith("_")]
    for name in public:
        assert not callable(getattr(registry, name)) or name in {
            "authorize",
            "register",
            "execute",
            "spec",
            "names",
            "specs",
            "validate_action",
        }, f"unexpected public callable '{name}' on ToolRegistry"
