"""The tool layer must be unreachable without action-bound signed authority."""

from __future__ import annotations

import pytest

from defiant_agent_harness import contracts as contracts_module
from defiant_agent_harness.contracts import (
    CapabilityGrant,
    Decision,
    EvidenceRecord,
    GrantError,
    ProposedAction,
    ResultStatus,
    SideEffect,
    sha256_of,
)
from defiant_agent_harness.evidence.store import GENESIS
from defiant_agent_harness.tools.builtin import default_registry
from defiant_agent_harness.tools.registry import (
    ToolContractError,
    ToolRegistry,
    ToolResult,
    ToolResultContractError,
    ToolResultLimitError,
    ToolSpec,
    canonical_workspace_target,
)
from defiant_agent_harness.tools import registry as registry_module


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


def test_capability_grant_normalizes_scalar_subclasses_before_use():
    class HostileString(str):
        def __len__(self):
            raise AssertionError("grant string hooks must not run")

        def strip(self, *args, **kwargs):
            raise AssertionError("grant string hooks must not run")

        def replace(self, *args, **kwargs):
            raise AssertionError("grant string hooks must not run")

        def __deepcopy__(self, memo):
            raise AssertionError("grant deepcopy hooks must not run")

    registry = default_registry()
    action = _action()
    grant = _grant_for(registry, action)
    grant.action_id = HostileString(grant.action_id)
    grant.tool_name = HostileString(grant.tool_name)
    grant.authorization_hash = HostileString(grant.authorization_hash)
    grant.evidence_record_id = HostileString(grant.evidence_record_id)
    grant.evidence_record_hash = HostileString(grant.evidence_record_hash)
    grant.issued_at = HostileString(grant.issued_at)
    grant.grant_id = HostileString(grant.grant_id)
    grant.signature = HostileString(grant.signature)

    registry.execute(action, grant)

    assert all(
        type(value) is str
        for value in (
            grant.action_id,
            grant.tool_name,
            grant.authorization_hash,
            grant.evidence_record_id,
            grant.evidence_record_hash,
            grant.issued_at,
            grant.grant_id,
            grant.signature,
        )
    )


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


def test_nested_payload_mutation_after_fingerprint_seal_voids_grant():
    registry = default_registry()
    action = _action({"message": {"body": "approved"}})
    grant = _grant_for(registry, action)
    action.seal_fingerprints()
    action.payload["message"]["body"] = "substituted"

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


def test_tool_result_accepts_exact_summary_limit_and_sanitizes_next(monkeypatch):
    monkeypatch.setattr(registry_module, "MAX_TOOL_RESULT_SUMMARY_CHARACTERS", 4)

    ToolResult(status="succeeded", summary="1234")
    with pytest.raises(ToolResultLimitError, match="summary exceeds") as exc:
        ToolResult(status="succeeded", summary="12345-secret")

    assert exc.value.limit_enforced == "tool_result_summary_characters"
    assert "secret" not in str(exc.value)


def test_tool_result_maps_bounded_output_failure_without_echoing_content(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_SCALAR_CHARACTERS", 4)

    ToolResult(status="succeeded", summary="accepted", output="1234")
    with pytest.raises(ToolResultLimitError, match="fixed canonical") as exc:
        ToolResult(status="succeeded", summary="refused", output="12345-secret")

    assert exc.value.limit_enforced == "tool_result_output_scalar_characters"
    assert "secret" not in str(exc.value)


def test_tool_result_maps_canonical_number_failure(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_NUMBER_CHARACTERS", 4)

    ToolResult(status="succeeded", summary="accepted", output=9999)
    with pytest.raises(ToolResultLimitError) as exc:
        ToolResult(status="succeeded", summary="refused", output=10000)

    assert exc.value.limit_enforced == "tool_result_output_number_characters"


def test_tool_result_maps_invalid_mapping_key_contract():
    with pytest.raises(ToolResultContractError) as exc:
        ToolResult(
            status="succeeded",
            summary="invalid keys",
            output={"text": 1, 2: "number"},
        )

    assert not isinstance(exc.value, ToolResultLimitError)
    assert exc.value.limit_enforced == "tool_result_output_contract"


def test_tool_result_completes_mapping_key_preflight_before_values(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_NUMBER_CHARACTERS", 2)

    with pytest.raises(ToolResultLimitError) as exc:
        ToolResult(
            status="succeeded",
            summary="invalid late key",
            output={1: object(), 100: "late invalid key"},
        )

    assert exc.value.limit_enforced == "tool_result_output_number_characters"
    assert "late invalid key" not in str(exc.value)


def test_tool_result_maps_canonical_string_token_failure(monkeypatch):
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_STRING_TOKEN_BYTES", 8)

    ToolResult(status="succeeded", summary="accepted", output="é")
    with pytest.raises(ToolResultLimitError) as exc:
        ToolResult(status="succeeded", summary="refused", output="😀")

    assert exc.value.limit_enforced == "tool_result_output_string_token_bytes"


@pytest.mark.parametrize(
    ("constant", "maximum", "exact", "beyond", "limit_enforced"),
    [
        ("MAX_ACTION_HASH_NESTING_DEPTH", 1, [None], [[None]], "nesting_depth"),
        ("MAX_ACTION_HASH_NODES", 2, [None], [None, None], "nodes"),
        (
            "MAX_ACTION_HASH_MAPPING_ENTRIES",
            1,
            {"a": 1},
            {"a": 1, "secret": 2},
            "mapping_entries",
        ),
        (
            "MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS",
            0,
            None,
            {"a": 1, "b": 2},
            "mapping_sort_work_units",
        ),
        ("MAX_ACTION_HASH_CANONICAL_BYTES", 4, None, False, "canonical_bytes"),
    ],
)
def test_tool_result_accepts_exact_output_bounds_and_maps_next_failure(
    monkeypatch,
    constant,
    maximum,
    exact,
    beyond,
    limit_enforced,
):
    monkeypatch.setattr(contracts_module, constant, maximum)

    ToolResult(status="succeeded", summary="accepted", output=exact)
    with pytest.raises(ToolResultLimitError) as exc:
        ToolResult(status="succeeded", summary="refused", output=beyond)

    assert exc.value.limit_enforced == f"tool_result_output_{limit_enforced}"


def test_tool_result_rejects_noncanonical_output_with_sanitized_contract_error():
    output = []
    output.append(output)

    with pytest.raises(ToolResultContractError, match="not canonical") as exc:
        ToolResult(status="succeeded", summary="refused", output=output)

    assert exc.value.limit_enforced == "tool_result_output_contract"


def test_tool_result_seal_revalidates_detaches_and_freezes(monkeypatch):
    output = {"nested": ["accepted"]}
    result = ToolResult(status="succeeded", summary="accepted", output=output)
    output["nested"].append("caller mutation")
    result.output = "12345-secret"
    original_limit = contracts_module.MAX_ACTION_HASH_SCALAR_CHARACTERS
    monkeypatch.setattr(contracts_module, "MAX_ACTION_HASH_SCALAR_CHARACTERS", 4)

    with pytest.raises(ToolResultLimitError):
        result.seal_contract()

    monkeypatch.setattr(
        contracts_module, "MAX_ACTION_HASH_SCALAR_CHARACTERS", original_limit
    )
    safe_output = {"nested": ["safe"]}
    expected_hash = sha256_of(safe_output)
    result.output = safe_output
    result.seal_contract()
    safe_output["nested"].append("caller mutation")

    assert result.output == {"nested": ["safe"]}
    assert result.output_hash == expected_hash

    with pytest.raises(ValueError, match="sealed tool result"):
        result.output = {"changed": True}
    with pytest.raises(ValueError, match="sealed tool result"):
        result._contract_sealed = False


def test_tool_result_seal_adopts_validated_snapshot_without_deepcopy_hooks():
    class HostileOutput(dict):
        def __deepcopy__(self, memo):
            raise AssertionError(
                "validated tool-result ownership must not use deepcopy"
            )

    output = HostileOutput({"nested": ["accepted"]})
    result = ToolResult(status="succeeded", summary="accepted", output=output)
    result.seal_contract()
    expected_hash = result.output_hash
    output["nested"].append("caller mutation")

    assert type(result.output) is dict
    assert result.output == {"nested": ["accepted"]}
    assert result.output_hash == expected_hash


def test_tool_result_seal_owns_exact_builtin_scalars_without_subclass_hooks():
    armed = False

    class HostileString(str):
        def __hash__(self):
            if armed:
                raise AssertionError("tool-result scalar hash hook must not run")
            return str.__hash__(self)

        def __len__(self):
            if armed:
                raise AssertionError("tool-result scalar length hook must not run")
            return str.__len__(self)

        def __deepcopy__(self, memo):
            raise AssertionError("tool-result scalar deepcopy hook must not run")

    key = HostileString("key")
    result = ToolResult(
        status=HostileString("succeeded"),
        summary=HostileString("accepted"),
        output={key: HostileString("value")},
    )
    result.status = HostileString("succeeded")
    result.summary = HostileString("accepted")
    armed = True

    result.seal_contract()

    assert type(result.status) is str
    assert type(result.summary) is str
    assert type(next(iter(result.output))) is str
    assert type(result.output["key"]) is str
    result.validate_fields()
