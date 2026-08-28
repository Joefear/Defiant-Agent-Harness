"""Read-only Command Core projection over local Defiant state.

Command Core is deliberately not another authority path. It never approves,
executes, or mutates harness state. It validates the evidence chain first and
then produces a small, JSON-safe operational snapshot for a future Command UI.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from ..approvals.store import APPROVAL_STATUSES, ApprovalError, PendingApproval
from ..budgets.ledger import BudgetError, BudgetLedger
from ..contracts import Decision, ResultStatus, utc_now
from ..evidence.store import ChainStatus, EvidenceError, EvidenceStore
from ..evidence_witness import EvidenceWitnessError
from ..limits import (
    MAX_AUTHORITY_PROFILE_STATE_BYTES,
    MAX_POLICY_CONTEXT_CHARACTERS,
    MAX_POLICY_CONTEXT_ENTRIES,
    MAX_POLICY_CONTEXT_KEY_CHARACTERS,
    MAX_POLICY_CONTEXT_VALUE_CHARACTERS,
    MAX_ACTION_HASH_CANONICAL_BYTES,
    MAX_ACTION_HASH_MAPPING_ENTRIES,
    MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS,
    MAX_ACTION_HASH_NESTING_DEPTH,
    MAX_ACTION_HASH_NODES,
    MAX_ACTION_HASH_NUMBER_CHARACTERS,
    MAX_ACTION_HASH_SCALAR_CHARACTERS,
    MAX_ACTION_HASH_STRING_TOKEN_BYTES,
    MAX_APPROVAL_STATE_BYTES,
    MAX_BUDGET_STATE_BYTES,
    MAX_DURABLE_JSON_BYTES,
    MAX_EVIDENCE_EXPORT_BYTES,
    MAX_EVIDENCE_HEAD_STATE_BYTES,
    MAX_EVIDENCE_RECORD_BYTES,
    MAX_HOOK_EVENT_BYTES,
    MAX_HOOK_EXECUTION_STATE_BYTES,
    MAX_JSON_LEXICAL_TOKENS,
    MAX_JSON_NESTING_DEPTH,
    MAX_JSON_NUMBER_TOKEN_CHARACTERS,
    MAX_JSON_STRING_TOKEN_CHARACTERS,
    MAX_MCP_CONFIG_BYTES,
    MAX_MCP_CONFIG_COLLECTION_ITEMS,
    MAX_MCP_DEPENDENCY_FILE_PINS,
    MAX_MCP_LAUNCH_ENVIRONMENT_ENTRIES,
    MAX_MCP_MESSAGE_BYTES,
    MAX_OPERATION_JOURNAL_BYTES,
    MAX_OPERATOR_TRUST_STATE_BYTES,
    MAX_POLICY_GLOB_MATCH_WORK_UNITS,
    MAX_POLICY_KNOWN_TOOLS,
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
    MAX_PROVENANCE_REFS,
    MAX_PROVENANCE_TEXT_CHARACTERS,
    MAX_PROVENANCE_TEXT_ITEM_CHARACTERS,
    MAX_REQUEST_ALLOWED_TOOL_CHARACTERS,
    MAX_REQUEST_ALLOWED_TOOLS,
    MAX_REQUEST_IDENTIFIER_CHARACTERS,
    MAX_REQUEST_TEXT_CHARACTERS,
    MAX_REQUEST_TEXT_ITEM_CHARACTERS,
    MAX_TOOL_RESULT_SUMMARY_CHARACTERS,
    MAX_TOOL_CALL_IDENTIFIER_CHARACTERS,
    MAX_TOOL_CALL_NAME_CHARACTERS,
    MAX_TRUSTED_PUBLIC_KEYS,
    MAX_TRUSTED_PUBLIC_KEY_BYTES,
    MAX_TRUSTED_PUBLIC_KEY_SET_BYTES,
    MAX_YAML_NESTING_DEPTH,
    MAX_YAML_NODES,
)
from ..money import ZERO, money, money_text
from ..operation_journal import (
    JournalOperation,
    OperationJournal,
    OperationJournalError,
)
from ..operator_identity import (
    DECISION_PURPOSE,
    RECONCILIATION_PURPOSE,
    OperatorIdentityStatus,
    OperatorTrustPolicy,
    unsigned_status,
    validate_external_trust_specs,
)
from ..persistence import PersistenceError, read_json
from ..state_integrity import StateIntegrityAuditor
from ..strict_json import STRICT_JSON_PROFILE
from ..strict_yaml import STRICT_YAML_PROFILE

SNAPSHOT_SCHEMA = "defiant.command.snapshot"
SNAPSHOT_VERSION = "0.58.0"


class CommandError(RuntimeError):
    """Command Core could not produce a trustworthy snapshot."""


class CommandCore:
    """Build a read-only operational snapshot from one harness work directory."""

    def __init__(
        self,
        workdir: str | Path,
        trusted_operator_keys: list[str] | None = None,
        workspace_root: str | Path | None = None,
        evidence_head_witness: str | Path | None = None,
        trusted_evidence_witness_keys: list[str] | None = None,
    ):
        self.workdir = Path(workdir)
        self.workspace_root = workspace_root
        self.evidence_head_witness = evidence_head_witness
        self.trusted_evidence_witness_keys = trusted_evidence_witness_keys or []
        validate_external_trust_specs(trusted_operator_keys or [], self.workdir)
        self.operator_trust = (
            OperatorTrustPolicy.from_specs(trusted_operator_keys)
            if trusted_operator_keys
            else None
        )

    def snapshot(self, *, limit: int = 10, request_id: str = "") -> dict[str, Any]:
        if limit < 0:
            raise CommandError("limit must not be negative")

        try:
            audit = StateIntegrityAuditor(
                self.workdir,
                operator_trust=self.operator_trust,
                workspace_root=self.workspace_root,
                evidence_head_witness=self.evidence_head_witness,
                trusted_evidence_witness_keys=self.trusted_evidence_witness_keys,
            ).audit()
            audit_payload = audit.to_dict()
            journal_operation = (
                None
                if audit.stores["operation_journal"]["state"] == "invalid"
                else OperationJournal(self.workdir / "operation_journal.json").active()
            )
            if audit.stores["evidence"]["state"] == "invalid":
                detail = _store_issue_detail(audit_payload, "evidence")
                integrity = ChainStatus(
                    False, audit.counts["evidence_records"], detail=detail
                )
                evidence, recent = None, []
            else:
                integrity, evidence, recent = self._evidence(limit, request_id)
            approvals = (
                _unavailable_approvals()
                if audit.stores["approvals"]["state"] == "invalid"
                else self._approvals(journal_operation)
            )
            authorization_reconciliation = (
                _unavailable_authorization_reconciliation()
                if audit.stores["evidence"]["state"] == "invalid"
                or audit.stores["approvals"]["state"] == "invalid"
                else self._authorization_reconciliation(journal_operation)
            )
            budget = (
                _unavailable_budget()
                if audit.stores["budget"]["state"] == "invalid"
                else self._budget()
            )
            return {
                "schema_name": SNAPSHOT_SCHEMA,
                "schema_version": SNAPSHOT_VERSION,
                "generated_at": utc_now(),
                "authoritative": integrity.ok and audit.safe_to_execute,
                "state_integrity": audit_payload,
                "operator_trust": audit_payload["stores"]["operator_trust"],
                "authority_profile": audit_payload["stores"]["authority_profile"],
                "state_storage": audit_payload["stores"]["state_storage"],
                "control_plane_isolation": audit_payload["stores"][
                    "control_plane_isolation"
                ],
                "workspace_integrity": audit_payload["stores"]["workspace_integrity"],
                "evidence_head": audit_payload["stores"]["evidence_head"],
                "evidence_witness": audit_payload["stores"]["evidence_witness"],
                "runtime_artifacts": audit_payload["stores"]["runtime_artifacts"],
                "launch_envelope": audit_payload["stores"]["launch_envelope"],
                "resource_limits": {
                    "tool_call_name_characters": MAX_TOOL_CALL_NAME_CHARACTERS,
                    "tool_call_identifier_characters": (
                        MAX_TOOL_CALL_IDENTIFIER_CHARACTERS
                    ),
                    "tool_call_mapping_entries": MAX_ACTION_HASH_MAPPING_ENTRIES,
                    "tool_call_mapping_sort_work_units": (
                        MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS
                    ),
                    "tool_call_nesting_depth": MAX_ACTION_HASH_NESTING_DEPTH,
                    "tool_call_nodes": MAX_ACTION_HASH_NODES,
                    "tool_call_number_characters": (MAX_ACTION_HASH_NUMBER_CHARACTERS),
                    "tool_call_scalar_characters": (MAX_ACTION_HASH_SCALAR_CHARACTERS),
                    "tool_call_string_token_bytes": (
                        MAX_ACTION_HASH_STRING_TOKEN_BYTES
                    ),
                    "tool_call_canonical_bytes": MAX_ACTION_HASH_CANONICAL_BYTES,
                    "action_hash_canonical_bytes": MAX_ACTION_HASH_CANONICAL_BYTES,
                    "action_hash_mapping_entries": MAX_ACTION_HASH_MAPPING_ENTRIES,
                    "action_hash_mapping_sort_work_units": (
                        MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS
                    ),
                    "action_hash_nesting_depth": MAX_ACTION_HASH_NESTING_DEPTH,
                    "action_hash_nodes": MAX_ACTION_HASH_NODES,
                    "action_hash_number_characters": (
                        MAX_ACTION_HASH_NUMBER_CHARACTERS
                    ),
                    "action_hash_scalar_characters": (
                        MAX_ACTION_HASH_SCALAR_CHARACTERS
                    ),
                    "action_hash_string_token_bytes": (
                        MAX_ACTION_HASH_STRING_TOKEN_BYTES
                    ),
                    "tool_result_summary_characters": (
                        MAX_TOOL_RESULT_SUMMARY_CHARACTERS
                    ),
                    "tool_result_output_nesting_depth": (MAX_ACTION_HASH_NESTING_DEPTH),
                    "tool_result_output_nodes": MAX_ACTION_HASH_NODES,
                    "tool_result_output_number_characters": (
                        MAX_ACTION_HASH_NUMBER_CHARACTERS
                    ),
                    "tool_result_output_scalar_characters": (
                        MAX_ACTION_HASH_SCALAR_CHARACTERS
                    ),
                    "tool_result_output_string_token_bytes": (
                        MAX_ACTION_HASH_STRING_TOKEN_BYTES
                    ),
                    "tool_result_output_canonical_bytes": (
                        MAX_ACTION_HASH_CANONICAL_BYTES
                    ),
                    "tool_result_output_mapping_entries": (
                        MAX_ACTION_HASH_MAPPING_ENTRIES
                    ),
                    "tool_result_output_mapping_sort_work_units": (
                        MAX_ACTION_HASH_MAPPING_SORT_WORK_UNITS
                    ),
                    "durable_json_bytes": MAX_DURABLE_JSON_BYTES,
                    "evidence_export_bytes": MAX_EVIDENCE_EXPORT_BYTES,
                    "evidence_record_bytes": MAX_EVIDENCE_RECORD_BYTES,
                    "mcp_message_bytes": MAX_MCP_MESSAGE_BYTES,
                    "hook_event_bytes": MAX_HOOK_EVENT_BYTES,
                    "hook_execution_state_bytes": MAX_HOOK_EXECUTION_STATE_BYTES,
                    "approval_state_bytes": MAX_APPROVAL_STATE_BYTES,
                    "budget_state_bytes": MAX_BUDGET_STATE_BYTES,
                    "evidence_head_state_bytes": MAX_EVIDENCE_HEAD_STATE_BYTES,
                    "operation_journal_bytes": MAX_OPERATION_JOURNAL_BYTES,
                    "authority_profile_state_bytes": (
                        MAX_AUTHORITY_PROFILE_STATE_BYTES
                    ),
                    "operator_trust_state_bytes": MAX_OPERATOR_TRUST_STATE_BYTES,
                    "json_lexical_tokens": MAX_JSON_LEXICAL_TOKENS,
                    "json_nesting_depth": MAX_JSON_NESTING_DEPTH,
                    "json_number_token_characters": MAX_JSON_NUMBER_TOKEN_CHARACTERS,
                    "json_string_token_characters": MAX_JSON_STRING_TOKEN_CHARACTERS,
                    "mcp_config_bytes": MAX_MCP_CONFIG_BYTES,
                    "mcp_config_collection_items": (MAX_MCP_CONFIG_COLLECTION_ITEMS),
                    "mcp_dependency_file_pins": MAX_MCP_DEPENDENCY_FILE_PINS,
                    "mcp_launch_environment_entries": (
                        MAX_MCP_LAUNCH_ENVIRONMENT_ENTRIES
                    ),
                    "policy_pack_bytes": MAX_POLICY_PACK_BYTES,
                    "policy_pack_count": MAX_POLICY_PACKS,
                    "policy_rule_count": MAX_POLICY_RULES,
                    "policy_known_tool_count": MAX_POLICY_KNOWN_TOOLS,
                    "policy_rule_field_items": MAX_POLICY_RULE_FIELD_ITEMS,
                    "policy_rule_list_items": MAX_POLICY_RULE_LIST_ITEMS,
                    "policy_text_item_characters": (MAX_POLICY_TEXT_ITEM_CHARACTERS),
                    "policy_text_characters": MAX_POLICY_TEXT_CHARACTERS,
                    "policy_match_payload_nesting_depth": (
                        MAX_POLICY_MATCH_PAYLOAD_NESTING_DEPTH
                    ),
                    "policy_match_payload_nodes": MAX_POLICY_MATCH_PAYLOAD_NODES,
                    "policy_match_payload_characters": (
                        MAX_POLICY_MATCH_PAYLOAD_CHARACTERS
                    ),
                    "policy_payload_match_work_units": (
                        MAX_POLICY_PAYLOAD_MATCH_WORK_UNITS
                    ),
                    "policy_match_tool_name_characters": (
                        MAX_POLICY_MATCH_TOOL_NAME_CHARACTERS
                    ),
                    "policy_match_target_characters": (
                        MAX_POLICY_MATCH_TARGET_CHARACTERS
                    ),
                    "policy_glob_match_work_units": (MAX_POLICY_GLOB_MATCH_WORK_UNITS),
                    "policy_context_entries": MAX_POLICY_CONTEXT_ENTRIES,
                    "policy_context_key_characters": (
                        MAX_POLICY_CONTEXT_KEY_CHARACTERS
                    ),
                    "policy_context_value_characters": (
                        MAX_POLICY_CONTEXT_VALUE_CHARACTERS
                    ),
                    "policy_context_characters": MAX_POLICY_CONTEXT_CHARACTERS,
                    "request_task_characters": MAX_REQUEST_TEXT_ITEM_CHARACTERS,
                    "request_identifier_characters": (
                        MAX_REQUEST_IDENTIFIER_CHARACTERS
                    ),
                    "request_allowed_tool_count": MAX_REQUEST_ALLOWED_TOOLS,
                    "request_allowed_tool_characters": (
                        MAX_REQUEST_ALLOWED_TOOL_CHARACTERS
                    ),
                    "request_text_characters": MAX_REQUEST_TEXT_CHARACTERS,
                    "provenance_ref_count": MAX_PROVENANCE_REFS,
                    "provenance_text_item_characters": (
                        MAX_PROVENANCE_TEXT_ITEM_CHARACTERS
                    ),
                    "provenance_text_characters": MAX_PROVENANCE_TEXT_CHARACTERS,
                    "trusted_public_key_count": MAX_TRUSTED_PUBLIC_KEYS,
                    "trusted_public_key_bytes": MAX_TRUSTED_PUBLIC_KEY_BYTES,
                    "trusted_public_key_set_bytes": MAX_TRUSTED_PUBLIC_KEY_SET_BYTES,
                    "yaml_nesting_depth": MAX_YAML_NESTING_DEPTH,
                    "yaml_nodes": MAX_YAML_NODES,
                },
                "authority_configuration": {
                    "yaml_parser_profile": STRICT_YAML_PROFILE,
                    "json_parser_profile": STRICT_JSON_PROFILE,
                    "json_structural_preflight": True,
                    "json_scalar_preflight": True,
                    "mcp_collection_preflight": True,
                    "policy_text_preflight": True,
                    "policy_payload_match_preflight": True,
                    "policy_glob_match_preflight": True,
                    "action_hash_preflight": True,
                    "canonical_number_preflight": True,
                    "canonical_string_preflight": True,
                    "canonical_value_preflight": True,
                    "canonical_mapping_preflight": True,
                    "canonical_mapping_sort_preflight": True,
                    "canonical_mapping_key_preflight": True,
                    "complete_mapping_key_preflight": True,
                    "validated_canonical_snapshot": True,
                    "validated_snapshot_ownership": True,
                    "validated_contract_collection_snapshots": True,
                    "validated_scalar_ownership": True,
                    "validated_authority_record_ownership": True,
                    "validated_policy_snapshot_ownership": True,
                    "sealed_policy_runtime_state": True,
                    "validated_policy_context_snapshot": True,
                    "validated_operation_journal_snapshot": True,
                    "validated_native_hook_event_snapshot": True,
                    "sealed_authority_continuity_state": True,
                    "sealed_native_hook_correlation_state": True,
                    "sealed_approval_record_state": True,
                    "validated_budget_ledger_snapshot": True,
                    "validated_evidence_head_snapshot": True,
                    "request_contract_preflight": True,
                    "tool_call_contract_preflight": True,
                    "tool_result_contract_preflight": True,
                    "yaml_aliases_allowed": False,
                    "duplicate_keys_allowed": False,
                    "non_finite_json_numbers_allowed": False,
                    "json_encoding": "utf-8",
                },
                "operation_journal": audit_payload["stores"]["operation_journal"],
                "evidence_integrity": {
                    "ok": integrity.ok,
                    "count": integrity.count,
                    "broken_at": integrity.broken_at,
                    "detail": integrity.detail,
                },
                "evidence": evidence,
                "reconciliation_required": bool(
                    approvals["reconciliation_required_count"]
                    or authorization_reconciliation["required_count"]
                ),
                "approvals": approvals,
                "authorization_reconciliation": authorization_reconciliation,
                "budget": budget,
                "recent_activity": recent,
            }
        except (
            ApprovalError,
            BudgetError,
            EvidenceError,
            EvidenceWitnessError,
            PersistenceError,
            OSError,
            OperationJournalError,
            TypeError,
            ValueError,
        ) as exc:
            raise CommandError(f"cannot build Command snapshot: {exc}") from exc

    def _evidence(
        self,
        limit: int,
        request_id: str,
    ) -> tuple[ChainStatus, dict[str, Any] | None, list[dict[str, Any]]]:
        path = self.workdir / "evidence.jsonl"
        if not path.exists():
            status = ChainStatus(True, 0, detail="chain intact (no evidence store)")
            return status, _empty_evidence(request_id), []

        store = EvidenceStore(path)
        status = store.verify()
        if not status.ok:
            # A broken chain is itself operationally important, but aggregates
            # derived from altered records must not be presented as truth.
            return status, None, []

        records = store.records()
        if request_id:
            records = [r for r in records if r.get("request_id") == request_id]

        decisions = Counter({value.value: 0 for value in Decision})
        results = Counter({value.value: 0 for value in ResultStatus})
        request_ids: set[str] = set()
        action_ids: set[str] = set()
        ruleset_hashes: set[str] = set()
        total_cost = ZERO

        for index, record in enumerate(records):
            decision = _enum_value(record, "decision", Decision, index)
            result = _enum_value(record, "result_status", ResultStatus, index)
            req = _required_text(record, "request_id", index)
            action = _required_text(record, "action_id", index)
            _required_text(record, "record_id", index)
            _required_text(record, "timestamp", index)

            decisions[decision] += 1
            results[result] += 1
            request_ids.add(req)
            action_ids.add(action)
            total_cost += money(
                record.get("cost_usd", "0"),
                field_name=f"record {index} cost_usd",
            )
            ruleset_hash = record.get("ruleset_hash", "")
            if ruleset_hash:
                if not isinstance(ruleset_hash, str):
                    raise CommandError(f"record {index} ruleset_hash must be text")
                ruleset_hashes.add(ruleset_hash)

        recent_source = records[-limit:] if limit else []
        recent = [_recent_record(record) for record in reversed(recent_source)]
        return (
            status,
            {
                "filtered_request_id": request_id or None,
                "record_count": len(records),
                "request_count": len(request_ids),
                "action_count": len(action_ids),
                "decisions": dict(decisions),
                "results": dict(results),
                "total_cost_usd": money_text(total_cost),
                "ruleset_hashes": sorted(ruleset_hashes),
                "latest_event_at": records[-1]["timestamp"] if records else None,
            },
            recent,
        )

    def _approvals(self, journal_operation: JournalOperation | None) -> dict[str, Any]:
        path = self.workdir / "approvals.json"
        status_counts = Counter({status: 0 for status in sorted(APPROVAL_STATUSES)})
        if not path.exists():
            return {
                "state": "not_initialized",
                "total_count": 0,
                "actionable_count": 0,
                "overdue_pending_count": 0,
                "reconciliation_required_count": 0,
                "operator_identity_policy": (
                    "signed_required"
                    if self.operator_trust is not None
                    else "not_configured"
                ),
                "identity_assurance": {},
                "statuses": dict(status_counts),
                "actionable": [],
            }

        raw_approvals = read_json(path, max_bytes=MAX_APPROVAL_STATE_BYTES)
        actionable: list[dict[str, Any]] = []
        identity_counts: Counter[str] = Counter()
        overdue = 0
        reconciliation_required_count = 0
        for approval_id, raw in raw_approvals.items():
            if not isinstance(raw, dict):
                raise CommandError(f"approval {approval_id} is not an object")
            approval = PendingApproval.from_dict(raw)
            if approval.approval_id != approval_id:
                raise CommandError(
                    f"approval key {approval_id} does not match its stored id"
                )
            status_counts[approval.status] += 1
            expired_pending = approval.status == "pending" and approval.is_expired()
            if expired_pending:
                overdue += 1
            if (
                approval.status in {"pending", "approved", "executing"}
                and not expired_pending
            ):
                completion_known = _journal_completes_approval(
                    journal_operation, approval
                )
                if approval.status == "executing" and not completion_known:
                    reconciliation_required_count += 1
                identity = self._operator_identity(approval)
                identity_counts[identity.assurance] += 1
                reconciliation_identity = (
                    self._reconciliation_identity(approval)
                    if approval.reconciliation_outcome
                    else None
                )
                actionable.append(
                    {
                        "approval_id": approval.approval_id,
                        "request_id": approval.request_id,
                        "action_id": approval.action_id,
                        "tool_name": approval.tool_name,
                        "status": approval.status,
                        "created_at": approval.created_at,
                        "expires_at": approval.expires_at or None,
                        "reconciliation_required": (
                            approval.status == "executing" and not completion_known
                        ),
                        "reconciliation_state": (
                            "known_result_recovery"
                            if completion_known
                            else "in_progress"
                            if approval.reconciliation_outcome
                            else "required"
                            if approval.status == "executing"
                            else "none"
                        ),
                        "operator_identity": _identity_projection(identity),
                        "reconciliation_identity": (
                            _identity_projection(reconciliation_identity)
                            if reconciliation_identity is not None
                            else None
                        ),
                    }
                )

        actionable.sort(key=lambda item: (item["created_at"], item["approval_id"]))
        return {
            "state": "ready",
            "total_count": len(raw_approvals),
            "actionable_count": len(actionable),
            "overdue_pending_count": overdue,
            "reconciliation_required_count": reconciliation_required_count,
            "operator_identity_policy": (
                "signed_required"
                if self.operator_trust is not None
                else "not_configured"
            ),
            "identity_assurance": dict(identity_counts),
            "statuses": dict(status_counts),
            "actionable": actionable,
        }

    def _operator_identity(self, approval: PendingApproval) -> OperatorIdentityStatus:
        if approval.status == "pending":
            return OperatorIdentityStatus(
                True,
                "not_applicable",
                "approval has not been decided",
            )
        if approval.decision_attestation is None:
            return unsigned_status(approval.decided_by or "")
        if self.operator_trust is None:
            return OperatorIdentityStatus(
                False,
                "unverified",
                "attestation present; no operator trust pins configured",
                operator=approval.decided_by or "",
                key_id=str(approval.decision_attestation.get("key_id", "")),
                signed_at=str(approval.decision_attestation.get("signed_at", "")),
            )
        return self.operator_trust.assess(
            approval.decision_attestation,
            approval,
            purpose=DECISION_PURPOSE,
            outcome="rejected" if approval.status == "rejected" else "approved",
            operator=approval.decided_by or "",
            note=approval.note,
        )

    def _authorization_reconciliation(
        self, journal_operation: JournalOperation | None
    ) -> dict[str, Any]:
        evidence_path = self.workdir / "evidence.jsonl"
        if not evidence_path.exists():
            return {
                "state": "not_initialized",
                "required_count": 0,
                "items": [],
            }
        approval_actions: set[str] = set()
        approvals_path = self.workdir / "approvals.json"
        if approvals_path.exists():
            approval_actions = {
                raw.get("action_id", "")
                for raw in read_json(approvals_path).values()
                if isinstance(raw, dict)
            }
        items = [
            {
                "authority_record_id": record["record_id"],
                "request_id": record["request_id"],
                "action_id": record["action_id"],
                "tool_name": record.get("tool_name", ""),
                "authorized_at": record["timestamp"],
                "reconciliation_state": "required",
            }
            for record in EvidenceStore(evidence_path).open_authorizations()
            if record.get("action_id") not in approval_actions
            and record.get("decision") == "allow"
            and not _journal_completes_authorization(journal_operation, record)
        ]
        items.sort(
            key=lambda item: (item["authorized_at"], item["authority_record_id"])
        )
        return {
            "state": "ready",
            "required_count": len(items),
            "items": items,
        }

    def _reconciliation_identity(
        self, approval: PendingApproval
    ) -> OperatorIdentityStatus:
        if approval.reconciliation_attestation is None:
            return unsigned_status(approval.reconciled_by)
        if self.operator_trust is None:
            return OperatorIdentityStatus(
                False,
                "unverified",
                "attestation present; no operator trust pins configured",
                operator=approval.reconciled_by,
                key_id=str(approval.reconciliation_attestation.get("key_id", "")),
                signed_at=str(approval.reconciliation_attestation.get("signed_at", "")),
            )
        return self.operator_trust.assess(
            approval.reconciliation_attestation,
            approval,
            purpose=RECONCILIATION_PURPOSE,
            outcome=approval.reconciliation_outcome,
            operator=approval.reconciled_by,
            note=approval.reconciliation_note,
        )

    def _budget(self) -> dict[str, Any]:
        path = self.workdir / "budget.json"
        if not path.exists():
            return {
                "state": "not_initialized",
                "summary": {
                    "balance_usd": "0",
                    "reserved_usd": "0",
                    "available_usd": "0",
                    "total_spent_usd": "0",
                    "entry_count": 0,
                },
                "drift": {
                    "total_estimated_usd": "0",
                    "total_spent_usd": "0",
                    "drift_usd": "0",
                    "drift_pct": "0",
                },
            }

        report = BudgetLedger(path).report()
        return {"state": "ready", **report}


def _empty_evidence(request_id: str) -> dict[str, Any]:
    return {
        "filtered_request_id": request_id or None,
        "record_count": 0,
        "request_count": 0,
        "action_count": 0,
        "decisions": {value.value: 0 for value in Decision},
        "results": {value.value: 0 for value in ResultStatus},
        "total_cost_usd": "0",
        "ruleset_hashes": [],
        "latest_event_at": None,
    }


def _unavailable_approvals() -> dict[str, Any]:
    return {
        "state": "invalid",
        "total_count": 0,
        "actionable_count": 0,
        "overdue_pending_count": 0,
        "reconciliation_required_count": 0,
        "operator_identity_policy": "unavailable",
        "identity_assurance": {},
        "statuses": {status: 0 for status in sorted(APPROVAL_STATUSES)},
        "actionable": [],
    }


def _unavailable_authorization_reconciliation() -> dict[str, Any]:
    return {
        "state": "invalid",
        "required_count": 0,
        "items": [],
    }


def _journal_completes_approval(
    operation: JournalOperation | None,
    approval: PendingApproval,
) -> bool:
    if operation is None or operation.kind != "execution_complete":
        return False
    authority = operation.payload.get("authority", {})
    return (
        operation.payload.get("approval_id") == approval.approval_id
        and authority.get("action_id") == approval.action_id
        and authority.get("request_id") == approval.request_id
        and authority.get("authorization_hash") == approval.authorization_hash
    )


def _journal_completes_authorization(
    operation: JournalOperation | None,
    authorization: dict[str, Any],
) -> bool:
    if operation is None or operation.kind != "execution_complete":
        return False
    authority = operation.payload.get("authority", {})
    return (
        authority.get("authority_record_id") == authorization.get("record_id")
        and authority.get("authority_record_hash") == authorization.get("record_hash")
        and authority.get("action_id") == authorization.get("action_id")
        and authority.get("request_id") == authorization.get("request_id")
        and authority.get("authorization_hash")
        == authorization.get("authorization_hash")
    )


def _identity_projection(status: OperatorIdentityStatus) -> dict[str, Any]:
    """Expose assurance metadata only; signatures and operator notes stay sealed."""
    return {
        "ok": status.ok,
        "assurance": status.assurance,
        "detail": status.detail,
        "operator": status.operator or None,
        "key_id": status.key_id or None,
        "signed_at": status.signed_at or None,
    }


def _unavailable_budget() -> dict[str, Any]:
    return {
        "state": "invalid",
        "summary": {
            "balance_usd": "0",
            "reserved_usd": "0",
            "available_usd": "0",
            "total_spent_usd": "0",
            "entry_count": 0,
        },
        "drift": {
            "total_estimated_usd": "0",
            "total_spent_usd": "0",
            "drift_usd": "0",
            "drift_pct": "0",
        },
    }


def _store_issue_detail(audit: dict[str, Any], store: str) -> str:
    for issue in audit["issues"]:
        if issue["store"] == store and issue["severity"] == "critical":
            return issue["detail"]
    return f"{store} state is invalid"


def _required_text(record: dict[str, Any], field: str, index: int) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        raise CommandError(f"record {index} {field} must be non-empty text")
    return value


def _enum_value(record: dict[str, Any], field: str, enum_type, index: int) -> str:
    value = _required_text(record, field, index)
    try:
        return enum_type(value).value
    except ValueError as exc:
        raise CommandError(f"record {index} has invalid {field}: {value}") from exc


def _recent_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return only operational metadata; never expose target or payload material."""

    return {
        "record_id": record["record_id"],
        "timestamp": record["timestamp"],
        "request_id": record["request_id"],
        "action_id": record["action_id"],
        "agent_runner": record.get("agent_runner", ""),
        "workspace_id": record.get("workspace_id", ""),
        "tool_name": record.get("tool_name", ""),
        "decision": record["decision"],
        "result_status": record["result_status"],
        "cost_usd": money_text(record.get("cost_usd", "0")),
    }
