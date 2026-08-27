from __future__ import annotations

import json

import pytest

import defiant_agent_harness.operation_journal as operation_journal_module
from defiant_agent_harness.adapters.mock import MockAgentAdapter, SCRIPTS
from defiant_agent_harness.approvals.store import ApprovalStore
from defiant_agent_harness.budgets.ledger import BudgetLedger
from defiant_agent_harness.command.core import CommandCore
from defiant_agent_harness.contracts import HarnessRequest, canonical_json, sha256_of
from defiant_agent_harness.evidence.store import EvidenceStore
from defiant_agent_harness.evidence.signing import generate_key_pair
from defiant_agent_harness.operation_journal import (
    JournalOperation,
    OperationJournal,
    OperationJournalError,
)
from defiant_agent_harness.operator_identity import (
    DECISION_PURPOSE,
    sign_operator_action,
)
from defiant_agent_harness.orchestrator.harness import build_harness
from defiant_agent_harness.persistence import PersistenceError
from defiant_agent_harness.state_integrity import StateIntegrityAuditor


class SimulatedCrash(RuntimeError):
    pass


PASSPHRASE = b"test-only journal operator passphrase"


def _harness(state, scenario="overspend"):
    return build_harness(
        state,
        MockAgentAdapter(script=SCRIPTS[scenario]),
        starting_budget_usd="500",
    )


def _request():
    return HarnessRequest(task="journal test", user_id="operator", workspace_id="ws")


def _entries(state, kind):
    raw = json.loads((state / "budget.json").read_text(encoding="utf-8"))
    return [entry for entry in raw["entries"] if entry["kind"] == kind]


def _approval_create_payload(state, monkeypatch):
    harness = _harness(state)
    captured = {}
    original = harness.operation_journal.prepare

    def capture(kind, payload):
        captured["kind"] = kind
        captured["payload"] = payload
        return original(kind, payload)

    monkeypatch.setattr(harness.operation_journal, "prepare", capture)
    harness.run(_request())
    return captured["kind"], captured["payload"]


def test_journal_prepare_snapshots_without_caller_hooks(tmp_path, monkeypatch):
    kind, payload = _approval_create_payload(tmp_path / "capture", monkeypatch)

    class HostileText(str):
        def __str__(self):
            raise AssertionError("caller string hook invoked")

        def __len__(self):
            raise AssertionError("caller string length hook invoked")

        def __deepcopy__(self, memo):
            raise AssertionError("caller string copy hook invoked")

    class HostilePayload(dict):
        def __bool__(self):
            raise AssertionError("caller truth hook invoked")

        def __len__(self):
            raise AssertionError("caller length hook invoked")

        def __iter__(self):
            raise AssertionError("caller iterator hook invoked")

        def keys(self):
            raise AssertionError("caller keys hook invoked")

        def items(self):
            raise AssertionError("caller items hook invoked")

        def get(self, key, default=None):
            raise AssertionError("caller get hook invoked")

        def __deepcopy__(self, memo):
            raise AssertionError("caller copy hook invoked")

    hostile = HostilePayload(payload)
    hostile["reserved_usd"] = HostileText(hostile["reserved_usd"])

    operation = JournalOperation.prepare(kind, hostile)

    assert operation.payload_hash == sha256_of(operation.payload)
    assert type(operation.payload["reserved_usd"]) is str
    assert operation.payload["approval"] == payload["approval"]


def test_journal_retains_a_sealed_payload_behind_defensive_projections(
    tmp_path, monkeypatch
):
    kind, payload = _approval_create_payload(tmp_path / "capture", monkeypatch)
    operation = JournalOperation.prepare(kind, payload)
    expected = operation.payload

    payload["reserved_usd"] = "999"
    payload["evidence"]["result_summary"] = "caller mutation"
    projection = operation.payload
    projection["reserved_usd"] = "888"
    projection["evidence"]["result_summary"] = "projection mutation"

    assert operation.payload == expected
    assert operation.to_dict()["payload"] == expected
    assert operation.payload_hash == sha256_of(expected)


def test_journal_from_dict_snapshots_hostile_operation_mapping(tmp_path, monkeypatch):
    kind, payload = _approval_create_payload(tmp_path / "capture", monkeypatch)
    prepared = JournalOperation.prepare(kind, payload)

    class HostileOperation(dict):
        def __iter__(self):
            raise AssertionError("caller iterator hook invoked")

        def items(self):
            raise AssertionError("caller items hook invoked")

        def get(self, key, default=None):
            raise AssertionError("caller get hook invoked")

        def __deepcopy__(self, memo):
            raise AssertionError("caller copy hook invoked")

    raw = HostileOperation(prepared.to_dict())
    restored = JournalOperation.from_dict(raw)
    raw["payload"]["reserved_usd"] = "999"

    assert restored == prepared
    assert restored.payload == prepared.payload


def test_journal_rejects_noncanonical_value_without_rendering_it(tmp_path, monkeypatch):
    kind, payload = _approval_create_payload(tmp_path / "capture", monkeypatch)

    class SecretValue:
        def __str__(self):
            raise AssertionError("secret rendered")

        def __repr__(self):
            raise AssertionError("secret represented")

        def __deepcopy__(self, memo):
            raise AssertionError("secret copied")

    payload["reserved_usd"] = SecretValue()

    with pytest.raises(
        OperationJournalError,
        match="journal payload exceeds bounded canonical contract",
    ) as failure:
        JournalOperation.prepare(kind, payload)

    assert "SecretValue" not in str(failure.value)


def test_journal_rejects_payload_over_canonical_byte_ceiling():
    with pytest.raises(
        OperationJournalError,
        match="journal payload exceeds bounded canonical contract",
    ):
        JournalOperation.prepare(
            "approval_create",
            {"oversized": "x" * (4 * 1024 * 1024)},
        )


def test_journal_writer_cannot_publish_a_file_its_reader_would_refuse(
    tmp_path, monkeypatch
):
    kind, payload = _approval_create_payload(tmp_path / "capture", monkeypatch)
    operation = JournalOperation.prepare(kind, payload)
    document = {
        "schema_name": operation_journal_module.JOURNAL_SCHEMA,
        "schema_version": operation_journal_module.JOURNAL_VERSION,
        "active": operation.to_dict(),
    }
    encoded_bytes = len(
        json.dumps(document, indent=2, sort_keys=True, allow_nan=False).encode("utf-8")
    )
    maximum = encoded_bytes - 1
    assert len(canonical_json(payload).encode("utf-8")) < maximum
    monkeypatch.setattr(
        operation_journal_module,
        "MAX_OPERATION_JOURNAL_BYTES",
        maximum,
    )
    path = tmp_path / "bounded" / "operation_journal.json"

    with pytest.raises(PersistenceError, match=f"exceeds {maximum} bytes"):
        OperationJournal(path).prepare(kind, payload)

    assert not path.exists()
    assert not list(path.parent.glob(".*.tmp"))


def test_restart_recovers_crash_after_prepared_approval_was_stored(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)
    original = harness.approvals.create_prepared

    def crash_after_store(approval):
        original(approval)
        raise SimulatedCrash("after approval store")

    monkeypatch.setattr(harness.approvals, "create_prepared", crash_after_store)
    with pytest.raises(SimulatedCrash):
        harness.run(_request())

    operation = OperationJournal(state / "operation_journal.json").active()
    assert operation is not None and operation.kind == "approval_create"
    assert len(_entries(state, "reserve")) == 1
    assert len(ApprovalStore(state / "approvals.json").list_pending()) == 1
    assert EvidenceStore(state / "evidence.jsonl").records() == []

    _harness(state)

    assert OperationJournal(state / "operation_journal.json").active() is None
    assert len(_entries(state, "reserve")) == 1
    assert len(ApprovalStore(state / "approvals.json").list_pending()) == 1
    assert len(EvidenceStore(state / "evidence.jsonl").records()) == 1


def test_restart_recognizes_evidence_when_crash_precedes_journal_completion(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)
    original = harness.operation_journal.complete

    def crash_before_complete(operation_id):
        raise SimulatedCrash(operation_id)

    monkeypatch.setattr(harness.operation_journal, "complete", crash_before_complete)
    with pytest.raises(SimulatedCrash):
        harness.run(_request())

    before = EvidenceStore(state / "evidence.jsonl").records()
    assert len(before) == 1
    monkeypatch.setattr(harness.operation_journal, "complete", original)

    _harness(state)

    after = EvidenceStore(state / "evidence.jsonl").records()
    assert after == before
    assert len(_entries(state, "reserve")) == 1


def test_restart_finishes_rejection_after_reservation_was_released(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)
    [held] = harness.run(_request())
    original = harness.budget.ensure_release

    def crash_after_release(*args):
        original(*args)
        raise SimulatedCrash("after release")

    monkeypatch.setattr(harness.budget, "ensure_release", crash_after_release)
    with pytest.raises(SimulatedCrash):
        harness.resume(held.approval_id, False, "alice", "declined")

    rejected = ApprovalStore(state / "approvals.json").get(held.approval_id)
    assert rejected is not None and rejected.status == "rejected"
    assert len(_entries(state, "release")) == 1

    _harness(state)

    records = EvidenceStore(state / "evidence.jsonl").records()
    assert [record["result_status"] for record in records] == [
        "pending_approval",
        "rejected",
    ]
    assert len(_entries(state, "release")) == 1


def test_terminal_approval_with_exact_journal_reservation_is_recovery_required(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)
    [held] = harness.run(_request())

    def crash_before_release(*_args):
        raise SimulatedCrash("before release")

    monkeypatch.setattr(harness.budget, "ensure_release", crash_before_release)
    with pytest.raises(SimulatedCrash):
        harness.resume(held.approval_id, False, "alice", "declined")

    report = StateIntegrityAuditor(state).audit()
    assert report.status == "recovery_required"
    assert report.safe_to_execute
    assert not any(
        issue.code == "terminal_approval_has_reservation" for issue in report.issues
    )


def test_signed_rejection_recovery_revalidates_durable_operator_identity(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    private = tmp_path / "operator-private.pem"
    public = tmp_path / "operator-public.pem"
    generate_key_pair(private, public, PASSPHRASE)
    trusted_keys = [f"alice={public}"]
    harness = build_harness(
        state,
        MockAgentAdapter(script=SCRIPTS["overspend"]),
        starting_budget_usd="500",
        trusted_operator_keys=trusted_keys,
    )
    [held] = harness.run(_request())
    approval = harness.approvals.get(held.approval_id)
    assert approval is not None
    attestation = sign_operator_action(
        approval,
        private,
        PASSPHRASE,
        purpose=DECISION_PURPOSE,
        outcome="rejected",
        operator="alice",
        note="declined",
    )

    def crash_before_evidence(_record):
        raise SimulatedCrash("after signed rejection")

    monkeypatch.setattr(harness.evidence, "append_idempotent", crash_before_evidence)
    with pytest.raises(SimulatedCrash):
        harness.resume(
            held.approval_id,
            False,
            "alice",
            "declined",
            attestation=attestation,
        )

    recovered = build_harness(
        state,
        MockAgentAdapter(script=SCRIPTS["overspend"]),
        starting_budget_usd="500",
        trusted_operator_keys=trusted_keys,
    )
    rejected = recovered.approvals.get(held.approval_id)
    assert rejected is not None and rejected.status == "rejected"
    assert recovered.approvals.decision_identity(rejected).assurance == "signed_trusted"
    assert OperationJournal(state / "operation_journal.json").active() is None
    records = EvidenceStore(state / "evidence.jsonl").records()
    assert [record["result_status"] for record in records] == [
        "pending_approval",
        "rejected",
    ]
    assert len(_entries(state, "release")) == 1


def test_restart_finishes_expiry_without_double_release(tmp_path, monkeypatch):
    state = tmp_path / "state"
    harness = _harness(state)
    [held] = harness.run(_request())
    approval = harness.approvals.get(held.approval_id)
    assert approval is not None
    approval.expires_at = "2020-01-01T00:00:00Z"
    harness.approvals._save(approval)

    def crash_before_evidence(_record):
        raise SimulatedCrash("before evidence")

    monkeypatch.setattr(harness.evidence, "append_idempotent", crash_before_evidence)
    with pytest.raises(SimulatedCrash):
        harness.reconcile_expired_approvals()

    expired = ApprovalStore(state / "approvals.json").get(held.approval_id)
    assert expired is not None and expired.status == "expired"
    assert len(_entries(state, "release")) == 1

    _harness(state)

    records = EvidenceStore(state / "evidence.jsonl").records()
    assert [record["result_status"] for record in records] == [
        "pending_approval",
        "expired",
    ]
    assert len(_entries(state, "release")) == 1


def test_command_core_reports_active_journal_without_exposing_payload(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)
    original = harness.budget.ensure_reservation

    def crash_after_reservation(*args):
        original(*args)
        raise SimulatedCrash("after reservation")

    monkeypatch.setattr(harness.budget, "ensure_reservation", crash_after_reservation)
    with pytest.raises(SimulatedCrash):
        harness.run(_request())
    journal_before = (state / "operation_journal.json").read_bytes()

    snapshot = CommandCore(state).snapshot()
    projected = snapshot["operation_journal"]

    assert projected["active"] is True
    assert projected["kind"] == "approval_create"
    assert "payload" not in projected
    assert "merchant" not in json.dumps(snapshot)
    assert snapshot["state_integrity"]["status"] == "recovery_required"
    assert snapshot["state_integrity"]["safe_to_execute"] is True
    assert (state / "operation_journal.json").read_bytes() == journal_before


def test_tampered_journal_is_critical_and_authority_refuses_recovery(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    path = state / "operation_journal.json"
    path.write_text(
        json.dumps(
            {
                "schema_name": "defiant.operation_journal",
                "schema_version": "0.1.0",
                "active": {
                    "operation_id": "op_tampered",
                    "kind": "approval_create",
                    "prepared_at": "2026-08-21T00:00:00Z",
                    "payload": {"forged": True},
                    "payload_hash": "sha256:" + "0" * 64,
                },
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)

    report = StateIntegrityAuditor(state).audit()
    assert not report.safe_to_execute
    assert any(issue.code == "operation_journal_invalid" for issue in report.issues)
    with pytest.raises(OperationJournalError):
        _harness(state)


def test_structurally_invalid_journal_fails_even_with_matching_payload_hash(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    payload = {"forged": True}
    (state / "operation_journal.json").write_text(
        json.dumps(
            {
                "schema_name": "defiant.operation_journal",
                "schema_version": "0.1.0",
                "active": {
                    "operation_id": "op_forged",
                    "kind": "approval_create",
                    "prepared_at": "2026-08-21T00:00:00Z",
                    "payload": payload,
                    "payload_hash": sha256_of(payload),
                },
            }
        ),
        encoding="utf-8",
    )
    (state / "operation_journal.json").chmod(0o600)

    report = StateIntegrityAuditor(state).audit()
    assert not report.safe_to_execute
    assert any(issue.code == "operation_journal_invalid" for issue in report.issues)
    with pytest.raises(OperationJournalError):
        _harness(state)


def test_conflicting_partial_reservation_fails_closed_and_keeps_journal(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)

    def crash_before_reservation(*_args):
        raise SimulatedCrash("before reservation")

    monkeypatch.setattr(harness.budget, "ensure_reservation", crash_before_reservation)
    with pytest.raises(SimulatedCrash):
        harness.run(_request())

    journal = OperationJournal(state / "operation_journal.json")
    operation = journal.active()
    assert operation is not None
    approval = operation.payload["approval"]
    BudgetLedger(state / "budget.json").reserve(
        "1.00", "conflicting_request", approval["action_id"]
    )

    with pytest.raises(RuntimeError, match="conflicts with journal"):
        _harness(state)

    assert StateIntegrityAuditor(state).audit().status == "unsafe"
    assert journal.active() == operation
    assert EvidenceStore(state / "evidence.jsonl").records() == []


def test_conflicting_approval_binding_fails_closed_and_keeps_journal(
    tmp_path, monkeypatch
):
    state = tmp_path / "state"
    harness = _harness(state)
    original = harness.approvals.ensure_rejected

    def crash_after_rejection(*args, **kwargs):
        original(*args, **kwargs)
        raise SimulatedCrash("after rejection")

    [held] = harness.run(_request())
    monkeypatch.setattr(harness.approvals, "ensure_rejected", crash_after_rejection)
    with pytest.raises(SimulatedCrash):
        harness.resume(held.approval_id, False, "alice", "declined")

    approval = ApprovalStore(state / "approvals.json").get(held.approval_id)
    assert approval is not None
    approval.request_id = "conflicting_request"
    ApprovalStore(state / "approvals.json")._save(approval)
    operation = OperationJournal(state / "operation_journal.json").active()

    with pytest.raises(RuntimeError, match="conflicts with journal bindings"):
        _harness(state)

    assert OperationJournal(state / "operation_journal.json").active() == operation


def test_journal_lock_is_a_critical_state_integrity_issue(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "operation_journal.json.lock").write_text("locked", encoding="utf-8")
    (state / "operation_journal.json.lock").chmod(0o600)

    report = StateIntegrityAuditor(state).audit()

    assert not report.safe_to_execute
    assert any(issue.code == "state_lock_present" for issue in report.issues)


def test_nonapproval_execution_completes_its_local_journal(tmp_path):
    state = tmp_path / "state"
    harness = _harness(state, scenario="read_statement")

    harness.run(_request())

    assert OperationJournal(state / "operation_journal.json").active() is None
    assert (state / "operation_journal.json").exists()
    assert BudgetLedger(state / "budget.json").summary()["reserved_usd"] == "0"
