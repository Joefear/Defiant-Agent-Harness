"""Witness observations must never initialize or reread an evidence store."""

import json

import pytest

import defiant_agent_harness.evidence_witness as witness_module
from defiant_agent_harness.adapters.mock import MockAgentAdapter
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.contracts import Decision, EvidenceRecord, ResultStatus
from defiant_agent_harness.evidence.signing import generate_key_pair
from defiant_agent_harness.evidence.store import EvidenceError, EvidenceStore
from defiant_agent_harness.evidence_witness import (
    EvidenceWitnessError,
    create_current_witness,
)
from defiant_agent_harness.orchestrator.harness import build_harness


def _files(root):
    return {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}


def _fixture(tmp_path, *, empty=False):
    state = tmp_path / "state"
    harness = build_harness(state, MockAgentAdapter())
    if not empty:
        harness.evidence.append(
            EvidenceRecord(
                request_id="req_capture",
                action_id="act_capture",
                decision=Decision.BLOCK,
                result_status=ResultStatus.BLOCKED,
            )
        )
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    password = b"witness-capture-test"
    generate_key_pair(private, public, password)
    witness = tmp_path / "witness.json"
    create_current_witness(
        state, private, password, signer="operator", note="retain", output_path=witness
    )
    args = [
        "--workdir",
        str(state),
        "verify-evidence-head-witness",
        str(witness),
        "--trusted-key",
        str(public),
    ]
    return state, private, password, args


@pytest.mark.parametrize("existing_root", [False, True])
def test_read_existing_records_never_creates_missing_state(tmp_path, existing_root):
    root = tmp_path / "missing"
    if existing_root:
        root.mkdir(mode=0o700)
    with pytest.raises(EvidenceError, match="cannot read evidence store"):
        EvidenceStore.read_existing_records(root / "evidence.jsonl")
    assert root.exists() is existing_root
    if existing_root:
        assert list(root.iterdir()) == []


@pytest.mark.parametrize("empty", [False, True])
def test_cli_missing_evidence_is_failure_without_initialization(
    tmp_path, capsys, empty
):
    state, _private, _password, args = _fixture(tmp_path, empty=empty)
    (state / "evidence.jsonl").unlink()
    before = _files(state)

    assert main(args) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert "cannot read evidence store" in result["detail"]
    assert _files(state) == before


def test_issuance_does_not_recreate_log_deleted_after_precheck(tmp_path, monkeypatch):
    state, private, password, _args = _fixture(tmp_path, empty=True)
    evidence = state / "evidence.jsonl"
    inspect = witness_module.inspect_state_file

    def disappear_after_inspection(path):
        observed = inspect(path)
        if path == evidence:
            evidence.unlink()
        return observed

    before = _files(state)
    del before["evidence.jsonl"]
    monkeypatch.setattr(
        witness_module, "inspect_state_file", disappear_after_inspection
    )
    output = tmp_path / "refused.json"
    with pytest.raises(EvidenceWitnessError, match="cannot verify durable evidence"):
        create_current_witness(
            state,
            private,
            password,
            signer="operator",
            note="retry",
            output_path=output,
        )
    assert not output.exists()
    assert _files(state) == before


def test_cli_verifies_one_capture_even_if_file_changes_after_read(
    tmp_path, capsys, monkeypatch
):
    state, _private, _password, args = _fixture(tmp_path)
    read = EvidenceStore.read_existing_records
    calls = []

    def capture_then_change(path):
        calls.append(path)
        records = read(path)
        path.write_bytes(b"{}\n")
        return records

    monkeypatch.setattr(
        EvidenceStore, "read_existing_records", staticmethod(capture_then_change)
    )
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert calls == [state / "evidence.jsonl"]
    assert (state / "evidence.jsonl").read_bytes() == b"{}\n"


def test_cli_refuses_invalid_capture_before_witness_assessment(tmp_path, capsys):
    state, _private, _password, args = _fixture(tmp_path)
    path = state / "evidence.jsonl"
    records = EvidenceStore.read_existing_records(path)
    records[-1]["result_summary"] = "changed without resealing"
    path.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8"
    )
    before = _files(state)

    assert main(args) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert "broken evidence chain" in result["detail"]
    assert _files(state) == before


def test_cli_malformed_evidence_is_structured_failure_without_writes(tmp_path, capsys):
    state, _private, _password, args = _fixture(tmp_path)
    (state / "evidence.jsonl").write_bytes(b'{"duplicate":1,"duplicate":2}\n')
    before = _files(state)

    assert main(args) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert "duplicate JSON key" in result["detail"]
    assert _files(state) == before
