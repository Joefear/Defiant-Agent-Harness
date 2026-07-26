from __future__ import annotations

import json

from defiant_agent_harness.contracts import Decision, EvidenceRecord, ResultStatus
import pytest

from defiant_agent_harness.evidence.store import (
    GENESIS,
    EvidenceError,
    EvidenceStore,
)


def rec(i: int) -> EvidenceRecord:
    return EvidenceRecord(
        request_id=f"req_{i}",
        action_id=f"act_{i}",
        decision=Decision.ALLOW,
        result_status=ResultStatus.SUCCEEDED,
        tool_name="read_file",
        target=f"workspace/{i}.txt",
    )


def test_first_record_chains_to_genesis(tmp_path):
    s = EvidenceStore(tmp_path / "e.jsonl")
    r = s.append(rec(0))
    assert r.previous_record_hash == GENESIS
    assert r.record_hash.startswith("sha256:")


def test_chain_verifies(tmp_path):
    s = EvidenceStore(tmp_path / "e.jsonl")
    for i in range(10):
        s.append(rec(i))
    status = s.verify()
    assert status.ok
    assert status.count == 10


def test_altering_a_record_breaks_the_chain(tmp_path):
    p = tmp_path / "e.jsonl"
    s = EvidenceStore(p)
    for i in range(5):
        s.append(rec(i))

    lines = p.read_text().splitlines()
    tampered = json.loads(lines[2])
    tampered["result_summary"] = "nothing to see here"
    lines[2] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n")

    status = s.verify()
    assert not status.ok
    assert status.broken_at == 2
    assert "altered in place" in status.detail


def test_deleting_a_record_breaks_the_chain(tmp_path):
    p = tmp_path / "e.jsonl"
    s = EvidenceStore(p)
    for i in range(5):
        s.append(rec(i))

    lines = p.read_text().splitlines()
    del lines[2]
    p.write_text("\n".join(lines) + "\n")

    status = s.verify()
    assert not status.ok
    assert status.broken_at == 2
    assert "altered or removed" in status.detail


def test_reordering_records_breaks_the_chain(tmp_path):
    p = tmp_path / "e.jsonl"
    s = EvidenceStore(p)
    for i in range(5):
        s.append(rec(i))
    lines = p.read_text().splitlines()
    lines[1], lines[3] = lines[3], lines[1]
    p.write_text("\n".join(lines) + "\n")
    assert not s.verify().ok


def test_export_pack_carries_chain_status(tmp_path):
    s = EvidenceStore(tmp_path / "e.jsonl")
    r = s.append(rec(1))
    pack = s.export_request(r.request_id)
    assert pack["record_count"] == 1
    assert pack["chain_status"]["ok"] is True


def test_append_is_durable_across_instances(tmp_path):
    p = tmp_path / "e.jsonl"
    EvidenceStore(p).append(rec(1))
    reopened = EvidenceStore(p)
    reopened.append(rec(2))
    assert reopened.verify().ok
    assert len(reopened.records()) == 2


def test_append_refuses_to_extend_a_corrupted_chain(tmp_path):
    path = tmp_path / "e.jsonl"
    store = EvidenceStore(path)
    store.append(rec(1))
    path.write_text(
        path.read_text().replace('"tool_name":"read_file"', '"tool_name":"tampered"')
    )

    with pytest.raises(EvidenceError, match="refusing to append to broken"):
        store.append(rec(2))
    assert len(path.read_text().splitlines()) == 1


def test_invalid_json_is_reported_and_cannot_be_extended(tmp_path):
    path = tmp_path / "e.jsonl"
    store = EvidenceStore(path)
    path.write_text('{"incomplete":\n')
    status = store.verify()
    assert not status.ok
    assert "not valid JSON" in status.detail
    with pytest.raises(EvidenceError):
        store.append(rec(1))
