"""Evidence inspection must not initialize or repair state."""

import json

import pytest

import defiant_agent_harness.evidence.store as store_module
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.contracts import Decision, EvidenceRecord, ResultStatus
from defiant_agent_harness.evidence.store import EvidenceStore


COMMANDS = ["history", "show", "verify"]


def _args(root, command, record_id="rec_absent"):
    return ["--workdir", str(root), command] + (
        [record_id] if command == "show" else []
    )


def _snapshot(root):
    if not root.exists():
        return None
    return {
        str(p.relative_to(root)): (
            p.read_bytes() if p.is_file() else None,
            p.stat().st_mtime_ns,
            p.stat().st_mode,
        )
        for p in [root, *root.rglob("*")]
    }


def _enroll(root):
    return EvidenceStore(root / "evidence.jsonl").append(
        EvidenceRecord(
            request_id="req_inspect",
            action_id="act_inspect",
            tool_name="read_file",
            decision=Decision.BLOCK,
            result_status=ResultStatus.BLOCKED,
        )
    )


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("state", ["missing_root", "missing_log", "deleted_log"])
def test_missing_inspection_never_initializes(tmp_path, capsys, command, state):
    root = tmp_path / "state"
    if state == "missing_log":
        root.mkdir(mode=0o700)
    elif state == "deleted_log":
        _enroll(root)
        (root / "evidence.jsonl").unlink()
    before = _snapshot(root)
    assert main(_args(root, command)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "cannot read evidence store" in captured.err
    assert _snapshot(root) == before


@pytest.mark.parametrize("command", COMMANDS)
def test_existing_empty_log_is_distinct_from_missing(tmp_path, capsys, command):
    root = tmp_path / "state"
    EvidenceStore(root / "evidence.jsonl")
    before = _snapshot(root)
    assert main(_args(root, command)) == (1 if command == "show" else 0)
    captured = capsys.readouterr()
    expected = {
        "verify": "0 records",
        "history": "no evidence yet",
        "show": "no record",
    }
    assert expected[command] in captured.out + captured.err
    assert _snapshot(root) == before


@pytest.mark.parametrize("command", COMMANDS)
def test_inspection_never_constructs_or_locks(tmp_path, capsys, monkeypatch, command):
    root = tmp_path / "state"
    record = _enroll(root)
    (root / "evidence.jsonl.lock").write_bytes(b"pid=99999\n")
    before = _snapshot(root)

    def forbid(*args, **kwargs):
        pytest.fail("inspection reached a state-writing boundary")

    monkeypatch.setattr(EvidenceStore, "__init__", forbid)
    monkeypatch.setattr(store_module, "exclusive_file_lock", forbid)
    monkeypatch.setattr(store_module, "prepare_storage_root", forbid)
    assert main(_args(root, command, record.record_id)) == 0
    assert capsys.readouterr().err == ""
    assert _snapshot(root) == before


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("suffix", [b"not-json\n", b'{"a":1,"a":2}\n', b"[]\n"])
def test_bad_tail_fails_before_output(tmp_path, capsys, command, suffix):
    root = tmp_path / "state"
    record = _enroll(root)
    path = root / "evidence.jsonl"
    path.write_bytes(path.read_bytes() + suffix)
    before = _snapshot(root)
    assert main(_args(root, command, record.record_id)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err
    assert _snapshot(root) == before


@pytest.mark.parametrize("command", COMMANDS)
def test_inspection_keeps_record_limit(tmp_path, capsys, monkeypatch, command):
    root = tmp_path / "state"
    record = _enroll(root)
    before = _snapshot(root)
    monkeypatch.setattr(store_module, "MAX_EVIDENCE_RECORD_BYTES", 16)
    assert main(_args(root, command, record.record_id)) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "exceeds 16 bytes" in captured.err
    assert _snapshot(root) == before


@pytest.mark.parametrize("command", COMMANDS)
def test_inspection_uses_one_capture(tmp_path, capsys, monkeypatch, command):
    root = tmp_path / "state"
    record = _enroll(root)
    reader = EvidenceStore.read_existing_records
    calls = []

    def capture_then_change(path):
        calls.append(path)
        records = reader(path)
        path.write_bytes(b"{}\n")
        return records

    monkeypatch.setattr(
        EvidenceStore, "read_existing_records", staticmethod(capture_then_change)
    )
    assert main(_args(root, command, record.record_id)) == 0
    capsys.readouterr()
    assert calls == [root / "evidence.jsonl"]
    assert (root / "evidence.jsonl").read_bytes() == b"{}\n"


def test_hash_corruption_remains_inspectable(tmp_path, capsys):
    root = tmp_path / "state"
    record = _enroll(root)
    path = root / "evidence.jsonl"
    data = json.loads(path.read_bytes())
    data["result_summary"] = "tampered"
    path.write_text(json.dumps(data) + "\n", encoding="utf-8")
    before = _snapshot(root)
    assert main(_args(root, "verify")) == 1
    assert "CHAIN BROKEN" in capsys.readouterr().out
    assert main(_args(root, "history")) == 0
    assert record.record_id in capsys.readouterr().out
    assert main(_args(root, "show", record.record_id)) == 0
    assert json.loads(capsys.readouterr().out)["result_summary"] == "tampered"
    assert _snapshot(root) == before
