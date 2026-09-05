"""Show and verify stream without hiding malformed tails or retaining history."""

import gc
import json
import weakref
from contextlib import contextmanager

import pytest

import defiant_agent_harness.evidence.store as store_module
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.contracts import sha256_of
from defiant_agent_harness.evidence.store import (
    GENESIS,
    EvidenceError,
    EvidenceStore,
    verify_evidence_records,
)


def _chain(count, size=0):
    previous = GENESIS
    for index in range(count):
        record = {
            "record_id": f"rec_{index}",
            "request_id": "req_stream",
            "previous_record_hash": previous,
            "result_summary": "x" * size + str(index),
        }
        record["record_hash"] = sha256_of(record)
        yield record
        previous = record["record_hash"]


def _log(root, records, tail=b""):
    path = EvidenceStore(root / "evidence.jsonl").path
    path.write_bytes(b"".join((json.dumps(r) + "\n").encode() for r in records) + tail)
    return path


def _handles(monkeypatch):
    handles = []
    original = store_module.open_state_file

    @contextmanager
    def observe(*args, **kwargs):
        with original(*args, **kwargs) as handle:
            handles.append(handle)
            yield handle

    monkeypatch.setattr(store_module, "open_state_file", observe)
    return handles


@pytest.mark.parametrize(
    "case",
    ["show_first", "show_last", "show_missing", "verify_intact", "verify_broken"],
)
def test_streaming_does_not_retain_decoded_history(tmp_path, capsys, monkeypatch, case):
    references, consumed, closed = [], [], []

    class TrackedRecord(dict):
        pass

    def records(path):
        try:
            for index, raw in enumerate(_chain(128, size=65536)):
                assert sum(reference() is not None for reference in references) <= 3
                record = TrackedRecord(raw)
                if case == "verify_broken" and index == 0:
                    record["previous_record_hash"] = "bad"
                references.append(weakref.ref(record))
                consumed.append(index)
                yield record
        finally:
            closed.append(True)

    def forbid(*args, **kwargs):
        pytest.fail("inspection reached a materializing or initializing boundary")

    monkeypatch.setattr(EvidenceStore, "_read_existing", staticmethod(records))
    monkeypatch.setattr(EvidenceStore, "read_existing_records", staticmethod(forbid))
    monkeypatch.setattr(EvidenceStore, "__init__", forbid)
    root = tmp_path / "absent"
    command = "show" if case.startswith("show") else "verify"
    args = ["--workdir", str(root), command]
    if command == "show":
        args += [
            {"show_first": "rec_0", "show_last": "rec_127", "show_missing": "absent"}[
                case
            ]
        ]
    assert main(args) == (1 if case in ("show_missing", "verify_broken") else 0)
    captured = capsys.readouterr()
    if case == "show_missing":
        assert captured.out == "" and "no record absent" in captured.err
    elif command == "show":
        result = json.loads(captured.out)
        assert result["record_id"] == args[-1]
        assert result["result_summary"] == "x" * 65536 + args[-1][4:]
        assert captured.err == ""
    else:
        assert (
            "CHAIN BROKEN" if case == "verify_broken" else "128 records"
        ) in captured.out
        assert captured.err == ""
    assert consumed == list(range(128)) and closed == [True]
    gc.collect()
    assert all(reference() is None for reference in references)
    assert not root.exists()


@pytest.mark.parametrize("command", ["show", "verify"])
@pytest.mark.parametrize("broken_first", [False, True])
@pytest.mark.parametrize(
    "tail_kind", ["json", "duplicate", "array", "utf8", "oversized"]
)
def test_bad_tail_takes_precedence_over_match_or_hash_failure(
    tmp_path, capsys, monkeypatch, command, broken_first, tail_kind
):
    records = list(_chain(3))
    if broken_first:
        records[0]["previous_record_hash"] = "bad"
    ceiling = max(len((json.dumps(r) + "\n").encode()) for r in records)
    tails = {
        "json": b"not-json\n",
        "duplicate": b'{"x":1,"x":2}\n',
        "array": b"[]\n",
        "utf8": b"\xff\n",
        "oversized": b"x" * (ceiling + 1),
    }
    path = _log(tmp_path / "state", records, tails[tail_kind])
    if tail_kind == "oversized":
        monkeypatch.setattr(store_module, "MAX_EVIDENCE_RECORD_BYTES", ceiling)
    handles = _handles(monkeypatch)
    before = path.read_bytes(), path.stat().st_mtime_ns
    args = ["--workdir", str(path.parent), command]
    if command == "show":
        args.append("rec_0")
    assert main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "record 3" in captured.err
    assert len(handles) == 1 and handles[0].closed
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.parametrize(
    "damage,index",
    [
        (None, None),
        ("previous", 0),
        ("previous", 2),
        ("previous", 4),
        ("content", 0),
        ("content", 2),
        ("content", 4),
    ],
)
def test_complete_verification_preserves_first_failure_status(damage, index):
    records = list(_chain(5))
    if damage == "previous":
        records[index]["previous_record_hash"] = "bad"
    elif damage == "content":
        records[index]["result_summary"] = "changed"
    expected = verify_evidence_records(records)
    consumed = []

    def stream():
        for position, record in enumerate(records):
            consumed.append(position)
            yield record

    assert verify_evidence_records(stream(), require_complete_read=True) == expected
    assert consumed == list(range(5))
    consumed.clear()
    assert verify_evidence_records(stream()) == expected
    assert consumed == list(range(5 if index is None else index + 1))


@pytest.mark.parametrize("complete", [False, True])
@pytest.mark.parametrize("broken_first", [False, True])
def test_complete_mode_raises_read_errors_without_changing_default(
    complete, broken_first
):
    records = list(_chain(2))
    if broken_first:
        records[0]["previous_record_hash"] = "bad"
    error = EvidenceError("late failure")
    consumed = []

    def stream():
        for index, record in enumerate(records):
            consumed.append(index)
            yield record
        raise error

    if complete:
        with pytest.raises(EvidenceError) as raised:
            verify_evidence_records(stream(), require_complete_read=True)
        assert raised.value is error and consumed == [0, 1]
    else:
        status = verify_evidence_records(stream())
        assert not status.ok
        assert consumed == ([0] if broken_first else [0, 1])
        if not broken_first:
            assert status.count == 2 and status.broken_at == 2
            assert status.detail == "late failure"


@pytest.mark.parametrize("damage", ["previous", "content"])
def test_complete_mode_drains_without_hashing_after_first_failure(monkeypatch, damage):
    records = list(_chain(5))
    records[0]["previous_record_hash" if damage == "previous" else "record_hash"] = (
        "bad"
    )
    calls = []

    def hash_once(body):
        calls.append(body["record_id"])
        assert calls == ["rec_0"]
        return sha256_of(body)

    monkeypatch.setattr(store_module, "sha256_of", hash_once)
    status = verify_evidence_records(iter(records), require_complete_read=True)
    assert not status.ok and status.count == 1 and status.broken_at == 0
    assert calls == ([] if damage == "previous" else ["rec_0"])


@pytest.mark.parametrize("command", ["show", "verify"])
def test_late_io_failure_closes_reader_and_prints_no_partial_result(
    tmp_path, capsys, monkeypatch, command
):
    records = list(_chain(2))
    records[0]["previous_record_hash"] = "bad"
    path = _log(tmp_path / "state", records)
    handles = _handles(monkeypatch)
    original = store_module.iter_bounded_evidence_lines

    def fail_after_first(handle):
        yield next(original(handle))
        raise OSError("late I/O failure")

    monkeypatch.setattr(store_module, "iter_bounded_evidence_lines", fail_after_first)
    args = ["--workdir", str(path.parent), command] + (
        ["rec_0"] if command == "show" else []
    )
    assert main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "late I/O failure" in captured.err
    assert len(handles) == 1 and handles[0].closed


def test_show_keeps_first_duplicate_match_losslessly(tmp_path, capsys):
    records = list(_chain(3))
    records[-1]["record_id"] = records[0]["record_id"]
    path = _log(tmp_path / "state", records)
    assert main(["--workdir", str(path.parent), "show", "rec_0"]) == 0
    assert json.loads(capsys.readouterr().out) == records[0]
