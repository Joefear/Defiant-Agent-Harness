"""Request exports retain selected evidence, not unrelated decoded history."""

import gc
import json
import weakref
from contextlib import contextmanager

import pytest

import defiant_agent_harness.cli.main as cli_module
import defiant_agent_harness.evidence.store as store_module
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.contracts import sha256_of
from defiant_agent_harness.evidence.signing import EXPORT_SCHEMA, EXPORT_VERSION
from defiant_agent_harness.evidence.store import (
    GENESIS,
    EvidenceStore,
    verify_evidence_records,
)


def _chain(count, size=0):
    previous = GENESIS
    for index in range(count):
        record = {
            "record_id": f"rec_{index}",
            "request_id": "selected" if index % 3 == 0 else "unrelated",
            "previous_record_hash": previous,
            "result_summary": "x" * size + str(index),
            "extra": {"lossless": ["\u001b[31m", "\u2603", None, False, 1.25]},
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


@pytest.mark.parametrize("request_id", ["selected", "absent"])
@pytest.mark.parametrize("broken_first", [False, True])
def test_export_retains_only_selected_history(
    tmp_path, monkeypatch, request_id, broken_first
):
    path = _log(tmp_path / "state", [])
    references, consumed, closed = [], [], []

    class TrackedRecord(dict):
        pass

    def stream(source):
        assert source == path
        try:
            for index, raw in enumerate(_chain(128, size=65536)):
                assert path.with_name("evidence.jsonl.lock").exists()
                assert (
                    sum(
                        ref() is not None
                        for selected, ref in references
                        if not selected
                    )
                    <= 2
                )
                record = TrackedRecord(raw)
                if broken_first and index == 0:
                    record["previous_record_hash"] = "bad"
                references.append(
                    (raw["request_id"] == request_id, weakref.ref(record))
                )
                consumed.append(index)
                yield record
        finally:
            assert path.with_name("evidence.jsonl.lock").exists()
            closed.append(True)

    def forbid(*args, **kwargs):
        pytest.fail("export materialized history or initialized a store")

    monkeypatch.setattr(EvidenceStore, "_read_existing", staticmethod(stream))
    monkeypatch.setattr(EvidenceStore, "read_existing_records", staticmethod(forbid))
    monkeypatch.setattr(EvidenceStore, "__init__", forbid)
    result = EvidenceStore.export_existing_request(path, request_id)
    assert consumed == list(range(128)) and closed == [True]
    expected = [r for r in _chain(128, size=65536) if r["request_id"] == request_id]
    if broken_first and expected:
        expected[0]["previous_record_hash"] = "bad"
    assert result["records"] == expected
    assert result["record_count"] == len(expected)
    assert result["full_chain_record_count"] == (1 if broken_first else 128)
    assert result["chain_status"]["ok"] is not broken_first
    gc.collect()
    assert all((ref() is not None) == selected for selected, ref in references)
    del result
    gc.collect()
    assert all(ref() is None for _, ref in references)
    assert list(path.parent.iterdir()) == [path] and path.read_bytes() == b""


@pytest.mark.parametrize("request_id", ["selected", "unrelated", "absent"])
@pytest.mark.parametrize(
    "damage,index",
    [
        (None, None),
        ("previous", 0),
        ("previous", 2),
        ("previous", 6),
        ("content", 0),
        ("content", 2),
        ("content", 6),
    ],
)
def test_streamed_export_matches_materialized_contract(
    tmp_path, monkeypatch, request_id, damage, index
):
    records = list(_chain(7))
    if damage:
        records[index][
            "previous_record_hash" if damage == "previous" else "record_hash"
        ] = "bad"
    status = verify_evidence_records(records)
    selected = [r for r in records if r["request_id"] == request_id]
    expected = {
        "schema_name": EXPORT_SCHEMA,
        "schema_version": EXPORT_VERSION,
        "request_id": request_id,
        "exported_at": "fixed-test-time",
        "record_count": len(selected),
        "full_chain_record_count": status.count,
        "chain_head_hash": records[-1]["record_hash"] if status.ok else None,
        "chain_status": status.__dict__,
        "records": selected,
    }
    path = _log(tmp_path / "state", records)
    path.write_bytes(b"\n" + path.read_bytes().replace(b"\n", b"\n \n"))
    before = path.read_bytes(), path.stat().st_mtime_ns
    monkeypatch.setattr(store_module, "utc_now", lambda: "fixed-test-time")
    handles = _handles(monkeypatch)
    assert EvidenceStore.export_existing_request(path, request_id) == expected
    assert len(handles) == 1 and handles[0].closed
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.parametrize("sink", ["stdout", "new_file", "existing_file", "signed_file"])
@pytest.mark.parametrize("broken_first", [False, True])
@pytest.mark.parametrize(
    "tail_kind", ["json", "duplicate", "array", "utf8", "oversized"]
)
def test_bad_tail_prevents_export_and_signing(
    tmp_path, monkeypatch, capsys, sink, broken_first, tail_kind
):
    records = list(_chain(3))
    if broken_first:
        records[0]["previous_record_hash"] = "bad"
    ceiling = max(len((json.dumps(r) + "\n").encode()) for r in records)
    tail = {
        "json": b"not-json\n",
        "duplicate": b'{"x":1,"x":2}\n',
        "array": b"[]\n",
        "utf8": b"\xff\n",
        "oversized": b"x" * (ceiling + 1),
    }[tail_kind]
    path = _log(tmp_path / "state", records, tail)
    if tail_kind == "oversized":
        monkeypatch.setattr(store_module, "MAX_EVIDENCE_RECORD_BYTES", ceiling)
    before = path.read_bytes(), path.stat().st_mtime_ns
    handles = _handles(monkeypatch)
    output = tmp_path / "export.json"
    args = ["--workdir", str(path.parent), "export", "selected"]
    if sink != "stdout":
        args += ["--output", str(output)]
    if sink == "existing_file":
        output.write_bytes(b"preserve destination")
    if sink == "signed_file":
        args += [
            "--signing-key",
            str(tmp_path / "missing.pem"),
            "--passphrase-file",
            str(tmp_path / "missing-passphrase"),
            "--signer",
            "operator",
            "--note",
            "handoff",
        ]

    def forbid(*args, **kwargs):
        pytest.fail("malformed evidence reached signing or publication")

    for name in ("sign_export", "read_passphrase", "write_export", "encode_export"):
        monkeypatch.setattr(cli_module, name, forbid)
    assert main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "record 3" in captured.err
    assert len(handles) == 1 and handles[0].closed
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    assert list(path.parent.iterdir()) == [path]
    if sink == "existing_file":
        assert output.read_bytes() == b"preserve destination"
    else:
        assert not output.exists()


@pytest.mark.parametrize("broken_first", [False, True])
def test_late_io_failure_closes_reader_and_releases_lock(
    tmp_path, monkeypatch, capsys, broken_first
):
    records = list(_chain(3))
    if broken_first:
        records[0]["previous_record_hash"] = "bad"
    path = _log(tmp_path / "state", records)
    handles = _handles(monkeypatch)
    original = store_module.iter_bounded_evidence_lines

    def fail_after_first(handle):
        yield next(original(handle))
        raise OSError("late I/O failure")

    monkeypatch.setattr(store_module, "iter_bounded_evidence_lines", fail_after_first)
    assert main(["--workdir", str(path.parent), "export", "selected"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "late I/O failure" in captured.err
    assert len(handles) == 1 and handles[0].closed
    assert list(path.parent.iterdir()) == [path]


def test_unexpected_hash_failure_also_closes_reader_and_releases_lock(
    tmp_path, monkeypatch
):
    path = _log(tmp_path / "state", list(_chain(3)))
    handles = _handles(monkeypatch)

    def fail(body):
        raise RuntimeError("injected hashing failure")

    monkeypatch.setattr(store_module, "sha256_of", fail)
    with pytest.raises(RuntimeError, match="injected hashing failure"):
        EvidenceStore.export_existing_request(path, "selected")
    assert len(handles) == 1 and handles[0].closed
    assert list(path.parent.iterdir()) == [path]
