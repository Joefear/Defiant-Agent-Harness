"""History retains bounded rendered rows, consumes the tail, and closes reads."""

import gc
import json
import weakref
from collections import deque
from contextlib import contextmanager

import pytest

import defiant_agent_harness.cli.main as cli_module
import defiant_agent_harness.evidence.store as store_module
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.evidence.store import EvidenceError, EvidenceStore


def _record(index):
    return {
        "timestamp": "2026-09-05T12:00:00Z",
        "tool_name": "read_file",
        "decision": "block",
        "result_status": "blocked",
        "record_id": f"rec_{index}",
        "request_id": "even" if index % 2 == 0 else "odd",
    }


def _log(root, tail=b""):
    path = EvidenceStore(root / "evidence.jsonl").path
    path.write_bytes(
        b"".join((json.dumps(_record(i)) + "\n").encode() for i in range(4)) + tail
    )
    return path


def _observe_handles(monkeypatch):
    handles = []
    original = store_module.open_state_file

    @contextmanager
    def observe(*args, **kwargs):
        with original(*args, **kwargs) as handle:
            handles.append(handle)
            yield handle

    monkeypatch.setattr(store_module, "open_state_file", observe)
    return handles


@pytest.mark.parametrize("limit", [None, 0, 1, 25, 10**40])
@pytest.mark.parametrize("request_filter", [None, "even"])
def test_history_retains_only_bounded_rows(
    tmp_path, capsys, monkeypatch, limit, request_filter
):
    references, buffers, consumed, closed = [], [], [], []
    effective_limit = 25 if limit is None else limit

    class TrackedRecord(dict):
        pass

    class Rows(deque):
        def __init__(self):
            super().__init__()
            buffers.append(self)

        def append(self, value):
            assert type(value) is str and len(value) <= 200
            super().append(value)
            assert len(self) <= effective_limit + 1

    def records(path):
        try:
            for index in range(128):
                assert sum(reference() is not None for reference in references) <= 2
                record = TrackedRecord(_record(index))
                record["unused_payload"] = "x" * 65536
                references.append(weakref.ref(record))
                consumed.append(index)
                yield record
        finally:
            closed.append(True)

    def forbid(*args, **kwargs):
        pytest.fail("history reached a materializing or initializing boundary")

    monkeypatch.setattr(EvidenceStore, "_read_existing", staticmethod(records))
    monkeypatch.setattr(EvidenceStore, "read_existing_records", staticmethod(forbid))
    monkeypatch.setattr(EvidenceStore, "__init__", forbid)
    monkeypatch.setattr(cli_module, "deque", Rows)
    root = tmp_path / "absent"
    args = ["--workdir", str(root), "history"]
    if limit is not None:
        args += ["--limit", str(limit)]
    if request_filter:
        args += ["--request", request_filter]
    assert main(args) == 0
    captured = capsys.readouterr()
    assert captured.err == "" and consumed == list(range(128)) and closed == [True]
    selected = [i for i in range(128) if request_filter is None or i % 2 == 0]
    expected = selected[-effective_limit:] if effective_limit else []
    if expected:
        actual = [line.split()[-1] for line in captured.out.splitlines()[3:-1]]
        assert actual == [f"rec_{i}" for i in expected]
    else:
        assert captured.out == "no evidence selected.\n"
    assert len(buffers) == 1 and len(buffers[0]) == len(expected)
    gc.collect()
    assert all(reference() is None for reference in references)
    assert not root.exists()


@pytest.mark.parametrize("limit", [0, 1, 25])
@pytest.mark.parametrize("request_filter", [None, "absent"])
@pytest.mark.parametrize("tail", [b"not-json\n", b'{"a":1,"a":2}\n', b"[]\n"])
def test_bad_tail_discards_buffer_and_closes_descriptor(
    tmp_path, capsys, monkeypatch, limit, request_filter, tail
):
    path = _log(tmp_path / "state", tail)
    before = path.read_bytes(), path.stat().st_mtime_ns
    handles = _observe_handles(monkeypatch)
    args = ["--workdir", str(path.parent), "history", "--limit", str(limit)]
    if request_filter:
        args += ["--request", request_filter]
    assert main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err
    assert len(handles) == 1 and handles[0].closed
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.parametrize(
    "field",
    ["timestamp", "tool_name", "decision", "result_status", "record_id", "request_id"],
)
def test_projection_failure_closes_descriptor(tmp_path, capsys, monkeypatch, field):
    bad = _record(9)
    bad[field] = None
    path = _log(tmp_path / "state", (json.dumps(bad) + "\n").encode())
    handles = _observe_handles(monkeypatch)
    assert main(["--workdir", str(path.parent), "history", "--limit", "1"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and f"history field: {field}" in captured.err
    assert len(handles) == 1 and handles[0].closed


@pytest.mark.parametrize("mode", ["complete", "early_exit", "consumer_error"])
def test_stream_context_closes_without_exhaustion(tmp_path, monkeypatch, mode):
    path = _log(tmp_path / "state")
    handles = _observe_handles(monkeypatch)
    raised = False
    try:
        with EvidenceStore.stream_existing_records(path) as records:
            assert next(records) == _record(0)
            assert len(handles) == 1 and not handles[0].closed
            if mode == "complete":
                assert list(records) == [_record(i) for i in range(1, 4)]
            elif mode == "consumer_error":
                raise RuntimeError("consumer stopped")
    except RuntimeError as exc:
        raised = True
        assert mode == "consumer_error" and str(exc) == "consumer stopped"
    assert raised == (mode == "consumer_error")
    assert len(handles) == 1 and handles[0].closed


@pytest.mark.parametrize("options", [[], ["--limit", "0"], ["--request", "absent"]])
def test_late_read_error_never_prints_buffer(tmp_path, capsys, monkeypatch, options):
    closed = []

    def records(path):
        try:
            yield _record(0)
            yield _record(1)
            raise EvidenceError("late read failed")
        finally:
            closed.append(True)

    monkeypatch.setattr(EvidenceStore, "_read_existing", staticmethod(records))
    assert main(["--workdir", str(tmp_path / "absent"), "history", *options]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "late read failed" in captured.err
    assert closed == [True]


@pytest.mark.parametrize("options", [["--limit", "0"], ["--request", "absent"]])
def test_unselected_records_are_validated_without_rendering(
    tmp_path, capsys, monkeypatch, options
):
    path = _log(tmp_path / "state")

    def forbid(*args, **kwargs):
        pytest.fail("unselected records reached rendering")

    monkeypatch.setattr(cli_module, "_terminal_text", forbid)
    assert main(["--workdir", str(path.parent), "history", *options]) == 0
    assert capsys.readouterr().out in ("no evidence yet.\n", "no evidence selected.\n")
