"""Pretty export encoding bounds accumulation without changing published bytes."""

import json
from decimal import Decimal

import pytest

import defiant_agent_harness.evidence.signing as signing_module
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.contracts import (
    Decision,
    EvidenceRecord,
    ResultStatus,
    canonical_json,
)
from defiant_agent_harness.evidence.signing import (
    EvidenceSigningError,
    encode_export,
    write_export,
)
from defiant_agent_harness.evidence.store import EvidenceStore


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"z": [], "a": {}},
        {"value": '\u2603\U0001f680\ud800\n\r\t\u001b"\\'},
        {"values": [None, True, False, 0, -12, 1.25, -0.0, 1e100]},
        {"records": [{"z": "last", "a": "first"}, {"nested": {"b": [1, 2]}}]},
        {"tuple": ("first", "second")},
        {1: "one", 2: "two"},
        {"payload": "x" * 10000},
        [],
        "root scalar",
    ],
)
@pytest.mark.parametrize("margin", [-1, 0, 1])
def test_exact_pretty_bytes_and_newline_boundary(monkeypatch, document, margin):
    expected = (
        json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    monkeypatch.setattr(
        signing_module, "MAX_EVIDENCE_EXPORT_BYTES", len(expected) + margin
    )
    if margin < 0:
        with pytest.raises(EvidenceSigningError, match="byte ceiling"):
            encode_export(document)
    else:
        assert encode_export(document) == expected


@pytest.mark.parametrize(
    "document",
    [
        {"v": {1}},
        {"v": b"x"},
        {"v": float("nan")},
        {"v": float("inf")},
        {"v": Decimal("1.2")},
        {1: "mixed", "two": "keys"},
    ],
)
def test_invalid_pretty_json_keeps_fixed_diagnostic(document):
    with pytest.raises(
        EvidenceSigningError, match="^evidence export is not valid JSON$"
    ):
        encode_export(document)


def test_circular_json_is_refused_without_partial_destination(tmp_path):
    document = {}
    document["cycle"] = document
    destination = tmp_path / "export.json"
    with pytest.raises(EvidenceSigningError, match="not valid JSON"):
        write_export(destination, document)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("tail", [object(), float("nan")])
def test_pretty_overflow_stops_before_invalid_tail(monkeypatch, tail):
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 32)
    with pytest.raises(EvidenceSigningError, match="fixed 32-byte ceiling") as raised:
        encode_export({"a": "sensitive" * 64, "z": tail})
    assert "sensitive" not in str(raised.value)


@pytest.mark.parametrize("first", [False, True])
def test_overflow_chunk_is_not_encoded_or_followed(monkeypatch, first):
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 8)
    encoded, yielded = [], []

    class Chunk(str):
        def encode(self, *args, **kwargs):
            encoded.append(str(self))
            return super().encode(*args, **kwargs)

    def chunks(self, document):
        if not first:
            yielded.append("prefix")
            yield Chunk("1234")
        yielded.append("overflow")
        yield Chunk("x" * (8 if first else 4))
        pytest.fail("encoder consumed chunks after size refusal")

    monkeypatch.setattr(json.JSONEncoder, "iterencode", chunks)
    with pytest.raises(EvidenceSigningError, match="fixed 8-byte ceiling"):
        encode_export({})
    assert yielded == (["overflow"] if first else ["prefix", "overflow"])
    assert encoded == ([] if first else ["1234"])


def test_real_encoder_stops_traversing_large_sequence_at_ceiling(monkeypatch):
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 256)
    visited = []

    class Items(list):
        def __iter__(self):
            for index in range(10000):
                visited.append(index)
                assert len(visited) < 10, (
                    "oversize encoder traversed the whole sequence"
                )
                yield "x" * 64

    # A nonempty list is needed because the JSON encoder checks truthiness.
    with pytest.raises(EvidenceSigningError, match="fixed 256-byte ceiling"):
        encode_export({"records": Items([None])})
    assert 1 < len(visited) < 10


@pytest.mark.parametrize(
    "document",
    [
        {"v": Decimal("1.2500")},
        {"v": Decision.BLOCK},
        {"v": (1, "\u2603")},
        {"v": -0.0},
    ],
)
def test_compact_canonical_bytes_are_unchanged(monkeypatch, document):
    expected = canonical_json(document).encode("utf-8")
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", len(expected))
    assert encode_export(document, pretty=False) == expected
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", len(expected) - 1)
    with pytest.raises(EvidenceSigningError, match="byte ceiling"):
        encode_export(document, pretty=False)


@pytest.mark.parametrize("existing", [False, True])
def test_oversize_file_has_no_partial_publication(tmp_path, monkeypatch, existing):
    destination = tmp_path / "export.json"
    if existing:
        destination.write_bytes(b"preserve destination")
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 32)
    with pytest.raises(EvidenceSigningError, match="fixed 32-byte ceiling"):
        write_export(destination, {"a": "x" * 1024})
    if existing:
        assert destination.read_bytes() == b"preserve destination"
        assert list(tmp_path.iterdir()) == [destination]
    else:
        assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("output_file", [False, True])
def test_cli_pretty_overflow_prevents_stdout_and_destination(
    tmp_path, monkeypatch, capsys, output_file
):
    root = tmp_path / "state"
    store = EvidenceStore(root / "evidence.jsonl")
    record = store.append(
        EvidenceRecord(
            request_id="req_incremental",
            action_id="act_one",
            tool_name="read_file",
            decision=Decision.BLOCK,
            result_status=ResultStatus.BLOCKED,
        )
    )
    before = store.path.read_bytes(), store.path.stat().st_mtime_ns
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 32)
    destination = tmp_path / "export.json"
    args = ["--workdir", str(root), "export", record.request_id]
    if output_file:
        args += ["--output", str(destination)]
    assert main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "fixed 32-byte ceiling" in captured.err
    assert record.request_id not in captured.err
    assert not destination.exists() and list(root.iterdir()) == [store.path]
    assert (store.path.read_bytes(), store.path.stat().st_mtime_ns) == before
