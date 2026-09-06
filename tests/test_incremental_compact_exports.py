"""Compact export buffering preserves canonical bytes and signing boundaries."""

import hashlib
import json
from decimal import Decimal
from enum import Enum, IntEnum

import pytest

import defiant_agent_harness.contracts as contracts_module
import defiant_agent_harness.evidence.signing as signing_module
from defiant_agent_harness.contracts import (
    Decision,
    EvidenceRecord,
    ResultStatus,
    canonical_json,
    iter_canonical_json,
)
from defiant_agent_harness.evidence.signing import (
    EvidenceSigningError,
    encode_export,
    generate_key_pair,
    sign_export,
    verify_export,
)
from defiant_agent_harness.evidence.store import EvidenceStore


class Number(IntEnum):
    ONE = 1


class Collection(Enum):
    VALUES = ["x", 2]


@pytest.mark.parametrize(
    "document",
    [
        {},
        [],
        "root scalar",
        None,
        {"text": '\u2603\U0001f680\ud800\n\t\u001b"\\'},
        {"values": [None, True, False, -12, -0.0, 1.25, 1e100]},
        {"nested": ({"amount": Decimal("0.1000")}, [Decision.BLOCK])},
        {"amount": Decimal("0.2500")},
        {"decision": Decision.ALLOW},
        {"number": Number.ONE, "collection": Collection.VALUES},
        {2: "two", 1: "one"},
        {"z": [], "a": {"last": "z", "first": "a"}},
        {"large": "x" * 10000},
    ],
)
@pytest.mark.parametrize("margin", [-1, 0, 1])
def test_compact_bytes_match_canonical_at_exact_ceiling(monkeypatch, document, margin):
    expected = canonical_json(document).encode("utf-8")
    chunks = list(iter_canonical_json(document))
    assert all(chunk.isascii() for chunk in chunks)
    assert "".join(chunks).encode("utf-8") == expected
    monkeypatch.setattr(
        signing_module, "MAX_EVIDENCE_EXPORT_BYTES", len(expected) + margin
    )
    if margin < 0:
        with pytest.raises(EvidenceSigningError, match="byte ceiling"):
            encode_export(document, pretty=False)
    else:
        assert encode_export(document, pretty=False) == expected


@pytest.mark.parametrize(
    "document",
    [
        {"bad": object()},
        {"bad": b"bytes"},
        {"bad": {1}},
        {"bad": float("nan")},
        {"bad": float("inf")},
        {"bad": Decimal("-0.2500")},
        {1: "one", "two": 2},
    ],
)
def test_invalid_compact_input_keeps_fixed_diagnostic(document):
    with pytest.raises(
        EvidenceSigningError, match="^evidence export is not valid JSON$"
    ):
        encode_export(document, pretty=False)


@pytest.mark.parametrize("tail", [object(), float("nan")])
def test_compact_overflow_precedes_later_encoding_error(monkeypatch, tail):
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 32)
    with pytest.raises(EvidenceSigningError, match="fixed 32-byte ceiling") as raised:
        encode_export({"a": "sensitive" * 64, "z": tail}, pretty=False)
    assert "sensitive" not in str(raised.value)


@pytest.mark.parametrize(
    "value", [Decimal("NaN"), Decimal("-0.25"), Decimal("Infinity")]
)
def test_full_normalization_errors_still_precede_encoding_overflow(monkeypatch, value):
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 32)
    with pytest.raises(EvidenceSigningError, match="not valid JSON"):
        encode_export({"a": "x" * 1024, "z": value}, pretty=False)


def test_normalization_still_finishes_before_first_chunk():
    visited = []

    class Values(list):
        def __iter__(self):
            for i in range(20):
                visited.append(i)
                yield Decimal("1.2500")

    chunks = iter_canonical_json({"values": Values([None])})
    assert visited == list(range(20))
    assert json.loads("".join(chunks)) == {"values": ["1.25"] * 20}


def test_compact_path_does_not_join_full_text_before_limit(monkeypatch):
    document = {"records": ["x" * 64 for _ in range(10000)]}
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 256)
    original = signing_module.iter_canonical_json
    consumed = []

    def observe(value):
        for chunk in original(value):
            consumed.append(len(chunk))
            assert len(consumed) < 20, "compact encoder traversed full encoded output"
            yield chunk

    def forbid(*args, **kwargs):
        pytest.fail("compact export used joined canonical text")

    monkeypatch.setattr(signing_module, "iter_canonical_json", observe)
    monkeypatch.setattr(signing_module, "canonical_json", forbid)
    monkeypatch.setattr(contracts_module.json, "dumps", forbid)
    with pytest.raises(EvidenceSigningError, match="fixed 256-byte ceiling"):
        encode_export(document, pretty=False)
    assert 1 < len(consumed) < 20


@pytest.mark.parametrize("first", [False, True])
def test_compact_overflow_chunk_is_not_copied_or_followed(monkeypatch, first):
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 8)
    encoded = []

    class Chunk(str):
        def encode(self, *args, **kwargs):
            encoded.append(str(self))
            return super().encode(*args, **kwargs)

    def chunks(document):
        if not first:
            yield Chunk("1234")
        yield Chunk("x" * (9 if first else 5))
        pytest.fail("compact encoder consumed after overflow")

    monkeypatch.setattr(signing_module, "iter_canonical_json", chunks)
    with pytest.raises(EvidenceSigningError, match="fixed 8-byte ceiling"):
        encode_export({}, pretty=False)
    assert encoded == ([] if first else ["1234"])


@pytest.mark.parametrize("operation", ["sign", "verify"])
def test_compact_overflow_stops_before_validation_and_keys(
    tmp_path, monkeypatch, operation
):
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 32)
    document = {"records": ["x" * 1024]}

    def forbid(*args, **kwargs):
        pytest.fail("oversized compact export reached validation, hashing, or keys")

    for name in (
        "_validate_export_payload",
        "_payload_hash",
        "_load_private_key",
        "_load_trusted_keys",
    ):
        monkeypatch.setattr(signing_module, name, forbid)
    if operation == "sign":
        with pytest.raises(EvidenceSigningError, match="fixed 32-byte ceiling"):
            sign_export(
                document,
                tmp_path / "absent.pem",
                b"passphrase",
                signer="operator",
                note="handoff",
            )
    else:
        result = verify_export(document, [tmp_path / "absent.pem"])
        assert (
            not result.ok
            and result.detail == "evidence export exceeds fixed 32-byte ceiling"
        )
    assert list(tmp_path.iterdir()) == []


def test_general_canonical_hashing_does_not_use_new_stream(monkeypatch):
    document = {"money": Decimal("1.2500"), "decision": Decision.BLOCK}
    expected = canonical_json(document)

    def forbid(*args, **kwargs):
        pytest.fail("general canonical hashing was rerouted")

    monkeypatch.setattr(contracts_module, "iter_canonical_json", forbid)
    assert canonical_json(document) == expected
    assert (
        contracts_module.sha256_of(document)
        == "sha256:" + hashlib.sha256(expected.encode()).hexdigest()
    )


def test_signature_and_payload_match_legacy_encoding(tmp_path, monkeypatch):
    store = EvidenceStore(tmp_path / "state" / "evidence.jsonl")
    record = store.append(
        EvidenceRecord(
            request_id="req_parity",
            action_id="act_parity",
            tool_name="read_file",
            decision=Decision.BLOCK,
            result_status=ResultStatus.BLOCKED,
        )
    )
    payload = store.export_request(record.request_id)
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    password = b"disposable test passphrase"
    generate_key_pair(private, public, password)
    options = {
        "signer": "operator",
        "note": "exact parity",
        "signed_at": "2026-09-05T12:00:00Z",
    }
    streamed = sign_export(payload, private, password, **options)
    assert verify_export(streamed, [public]).ok

    def legacy(document, *, pretty=True):
        text = (
            json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
            if pretty
            else canonical_json(document)
        )
        return text.encode("utf-8")

    monkeypatch.setattr(signing_module, "encode_export", legacy)
    monkeypatch.setattr(
        signing_module,
        "_check_export_size",
        lambda document, *, pretty=True: legacy(document, pretty=pretty),
    )
    assert sign_export(payload, private, password, **options) == streamed
    assert verify_export(streamed, [public]).ok
