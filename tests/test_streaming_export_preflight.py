"""Size-only export checks and payload hashes avoid complete output buffers."""

import gc
import hashlib
import json
import weakref
from decimal import Decimal

import pytest

import defiant_agent_harness.evidence.signing as signing_module
from defiant_agent_harness.contracts import (
    Decision,
    EvidenceRecord,
    ResultStatus,
    canonical_json,
    sha256_of,
)
from defiant_agent_harness.evidence.signing import (
    EvidenceSigningError,
    encode_export,
    generate_key_pair,
    sign_export,
    verify_export,
)
from defiant_agent_harness.evidence.store import EvidenceStore


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"text": "\u2603\U0001f680\ud800\n"},
        {"values": [None, False, -0.0, 1.25]},
        {"records": [{"z": [1, 2], "a": "first"}] * 8},
    ],
)
@pytest.mark.parametrize("pretty", [False, True])
@pytest.mark.parametrize("margin", [-1, 0, 1])
def test_size_only_check_matches_exact_serialized_boundary(
    monkeypatch, document, pretty, margin
):
    text = (
        json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if pretty
        else canonical_json(document)
    )
    expected = text.encode("utf-8")
    monkeypatch.setattr(
        signing_module, "MAX_EVIDENCE_EXPORT_BYTES", len(expected) + margin
    )
    if margin < 0:
        with pytest.raises(EvidenceSigningError, match="byte ceiling"):
            signing_module._check_export_size(document, pretty=pretty)
        with pytest.raises(EvidenceSigningError, match="byte ceiling"):
            encode_export(document, pretty=pretty)
    else:
        assert signing_module._check_export_size(document, pretty=pretty) is None
        assert encode_export(document, pretty=pretty) == expected


@pytest.mark.parametrize("pretty", [False, True])
def test_size_check_retains_no_chunk_history_or_byte_copies(monkeypatch, pretty):
    references, consumed = [], []

    class Chunk(str):
        def encode(self, *args, **kwargs):
            pytest.fail("size-only check copied a UTF-8 chunk")

    def chunks(*args, **kwargs):
        for i in range(128):
            assert sum(ref() is not None for ref in references) <= 2
            chunk = Chunk("x" * 65536 + str(i))
            references.append(weakref.ref(chunk))
            consumed.append(i)
            yield chunk

    def forbid(*args, **kwargs):
        pytest.fail("size-only check reached output allocation")

    monkeypatch.setattr(signing_module, "bytearray", forbid, raising=False)
    monkeypatch.setattr(signing_module, "encode_export", forbid)
    if pretty:
        monkeypatch.setattr(json.JSONEncoder, "iterencode", chunks)
    else:
        monkeypatch.setattr(signing_module, "iter_canonical_json", chunks)
    signing_module._check_export_size({}, pretty=pretty)
    assert consumed == list(range(128))
    gc.collect()
    assert all(ref() is None for ref in references)


@pytest.mark.parametrize("pretty", [False, True])
@pytest.mark.parametrize("tail", [object(), float("nan")])
def test_size_only_overflow_keeps_early_refusal(monkeypatch, pretty, tail):
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 32)
    with pytest.raises(EvidenceSigningError, match="fixed 32-byte ceiling"):
        signing_module._check_export_size({"a": "x" * 1024, "z": tail}, pretty=pretty)


@pytest.mark.parametrize("pretty", [False, True])
@pytest.mark.parametrize("value", [object(), float("nan"), b"unsupported"])
def test_size_only_invalid_json_keeps_fixed_error(pretty, value):
    with pytest.raises(
        EvidenceSigningError, match="^evidence export is not valid JSON$"
    ):
        signing_module._check_export_size({"value": value}, pretty=pretty)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"amount": Decimal("1.2500"), "decision": Decision.BLOCK},
        {"unicode": "\u2603\ud800", "values": (None, False, -0.0)},
        {"records": ["x" * 256 for _ in range(128)]},
    ],
)
def test_streamed_payload_hash_matches_legacy_without_joined_text(monkeypatch, payload):
    expected_text = canonical_json(payload).encode("utf-8")
    expected = sha256_of(payload)
    factory = hashlib.sha256
    updates = []

    class Digest:
        def __init__(self):
            self.inner = factory()

        def update(self, chunk):
            updates.append(len(chunk))
            self.inner.update(chunk)

        def hexdigest(self):
            return self.inner.hexdigest()

    def forbid(*args, **kwargs):
        pytest.fail("payload hashing built complete canonical output")

    monkeypatch.setattr(signing_module, "sha256_of", forbid)
    monkeypatch.setattr(signing_module, "canonical_json", forbid)
    monkeypatch.setattr(signing_module, "encode_export", forbid)
    monkeypatch.setattr(hashlib, "sha256", Digest)
    assert signing_module._payload_hash(payload) == expected
    assert sum(updates) == len(expected_text)
    if "records" in payload:
        assert len(updates) > 128 and max(updates) < len(expected_text)


@pytest.mark.parametrize("margin", [-1, 0, 1])
def test_payload_hash_enforces_its_own_exact_byte_limit(monkeypatch, margin):
    payload = {"text": "\u2603" * 20}
    expected = sha256_of(payload)
    size = len(canonical_json(payload).encode())
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", size + margin)
    if margin < 0:
        with pytest.raises(EvidenceSigningError, match="byte ceiling"):
            signing_module._payload_hash(payload)
    else:
        assert signing_module._payload_hash(payload) == expected


@pytest.mark.parametrize(
    "value", [object(), float("nan"), Decimal("-1"), Decimal("NaN")]
)
def test_payload_hash_keeps_canonical_error(value):
    with pytest.raises(
        EvidenceSigningError, match="^evidence export is not canonical JSON$"
    ):
        signing_module._payload_hash({"value": value})


def _signed_fixture(tmp_path):
    store = EvidenceStore(tmp_path / "state" / "evidence.jsonl")
    record = store.append(
        EvidenceRecord(
            request_id="req_stream",
            action_id="act_stream",
            tool_name="read_file",
            decision=Decision.BLOCK,
            result_status=ResultStatus.BLOCKED,
        )
    )
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    password = b"disposable fixture passphrase"
    generate_key_pair(private, public, password)
    return store.export_request(record.request_id), private, public, password


def test_sign_and_verify_do_not_call_output_encoder(tmp_path, monkeypatch):
    payload, private, public, password = _signed_fixture(tmp_path)

    def forbid(*args, **kwargs):
        pytest.fail("signing or verification allocated serialized output just for size")

    monkeypatch.setattr(signing_module, "encode_export", forbid)
    signed = sign_export(payload, private, password, signer="operator", note="handoff")
    assert verify_export(signed, [public]).ok


def test_signatures_match_legacy_preflight_and_hashing(tmp_path, monkeypatch):
    payload, private, public, password = _signed_fixture(tmp_path)
    options = {
        "signer": "operator",
        "note": "exact parity",
        "signed_at": "2026-09-05T12:00:00Z",
    }
    streamed = sign_export(payload, private, password, **options)
    assert verify_export(streamed, [public]).ok

    def legacy_check(document, *, pretty=True):
        encoded = (
            (json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n")
            if pretty
            else canonical_json(document)
        ).encode()
        assert len(encoded) <= signing_module.MAX_EVIDENCE_EXPORT_BYTES

    monkeypatch.setattr(signing_module, "_check_export_size", legacy_check)
    monkeypatch.setattr(signing_module, "_payload_hash", sha256_of)
    assert sign_export(payload, private, password, **options) == streamed
    assert verify_export(streamed, [public]).ok


def test_late_hash_error_cannot_return_partial_digest_or_sign(tmp_path, monkeypatch):
    payload, private, _public, password = _signed_fixture(tmp_path)
    original = signing_module._bounded_export_chunks

    def broken(document, *, pretty):
        yield "{"
        raise ValueError("injected late encoding failure")

    # Let both normal preflight and schema validation finish; fail only hashing.
    original_hash = signing_module._payload_hash

    def fail_hash(document):
        monkeypatch.setattr(signing_module, "_bounded_export_chunks", broken)
        try:
            return original_hash(document)
        finally:
            monkeypatch.setattr(signing_module, "_bounded_export_chunks", original)

    def forbid(*args, **kwargs):
        pytest.fail("failed payload hash reached signature construction")

    monkeypatch.setattr(signing_module, "_payload_hash", fail_hash)
    monkeypatch.setattr(signing_module, "_statement_bytes", forbid)
    with pytest.raises(EvidenceSigningError, match="not canonical JSON"):
        sign_export(payload, private, password, signer="operator", note="handoff")
