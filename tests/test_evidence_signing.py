from __future__ import annotations

import json

import pytest

from defiant_agent_harness.evidence import signing as signing_module
from defiant_agent_harness.cli.main import main
from defiant_agent_harness.contracts import Decision, EvidenceRecord, ResultStatus
from defiant_agent_harness.evidence.signing import (
    EvidenceSigningError,
    generate_key_pair,
    load_export,
    sign_export,
    verify_export,
    write_export,
)
from defiant_agent_harness.evidence.store import EvidenceStore


PASSPHRASE = b"correct horse battery staple"


def _record(request_id: str = "req_signed") -> EvidenceRecord:
    return EvidenceRecord(
        request_id=request_id,
        action_id="act_signed",
        decision=Decision.ALLOW,
        result_status=ResultStatus.SUCCEEDED,
        tool_name="read_file",
        target="workspace/report.txt",
    )


def _payload(tmp_path) -> dict:
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    record = store.append(_record())
    return store.export_request(record.request_id)


def _keys(tmp_path, stem: str = "signer") -> tuple:
    private_key = tmp_path / f"{stem}.private.pem"
    public_key = tmp_path / f"{stem}.public.pem"
    key_id = generate_key_pair(private_key, public_key, PASSPHRASE)
    return private_key, public_key, key_id


def _signed(tmp_path, stem: str = "signer") -> tuple[dict, object, object, str]:
    private_key, public_key, key_id = _keys(tmp_path, stem)
    document = sign_export(
        _payload(tmp_path / "state"),
        private_key,
        PASSPHRASE,
        signer="operator-7",
        note="quarterly evidence handoff",
        signed_at="2026-08-21T12:00:00Z",
    )
    return document, private_key, public_key, key_id


def test_signed_export_verifies_against_pinned_public_key(tmp_path):
    document, _, public_key, key_id = _signed(tmp_path)

    status = verify_export(document, [public_key])

    assert status.ok is True
    assert status.key_id == key_id
    assert status.signer == "operator-7"
    assert status.note == "quarterly evidence handoff"


def test_payload_tampering_invalidates_attestation(tmp_path):
    document, _, public_key, _ = _signed(tmp_path)
    document["exported_at"] = "2026-08-21T13:00:00Z"

    status = verify_export(document, [public_key])

    assert status.ok is False
    assert "payload hash" in status.detail


def test_signed_document_is_detached_from_mutable_source_payload(tmp_path):
    private_key, public_key, _ = _keys(tmp_path)
    payload = _payload(tmp_path / "state")
    document = sign_export(
        payload,
        private_key,
        PASSPHRASE,
        signer="operator-7",
        note="immutable handoff",
    )

    payload["records"][0]["target"] = "workspace/mutated-after-signing.txt"

    assert verify_export(document, [public_key]).ok is True


def test_attestation_identity_tampering_invalidates_signature(tmp_path):
    document, _, public_key, _ = _signed(tmp_path)
    document["attestation"]["signer"] = "different-operator"

    status = verify_export(document, [public_key])

    assert status.ok is False
    assert "signature is invalid" in status.detail


def test_untrusted_key_is_rejected_and_rotation_set_is_supported(tmp_path):
    document, _, old_public, _ = _signed(tmp_path, "old")
    _, new_public, _ = _keys(tmp_path, "new")

    untrusted = verify_export(document, [new_public])
    rotated = verify_export(document, [new_public, old_public])

    assert untrusted.ok is False
    assert "not trusted" in untrusted.detail
    assert rotated.ok is True


def test_export_verification_rejects_excess_keys_before_filesystem_access(
    tmp_path, monkeypatch
):
    document, _, _public_key, _ = _signed(tmp_path)
    monkeypatch.setattr(signing_module, "MAX_TRUSTED_PUBLIC_KEYS", 1)

    status = verify_export(
        document,
        [tmp_path / "missing-one.pem", tmp_path / "missing-two.pem"],
    )

    assert status.ok is False
    assert status.detail == "trusted public key count exceeds fixed limit of 1"


def test_export_verification_rejects_aggregate_key_bytes(tmp_path, monkeypatch):
    document, _, first_public, _ = _signed(tmp_path, "first")
    _private, second_public, _key_id = _keys(tmp_path, "second")
    maximum = first_public.stat().st_size + second_public.stat().st_size - 1
    monkeypatch.setattr(
        signing_module,
        "MAX_TRUSTED_PUBLIC_KEY_SET_BYTES",
        maximum,
    )

    status = verify_export(document, [first_public, second_public])

    assert status.ok is False
    assert status.detail == (
        f"trusted public key set exceeds fixed {maximum}-byte ceiling"
    )


def test_export_verification_rejects_oversized_public_key(tmp_path, monkeypatch):
    document, _, public_key, _ = _signed(tmp_path)
    maximum = public_key.stat().st_size - 1
    monkeypatch.setattr(
        signing_module,
        "MAX_TRUSTED_PUBLIC_KEY_BYTES",
        maximum,
    )

    status = verify_export(document, [public_key])

    assert status.ok is False
    assert f"fixed {maximum}-byte ceiling" in status.detail


def test_wrong_private_key_passphrase_is_rejected(tmp_path):
    private_key, _, _ = _keys(tmp_path)

    with pytest.raises(EvidenceSigningError, match="cannot load encrypted"):
        sign_export(
            _payload(tmp_path / "state"),
            private_key,
            b"wrong passphrase",
            signer="operator-7",
            note="authorized export",
        )


def test_signing_requires_operator_identity_and_note(tmp_path):
    private_key, _, _ = _keys(tmp_path)
    payload = _payload(tmp_path / "state")

    with pytest.raises(EvidenceSigningError, match="signer"):
        sign_export(payload, private_key, PASSPHRASE, signer="", note="reason")
    with pytest.raises(EvidenceSigningError, match="note"):
        sign_export(payload, private_key, PASSPHRASE, signer="operator", note=" ")
    with pytest.raises(EvidenceSigningError, match="signed_at"):
        sign_export(
            payload,
            private_key,
            PASSPHRASE,
            signer="operator",
            note="reason",
            signed_at="not-a-time",
        )
    with pytest.raises(EvidenceSigningError, match="signer exceeds"):
        sign_export(
            payload,
            private_key,
            PASSPHRASE,
            signer="x" * 257,
            note="reason",
        )


def test_key_generation_and_export_writes_refuse_overwrite(tmp_path):
    private_key, public_key, _ = _keys(tmp_path)
    with pytest.raises(EvidenceSigningError, match="overwrite"):
        generate_key_pair(private_key, public_key, PASSPHRASE)

    document = sign_export(
        _payload(tmp_path / "state"),
        private_key,
        PASSPHRASE,
        signer="operator-7",
        note="authorized export",
    )
    destination = tmp_path / "signed-export.json"
    write_export(destination, document)
    with pytest.raises(EvidenceSigningError, match="overwrite"):
        write_export(destination, document)


def test_duplicate_json_keys_are_rejected_before_verification(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_name":"one","schema_name":"two"}', encoding="utf-8")

    with pytest.raises(EvidenceSigningError, match="duplicate JSON key"):
        load_export(path)


def test_export_load_is_bounded_before_json_parsing(tmp_path, monkeypatch):
    path = tmp_path / "oversized.json"
    path.write_bytes(b"SENSITIVE-CONTENT-SENSITIVE-CONTENT")
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 32)

    def unexpected_parse(*_args, **_kwargs):
        pytest.fail("oversized export reached the JSON parser")

    monkeypatch.setattr(signing_module, "loads_strict_json", unexpected_parse)

    with pytest.raises(EvidenceSigningError, match="fixed 32-byte ceiling") as error:
        load_export(path)

    assert "SENSITIVE-CONTENT" not in str(error.value)


def test_export_load_accepts_exact_byte_ceiling(tmp_path, monkeypatch):
    path = tmp_path / "bounded.json"
    content = b"{}" + (b" " * 30)
    path.write_bytes(content)
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", len(content))

    assert load_export(path) == {}


def test_export_serialization_refuses_oversize_without_partial_file(
    tmp_path, monkeypatch
):
    destination = tmp_path / "oversized.json"
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 32)

    with pytest.raises(EvidenceSigningError, match="fixed 32-byte ceiling"):
        write_export(destination, {"content": "sensitive-export-content"})

    assert not destination.exists()
    assert list(tmp_path.glob(".*.tmp")) == []


def test_direct_sign_and_verify_entry_points_enforce_export_ceiling(
    tmp_path, monkeypatch
):
    document, private_key, public_key, _ = _signed(tmp_path)
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 32)

    with pytest.raises(EvidenceSigningError, match="fixed 32-byte ceiling"):
        sign_export(
            _payload(tmp_path / "other-state"),
            private_key,
            PASSPHRASE,
            signer="operator-7",
            note="bounded handoff",
        )

    status = verify_export(document, [public_key])
    assert status.ok is False
    assert status.detail == "evidence export exceeds fixed 32-byte ceiling"


def test_cli_export_refuses_oversized_stdout_without_partial_document(
    tmp_path, monkeypatch, capsys
):
    state = tmp_path / "state"
    record = EvidenceStore(state / "evidence.jsonl").append(_record())
    monkeypatch.setattr(signing_module, "MAX_EVIDENCE_EXPORT_BYTES", 32)

    exit_code = main(["--workdir", str(state), "export", record.request_id])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "fixed 32-byte ceiling" in captured.err
    assert record.request_id not in captured.err


def test_broken_chain_cannot_be_signed(tmp_path):
    state = tmp_path / "state"
    store = EvidenceStore(state / "evidence.jsonl")
    record = store.append(_record())
    private_key, _, _ = _keys(tmp_path)
    store.path.write_text(
        store.path.read_text().replace(
            '"tool_name":"read_file"', '"tool_name":"altered"'
        )
    )

    with pytest.raises(EvidenceSigningError, match="untrusted evidence chain"):
        sign_export(
            store.export_request(record.request_id),
            private_key,
            PASSPHRASE,
            signer="operator-7",
            note="must not sign broken state",
        )


def test_signing_rejects_cross_request_record_injection(tmp_path):
    private_key, _, _ = _keys(tmp_path)
    payload = _payload(tmp_path / "state")
    payload["records"][0]["request_id"] = "req_other"

    with pytest.raises(EvidenceSigningError, match="does not belong"):
        sign_export(
            payload,
            private_key,
            PASSPHRASE,
            signer="operator-7",
            note="invalid mixed export",
        )


def test_signing_rejects_record_body_that_does_not_match_record_hash(tmp_path):
    private_key, _, _ = _keys(tmp_path)
    payload = _payload(tmp_path / "state")
    payload["records"][0]["target"] = "workspace/tampered-before-signing.txt"

    with pytest.raises(EvidenceSigningError, match="does not match its record hash"):
        sign_export(
            payload,
            private_key,
            PASSPHRASE,
            signer="operator-7",
            note="must not sign inconsistent records",
        )


def test_verifier_rejects_invalid_timestamp_and_non_finite_json(tmp_path):
    document, _, public_key, _ = _signed(tmp_path)
    document["attestation"]["signed_at"] = "yesterday"
    assert verify_export(document, [public_key]).ok is False

    path = tmp_path / "nan.json"
    path.write_text('{"value":NaN}', encoding="utf-8")
    with pytest.raises(EvidenceSigningError, match="non-finite"):
        load_export(path)


def test_cli_keygen_signed_export_and_offline_verification(tmp_path, capsys):
    state = tmp_path / "state"
    store = EvidenceStore(state / "evidence.jsonl")
    record = store.append(_record())
    passphrase = tmp_path / "passphrase.txt"
    passphrase.write_bytes(PASSPHRASE + b"\n")
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    export_path = tmp_path / "export.json"

    assert (
        main(
            [
                "signing-keygen",
                "--private-key",
                str(private_key),
                "--public-key",
                str(public_key),
                "--passphrase-file",
                str(passphrase),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert (
        main(
            [
                "--workdir",
                str(state),
                "export",
                record.request_id,
                "--signing-key",
                str(private_key),
                "--passphrase-file",
                str(passphrase),
                "--signer",
                "operator-7",
                "--note",
                "release evidence",
                "--output",
                str(export_path),
            ]
        )
        == 0
    )
    capsys.readouterr()

    assert (
        main(
            [
                "verify-export",
                str(export_path),
                "--trusted-key",
                str(public_key),
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is True
    assert result["signer"] == "operator-7"


def test_cli_refuses_private_key_or_passphrase_inside_state(tmp_path, capsys):
    state = tmp_path / "state"
    state.mkdir()
    passphrase = state / "passphrase.txt"
    passphrase.write_bytes(PASSPHRASE)

    exit_code = main(
        [
            "--workdir",
            str(state),
            "signing-keygen",
            "--private-key",
            str(state / "private.pem"),
            "--public-key",
            str(tmp_path / "public.pem"),
            "--passphrase-file",
            str(passphrase),
        ]
    )

    assert exit_code == 1
    assert "outside the workdir" in capsys.readouterr().err
