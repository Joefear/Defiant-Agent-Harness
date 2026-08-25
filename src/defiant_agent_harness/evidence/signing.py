"""Offline-verifiable Ed25519 attestations for evidence exports."""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..contracts import canonical_json, sha256_of, utc_now
from ..limits import (
    MAX_EVIDENCE_EXPORT_BYTES,
    MAX_TRUSTED_PUBLIC_KEYS,
    MAX_TRUSTED_PUBLIC_KEY_BYTES,
    MAX_TRUSTED_PUBLIC_KEY_SET_BYTES,
)
from ..strict_json import StrictJsonError, loads_strict_json

EXPORT_SCHEMA = "defiant.evidence.export"
EXPORT_VERSION = "0.2.0"
ATTESTATION_SCHEMA = "defiant.evidence.attestation"
ATTESTATION_VERSION = "0.1.0"
ALGORITHM = "Ed25519"
_DOMAIN = b"Defiant Agent Harness evidence export attestation v0.1.0\x00"
_MAX_KEY_BYTES = 64 * 1024
_MAX_PASSPHRASE_BYTES = 4096
_MAX_SIGNER_CHARS = 256
_MAX_NOTE_CHARS = 4096
_ATTESTATION_FIELDS = {
    "schema_name",
    "schema_version",
    "algorithm",
    "key_id",
    "signed_at",
    "signer",
    "note",
    "payload_hash",
    "signature",
}


class EvidenceSigningError(RuntimeError):
    """An evidence export could not be signed or verified safely."""


@dataclass(frozen=True)
class AttestationStatus:
    ok: bool
    detail: str
    key_id: str = ""
    signer: str = ""
    note: str = ""
    signed_at: str = ""
    payload_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def read_passphrase(path: str | Path) -> bytes:
    source = Path(path)
    try:
        with source.open("rb") as fh:
            value = fh.read(_MAX_PASSPHRASE_BYTES + 1)
    except (OSError, UnicodeError) as exc:
        raise EvidenceSigningError(
            f"cannot read passphrase file {source}: {exc}"
        ) from exc
    if len(value) > _MAX_PASSPHRASE_BYTES:
        raise EvidenceSigningError("passphrase file is too large")
    value = value.rstrip(b"\r\n")
    if not value:
        raise EvidenceSigningError("passphrase file must contain a non-empty value")
    return value


def generate_key_pair(
    private_path: str | Path,
    public_path: str | Path,
    passphrase: bytes,
) -> str:
    """Generate a new encrypted private key and its out-of-band trust key."""

    private_destination = Path(private_path)
    public_destination = Path(public_path)
    if not passphrase:
        raise EvidenceSigningError("private-key passphrase must be non-empty")
    if private_destination.resolve() == public_destination.resolve():
        raise EvidenceSigningError("private and public key paths must differ")
    for destination in (private_destination, public_destination):
        if destination.exists():
            raise EvidenceSigningError(
                f"refusing to overwrite existing key: {destination}"
            )

    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase),
    )
    public_key = key.public_key()
    public_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_created = False
    try:
        _write_new(private_destination, private_bytes, 0o600)
        private_created = True
        _write_new(public_destination, public_bytes, 0o644)
    except Exception:
        if private_created:
            try:
                private_destination.unlink()
            except OSError:
                pass
        raise
    return public_key_id(public_key)


def sign_export(
    payload: dict[str, Any],
    private_key_path: str | Path,
    passphrase: bytes,
    *,
    signer: str,
    note: str,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """Return a signed copy of a trustworthy evidence export payload."""

    encode_export(payload, pretty=False)
    _validate_export_payload(payload)
    if "attestation" in payload:
        raise EvidenceSigningError("refusing to sign an already attested export")
    signer = _bounded_text(signer, "signer", _MAX_SIGNER_CHARS)
    note = _bounded_text(note, "note", _MAX_NOTE_CHARS)
    key = _load_private_key(private_key_path, passphrase)
    key_id = public_key_id(key.public_key())
    payload_hash = _payload_hash(payload)
    statement = {
        "schema_name": ATTESTATION_SCHEMA,
        "schema_version": ATTESTATION_VERSION,
        "algorithm": ALGORITHM,
        "key_id": key_id,
        "signed_at": _timestamp(signed_at or utc_now(), "signed_at"),
        "signer": signer,
        "note": note,
        "payload_hash": payload_hash,
    }
    signature = key.sign(_statement_bytes(statement))
    document = json.loads(canonical_json(payload))
    document["attestation"] = {
        **statement,
        "signature": "base64:" + base64.b64encode(signature).decode("ascii"),
    }
    encode_export(document)
    return document


def verify_export(
    document: dict[str, Any],
    trusted_public_keys: Iterable[str | Path],
) -> AttestationStatus:
    """Verify payload integrity and signature against explicitly trusted keys."""

    try:
        if not isinstance(document, dict):
            raise EvidenceSigningError("signed export root must be an object")
        encode_export(document, pretty=False)
        attestation = document.get("attestation")
        if not isinstance(attestation, dict):
            raise EvidenceSigningError("signed export is missing its attestation")
        if set(attestation) != _ATTESTATION_FIELDS:
            raise EvidenceSigningError("attestation fields do not match the schema")

        payload = {
            key: value for key, value in document.items() if key != "attestation"
        }
        _validate_export_payload(payload)
        _validate_attestation(attestation)
        expected_hash = _payload_hash(payload)
        if not hmac.compare_digest(expected_hash, attestation["payload_hash"]):
            raise EvidenceSigningError("export payload hash does not match attestation")

        trusted = _load_trusted_keys(trusted_public_keys)
        key = trusted.get(attestation["key_id"])
        if key is None:
            raise EvidenceSigningError(
                f"attestation key is not trusted: {attestation['key_id']}"
            )
        signature = _decode_signature(attestation["signature"])
        statement = {
            key: value for key, value in attestation.items() if key != "signature"
        }
        try:
            key.verify(signature, _statement_bytes(statement))
        except InvalidSignature as exc:
            raise EvidenceSigningError("attestation signature is invalid") from exc
        return AttestationStatus(
            True,
            "signature valid and key trusted",
            key_id=attestation["key_id"],
            signer=attestation["signer"],
            note=attestation["note"],
            signed_at=attestation["signed_at"],
            payload_hash=attestation["payload_hash"],
        )
    except (EvidenceSigningError, TypeError, ValueError, OverflowError) as exc:
        return AttestationStatus(False, str(exc))


def load_export(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        content = _read_limited(
            source,
            MAX_EVIDENCE_EXPORT_BYTES,
            "evidence export",
            disclose_path=False,
        )
        value = loads_strict_json(content, label="evidence export")
    except OSError as exc:
        raise EvidenceSigningError(f"cannot read valid export {source}: {exc}") from exc
    except StrictJsonError as exc:
        raise EvidenceSigningError(str(exc)) from exc
    if not isinstance(value, dict):
        raise EvidenceSigningError("signed export root must be an object")
    return value


def write_export(path: str | Path, document: dict[str, Any]) -> None:
    destination = Path(path)
    _write_new(destination, encode_export(document), 0o600)


def encode_export(document: dict[str, Any], *, pretty: bool = True) -> bytes:
    """Serialize one export and refuse output beyond the fixed byte ceiling."""

    try:
        text = (
            json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
            if pretty
            else canonical_json(document)
        )
        encoded = text.encode("utf-8")
    except (TypeError, UnicodeError, ValueError, OverflowError) as exc:
        raise EvidenceSigningError("evidence export is not valid JSON") from exc
    if len(encoded) > MAX_EVIDENCE_EXPORT_BYTES:
        raise EvidenceSigningError(
            f"evidence export exceeds fixed {MAX_EVIDENCE_EXPORT_BYTES}-byte ceiling"
        )
    return encoded


def public_key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sha256_of({"algorithm": ALGORITHM, "public_key": raw.hex()})


def _load_private_key(path: str | Path, passphrase: bytes) -> Ed25519PrivateKey:
    source = Path(path)
    if not passphrase:
        raise EvidenceSigningError("private-key passphrase must be non-empty")
    try:
        key = serialization.load_pem_private_key(
            _read_limited(source, _MAX_KEY_BYTES, "private key"), password=passphrase
        )
    except (OSError, TypeError, ValueError) as exc:
        raise EvidenceSigningError(
            f"cannot load encrypted Ed25519 private key {source}"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise EvidenceSigningError("signing key must be an Ed25519 private key")
    return key


def _public_key_from_bytes(value: bytes, source: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(value)
    except (TypeError, ValueError) as exc:
        raise EvidenceSigningError(f"cannot load public key {source}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise EvidenceSigningError(f"trusted key must be Ed25519: {source}")
    return key


def _load_trusted_keys(paths: Iterable[str | Path]) -> dict[str, Ed25519PublicKey]:
    bounded_paths = _bounded_trusted_key_paths(paths)
    trusted: dict[str, Ed25519PublicKey] = {}
    total_key_bytes = 0
    for path in bounded_paths:
        source = Path(path)
        key_bytes = _read_limited(
            source,
            MAX_TRUSTED_PUBLIC_KEY_BYTES,
            "public key",
        )
        total_key_bytes += len(key_bytes)
        if total_key_bytes > MAX_TRUSTED_PUBLIC_KEY_SET_BYTES:
            raise EvidenceSigningError(
                "trusted public key set exceeds fixed "
                f"{MAX_TRUSTED_PUBLIC_KEY_SET_BYTES}-byte ceiling"
            )
        key = _public_key_from_bytes(key_bytes, source)
        trusted[public_key_id(key)] = key
    if not trusted:
        raise EvidenceSigningError("at least one trusted public key is required")
    return trusted


def _bounded_trusted_key_paths(
    paths: Iterable[str | Path],
) -> tuple[str | Path, ...]:
    bounded: list[str | Path] = []
    for path in paths:
        if len(bounded) >= MAX_TRUSTED_PUBLIC_KEYS:
            raise EvidenceSigningError(
                f"trusted public key count exceeds fixed limit of "
                f"{MAX_TRUSTED_PUBLIC_KEYS}"
            )
        bounded.append(path)
    return tuple(bounded)


def _validate_export_payload(payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        raise EvidenceSigningError("evidence export payload must be an object")
    if payload.get("schema_name") != EXPORT_SCHEMA:
        raise EvidenceSigningError("unsupported evidence export schema")
    if payload.get("schema_version") != EXPORT_VERSION:
        raise EvidenceSigningError("unsupported evidence export version")
    _required_text(payload.get("request_id"), "request_id")
    _timestamp(payload.get("exported_at"), "exported_at")
    records = payload.get("records")
    if not isinstance(records, list):
        raise EvidenceSigningError("evidence export records must be an array")
    record_count = payload.get("record_count")
    if type(record_count) is not int or record_count != len(records):
        raise EvidenceSigningError("evidence export record_count is inconsistent")
    if record_count == 0:
        raise EvidenceSigningError("refusing to sign an empty evidence export")
    chain_status = payload.get("chain_status")
    if not isinstance(chain_status, dict) or chain_status.get("ok") is not True:
        raise EvidenceSigningError(
            "refusing an export from an untrusted evidence chain"
        )
    full_count = payload.get("full_chain_record_count")
    if type(full_count) is not int or full_count < record_count:
        raise EvidenceSigningError("full-chain record count is inconsistent")
    if (
        type(chain_status.get("count")) is not int
        or chain_status.get("count") != full_count
        or chain_status.get("broken_at") is not None
    ):
        raise EvidenceSigningError("chain status does not match the exported chain")
    head = payload.get("chain_head_hash")
    if not isinstance(head, str) or not _is_sha256(head):
        raise EvidenceSigningError("chain head hash is invalid")
    record_ids: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise EvidenceSigningError(f"export record {index} must be an object")
        if record.get("request_id") != payload["request_id"]:
            raise EvidenceSigningError(
                f"export record {index} does not belong to the exported request"
            )
        if not _is_sha256(record.get("record_hash")):
            raise EvidenceSigningError(f"export record {index} has invalid record hash")
        record_id = _required_text(record.get("record_id"), f"record {index} id")
        if record_id in record_ids:
            raise EvidenceSigningError(f"duplicate export record id: {record_id}")
        record_ids.add(record_id)
        try:
            recomputed = sha256_of(
                {key: value for key, value in record.items() if key != "record_hash"}
            )
        except (TypeError, ValueError, OverflowError) as exc:
            raise EvidenceSigningError(
                f"export record {index} is not canonical JSON"
            ) from exc
        if not hmac.compare_digest(recomputed, record["record_hash"]):
            raise EvidenceSigningError(
                f"export record {index} content does not match its record hash"
            )


def _validate_attestation(attestation: dict[str, Any]) -> None:
    if attestation.get("schema_name") != ATTESTATION_SCHEMA:
        raise EvidenceSigningError("unsupported attestation schema")
    if attestation.get("schema_version") != ATTESTATION_VERSION:
        raise EvidenceSigningError("unsupported attestation version")
    if attestation.get("algorithm") != ALGORITHM:
        raise EvidenceSigningError("unsupported attestation algorithm")
    for field in ("key_id", "payload_hash", "signature"):
        _required_text(attestation.get(field), field)
    _bounded_text(attestation.get("signer"), "signer", _MAX_SIGNER_CHARS)
    _bounded_text(attestation.get("note"), "note", _MAX_NOTE_CHARS)
    _timestamp(attestation.get("signed_at"), "signed_at")
    if not _is_sha256(attestation["key_id"]):
        raise EvidenceSigningError("attestation key id is invalid")
    if not _is_sha256(attestation["payload_hash"]):
        raise EvidenceSigningError("attestation payload hash is invalid")


def _statement_bytes(statement: dict[str, Any]) -> bytes:
    return _DOMAIN + canonical_json(statement).encode("utf-8")


def _payload_hash(payload: dict[str, Any]) -> str:
    try:
        return sha256_of(payload)
    except (TypeError, ValueError, OverflowError) as exc:
        raise EvidenceSigningError("evidence export is not canonical JSON") from exc


def _decode_signature(value: str) -> bytes:
    if not value.startswith("base64:"):
        raise EvidenceSigningError("attestation signature encoding is invalid")
    try:
        signature = base64.b64decode(value[7:].encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise EvidenceSigningError("attestation signature encoding is invalid") from exc
    if len(signature) != 64:
        raise EvidenceSigningError("Ed25519 signature must be 64 bytes")
    return signature


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceSigningError(f"{field} must be non-empty text")
    return value


def _bounded_text(value: Any, field: str, maximum: int) -> str:
    text = _required_text(value, field)
    if len(text) > maximum:
        raise EvidenceSigningError(f"{field} exceeds {maximum} characters")
    return text


def _timestamp(value: Any, field: str) -> str:
    text = _required_text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceSigningError(f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceSigningError(f"{field} must include a timezone")
    return text


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value[7:]
    return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)


def _read_limited(
    path: Path,
    maximum: int,
    label: str,
    *,
    disclose_path: bool = True,
) -> bytes:
    try:
        with path.open("rb") as fh:
            content = fh.read(maximum + 1)
    except OSError as exc:
        suffix = f" {path}" if disclose_path else ""
        raise EvidenceSigningError(f"cannot read {label}{suffix}") from exc
    if len(content) > maximum:
        suffix = f": {path}" if disclose_path else ""
        raise EvidenceSigningError(
            f"{label} exceeds fixed {maximum}-byte ceiling{suffix}"
        )
    return content


def _write_new(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        fd = os.open(temporary, flags, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.link(temporary, path)
    except FileExistsError as exc:
        raise EvidenceSigningError(
            f"refusing to overwrite existing file: {path}"
        ) from exc
    except OSError as exc:
        raise EvidenceSigningError(f"cannot write {path}: {exc}") from exc
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass
