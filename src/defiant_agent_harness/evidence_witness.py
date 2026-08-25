"""Operator-signed, externally retained witnesses for the evidence-chain head."""

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

from .authority_profile import AuthorityProfileState
from .contracts import canonical_json, sha256_of, utc_now
from .evidence.store import EvidenceStore
from .evidence.signing import public_key_id
from .evidence_head import (
    EvidenceHeadStateStore,
    GENESIS_HEAD,
    assess_evidence_head,
)
from .limits import (
    MAX_TRUSTED_PUBLIC_KEYS,
    MAX_TRUSTED_PUBLIC_KEY_BYTES,
    MAX_TRUSTED_PUBLIC_KEY_SET_BYTES,
)
from .persistence import (
    PersistenceError,
    atomic_write_json,
    exclusive_file_lock,
    inspect_state_file,
    inspect_storage_root,
    read_json,
)
from .state_storage import StateStorageStateStore
from .strict_json import StrictJsonError, loads_strict_json

WITNESS_SCHEMA = "defiant.evidence.head_witness"
WITNESS_VERSION = "0.1.0"
ATTESTATION_SCHEMA = "defiant.evidence.head_witness.attestation"
ATTESTATION_VERSION = "0.1.0"
POLICY_SCHEMA = "defiant.evidence.head_witness_policy"
POLICY_VERSION = "0.2.0"
WITNESS_MODE = "signed_external_required"
WITNESS_NOT_CONFIGURED = "not_configured"
ALGORITHM = "Ed25519"

_DOMAIN = b"Defiant Agent Harness evidence head witness v0.1.0\x00"
_WITNESS_FIELDS = {
    "schema_name",
    "schema_version",
    "deployment_root_hash",
    "authority_generation",
    "authority_profile_hash",
    "record_count",
    "head_hash",
    "observed_at",
    "attestation",
}
_PAYLOAD_FIELDS = _WITNESS_FIELDS - {"attestation"}
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
_POLICY_FIELDS_V1 = {
    "schema_name",
    "schema_version",
    "profile_hash",
    "mode",
    "trusted_key_ids",
    "recorded_at",
}
_POLICY_FIELDS = _POLICY_FIELDS_V1 | {"max_unwitnessed_records"}
_MAX_DOCUMENT_BYTES = 256 * 1024
_MAX_KEY_BYTES = 64 * 1024
_MAX_SIGNER_CHARS = 256
_MAX_NOTE_CHARS = 4096


class EvidenceWitnessError(RuntimeError):
    """An external evidence-head witness could not be trusted."""


@dataclass(frozen=True)
class EvidenceWitnessPolicy:
    trusted_key_ids: tuple[str, ...]
    trusted_key_paths: tuple[Path, ...]
    max_unwitnessed_records: int | None = None

    @classmethod
    def from_paths(
        cls,
        paths: Iterable[str | Path],
        *,
        max_unwitnessed_records: int | None = None,
    ) -> "EvidenceWitnessPolicy":
        max_unwitnessed_records = _optional_non_negative_int(
            max_unwitnessed_records,
            "max_unwitnessed_records",
        )
        key_paths = tuple(
            Path(path).resolve() for path in _bounded_trusted_key_paths(paths)
        )
        if not key_paths:
            raise EvidenceWitnessError("at least one trusted witness key is required")
        keys = _load_trusted_public_keys(key_paths)
        key_ids = tuple(sorted({public_key_id(key) for key in keys}))
        if len(key_ids) != len(key_paths):
            raise EvidenceWitnessError("trusted witness keys must be unique")
        return cls(key_ids, key_paths, max_unwitnessed_records)

    def authority_dict(self) -> dict[str, Any]:
        result = {
            "mode": WITNESS_MODE,
            "schema_version": WITNESS_VERSION,
            "trusted_key_ids": list(self.trusted_key_ids),
        }
        if self.max_unwitnessed_records is not None:
            result["max_unwitnessed_records"] = self.max_unwitnessed_records
        return result


@dataclass(frozen=True)
class EvidenceWitnessPolicyState:
    profile_hash: str
    mode: str
    trusted_key_ids: tuple[str, ...]
    max_unwitnessed_records: int | None
    recorded_at: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EvidenceWitnessPolicyState":
        if not isinstance(raw, dict):
            raise EvidenceWitnessError(
                "evidence witness policy fields do not match schema"
            )
        if raw.get("schema_name") != POLICY_SCHEMA:
            raise EvidenceWitnessError("unsupported evidence witness policy schema")
        version = raw.get("schema_version")
        if version not in {"0.1.0", POLICY_VERSION}:
            raise EvidenceWitnessError("unsupported evidence witness policy version")
        expected_fields = _POLICY_FIELDS_V1 if version == "0.1.0" else _POLICY_FIELDS
        if set(raw) != expected_fields:
            raise EvidenceWitnessError(
                "evidence witness policy fields do not match schema"
            )
        profile_hash = _hash(raw.get("profile_hash"), "profile_hash")
        mode = raw.get("mode")
        if mode not in {WITNESS_MODE, WITNESS_NOT_CONFIGURED}:
            raise EvidenceWitnessError("unsupported evidence witness policy mode")
        values = raw.get("trusted_key_ids")
        if not isinstance(values, list) or any(
            not isinstance(value, str) for value in values
        ):
            raise EvidenceWitnessError("trusted_key_ids must be an array")
        key_ids = tuple(_hash(value, "trusted_key_id") for value in values)
        if len(key_ids) > MAX_TRUSTED_PUBLIC_KEYS:
            raise EvidenceWitnessError(
                f"trusted witness key count exceeds fixed limit of "
                f"{MAX_TRUSTED_PUBLIC_KEYS}"
            )
        if tuple(sorted(set(key_ids))) != key_ids:
            raise EvidenceWitnessError("trusted_key_ids must be sorted and unique")
        if mode == WITNESS_MODE and not key_ids:
            raise EvidenceWitnessError("required witness policy must trust a key")
        if mode == WITNESS_NOT_CONFIGURED and key_ids:
            raise EvidenceWitnessError("unconfigured witness policy cannot trust keys")
        max_unwitnessed_records = _optional_non_negative_int(
            raw.get("max_unwitnessed_records"),
            "max_unwitnessed_records",
        )
        if mode == WITNESS_NOT_CONFIGURED and max_unwitnessed_records is not None:
            raise EvidenceWitnessError(
                "unconfigured witness policy cannot set a witness lag bound"
            )
        recorded_at = _timestamp(raw.get("recorded_at"), "recorded_at")
        return cls(
            profile_hash,
            mode,
            key_ids,
            max_unwitnessed_records,
            recorded_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": POLICY_SCHEMA,
            "schema_version": POLICY_VERSION,
            "profile_hash": self.profile_hash,
            "mode": self.mode,
            "trusted_key_ids": list(self.trusted_key_ids),
            "max_unwitnessed_records": self.max_unwitnessed_records,
            "recorded_at": self.recorded_at,
        }

    def projection(
        self,
        *,
        verification: str,
        assessment: "EvidenceWitnessAssessment | None" = None,
    ) -> dict[str, Any]:
        return {
            "state": self.mode,
            "verification": verification,
            "profile_hash": self.profile_hash,
            "trusted_key_count": len(self.trusted_key_ids),
            "max_unwitnessed_records": self.max_unwitnessed_records,
            "unwitnessed_record_count": (
                assessment.unwitnessed_record_count if assessment is not None else 0
            ),
            "witnessed_record_count": (
                assessment.record_count if assessment is not None else 0
            ),
            "witnessed_head_hash": (
                assessment.head_hash if assessment is not None else None
            ),
            "witnessed_profile_generation": (
                assessment.authority_generation if assessment is not None else 0
            ),
            "witnessed_profile_hash": (
                assessment.authority_profile_hash if assessment is not None else None
            ),
            "key_id": assessment.key_id if assessment is not None else None,
            "signer": assessment.signer if assessment is not None else None,
            "signed_at": assessment.signed_at if assessment is not None else None,
        }


@dataclass(frozen=True)
class EvidenceWitnessAssessment:
    ok: bool
    verification: str
    detail: str
    record_count: int = 0
    head_hash: str = ""
    authority_generation: int = 0
    authority_profile_hash: str = ""
    key_id: str = ""
    signer: str = ""
    signed_at: str = ""
    payload_hash: str = ""
    unwitnessed_record_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EvidenceWitnessPolicyStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self) -> EvidenceWitnessPolicyState | None:
        try:
            if inspect_storage_root(self.path.parent) is None:
                return None
            current = inspect_state_file(self.path)
            if current is None:
                return None
            if current.st_size > _MAX_DOCUMENT_BYTES:
                raise EvidenceWitnessError("evidence witness policy is too large")
            return EvidenceWitnessPolicyState.from_dict(read_json(self.path))
        except EvidenceWitnessError:
            raise
        except (OSError, PersistenceError, RuntimeError) as exc:
            raise EvidenceWitnessError(_error_detail(exc)) from exc

    def record(
        self,
        profile_hash: str,
        policy: EvidenceWitnessPolicy | None,
    ) -> EvidenceWitnessPolicyState:
        profile_hash = _hash(profile_hash, "profile_hash")
        try:
            with exclusive_file_lock(self.path):
                current = self.get()
                mode = WITNESS_MODE if policy is not None else WITNESS_NOT_CONFIGURED
                key_ids = policy.trusted_key_ids if policy is not None else ()
                max_unwitnessed_records = (
                    policy.max_unwitnessed_records if policy is not None else None
                )
                if current is not None and current.profile_hash == profile_hash:
                    if (
                        current.mode != mode
                        or current.trusted_key_ids != key_ids
                        or current.max_unwitnessed_records != max_unwitnessed_records
                    ):
                        raise EvidenceWitnessError(
                            "evidence witness policy changed within one authority profile"
                        )
                    return current
                state = EvidenceWitnessPolicyState(
                    profile_hash=profile_hash,
                    mode=mode,
                    trusted_key_ids=key_ids,
                    max_unwitnessed_records=max_unwitnessed_records,
                    recorded_at=utc_now(),
                )
                atomic_write_json(self.path, state.to_dict())
                return state
        except EvidenceWitnessError:
            raise
        except (OSError, PersistenceError) as exc:
            raise EvidenceWitnessError(_error_detail(exc)) from exc


def validate_external_witness_paths(
    state_root: str | Path,
    witness_path: str | Path | None,
    trusted_key_paths: Iterable[str | Path],
) -> None:
    root = Path(state_root).resolve()
    candidates = [Path(path).resolve() for path in trusted_key_paths]
    if witness_path is not None:
        candidates.append(Path(witness_path).resolve())
    for candidate in candidates:
        if candidate == root or candidate.is_relative_to(root):
            raise EvidenceWitnessError(
                "evidence witness files and trust keys must be stored outside harness state"
            )


def build_witness_payload(workdir: str | Path) -> dict[str, Any]:
    """Build a signable head observation without mutating harness state."""

    root = Path(workdir)
    from .authority_profile import AuthorityProfileStore

    profile = AuthorityProfileStore(root / "authority_profile.json").get()
    storage = StateStorageStateStore(root / "state_storage.json").get()
    checkpoint = EvidenceHeadStateStore(root / "evidence_head.json").get()
    if profile is None or storage is None or checkpoint is None:
        raise EvidenceWitnessError(
            "authority profile, state storage, and evidence head must be enrolled"
        )
    if storage.profile_hash != profile.profile_hash:
        raise EvidenceWitnessError("state storage is not bound to the active profile")
    if checkpoint.profile_hash != profile.profile_hash:
        raise EvidenceWitnessError("evidence head is not bound to the active profile")
    evidence = EvidenceStore(root / "evidence.jsonl")
    status = evidence.verify()
    if not status.ok:
        raise EvidenceWitnessError("refusing to witness a broken evidence chain")
    records = evidence.records()
    if assess_evidence_head(checkpoint, records) != "verified":
        raise EvidenceWitnessError(
            "evidence chain must exactly match its durable checkpoint before witnessing"
        )
    return {
        "schema_name": WITNESS_SCHEMA,
        "schema_version": WITNESS_VERSION,
        "deployment_root_hash": storage.root_hash,
        "authority_generation": profile.generation,
        "authority_profile_hash": profile.profile_hash,
        "record_count": checkpoint.record_count,
        "head_hash": checkpoint.head_hash,
        "observed_at": utc_now(),
    }


def sign_witness(
    payload: dict[str, Any],
    private_key_path: str | Path,
    passphrase: bytes,
    *,
    signer: str,
    note: str,
    signed_at: str | None = None,
) -> dict[str, Any]:
    _validate_payload(payload)
    signer = _bounded_text(signer, "signer", _MAX_SIGNER_CHARS)
    note = _bounded_text(note, "note", _MAX_NOTE_CHARS)
    key = _load_private_key(private_key_path, passphrase)
    payload_hash = sha256_of(payload)
    statement = {
        "schema_name": ATTESTATION_SCHEMA,
        "schema_version": ATTESTATION_VERSION,
        "algorithm": ALGORITHM,
        "key_id": public_key_id(key.public_key()),
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
    return document


def assess_witness(
    document: dict[str, Any],
    policy: EvidenceWitnessPolicy,
    *,
    deployment_root_hash: str,
    profile: AuthorityProfileState,
    records: list[dict[str, Any]],
) -> EvidenceWitnessAssessment:
    try:
        payload, attestation = _verify_signature(document, policy)
        if not hmac.compare_digest(
            payload["deployment_root_hash"],
            _hash(deployment_root_hash, "deployment_root_hash"),
        ):
            raise EvidenceWitnessError("witness belongs to a different state root")
        expected_profile = _profile_hash_at_generation(
            profile, payload["authority_generation"]
        )
        if not hmac.compare_digest(expected_profile, payload["authority_profile_hash"]):
            raise EvidenceWitnessError(
                "witness authority profile is not in the enrolled profile history"
            )
        verification = _assess_position(
            payload["record_count"], payload["head_hash"], records
        )
        if verification == "rollback":
            raise EvidenceWitnessError("evidence chain is behind the external witness")
        if verification == "diverged":
            raise EvidenceWitnessError(
                "evidence chain diverges from the external witness"
            )
        lag = len(records) - payload["record_count"]
        if (
            policy.max_unwitnessed_records is not None
            and lag > policy.max_unwitnessed_records
        ):
            return EvidenceWitnessAssessment(
                False,
                "lag_exceeded",
                "external evidence witness is too far behind the live chain",
                record_count=payload["record_count"],
                head_hash=payload["head_hash"],
                authority_generation=payload["authority_generation"],
                authority_profile_hash=payload["authority_profile_hash"],
                key_id=attestation["key_id"],
                signer=attestation["signer"],
                signed_at=attestation["signed_at"],
                payload_hash=attestation["payload_hash"],
                unwitnessed_record_count=lag,
            )
        return EvidenceWitnessAssessment(
            True,
            verification,
            (
                "evidence chain matches the trusted external witness"
                if verification == "verified"
                else "evidence chain validly extends the trusted external witness"
            ),
            record_count=payload["record_count"],
            head_hash=payload["head_hash"],
            authority_generation=payload["authority_generation"],
            authority_profile_hash=payload["authority_profile_hash"],
            key_id=attestation["key_id"],
            signer=attestation["signer"],
            signed_at=attestation["signed_at"],
            payload_hash=attestation["payload_hash"],
            unwitnessed_record_count=lag,
        )
    except (EvidenceWitnessError, TypeError, ValueError, OverflowError) as exc:
        return EvidenceWitnessAssessment(False, "invalid", str(exc))


def load_witness(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        raw = _read_limited(source, _MAX_DOCUMENT_BYTES, "evidence witness")
        value = loads_strict_json(raw, label="evidence witness")
    except (OSError, StrictJsonError) as exc:
        raise EvidenceWitnessError(
            f"cannot read valid evidence witness {source}"
        ) from exc
    if not isinstance(value, dict):
        raise EvidenceWitnessError("evidence witness root must be an object")
    return value


def write_witness(path: str | Path, document: dict[str, Any]) -> None:
    try:
        encoded = (
            json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise EvidenceWitnessError("evidence witness is not valid JSON") from exc
    _write_new(Path(path), encoded, 0o600)


def _verify_signature(
    document: dict[str, Any],
    policy: EvidenceWitnessPolicy,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(document, dict) or set(document) != _WITNESS_FIELDS:
        raise EvidenceWitnessError("evidence witness fields do not match schema")
    payload = {key: value for key, value in document.items() if key != "attestation"}
    attestation = document.get("attestation")
    _validate_payload(payload)
    _validate_attestation(attestation)
    if _parse_timestamp(attestation["signed_at"]) < _parse_timestamp(
        payload["observed_at"]
    ):
        raise EvidenceWitnessError("witness signature predates its observation")
    expected_hash = sha256_of(payload)
    if not hmac.compare_digest(expected_hash, attestation["payload_hash"]):
        raise EvidenceWitnessError("witness payload hash does not match attestation")
    trusted = {
        public_key_id(key): key
        for key in _load_trusted_public_keys(policy.trusted_key_paths)
    }
    if tuple(sorted(trusted)) != policy.trusted_key_ids:
        raise EvidenceWitnessError(
            "trusted witness keys changed after policy preparation"
        )
    key = trusted.get(attestation["key_id"])
    if key is None:
        raise EvidenceWitnessError(
            f"witness key is not trusted: {attestation['key_id']}"
        )
    try:
        key.verify(
            _decode_signature(attestation["signature"]),
            _statement_bytes(
                {key: value for key, value in attestation.items() if key != "signature"}
            ),
        )
    except InvalidSignature as exc:
        raise EvidenceWitnessError("witness signature is invalid") from exc
    return payload, attestation


def _validate_payload(payload: dict[str, Any]) -> None:
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_FIELDS:
        raise EvidenceWitnessError(
            "evidence witness payload fields do not match schema"
        )
    if payload.get("schema_name") != WITNESS_SCHEMA:
        raise EvidenceWitnessError("unsupported evidence witness schema")
    if payload.get("schema_version") != WITNESS_VERSION:
        raise EvidenceWitnessError("unsupported evidence witness version")
    _hash(payload.get("deployment_root_hash"), "deployment_root_hash")
    generation = payload.get("authority_generation")
    if type(generation) is not int or generation < 1:
        raise EvidenceWitnessError("authority_generation must be a positive integer")
    _hash(payload.get("authority_profile_hash"), "authority_profile_hash")
    count = payload.get("record_count")
    if type(count) is not int or count < 0:
        raise EvidenceWitnessError("record_count must be a non-negative integer")
    head = _hash(payload.get("head_hash"), "head_hash")
    if count == 0 and head != GENESIS_HEAD:
        raise EvidenceWitnessError("empty evidence witness must use the genesis head")
    _timestamp(payload.get("observed_at"), "observed_at")


def _validate_attestation(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != _ATTESTATION_FIELDS:
        raise EvidenceWitnessError("witness attestation fields do not match schema")
    if value.get("schema_name") != ATTESTATION_SCHEMA:
        raise EvidenceWitnessError("unsupported witness attestation schema")
    if value.get("schema_version") != ATTESTATION_VERSION:
        raise EvidenceWitnessError("unsupported witness attestation version")
    if value.get("algorithm") != ALGORITHM:
        raise EvidenceWitnessError("unsupported witness attestation algorithm")
    _hash(value.get("key_id"), "key_id")
    _hash(value.get("payload_hash"), "payload_hash")
    _timestamp(value.get("signed_at"), "signed_at")
    _bounded_text(value.get("signer"), "signer", _MAX_SIGNER_CHARS)
    _bounded_text(value.get("note"), "note", _MAX_NOTE_CHARS)
    _decode_signature(value.get("signature"))


def _profile_hash_at_generation(profile: AuthorityProfileState, generation: int) -> str:
    if generation < 1 or generation > profile.generation:
        raise EvidenceWitnessError(
            "witness authority generation is not in the enrolled profile history"
        )
    if generation == 1:
        return profile.initial_profile_hash
    return profile.transitions[generation - 2]["to_profile_hash"]


def _assess_position(count: int, head: str, records: list[dict[str, Any]]) -> str:
    current_count = len(records)
    current_head = records[-1]["record_hash"] if records else GENESIS_HEAD
    if current_count == count:
        return "verified" if hmac.compare_digest(current_head, head) else "diverged"
    if current_count < count:
        return "rollback"
    if count == 0:
        return "forward" if head == GENESIS_HEAD else "diverged"
    prefix = records[count - 1].get("record_hash")
    return (
        "forward"
        if isinstance(prefix, str) and hmac.compare_digest(prefix, head)
        else "diverged"
    )


def _load_private_key(path: str | Path, passphrase: bytes) -> Ed25519PrivateKey:
    if not passphrase:
        raise EvidenceWitnessError("private-key passphrase must be non-empty")
    try:
        key = serialization.load_pem_private_key(
            _read_limited(Path(path), _MAX_KEY_BYTES, "private key"),
            password=passphrase,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise EvidenceWitnessError("cannot load encrypted Ed25519 private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise EvidenceWitnessError("private key is not Ed25519")
    return key


def _public_key_from_bytes(value: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(value)
    except (TypeError, ValueError) as exc:
        raise EvidenceWitnessError("cannot load Ed25519 trusted public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise EvidenceWitnessError("trusted public key is not Ed25519")
    return key


def _load_trusted_public_keys(
    paths: Iterable[str | Path],
) -> tuple[Ed25519PublicKey, ...]:
    bounded_paths = _bounded_trusted_key_paths(paths)
    keys: list[Ed25519PublicKey] = []
    total_key_bytes = 0
    for path in bounded_paths:
        key_bytes = _read_limited(
            Path(path),
            MAX_TRUSTED_PUBLIC_KEY_BYTES,
            "trusted public key",
        )
        total_key_bytes += len(key_bytes)
        if total_key_bytes > MAX_TRUSTED_PUBLIC_KEY_SET_BYTES:
            raise EvidenceWitnessError(
                "trusted witness public key set exceeds fixed "
                f"{MAX_TRUSTED_PUBLIC_KEY_SET_BYTES}-byte ceiling"
            )
        keys.append(_public_key_from_bytes(key_bytes))
    return tuple(keys)


def _bounded_trusted_key_paths(
    paths: Iterable[str | Path],
) -> tuple[str | Path, ...]:
    bounded: list[str | Path] = []
    for path in paths:
        if len(bounded) >= MAX_TRUSTED_PUBLIC_KEYS:
            raise EvidenceWitnessError(
                f"trusted witness key count exceeds fixed limit of "
                f"{MAX_TRUSTED_PUBLIC_KEYS}"
            )
        bounded.append(path)
    return tuple(bounded)


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not value.startswith("base64:"):
        raise EvidenceWitnessError("witness signature encoding is invalid")
    try:
        signature = base64.b64decode(value[7:].encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise EvidenceWitnessError("witness signature encoding is invalid") from exc
    if len(signature) != 64:
        raise EvidenceWitnessError("Ed25519 signature must be 64 bytes")
    return signature


def _statement_bytes(statement: dict[str, Any]) -> bytes:
    return _DOMAIN + canonical_json(statement).encode("utf-8")


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise EvidenceWitnessError(f"{field} is not a sha256 identifier")
    digest = value[7:]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise EvidenceWitnessError(f"{field} is not a sha256 identifier")
    return value


def _optional_non_negative_int(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise EvidenceWitnessError(f"{field} must be a non-negative integer")
    return value


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceWitnessError(f"{field} must be non-empty text")
    return value


def _bounded_text(value: Any, field: str, maximum: int) -> str:
    text = _required_text(value, field)
    if len(text) > maximum:
        raise EvidenceWitnessError(f"{field} exceeds {maximum} characters")
    return text


def _timestamp(value: Any, field: str) -> str:
    text = _required_text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceWitnessError(f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceWitnessError(f"{field} must include a timezone")
    return text


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _read_limited(path: Path, maximum: int, label: str) -> bytes:
    try:
        with path.open("rb") as fh:
            content = fh.read(maximum + 1)
    except OSError as exc:
        raise EvidenceWitnessError(f"cannot read {label}: {path}") from exc
    if len(content) > maximum:
        raise EvidenceWitnessError(f"{label} file is too large: {path}")
    return content


def _write_new(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.link(temporary, path)
    except FileExistsError as exc:
        raise EvidenceWitnessError(
            f"refusing to overwrite existing file: {path}"
        ) from exc
    except OSError as exc:
        raise EvidenceWitnessError(f"cannot write {path}: {exc}") from exc
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def _error_detail(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        return exc.strerror or exc.__class__.__name__
    return str(exc)
