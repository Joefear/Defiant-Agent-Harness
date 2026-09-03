"""Externally retained signed witnesses for authority-publication continuity."""

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

from .authority_profile import AuthorityProfileState, AuthorityProfileStore
from .authority_publication import (
    AuthorityPublicationState,
    AuthorityPublicationStore,
    assess_authority_publication_continuity,
)
from .authority_publication_continuity import AuthorityPublicationContinuityState
from .contracts import (
    authority_snapshot_and_sha256_of,
    canonical_json,
    sha256_of,
    utc_now,
)
from .evidence.signing import public_key_id
from .evidence_witness import EvidenceWitnessError
from .limits import (
    MAX_AUTHORITY_PUBLICATION_WITNESS_POLICY_STATE_BYTES,
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

WITNESS_SCHEMA = "defiant.authority.publication_witness"
WITNESS_VERSION = "0.1.0"
ATTESTATION_SCHEMA = "defiant.authority.publication_witness.attestation"
ATTESTATION_VERSION = "0.1.0"
POLICY_SCHEMA = "defiant.authority.publication_witness_policy"
POLICY_VERSION = "0.1.0"
WITNESS_MODE = "signed_external_required"
WITNESS_NOT_CONFIGURED = "not_configured"
ALGORITHM = "Ed25519"

_DOMAIN = b"Defiant Agent Harness authority publication witness v0.1.0\x00"
_WITNESS_FIELDS = {
    "schema_name",
    "schema_version",
    "deployment_root_hash",
    "authority_generation",
    "authority_profile_hash",
    "continuity_sequence",
    "checkpoint_hash",
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
_POLICY_FIELDS = {
    "schema_name",
    "schema_version",
    "profile_hash",
    "mode",
    "trusted_key_ids",
    "recorded_at",
}
_MAX_DOCUMENT_BYTES = 256 * 1024
_MAX_POLICY_STATE_BYTES = MAX_AUTHORITY_PUBLICATION_WITNESS_POLICY_STATE_BYTES
_MAX_KEY_BYTES = 64 * 1024
_MAX_SIGNER_CHARS = 256
_MAX_NOTE_CHARS = 4096


class AuthorityPublicationWitnessError(EvidenceWitnessError):
    """An external publication witness could not be trusted."""


@dataclass(frozen=True)
class AuthorityPublicationWitnessPolicy:
    trusted_key_ids: tuple[str, ...]
    trusted_key_paths: tuple[Path, ...]

    @classmethod
    def from_paths(
        cls,
        paths: Iterable[str | Path],
    ) -> "AuthorityPublicationWitnessPolicy":
        key_paths = tuple(Path(path).resolve() for path in _bounded_key_paths(paths))
        if not key_paths:
            raise AuthorityPublicationWitnessError(
                "at least one trusted publication witness key is required"
            )
        keys = _load_public_keys(key_paths)
        key_ids = tuple(sorted({public_key_id(key) for key in keys}))
        if len(key_ids) != len(key_paths):
            raise AuthorityPublicationWitnessError(
                "trusted publication witness keys must be unique"
            )
        return cls(key_ids, key_paths)

    def authority_dict(self) -> dict[str, Any]:
        return {
            "mode": WITNESS_MODE,
            "schema_version": WITNESS_VERSION,
            "trusted_key_ids": list(self.trusted_key_ids),
        }


@dataclass(frozen=True)
class AuthorityPublicationWitnessPolicyState:
    profile_hash: str
    mode: str
    trusted_key_ids: tuple[str, ...]
    recorded_at: str

    @classmethod
    def from_dict(cls, raw: Any) -> "AuthorityPublicationWitnessPolicyState":
        snapshot = _policy_snapshot(raw)
        if set(snapshot) != _POLICY_FIELDS:
            raise AuthorityPublicationWitnessError(
                "publication witness policy fields do not match schema"
            )
        if snapshot.get("schema_name") != POLICY_SCHEMA:
            raise AuthorityPublicationWitnessError(
                "unsupported publication witness policy schema"
            )
        if snapshot.get("schema_version") != POLICY_VERSION:
            raise AuthorityPublicationWitnessError(
                "unsupported publication witness policy version"
            )
        mode = snapshot.get("mode")
        if mode not in {WITNESS_MODE, WITNESS_NOT_CONFIGURED}:
            raise AuthorityPublicationWitnessError(
                "unsupported publication witness policy mode"
            )
        values = snapshot.get("trusted_key_ids")
        if type(values) is not list:
            raise AuthorityPublicationWitnessError(
                "trusted publication witness key ids must be an array"
            )
        key_ids = tuple(_hash(value, "trusted_key_id") for value in values)
        if len(key_ids) > MAX_TRUSTED_PUBLIC_KEYS:
            raise AuthorityPublicationWitnessError(
                "trusted publication witness key count exceeds fixed limit"
            )
        if tuple(sorted(set(key_ids))) != key_ids:
            raise AuthorityPublicationWitnessError(
                "trusted publication witness key ids must be sorted and unique"
            )
        if mode == WITNESS_MODE and not key_ids:
            raise AuthorityPublicationWitnessError(
                "required publication witness policy must trust a key"
            )
        if mode == WITNESS_NOT_CONFIGURED and key_ids:
            raise AuthorityPublicationWitnessError(
                "unconfigured publication witness policy cannot trust keys"
            )
        return cls(
            profile_hash=_hash(snapshot.get("profile_hash"), "profile_hash"),
            mode=mode,
            trusted_key_ids=key_ids,
            recorded_at=_timestamp(snapshot.get("recorded_at"), "recorded_at"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": POLICY_SCHEMA,
            "schema_version": POLICY_VERSION,
            "profile_hash": self.profile_hash,
            "mode": self.mode,
            "trusted_key_ids": list(self.trusted_key_ids),
            "recorded_at": self.recorded_at,
        }

    def projection(
        self,
        *,
        verification: str,
        assessment: "AuthorityPublicationWitnessAssessment | None" = None,
    ) -> dict[str, Any]:
        return {
            "state": self.mode,
            "verification": verification,
            "profile_hash": self.profile_hash,
            "trusted_key_count": len(self.trusted_key_ids),
            "witnessed_continuity_sequence": (
                assessment.continuity_sequence if assessment is not None else 0
            ),
            "unwitnessed_publication_count": (
                assessment.unwitnessed_publication_count
                if assessment is not None
                else 0
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
class AuthorityPublicationWitnessAssessment:
    ok: bool
    verification: str
    detail: str
    continuity_sequence: int = 0
    checkpoint_hash: str = ""
    authority_generation: int = 0
    authority_profile_hash: str = ""
    key_id: str = ""
    signer: str = ""
    signed_at: str = ""
    payload_hash: str = ""
    unwitnessed_publication_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuthorityPublicationWitnessPolicyStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self) -> AuthorityPublicationWitnessPolicyState | None:
        try:
            if inspect_storage_root(self.path.parent) is None:
                return None
            if inspect_state_file(self.path) is None:
                return None
            return AuthorityPublicationWitnessPolicyState.from_dict(
                read_json(self.path, max_bytes=_MAX_POLICY_STATE_BYTES)
            )
        except AuthorityPublicationWitnessError:
            raise
        except (OSError, PersistenceError, RuntimeError) as exc:
            raise AuthorityPublicationWitnessError(_error_detail(exc)) from exc

    def record(
        self,
        profile_hash: str,
        policy: AuthorityPublicationWitnessPolicy | None,
    ) -> AuthorityPublicationWitnessPolicyState:
        candidate = AuthorityPublicationWitnessPolicyState.from_dict(
            {
                "schema_name": POLICY_SCHEMA,
                "schema_version": POLICY_VERSION,
                "profile_hash": profile_hash,
                "mode": WITNESS_MODE if policy is not None else WITNESS_NOT_CONFIGURED,
                "trusted_key_ids": (
                    list(policy.trusted_key_ids) if policy is not None else []
                ),
                "recorded_at": utc_now(),
            }
        )
        try:
            with exclusive_file_lock(self.path):
                current = self.get()
                if (
                    current is not None
                    and current.profile_hash == candidate.profile_hash
                ):
                    if (
                        current.mode != candidate.mode
                        or current.trusted_key_ids != candidate.trusted_key_ids
                    ):
                        raise AuthorityPublicationWitnessError(
                            "publication witness policy changed within one authority profile"
                        )
                    return current
                atomic_write_json(
                    self.path,
                    candidate.to_dict(),
                    max_bytes=_MAX_POLICY_STATE_BYTES,
                )
                return candidate
        except AuthorityPublicationWitnessError:
            raise
        except (OSError, PersistenceError) as exc:
            raise AuthorityPublicationWitnessError(_error_detail(exc)) from exc


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
            raise AuthorityPublicationWitnessError(
                "publication witness files and trust keys must be outside harness state"
            )


def build_witness_payload(workdir: str | Path) -> dict[str, Any]:
    """Build a signable publication-head observation without mutating state."""

    root = Path(workdir)
    profile = AuthorityProfileStore(root / "authority_profile.json").get()
    storage = StateStorageStateStore(root / "state_storage.json").get()
    store = AuthorityPublicationStore(root / "authority_publication.json")
    publication = store.get()
    continuity = store.get_continuity()
    if profile is None or storage is None or publication is None or continuity is None:
        raise AuthorityPublicationWitnessError(
            "authority profile, state storage, publication, and continuity must be enrolled"
        )
    if storage.profile_hash != profile.profile_hash:
        raise AuthorityPublicationWitnessError(
            "state storage is not bound to the active profile"
        )
    if (
        publication.completed is None
        or publication.completed.profile_hash != profile.profile_hash
    ):
        raise AuthorityPublicationWitnessError(
            "authority publication is not bound to the active profile"
        )
    if assess_authority_publication_continuity(publication, continuity) != "verified":
        raise AuthorityPublicationWitnessError(
            "publication must exactly match its continuity anchor before witnessing"
        )
    return {
        "schema_name": WITNESS_SCHEMA,
        "schema_version": WITNESS_VERSION,
        "deployment_root_hash": storage.root_hash,
        "authority_generation": profile.generation,
        "authority_profile_hash": profile.profile_hash,
        "continuity_sequence": continuity.sequence,
        "checkpoint_hash": continuity.checkpoint_hash,
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
    payload = _payload_snapshot(payload)
    _validate_payload(payload)
    key = _load_private_key(private_key_path, passphrase)
    statement = {
        "schema_name": ATTESTATION_SCHEMA,
        "schema_version": ATTESTATION_VERSION,
        "algorithm": ALGORITHM,
        "key_id": public_key_id(key.public_key()),
        "signed_at": _timestamp(signed_at or utc_now(), "signed_at"),
        "signer": _bounded_text(signer, "signer", _MAX_SIGNER_CHARS),
        "note": _bounded_text(note, "note", _MAX_NOTE_CHARS),
        "payload_hash": sha256_of(payload),
    }
    signature = key.sign(_statement_bytes(statement))
    return {
        **payload,
        "attestation": {
            **statement,
            "signature": "base64:" + base64.b64encode(signature).decode("ascii"),
        },
    }


def assess_witness(
    document: dict[str, Any],
    policy: AuthorityPublicationWitnessPolicy,
    *,
    deployment_root_hash: str,
    profile: AuthorityProfileState,
    publication: AuthorityPublicationState,
    continuity: AuthorityPublicationContinuityState,
) -> AuthorityPublicationWitnessAssessment:
    try:
        payload, attestation = _verify_signature(document, policy)
        if not hmac.compare_digest(
            payload["deployment_root_hash"],
            _hash(deployment_root_hash, "deployment_root_hash"),
        ):
            raise AuthorityPublicationWitnessError(
                "publication witness belongs to a different state root"
            )
        expected_profile = _profile_hash_at_generation(
            profile, payload["authority_generation"]
        )
        if not hmac.compare_digest(expected_profile, payload["authority_profile_hash"]):
            raise AuthorityPublicationWitnessError(
                "publication witness profile is not in enrolled history"
            )
        if (
            assess_authority_publication_continuity(publication, continuity)
            != "verified"
        ):
            raise AuthorityPublicationWitnessError(
                "local publication continuity must be verified first"
            )
        sequence = payload["continuity_sequence"]
        checkpoint_hash = payload["checkpoint_hash"]
        if sequence > continuity.sequence:
            raise AuthorityPublicationWitnessError(
                "publication continuity is behind the external witness"
            )
        if sequence == continuity.sequence:
            verification = (
                "verified"
                if hmac.compare_digest(checkpoint_hash, continuity.checkpoint_hash)
                else "diverged"
            )
        elif sequence + 1 == continuity.sequence:
            verification = (
                "forward"
                if hmac.compare_digest(
                    checkpoint_hash, continuity.prior_checkpoint_hash
                )
                else "diverged"
            )
        else:
            verification = "lag_unverifiable"
        if verification == "diverged":
            raise AuthorityPublicationWitnessError(
                "publication continuity diverges from the external witness"
            )
        if verification == "lag_unverifiable":
            raise AuthorityPublicationWitnessError(
                "publication witness is beyond the compact continuity window"
            )
        lag = continuity.sequence - sequence
        return AuthorityPublicationWitnessAssessment(
            True,
            verification,
            (
                "publication continuity matches the trusted external witness"
                if verification == "verified"
                else "publication continuity is one verified step beyond the witness"
            ),
            continuity_sequence=sequence,
            checkpoint_hash=checkpoint_hash,
            authority_generation=payload["authority_generation"],
            authority_profile_hash=payload["authority_profile_hash"],
            key_id=attestation["key_id"],
            signer=attestation["signer"],
            signed_at=attestation["signed_at"],
            payload_hash=attestation["payload_hash"],
            unwitnessed_publication_count=lag,
        )
    except (AuthorityPublicationWitnessError, TypeError, ValueError) as exc:
        return AuthorityPublicationWitnessAssessment(False, "invalid", str(exc))


def load_witness(path: str | Path) -> dict[str, Any]:
    try:
        value = loads_strict_json(
            _read_limited(Path(path), _MAX_DOCUMENT_BYTES, "publication witness"),
            label="publication witness",
        )
    except (OSError, StrictJsonError) as exc:
        raise AuthorityPublicationWitnessError(
            "cannot read valid publication witness"
        ) from exc
    if type(value) is not dict:
        raise AuthorityPublicationWitnessError(
            "publication witness root must be an object"
        )
    return value


def write_witness(path: str | Path, document: dict[str, Any]) -> None:
    document = _document_snapshot(document)
    try:
        encoded = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    except (TypeError, ValueError) as exc:
        raise AuthorityPublicationWitnessError(
            "publication witness is not valid JSON"
        ) from exc
    _write_new(Path(path), encoded)


def _verify_signature(
    document: dict[str, Any],
    policy: AuthorityPublicationWitnessPolicy,
) -> tuple[dict[str, Any], dict[str, Any]]:
    document = _document_snapshot(document)
    if set(document) != _WITNESS_FIELDS:
        raise AuthorityPublicationWitnessError(
            "publication witness fields do not match schema"
        )
    payload = {key: value for key, value in document.items() if key != "attestation"}
    attestation = document.get("attestation")
    _validate_payload(payload)
    _validate_attestation(attestation)
    if _parse_timestamp(attestation["signed_at"]) < _parse_timestamp(
        payload["observed_at"]
    ):
        raise AuthorityPublicationWitnessError(
            "publication witness signature predates observation"
        )
    if not hmac.compare_digest(sha256_of(payload), attestation["payload_hash"]):
        raise AuthorityPublicationWitnessError(
            "publication witness payload hash does not match attestation"
        )
    trusted = {
        public_key_id(key): key for key in _load_public_keys(policy.trusted_key_paths)
    }
    if tuple(sorted(trusted)) != policy.trusted_key_ids:
        raise AuthorityPublicationWitnessError(
            "trusted publication witness keys changed after policy preparation"
        )
    key = trusted.get(attestation["key_id"])
    if key is None:
        raise AuthorityPublicationWitnessError("publication witness key is not trusted")
    try:
        key.verify(
            _decode_signature(attestation["signature"]),
            _statement_bytes(
                {key: value for key, value in attestation.items() if key != "signature"}
            ),
        )
    except InvalidSignature as exc:
        raise AuthorityPublicationWitnessError(
            "publication witness signature is invalid"
        ) from exc
    return payload, attestation


def _validate_payload(payload: dict[str, Any]) -> None:
    if set(payload) != _PAYLOAD_FIELDS:
        raise AuthorityPublicationWitnessError(
            "publication witness payload fields do not match schema"
        )
    if payload.get("schema_name") != WITNESS_SCHEMA:
        raise AuthorityPublicationWitnessError("unsupported publication witness schema")
    if payload.get("schema_version") != WITNESS_VERSION:
        raise AuthorityPublicationWitnessError(
            "unsupported publication witness version"
        )
    _hash(payload.get("deployment_root_hash"), "deployment_root_hash")
    generation = payload.get("authority_generation")
    if type(generation) is not int or generation < 1:
        raise AuthorityPublicationWitnessError(
            "authority_generation must be a positive integer"
        )
    _hash(payload.get("authority_profile_hash"), "authority_profile_hash")
    sequence = payload.get("continuity_sequence")
    if type(sequence) is not int or sequence < 1:
        raise AuthorityPublicationWitnessError(
            "continuity_sequence must be a positive integer"
        )
    _hash(payload.get("checkpoint_hash"), "checkpoint_hash")
    _timestamp(payload.get("observed_at"), "observed_at")


def _validate_attestation(value: Any) -> None:
    if type(value) is not dict or set(value) != _ATTESTATION_FIELDS:
        raise AuthorityPublicationWitnessError(
            "publication witness attestation fields do not match schema"
        )
    if value.get("schema_name") != ATTESTATION_SCHEMA:
        raise AuthorityPublicationWitnessError(
            "unsupported publication witness attestation schema"
        )
    if value.get("schema_version") != ATTESTATION_VERSION:
        raise AuthorityPublicationWitnessError(
            "unsupported publication witness attestation version"
        )
    if value.get("algorithm") != ALGORITHM:
        raise AuthorityPublicationWitnessError(
            "unsupported publication witness algorithm"
        )
    _hash(value.get("key_id"), "key_id")
    _hash(value.get("payload_hash"), "payload_hash")
    _timestamp(value.get("signed_at"), "signed_at")
    _bounded_text(value.get("signer"), "signer", _MAX_SIGNER_CHARS)
    _bounded_text(value.get("note"), "note", _MAX_NOTE_CHARS)
    _decode_signature(value.get("signature"))


def _profile_hash_at_generation(profile: AuthorityProfileState, generation: int) -> str:
    if generation < 1 or generation > profile.generation:
        raise AuthorityPublicationWitnessError(
            "publication witness generation is not in enrolled profile history"
        )
    return (
        profile.initial_profile_hash
        if generation == 1
        else profile.transitions[generation - 2]["to_profile_hash"]
    )


def _load_private_key(path: str | Path, passphrase: bytes) -> Ed25519PrivateKey:
    if not passphrase:
        raise AuthorityPublicationWitnessError(
            "private-key passphrase must be non-empty"
        )
    try:
        key = serialization.load_pem_private_key(
            _read_limited(Path(path), _MAX_KEY_BYTES, "private key"),
            password=passphrase,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise AuthorityPublicationWitnessError(
            "cannot load encrypted Ed25519 private key"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AuthorityPublicationWitnessError("private key is not Ed25519")
    return key


def _load_public_keys(paths: Iterable[str | Path]) -> tuple[Ed25519PublicKey, ...]:
    keys = []
    total = 0
    for path in _bounded_key_paths(paths):
        encoded = _read_limited(
            Path(path), MAX_TRUSTED_PUBLIC_KEY_BYTES, "trusted public key"
        )
        total += len(encoded)
        if total > MAX_TRUSTED_PUBLIC_KEY_SET_BYTES:
            raise AuthorityPublicationWitnessError(
                "trusted publication witness key set exceeds fixed byte ceiling"
            )
        try:
            key = serialization.load_pem_public_key(encoded)
        except (TypeError, ValueError) as exc:
            raise AuthorityPublicationWitnessError(
                "cannot load trusted Ed25519 public key"
            ) from exc
        if not isinstance(key, Ed25519PublicKey):
            raise AuthorityPublicationWitnessError("trusted public key is not Ed25519")
        keys.append(key)
    return tuple(keys)


def _bounded_key_paths(paths: Iterable[str | Path]) -> tuple[str | Path, ...]:
    bounded = []
    for path in paths:
        if len(bounded) >= MAX_TRUSTED_PUBLIC_KEYS:
            raise AuthorityPublicationWitnessError(
                "trusted publication witness key count exceeds fixed limit"
            )
        bounded.append(path)
    return tuple(bounded)


def _decode_signature(value: Any) -> bytes:
    if not isinstance(value, str) or not value.startswith("base64:"):
        raise AuthorityPublicationWitnessError(
            "publication witness signature encoding is invalid"
        )
    try:
        signature = base64.b64decode(value[7:].encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise AuthorityPublicationWitnessError(
            "publication witness signature encoding is invalid"
        ) from exc
    if len(signature) != 64:
        raise AuthorityPublicationWitnessError(
            "Ed25519 publication witness signature must be 64 bytes"
        )
    return signature


def _statement_bytes(statement: dict[str, Any]) -> bytes:
    return _DOMAIN + canonical_json(statement).encode()


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AuthorityPublicationWitnessError(f"{field} is not a sha256 identifier")
    normalized = str.__str__(value)
    if not normalized.startswith("sha256:"):
        raise AuthorityPublicationWitnessError(f"{field} is not a sha256 identifier")
    digest = normalized[7:]
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise AuthorityPublicationWitnessError(f"{field} is not a sha256 identifier")
    return normalized


def _bounded_text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise AuthorityPublicationWitnessError(f"{field} must be non-empty text")
    normalized = str.__str__(value)
    if not normalized.strip():
        raise AuthorityPublicationWitnessError(f"{field} must be non-empty text")
    if len(normalized) > maximum:
        raise AuthorityPublicationWitnessError(f"{field} exceeds {maximum} characters")
    return normalized


def _timestamp(value: Any, field: str) -> str:
    text = _bounded_text(value, field, 128)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorityPublicationWitnessError(
            f"{field} must be an RFC3339 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorityPublicationWitnessError(f"{field} must include a timezone")
    return text


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _read_limited(path: Path, maximum: int, label: str) -> bytes:
    try:
        with path.open("rb") as stream:
            content = stream.read(maximum + 1)
    except OSError as exc:
        raise AuthorityPublicationWitnessError(f"cannot read {label}") from exc
    if len(content) > maximum:
        raise AuthorityPublicationWitnessError(f"{label} file is too large")
    return content


def _write_new(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    except FileExistsError as exc:
        raise AuthorityPublicationWitnessError(
            "refusing to overwrite existing publication witness"
        ) from exc
    except OSError as exc:
        raise AuthorityPublicationWitnessError(
            "cannot write publication witness"
        ) from exc
    finally:
        try:
            temporary.unlink()
        except OSError:
            pass


def _payload_snapshot(value: Any) -> dict[str, Any]:
    snapshot = _bounded_snapshot(value, _MAX_DOCUMENT_BYTES, "publication witness")
    if type(snapshot) is not dict:
        raise AuthorityPublicationWitnessError(
            "publication witness payload fields do not match schema"
        )
    return snapshot


def _document_snapshot(value: Any) -> dict[str, Any]:
    snapshot = _bounded_snapshot(value, _MAX_DOCUMENT_BYTES, "publication witness")
    if type(snapshot) is not dict:
        raise AuthorityPublicationWitnessError(
            "publication witness fields do not match schema"
        )
    return snapshot


def _policy_snapshot(value: Any) -> dict[str, Any]:
    snapshot = _bounded_snapshot(
        value, _MAX_POLICY_STATE_BYTES, "publication witness policy"
    )
    if type(snapshot) is not dict:
        raise AuthorityPublicationWitnessError(
            "publication witness policy fields do not match schema"
        )
    return snapshot


def _bounded_snapshot(value: Any, maximum: int, label: str) -> Any:
    try:
        snapshot, _ = authority_snapshot_and_sha256_of(
            value, maximum_canonical_bytes=maximum
        )
    except ValueError as exc:
        raise AuthorityPublicationWitnessError(
            f"{label} exceeds bounded canonical state"
        ) from exc
    return snapshot


def _error_detail(exc: BaseException) -> str:
    return exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
