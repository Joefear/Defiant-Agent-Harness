"""Cryptographically bound operator actions for approval authority."""

from __future__ import annotations

import base64
import binascii
import hmac
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .contracts import canonical_json, sha256_of, utc_now

if TYPE_CHECKING:
    from .approvals.store import PendingApproval

ATTESTATION_SCHEMA = "defiant.operator.attestation"
ATTESTATION_VERSION = "0.1.0"
ALGORITHM = "Ed25519"
DECISION_PURPOSE = "approval_decision"
RECONCILIATION_PURPOSE = "execution_reconciliation"
_PURPOSES = {DECISION_PURPOSE, RECONCILIATION_PURPOSE}
_DOMAIN = b"Defiant Agent Harness operator authority v0.1.0\x00"
_MAX_KEY_BYTES = 64 * 1024
_MAX_OPERATOR_CHARS = 256
_MAX_NOTE_CHARS = 4096
_FIELDS = {
    "schema_name",
    "schema_version",
    "algorithm",
    "purpose",
    "key_id",
    "signed_at",
    "operator",
    "note",
    "outcome",
    "approval_id",
    "action_id",
    "request_id",
    "authorization_hash",
    "signature",
}


class OperatorIdentityError(RuntimeError):
    """Operator identity could not be established safely."""


@dataclass(frozen=True)
class OperatorIdentityStatus:
    ok: bool
    assurance: str
    detail: str
    operator: str = ""
    key_id: str = ""
    signed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class OperatorTrustPolicy:
    """Out-of-band mapping from an operator identity to trusted public keys."""

    def __init__(self, keys: dict[str, dict[str, Ed25519PublicKey]]):
        if not keys:
            raise OperatorIdentityError("at least one trusted operator key is required")
        self._keys = keys

    @classmethod
    def from_specs(cls, specs: Iterable[str | Path]) -> "OperatorTrustPolicy":
        keys: dict[str, dict[str, Ed25519PublicKey]] = {}
        key_owners: dict[str, str] = {}
        for raw_spec in specs:
            spec = str(raw_spec)
            operator, separator, raw_path = spec.partition("=")
            operator = operator.strip()
            raw_path = raw_path.strip()
            if not separator or not operator or not raw_path:
                raise OperatorIdentityError(
                    "trusted operator keys must use IDENTITY=PUBLIC_KEY.pem"
                )
            operator = _bounded_text(operator, "operator", _MAX_OPERATOR_CHARS)
            key = _load_public_key(raw_path)
            key_id = public_key_id(key)
            previous = key_owners.get(key_id)
            if previous is not None and previous != operator:
                raise OperatorIdentityError(
                    f"trusted key {key_id} is assigned to multiple operators"
                )
            key_owners[key_id] = operator
            keys.setdefault(operator, {})[key_id] = key
        return cls(keys)

    @property
    def operator_count(self) -> int:
        return len(self._keys)

    @property
    def key_count(self) -> int:
        return sum(len(value) for value in self._keys.values())

    def verify(self, attestation: dict[str, Any], approval: "PendingApproval") -> OperatorIdentityStatus:
        try:
            _validate_attestation(attestation)
            operator = attestation["operator"]
            key_id = attestation["key_id"]
            key = self._keys.get(operator, {}).get(key_id)
            if key is None:
                raise OperatorIdentityError(
                    f"key {key_id} is not trusted for operator {operator!r}"
                )
            _validate_binding(attestation, approval)
            signature = _decode_signature(attestation["signature"])
            statement = {
                name: value for name, value in attestation.items() if name != "signature"
            }
            try:
                key.verify(signature, _statement_bytes(statement))
            except InvalidSignature as exc:
                raise OperatorIdentityError("operator attestation signature is invalid") from exc
            return OperatorIdentityStatus(
                True,
                "signed_trusted",
                "signature valid and operator key trusted",
                operator=operator,
                key_id=key_id,
                signed_at=attestation["signed_at"],
            )
        except (OperatorIdentityError, TypeError, ValueError, OverflowError) as exc:
            return OperatorIdentityStatus(False, "invalid", str(exc))

    def require(
        self,
        attestation: dict[str, Any] | None,
        approval: "PendingApproval",
        *,
        purpose: str,
        outcome: str,
        operator: str,
        note: str,
    ) -> OperatorIdentityStatus:
        if not isinstance(attestation, dict):
            raise OperatorIdentityError("a signed operator attestation is required")
        status = self.verify(attestation, approval)
        if not status.ok:
            raise OperatorIdentityError(status.detail)
        expected = {
            "purpose": purpose,
            "outcome": outcome,
            "operator": operator.strip(),
            "note": note.strip(),
        }
        for field, value in expected.items():
            if not hmac.compare_digest(attestation[field], value):
                raise OperatorIdentityError(
                    f"operator attestation {field} does not match the requested action"
                )
        return status

    def assess(
        self,
        attestation: dict[str, Any] | None,
        approval: "PendingApproval",
        *,
        purpose: str,
        outcome: str,
        operator: str,
        note: str,
    ) -> OperatorIdentityStatus:
        try:
            return self.require(
                attestation,
                approval,
                purpose=purpose,
                outcome=outcome,
                operator=operator,
                note=note,
            )
        except (OperatorIdentityError, TypeError, ValueError, OverflowError) as exc:
            return OperatorIdentityStatus(False, "invalid", str(exc))


def sign_operator_action(
    approval: "PendingApproval",
    private_key_path: str | Path,
    passphrase: bytes,
    *,
    purpose: str,
    outcome: str,
    operator: str,
    note: str,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """Sign one exact operator decision or reconciliation statement."""

    if purpose not in _PURPOSES:
        raise OperatorIdentityError(f"unsupported operator purpose: {purpose}")
    operator = _bounded_text(operator.strip(), "operator", _MAX_OPERATOR_CHARS)
    note = _bounded_text(note.strip(), "note", _MAX_NOTE_CHARS)
    outcome = _bounded_text(outcome.strip(), "outcome", 64)
    key = _load_private_key(private_key_path, passphrase)
    statement = {
        "schema_name": ATTESTATION_SCHEMA,
        "schema_version": ATTESTATION_VERSION,
        "algorithm": ALGORITHM,
        "purpose": purpose,
        "key_id": public_key_id(key.public_key()),
        "signed_at": _timestamp(signed_at or utc_now(), "signed_at"),
        "operator": operator,
        "note": note,
        "outcome": outcome,
        "approval_id": approval.approval_id,
        "action_id": approval.action_id,
        "request_id": approval.request_id,
        "authorization_hash": approval.authorization_hash,
    }
    signature = key.sign(_statement_bytes(statement))
    return {
        **statement,
        "signature": "base64:" + base64.b64encode(signature).decode("ascii"),
    }


def public_key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sha256_of({"algorithm": ALGORITHM, "public_key": raw.hex()})


def unsigned_status(operator: str = "") -> OperatorIdentityStatus:
    return OperatorIdentityStatus(
        False,
        "unsigned",
        "operator identity is asserted but not cryptographically bound",
        operator=operator,
    )


def validate_external_trust_specs(
    specs: Iterable[str | Path], state_root: str | Path
) -> None:
    """Refuse trust roots stored inside mutable harness state."""
    root = Path(state_root).resolve()
    for raw_spec in specs:
        spec = str(raw_spec)
        _, separator, raw_path = spec.partition("=")
        if not separator or not raw_path.strip():
            raise OperatorIdentityError(
                "trusted operator keys must use IDENTITY=PUBLIC_KEY.pem"
            )
        candidate = Path(raw_path.strip()).resolve()
        if candidate == root or candidate.is_relative_to(root):
            raise OperatorIdentityError(
                "trusted operator public keys must be stored outside the workdir"
            )


def _validate_binding(attestation: dict[str, Any], approval: "PendingApproval") -> None:
    expected = {
        "approval_id": approval.approval_id,
        "action_id": approval.action_id,
        "request_id": approval.request_id,
        "authorization_hash": approval.authorization_hash,
    }
    for field, value in expected.items():
        if not hmac.compare_digest(attestation[field], value):
            raise OperatorIdentityError(
                f"operator attestation {field} does not match approval authority"
            )
    signed_at = _parsed_timestamp(attestation["signed_at"], "signed_at")
    created_at = _parsed_timestamp(approval.created_at, "approval created_at")
    if signed_at < created_at:
        raise OperatorIdentityError("operator signature predates approval creation")
    if signed_at > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise OperatorIdentityError("operator signature time is too far in the future")
    if attestation["purpose"] == DECISION_PURPOSE and approval.expires_at:
        expires_at = _parsed_timestamp(approval.expires_at, "approval expires_at")
        if signed_at >= expires_at:
            raise OperatorIdentityError("operator decision was signed after approval expiry")
    if attestation["purpose"] == RECONCILIATION_PURPOSE and approval.decided_at:
        decided_at = _parsed_timestamp(approval.decided_at, "approval decided_at")
        if signed_at < decided_at:
            raise OperatorIdentityError(
                "reconciliation signature predates the approval decision"
            )


def _validate_attestation(attestation: dict[str, Any]) -> None:
    if set(attestation) != _FIELDS:
        raise OperatorIdentityError("operator attestation fields do not match the schema")
    if attestation.get("schema_name") != ATTESTATION_SCHEMA:
        raise OperatorIdentityError("unsupported operator attestation schema")
    if attestation.get("schema_version") != ATTESTATION_VERSION:
        raise OperatorIdentityError("unsupported operator attestation version")
    if attestation.get("algorithm") != ALGORITHM:
        raise OperatorIdentityError("unsupported operator attestation algorithm")
    if attestation.get("purpose") not in _PURPOSES:
        raise OperatorIdentityError("unsupported operator attestation purpose")
    for field in (
        "key_id",
        "operator",
        "note",
        "outcome",
        "approval_id",
        "action_id",
        "request_id",
        "authorization_hash",
        "signature",
    ):
        _bounded_text(attestation.get(field), field, _MAX_NOTE_CHARS)
    _timestamp(attestation.get("signed_at"), "signed_at")
    if not _is_sha256(attestation["key_id"]):
        raise OperatorIdentityError("operator attestation key id is invalid")
    if not _is_sha256(attestation["authorization_hash"]):
        raise OperatorIdentityError("operator authorization hash is invalid")


def _load_private_key(path: str | Path, passphrase: bytes) -> Ed25519PrivateKey:
    if not passphrase:
        raise OperatorIdentityError("private-key passphrase must be non-empty")
    source = Path(path)
    try:
        key = serialization.load_pem_private_key(
            _read_limited(source, "private key"), password=passphrase
        )
    except (OSError, TypeError, ValueError) as exc:
        raise OperatorIdentityError(
            f"cannot load encrypted Ed25519 private key {source}"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise OperatorIdentityError("operator key must be an Ed25519 private key")
    return key


def _load_public_key(path: str | Path) -> Ed25519PublicKey:
    source = Path(path)
    try:
        key = serialization.load_pem_public_key(_read_limited(source, "public key"))
    except (OSError, TypeError, ValueError) as exc:
        raise OperatorIdentityError(f"cannot load operator public key {source}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise OperatorIdentityError(f"trusted operator key must be Ed25519: {source}")
    return key


def _read_limited(path: Path, label: str) -> bytes:
    try:
        with path.open("rb") as handle:
            value = handle.read(_MAX_KEY_BYTES + 1)
    except OSError as exc:
        raise OperatorIdentityError(f"cannot read {label} {path}") from exc
    if len(value) > _MAX_KEY_BYTES:
        raise OperatorIdentityError(f"{label} file is too large: {path}")
    return value


def _statement_bytes(statement: dict[str, Any]) -> bytes:
    return _DOMAIN + canonical_json(statement).encode("utf-8")


def _decode_signature(value: str) -> bytes:
    if not value.startswith("base64:"):
        raise OperatorIdentityError("operator signature encoding is invalid")
    try:
        signature = base64.b64decode(value[7:].encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise OperatorIdentityError("operator signature encoding is invalid") from exc
    if len(signature) != 64:
        raise OperatorIdentityError("Ed25519 signature must be 64 bytes")
    return signature


def _bounded_text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OperatorIdentityError(f"{field} must be non-empty text")
    if len(value) > maximum:
        raise OperatorIdentityError(f"{field} exceeds {maximum} characters")
    return value


def _timestamp(value: Any, field: str) -> str:
    text = _bounded_text(value, field, 128)
    _parsed_timestamp(text, field)
    return text


def _parsed_timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperatorIdentityError(f"{field} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OperatorIdentityError(f"{field} must include a timezone")
    return parsed


def _is_sha256(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value[7:]
    return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)
