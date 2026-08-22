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
AUTHORIZATION_RECONCILIATION_SCHEMA = "defiant.operator.authorization_reconciliation"
AUTHORIZATION_RECONCILIATION_VERSION = "0.1.0"
AUTHORIZATION_RECONCILIATION_PURPOSE = "authorization_reconciliation"
_AUTHORIZATION_RECONCILIATION_DOMAIN = (
    b"Defiant Agent Harness authorization reconciliation v0.1.0\x00"
)
TRUST_TRANSITION_SCHEMA = "defiant.operator.trust_transition"
TRUST_TRANSITION_VERSION = "0.1.0"
TRUST_TRANSITION_PURPOSE = "operator_trust_rotation"
_TRUST_DOMAIN = b"Defiant Agent Harness operator trust transition v0.1.0\x00"
AUTHORITY_PROFILE_TRANSITION_SCHEMA = "defiant.operator.authority_profile_transition"
AUTHORITY_PROFILE_TRANSITION_VERSION = "0.1.0"
AUTHORITY_PROFILE_TRANSITION_PURPOSE = "authority_profile_rotation"
_AUTHORITY_PROFILE_DOMAIN = (
    b"Defiant Agent Harness authority profile transition v0.1.0\x00"
)
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
_TRUST_TRANSITION_FIELDS = {
    "schema_name",
    "schema_version",
    "algorithm",
    "purpose",
    "key_id",
    "signed_at",
    "operator",
    "note",
    "from_generation",
    "to_generation",
    "from_bindings_hash",
    "to_bindings_hash",
    "signature",
}
_AUTHORITY_PROFILE_TRANSITION_FIELDS = {
    "schema_name",
    "schema_version",
    "algorithm",
    "purpose",
    "key_id",
    "signed_at",
    "operator",
    "note",
    "from_generation",
    "to_generation",
    "from_profile_hash",
    "to_profile_hash",
    "signature",
}
_AUTHORIZATION_RECONCILIATION_FIELDS = {
    "schema_name",
    "schema_version",
    "algorithm",
    "purpose",
    "key_id",
    "signed_at",
    "operator",
    "note",
    "outcome",
    "authority_record_id",
    "authority_record_hash",
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


@dataclass(frozen=True)
class AuthorizationReconciliationSubject:
    """Exact sealed authorization requiring an operator-supplied outcome."""

    authority_record_id: str
    authority_record_hash: str
    action_id: str
    request_id: str
    authorization_hash: str
    authorized_at: str

    def __post_init__(self) -> None:
        for field in (
            "authority_record_id",
            "authority_record_hash",
            "action_id",
            "request_id",
            "authorization_hash",
            "authorized_at",
        ):
            _bounded_text(getattr(self, field), field, _MAX_NOTE_CHARS)
        for field in ("authority_record_hash", "authorization_hash"):
            if not _is_sha256(getattr(self, field)):
                raise OperatorIdentityError(f"{field} is invalid")
        _timestamp(self.authorized_at, "authorized_at")

    @classmethod
    def from_record(
        cls, record: dict[str, Any]
    ) -> "AuthorizationReconciliationSubject":
        if not isinstance(record, dict):
            raise OperatorIdentityError("authorization evidence must be an object")
        if record.get("result_status") != "skipped":
            raise OperatorIdentityError("evidence is not an execution authorization")
        if record.get("decision") != "allow":
            raise OperatorIdentityError(
                "evidence is not an approval-free execution authorization"
            )
        values = {
            "authority_record_id": record.get("record_id"),
            "authority_record_hash": record.get("record_hash"),
            "action_id": record.get("action_id"),
            "request_id": record.get("request_id"),
            "authorization_hash": record.get("authorization_hash"),
            "authorized_at": record.get("timestamp"),
        }
        return cls(**values)


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

    @property
    def bindings(self) -> dict[str, list[str]]:
        return {operator: sorted(keys) for operator, keys in sorted(self._keys.items())}

    @property
    def bindings_hash(self) -> str:
        return sha256_of(self.bindings)

    def is_additive_successor(self, newer: "OperatorTrustPolicy") -> bool:
        current = self.bindings
        candidate = newer.bindings
        if current == candidate:
            return False
        return all(
            operator in candidate and set(key_ids).issubset(candidate[operator])
            for operator, key_ids in current.items()
        )

    def verify(
        self, attestation: dict[str, Any], approval: "PendingApproval"
    ) -> OperatorIdentityStatus:
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
                name: value
                for name, value in attestation.items()
                if name != "signature"
            }
            try:
                key.verify(signature, _statement_bytes(statement))
            except InvalidSignature as exc:
                raise OperatorIdentityError(
                    "operator attestation signature is invalid"
                ) from exc
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

    def require_authorization_reconciliation(
        self,
        attestation: dict[str, Any] | None,
        subject: AuthorizationReconciliationSubject,
        *,
        outcome: str,
        operator: str,
        note: str,
    ) -> OperatorIdentityStatus:
        if not isinstance(attestation, dict):
            raise OperatorIdentityError(
                "a signed authorization reconciliation is required"
            )
        status = self.verify_authorization_reconciliation(attestation, subject)
        if not status.ok:
            raise OperatorIdentityError(status.detail)
        expected = {
            "outcome": outcome,
            "operator": operator.strip(),
            "note": note.strip(),
        }
        for field, value in expected.items():
            if not hmac.compare_digest(attestation[field], value):
                raise OperatorIdentityError(
                    f"authorization reconciliation {field} does not match"
                )
        return status

    def verify_authorization_reconciliation(
        self,
        attestation: dict[str, Any],
        subject: AuthorizationReconciliationSubject,
    ) -> OperatorIdentityStatus:
        try:
            _validate_authorization_reconciliation(attestation)
            operator = attestation["operator"]
            key_id = attestation["key_id"]
            key = self._keys.get(operator, {}).get(key_id)
            if key is None:
                raise OperatorIdentityError(
                    f"key {key_id} is not trusted for operator {operator!r}"
                )
            expected = {
                "authority_record_id": subject.authority_record_id,
                "authority_record_hash": subject.authority_record_hash,
                "action_id": subject.action_id,
                "request_id": subject.request_id,
                "authorization_hash": subject.authorization_hash,
            }
            for field, value in expected.items():
                if not hmac.compare_digest(attestation[field], value):
                    raise OperatorIdentityError(
                        f"authorization reconciliation {field} does not match authority"
                    )
            signed_at = _parsed_timestamp(attestation["signed_at"], "signed_at")
            authorized_at = _parsed_timestamp(subject.authorized_at, "authorized_at")
            if signed_at < authorized_at:
                raise OperatorIdentityError(
                    "reconciliation signature predates authorization"
                )
            if signed_at > datetime.now(timezone.utc) + timedelta(minutes=5):
                raise OperatorIdentityError(
                    "operator signature time is too far in the future"
                )
            signature = _decode_signature(attestation["signature"])
            statement = {
                name: value
                for name, value in attestation.items()
                if name != "signature"
            }
            try:
                key.verify(
                    signature,
                    _authorization_reconciliation_statement_bytes(statement),
                )
            except InvalidSignature as exc:
                raise OperatorIdentityError(
                    "authorization reconciliation signature is invalid"
                ) from exc
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

    def assess_authorization_reconciliation(
        self,
        attestation: dict[str, Any] | None,
        subject: AuthorizationReconciliationSubject,
        *,
        outcome: str,
        operator: str,
        note: str,
    ) -> OperatorIdentityStatus:
        try:
            return self.require_authorization_reconciliation(
                attestation,
                subject,
                outcome=outcome,
                operator=operator,
                note=note,
            )
        except (OperatorIdentityError, TypeError, ValueError, OverflowError) as exc:
            return OperatorIdentityStatus(False, "invalid", str(exc))

    def require_trust_transition(
        self,
        attestation: dict[str, Any] | None,
        *,
        from_generation: int,
        from_bindings_hash: str,
        to_bindings_hash: str,
        operator: str,
        note: str,
    ) -> OperatorIdentityStatus:
        if not isinstance(attestation, dict):
            raise OperatorIdentityError("a signed trust transition is required")
        _validate_trust_transition(attestation)
        expected = {
            "from_generation": from_generation,
            "to_generation": from_generation + 1,
            "from_bindings_hash": from_bindings_hash,
            "to_bindings_hash": to_bindings_hash,
            "operator": operator.strip(),
            "note": note.strip(),
        }
        for field, value in expected.items():
            supplied = attestation[field]
            if isinstance(value, str):
                matches = hmac.compare_digest(supplied, value)
            else:
                matches = supplied == value
            if not matches:
                raise OperatorIdentityError(
                    f"trust transition {field} does not match the requested rotation"
                )
        key_id = attestation["key_id"]
        key = self._keys.get(operator.strip(), {}).get(key_id)
        if key is None:
            raise OperatorIdentityError(
                f"key {key_id} is not trusted for operator {operator.strip()!r}"
            )
        signature = _decode_signature(attestation["signature"])
        statement = {
            name: value for name, value in attestation.items() if name != "signature"
        }
        try:
            key.verify(signature, _trust_statement_bytes(statement))
        except InvalidSignature as exc:
            raise OperatorIdentityError(
                "trust transition signature is invalid"
            ) from exc
        return OperatorIdentityStatus(
            True,
            "signed_trusted",
            "trust transition signature valid and operator key trusted",
            operator=operator.strip(),
            key_id=key_id,
            signed_at=attestation["signed_at"],
        )

    def require_authority_profile_transition(
        self,
        attestation: dict[str, Any] | None,
        *,
        from_generation: int,
        from_profile_hash: str,
        to_profile_hash: str,
        operator: str,
        note: str,
    ) -> OperatorIdentityStatus:
        """Verify a rotation statement against the currently trusted operator."""
        if not isinstance(attestation, dict):
            raise OperatorIdentityError(
                "a signed authority profile transition is required"
            )
        _validate_authority_profile_transition(attestation)
        expected = {
            "from_generation": from_generation,
            "to_generation": from_generation + 1,
            "from_profile_hash": from_profile_hash,
            "to_profile_hash": to_profile_hash,
            "operator": operator.strip(),
            "note": note.strip(),
        }
        for field, value in expected.items():
            supplied = attestation[field]
            matches = (
                hmac.compare_digest(supplied, value)
                if isinstance(value, str)
                else supplied == value
            )
            if not matches:
                raise OperatorIdentityError(
                    f"authority profile transition {field} does not match"
                )
        key_id = attestation["key_id"]
        key = self._keys.get(operator.strip(), {}).get(key_id)
        if key is None:
            raise OperatorIdentityError(
                f"key {key_id} is not trusted for operator {operator.strip()!r}"
            )
        signature = _decode_signature(attestation["signature"])
        statement = {
            name: value for name, value in attestation.items() if name != "signature"
        }
        try:
            key.verify(signature, _authority_profile_statement_bytes(statement))
        except InvalidSignature as exc:
            raise OperatorIdentityError(
                "authority profile transition signature is invalid"
            ) from exc
        return OperatorIdentityStatus(
            True,
            "signed_trusted",
            "authority profile transition signature valid and operator key trusted",
            operator=operator.strip(),
            key_id=key_id,
            signed_at=attestation["signed_at"],
        )


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


def sign_authorization_reconciliation(
    subject: AuthorizationReconciliationSubject,
    private_key_path: str | Path,
    passphrase: bytes,
    *,
    outcome: str,
    operator: str,
    note: str,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """Sign one explicit outcome for a sealed approval-free authorization."""

    operator = _bounded_text(operator.strip(), "operator", _MAX_OPERATOR_CHARS)
    note = _bounded_text(note.strip(), "note", _MAX_NOTE_CHARS)
    outcome = _bounded_text(outcome.strip(), "outcome", 64)
    if outcome not in {"succeeded", "failed", "not_executed"}:
        raise OperatorIdentityError("invalid authorization reconciliation outcome")
    key = _load_private_key(private_key_path, passphrase)
    statement = {
        "schema_name": AUTHORIZATION_RECONCILIATION_SCHEMA,
        "schema_version": AUTHORIZATION_RECONCILIATION_VERSION,
        "algorithm": ALGORITHM,
        "purpose": AUTHORIZATION_RECONCILIATION_PURPOSE,
        "key_id": public_key_id(key.public_key()),
        "signed_at": _timestamp(signed_at or utc_now(), "signed_at"),
        "operator": operator,
        "note": note,
        "outcome": outcome,
        "authority_record_id": subject.authority_record_id,
        "authority_record_hash": subject.authority_record_hash,
        "action_id": subject.action_id,
        "request_id": subject.request_id,
        "authorization_hash": subject.authorization_hash,
    }
    signature = key.sign(_authorization_reconciliation_statement_bytes(statement))
    return {
        **statement,
        "signature": "base64:" + base64.b64encode(signature).decode("ascii"),
    }


def sign_trust_transition(
    private_key_path: str | Path,
    passphrase: bytes,
    *,
    from_generation: int,
    from_bindings_hash: str,
    to_bindings_hash: str,
    operator: str,
    note: str,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """Sign one additive operator trust-policy generation transition."""
    if type(from_generation) is not int or from_generation < 1:
        raise OperatorIdentityError("from_generation must be a positive integer")
    if not _is_sha256(from_bindings_hash) or not _is_sha256(to_bindings_hash):
        raise OperatorIdentityError("trust transition binding hashes are invalid")
    if hmac.compare_digest(from_bindings_hash, to_bindings_hash):
        raise OperatorIdentityError("trust transition must change the bindings")
    operator = _bounded_text(operator.strip(), "operator", _MAX_OPERATOR_CHARS)
    note = _bounded_text(note.strip(), "note", _MAX_NOTE_CHARS)
    key = _load_private_key(private_key_path, passphrase)
    statement = {
        "schema_name": TRUST_TRANSITION_SCHEMA,
        "schema_version": TRUST_TRANSITION_VERSION,
        "algorithm": ALGORITHM,
        "purpose": TRUST_TRANSITION_PURPOSE,
        "key_id": public_key_id(key.public_key()),
        "signed_at": _timestamp(signed_at or utc_now(), "signed_at"),
        "operator": operator,
        "note": note,
        "from_generation": from_generation,
        "to_generation": from_generation + 1,
        "from_bindings_hash": from_bindings_hash,
        "to_bindings_hash": to_bindings_hash,
    }
    signature = key.sign(_trust_statement_bytes(statement))
    return {
        **statement,
        "signature": "base64:" + base64.b64encode(signature).decode("ascii"),
    }


def sign_authority_profile_transition(
    private_key_path: str | Path,
    passphrase: bytes,
    *,
    from_generation: int,
    from_profile_hash: str,
    to_profile_hash: str,
    operator: str,
    note: str,
    signed_at: str | None = None,
) -> dict[str, Any]:
    """Sign one exact durable authority-profile generation transition."""
    if type(from_generation) is not int or from_generation < 1:
        raise OperatorIdentityError("from_generation must be a positive integer")
    if not _is_sha256(from_profile_hash) or not _is_sha256(to_profile_hash):
        raise OperatorIdentityError("authority profile hashes are invalid")
    if hmac.compare_digest(from_profile_hash, to_profile_hash):
        raise OperatorIdentityError("authority profile rotation must change the hash")
    operator = _bounded_text(operator.strip(), "operator", _MAX_OPERATOR_CHARS)
    note = _bounded_text(note.strip(), "note", _MAX_NOTE_CHARS)
    key = _load_private_key(private_key_path, passphrase)
    statement = {
        "schema_name": AUTHORITY_PROFILE_TRANSITION_SCHEMA,
        "schema_version": AUTHORITY_PROFILE_TRANSITION_VERSION,
        "algorithm": ALGORITHM,
        "purpose": AUTHORITY_PROFILE_TRANSITION_PURPOSE,
        "key_id": public_key_id(key.public_key()),
        "signed_at": _timestamp(signed_at or utc_now(), "signed_at"),
        "operator": operator,
        "note": note,
        "from_generation": from_generation,
        "to_generation": from_generation + 1,
        "from_profile_hash": from_profile_hash,
        "to_profile_hash": to_profile_hash,
    }
    signature = key.sign(_authority_profile_statement_bytes(statement))
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
            raise OperatorIdentityError(
                "operator decision was signed after approval expiry"
            )
    if attestation["purpose"] == RECONCILIATION_PURPOSE and approval.decided_at:
        decided_at = _parsed_timestamp(approval.decided_at, "approval decided_at")
        if signed_at < decided_at:
            raise OperatorIdentityError(
                "reconciliation signature predates the approval decision"
            )


def _validate_attestation(attestation: dict[str, Any]) -> None:
    if set(attestation) != _FIELDS:
        raise OperatorIdentityError(
            "operator attestation fields do not match the schema"
        )
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


def _validate_authorization_reconciliation(attestation: dict[str, Any]) -> None:
    if set(attestation) != _AUTHORIZATION_RECONCILIATION_FIELDS:
        raise OperatorIdentityError(
            "authorization reconciliation fields do not match the schema"
        )
    if attestation.get("schema_name") != AUTHORIZATION_RECONCILIATION_SCHEMA:
        raise OperatorIdentityError("unsupported authorization reconciliation schema")
    if attestation.get("schema_version") != AUTHORIZATION_RECONCILIATION_VERSION:
        raise OperatorIdentityError("unsupported authorization reconciliation version")
    if attestation.get("algorithm") != ALGORITHM:
        raise OperatorIdentityError(
            "unsupported authorization reconciliation algorithm"
        )
    if attestation.get("purpose") != AUTHORIZATION_RECONCILIATION_PURPOSE:
        raise OperatorIdentityError("unsupported authorization reconciliation purpose")
    for field in (
        "key_id",
        "operator",
        "note",
        "outcome",
        "authority_record_id",
        "authority_record_hash",
        "action_id",
        "request_id",
        "authorization_hash",
        "signature",
    ):
        _bounded_text(attestation.get(field), field, _MAX_NOTE_CHARS)
    if attestation["outcome"] not in {"succeeded", "failed", "not_executed"}:
        raise OperatorIdentityError("invalid authorization reconciliation outcome")
    _timestamp(attestation.get("signed_at"), "signed_at")
    for field in ("key_id", "authority_record_hash", "authorization_hash"):
        if not _is_sha256(attestation[field]):
            raise OperatorIdentityError(
                f"authorization reconciliation {field} is invalid"
            )
    _decode_signature(attestation["signature"])


def _validate_trust_transition(attestation: dict[str, Any]) -> None:
    if set(attestation) != _TRUST_TRANSITION_FIELDS:
        raise OperatorIdentityError("trust transition fields do not match the schema")
    if attestation.get("schema_name") != TRUST_TRANSITION_SCHEMA:
        raise OperatorIdentityError("unsupported trust transition schema")
    if attestation.get("schema_version") != TRUST_TRANSITION_VERSION:
        raise OperatorIdentityError("unsupported trust transition version")
    if attestation.get("algorithm") != ALGORITHM:
        raise OperatorIdentityError("unsupported trust transition algorithm")
    if attestation.get("purpose") != TRUST_TRANSITION_PURPOSE:
        raise OperatorIdentityError("unsupported trust transition purpose")
    for field in (
        "key_id",
        "operator",
        "note",
        "from_bindings_hash",
        "to_bindings_hash",
        "signature",
    ):
        _bounded_text(attestation.get(field), field, _MAX_NOTE_CHARS)
    for field in ("from_generation", "to_generation"):
        value = attestation.get(field)
        if type(value) is not int or value < 1:
            raise OperatorIdentityError(f"{field} must be a positive integer")
    if attestation["to_generation"] != attestation["from_generation"] + 1:
        raise OperatorIdentityError("trust transition generation is not contiguous")
    if not _is_sha256(attestation["key_id"]):
        raise OperatorIdentityError("trust transition key id is invalid")
    if not _is_sha256(attestation["from_bindings_hash"]) or not _is_sha256(
        attestation["to_bindings_hash"]
    ):
        raise OperatorIdentityError("trust transition binding hash is invalid")
    signed_at = _parsed_timestamp(
        _timestamp(attestation.get("signed_at"), "signed_at"), "signed_at"
    )
    if signed_at > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise OperatorIdentityError("trust transition time is too far in the future")
    _decode_signature(attestation["signature"])


def _validate_authority_profile_transition(attestation: dict[str, Any]) -> None:
    if set(attestation) != _AUTHORITY_PROFILE_TRANSITION_FIELDS:
        raise OperatorIdentityError(
            "authority profile transition fields do not match the schema"
        )
    if attestation.get("schema_name") != AUTHORITY_PROFILE_TRANSITION_SCHEMA:
        raise OperatorIdentityError("unsupported authority profile transition schema")
    if attestation.get("schema_version") != AUTHORITY_PROFILE_TRANSITION_VERSION:
        raise OperatorIdentityError("unsupported authority profile transition version")
    if attestation.get("algorithm") != ALGORITHM:
        raise OperatorIdentityError(
            "unsupported authority profile transition algorithm"
        )
    if attestation.get("purpose") != AUTHORITY_PROFILE_TRANSITION_PURPOSE:
        raise OperatorIdentityError("unsupported authority profile transition purpose")
    for field in (
        "key_id",
        "operator",
        "note",
        "from_profile_hash",
        "to_profile_hash",
        "signature",
    ):
        _bounded_text(attestation.get(field), field, _MAX_NOTE_CHARS)
    for field in ("from_generation", "to_generation"):
        value = attestation.get(field)
        if type(value) is not int or value < 1:
            raise OperatorIdentityError(f"{field} must be a positive integer")
    if attestation["to_generation"] != attestation["from_generation"] + 1:
        raise OperatorIdentityError(
            "authority profile transition generation is not contiguous"
        )
    for field in ("key_id", "from_profile_hash", "to_profile_hash"):
        if not _is_sha256(attestation[field]):
            raise OperatorIdentityError(
                f"authority profile transition {field} is invalid"
            )
    if hmac.compare_digest(
        attestation["from_profile_hash"], attestation["to_profile_hash"]
    ):
        raise OperatorIdentityError("authority profile transition must change the hash")
    signed_at = _parsed_timestamp(
        _timestamp(attestation.get("signed_at"), "signed_at"), "signed_at"
    )
    if signed_at > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise OperatorIdentityError(
            "authority profile transition time is too far in the future"
        )
    _decode_signature(attestation["signature"])


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
        raise OperatorIdentityError(
            f"cannot load operator public key {source}"
        ) from exc
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


def _authorization_reconciliation_statement_bytes(
    statement: dict[str, Any],
) -> bytes:
    return _AUTHORIZATION_RECONCILIATION_DOMAIN + canonical_json(statement).encode(
        "utf-8"
    )


def _trust_statement_bytes(statement: dict[str, Any]) -> bytes:
    return _TRUST_DOMAIN + canonical_json(statement).encode("utf-8")


def _authority_profile_statement_bytes(statement: dict[str, Any]) -> bytes:
    return _AUTHORITY_PROFILE_DOMAIN + canonical_json(statement).encode("utf-8")


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
