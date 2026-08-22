"""Durable continuity for the complete runtime authority profile."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .contracts import utc_now
from .operator_identity import OperatorIdentityError, OperatorTrustPolicy
from .persistence import (
    atomic_write_json,
    exclusive_file_lock,
    prepare_storage_root,
    read_json,
)

AUTHORITY_PROFILE_SCHEMA = "defiant.authority.profile"
AUTHORITY_PROFILE_VERSION = "0.1.0"

_STATE_FIELDS = {
    "schema_name",
    "schema_version",
    "generation",
    "enrolled_at",
    "updated_at",
    "initial_profile_hash",
    "profile_hash",
    "transitions",
    "pending_rotation",
}
_TRANSITION_FIELDS = {
    "from_generation",
    "to_generation",
    "from_profile_hash",
    "to_profile_hash",
    "operator",
    "note",
    "requested_at",
    "attestation",
}
_MAX_STATE_BYTES = 1024 * 1024
_MAX_TRANSITIONS = 1024
_MAX_OPERATOR_CHARS = 256
_MAX_NOTE_CHARS = 4096


class AuthorityProfileError(OperatorIdentityError):
    """Durable authority-profile continuity could not be established safely."""


@dataclass(frozen=True)
class AuthorityProfileState:
    generation: int
    enrolled_at: str
    updated_at: str
    initial_profile_hash: str
    profile_hash: str
    transitions: list[dict[str, Any]]
    pending_rotation: dict[str, Any] | None = None

    @classmethod
    def enrolled(cls, profile_hash: str) -> "AuthorityProfileState":
        profile_hash = _hash(profile_hash, "profile_hash")
        now = utc_now()
        return cls(
            generation=1,
            enrolled_at=now,
            updated_at=now,
            initial_profile_hash=profile_hash,
            profile_hash=profile_hash,
            transitions=[],
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AuthorityProfileState":
        if set(raw) != _STATE_FIELDS:
            raise AuthorityProfileError(
                "authority profile state fields do not match the schema"
            )
        if raw.get("schema_name") != AUTHORITY_PROFILE_SCHEMA:
            raise AuthorityProfileError("unsupported authority profile schema")
        if raw.get("schema_version") != AUTHORITY_PROFILE_VERSION:
            raise AuthorityProfileError("unsupported authority profile version")
        generation = raw.get("generation")
        if type(generation) is not int or generation < 1:
            raise AuthorityProfileError(
                "authority profile generation must be a positive integer"
            )
        enrolled_at = _timestamp(raw.get("enrolled_at"), "enrolled_at")
        updated_at = _timestamp(raw.get("updated_at"), "updated_at")
        if updated_at < enrolled_at:
            raise AuthorityProfileError(
                "authority profile updated_at precedes enrollment"
            )
        initial_hash = _hash(raw.get("initial_profile_hash"), "initial_profile_hash")
        current_hash = _hash(raw.get("profile_hash"), "profile_hash")
        transitions = raw.get("transitions")
        if not isinstance(transitions, list):
            raise AuthorityProfileError("authority profile transitions must be a list")
        if len(transitions) > _MAX_TRANSITIONS:
            raise AuthorityProfileError("authority profile transition limit exceeded")
        if len(transitions) != generation - 1:
            raise AuthorityProfileError(
                "authority profile transition count does not match its generation"
            )

        previous_hash = initial_hash
        previous_time = enrolled_at
        normalized: list[dict[str, Any]] = []
        for index, value in enumerate(transitions, start=1):
            transition = _transition(value, f"transition {index}")
            if (
                transition["from_generation"] != index
                or transition["to_generation"] != index + 1
            ):
                raise AuthorityProfileError(
                    f"authority profile transition {index} is not contiguous"
                )
            if not hmac.compare_digest(transition["from_profile_hash"], previous_hash):
                raise AuthorityProfileError(
                    f"authority profile transition {index} does not bind its predecessor"
                )
            transition_time = _timestamp(
                transition["requested_at"], f"transition {index} requested_at"
            )
            if transition_time < previous_time:
                raise AuthorityProfileError(
                    f"authority profile transition {index} predates its predecessor"
                )
            normalized.append(transition)
            previous_hash = transition["to_profile_hash"]
            previous_time = transition_time
        if not hmac.compare_digest(previous_hash, current_hash):
            raise AuthorityProfileError(
                "authority profile transition chain does not reach current profile"
            )
        if normalized and updated_at != previous_time:
            raise AuthorityProfileError(
                "authority profile updated_at does not match its latest transition"
            )
        if not normalized and updated_at != enrolled_at:
            raise AuthorityProfileError(
                "initial authority profile timestamps do not match"
            )

        pending_raw = raw.get("pending_rotation")
        pending = None
        if pending_raw is not None:
            pending = _transition(pending_raw, "pending rotation")
            if (
                pending["from_generation"] != generation
                or pending["to_generation"] != generation + 1
                or not hmac.compare_digest(pending["from_profile_hash"], current_hash)
            ):
                raise AuthorityProfileError(
                    "pending authority profile rotation does not bind current generation"
                )
            if _timestamp(pending["requested_at"], "pending requested_at") < updated_at:
                raise AuthorityProfileError(
                    "pending authority profile rotation predates current generation"
                )

        return cls(
            generation=generation,
            enrolled_at=raw["enrolled_at"],
            updated_at=raw["updated_at"],
            initial_profile_hash=initial_hash,
            profile_hash=current_hash,
            transitions=normalized,
            pending_rotation=pending,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": AUTHORITY_PROFILE_SCHEMA,
            "schema_version": AUTHORITY_PROFILE_VERSION,
            "generation": self.generation,
            "enrolled_at": self.enrolled_at,
            "updated_at": self.updated_at,
            "initial_profile_hash": self.initial_profile_hash,
            "profile_hash": self.profile_hash,
            "transitions": self.transitions,
            "pending_rotation": self.pending_rotation,
        }

    def verify(self, operator_trust: OperatorTrustPolicy | None) -> None:
        for index, transition in enumerate(self.transitions, start=1):
            self._verify_transition(transition, operator_trust, f"transition {index}")
        if self.pending_rotation is not None:
            self._verify_transition(
                self.pending_rotation, operator_trust, "pending rotation"
            )

    @staticmethod
    def _verify_transition(
        transition: dict[str, Any],
        operator_trust: OperatorTrustPolicy | None,
        label: str,
    ) -> None:
        attestation = transition["attestation"]
        if attestation is None:
            # Unsigned deployments retain an explicit operator and note. Historical
            # unsigned generations remain readable if signed trust is later enrolled.
            return
        if operator_trust is None:
            raise AuthorityProfileError(
                f"{label} is signed but no trusted operator keys are configured"
            )
        try:
            operator_trust.require_authority_profile_transition(
                attestation,
                from_generation=transition["from_generation"],
                from_profile_hash=transition["from_profile_hash"],
                to_profile_hash=transition["to_profile_hash"],
                operator=transition["operator"],
                note=transition["note"],
            )
        except OperatorIdentityError as exc:
            raise AuthorityProfileError(str(exc)) from exc

    def projection(self, *, verification: str) -> dict[str, Any]:
        pending = self.pending_rotation
        signed = sum(1 for item in self.transitions if item["attestation"] is not None)
        unsigned = len(self.transitions) - signed
        return {
            "state": "rotation_required" if pending else "ready",
            "generation": self.generation,
            "profile_hash": self.profile_hash,
            "verification": verification,
            "rotation_required": pending is not None,
            "pending_profile_hash": (
                pending["to_profile_hash"] if pending is not None else None
            ),
            "pending_assurance": (
                "signed_trusted"
                if pending is not None and pending["attestation"] is not None
                else "unsigned"
                if pending is not None
                else "not_applicable"
            ),
            "signed_transition_count": signed,
            "unsigned_transition_count": unsigned,
        }


class AuthorityProfileStore:
    """Pin, stage, and atomically activate runtime authority profiles."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self) -> AuthorityProfileState | None:
        if not self.path.exists():
            return None
        try:
            if self.path.stat().st_size > _MAX_STATE_BYTES:
                raise AuthorityProfileError("authority profile state is too large")
            return AuthorityProfileState.from_dict(read_json(self.path))
        except AuthorityProfileError:
            raise
        except (OSError, RuntimeError) as exc:
            raise AuthorityProfileError(str(exc)) from exc

    def resolve_for_authority(
        self,
        profile_hash: str,
        operator_trust: OperatorTrustPolicy | None,
    ) -> AuthorityProfileState:
        """Enroll or activate only the exact configured profile under the caller lock."""
        profile_hash = _hash(profile_hash, "configured profile_hash")
        self._require_enrolled_trust(operator_trust)
        prepare_storage_root(self.path.parent)
        with exclusive_file_lock(self.path):
            state = self.get()
            if state is None:
                state = AuthorityProfileState.enrolled(profile_hash)
                atomic_write_json(self.path, state.to_dict())
                return state
            state.verify(operator_trust)
            if hmac.compare_digest(state.profile_hash, profile_hash):
                return state
            pending = state.pending_rotation
            if pending is not None and hmac.compare_digest(
                pending["to_profile_hash"], profile_hash
            ):
                if operator_trust is not None and pending["attestation"] is None:
                    raise AuthorityProfileError(
                        "signed operator trust is enrolled; pending authority profile "
                        "rotation must have a trusted signature"
                    )
                updated = AuthorityProfileState.from_dict(
                    {
                        **state.to_dict(),
                        "generation": state.generation + 1,
                        "updated_at": pending["requested_at"],
                        "profile_hash": pending["to_profile_hash"],
                        "transitions": [*state.transitions, pending],
                        "pending_rotation": None,
                    }
                )
                updated.verify(operator_trust)
                atomic_write_json(self.path, updated.to_dict())
                return updated
            pending_detail = (
                f"; approved pending profile is {pending['to_profile_hash']}"
                if pending is not None
                else ""
            )
            raise AuthorityProfileError(
                "configured authority profile does not match durable enrollment: "
                f"configured {profile_hash}, enrolled {state.profile_hash}"
                f"{pending_detail}; authorize an explicit authority-profile rotation"
            )

    def request_rotation(
        self,
        to_profile_hash: str,
        *,
        operator: str,
        note: str,
        operator_trust: OperatorTrustPolicy | None,
        attestation: dict[str, Any] | None = None,
    ) -> AuthorityProfileState:
        """Durably stage one exact next generation without activating it."""
        target = _hash(to_profile_hash, "to_profile_hash")
        self._require_enrolled_trust(operator_trust)
        operator = _text(operator, "operator", _MAX_OPERATOR_CHARS)
        note = _text(note, "note", _MAX_NOTE_CHARS)
        with exclusive_file_lock(self.path):
            state = self.get()
            if state is None:
                raise AuthorityProfileError(
                    "authority profile is not enrolled; start an authority path once first"
                )
            state.verify(operator_trust)
            if hmac.compare_digest(state.profile_hash, target):
                if state.pending_rotation is None:
                    return state
                raise AuthorityProfileError(
                    "target profile is already active but another rotation is pending"
                )
            if operator_trust is None:
                if attestation is not None:
                    raise AuthorityProfileError(
                        "trusted operator keys are required to store a signed rotation"
                    )
                requested_at = utc_now()
            else:
                if not isinstance(attestation, dict):
                    raise AuthorityProfileError(
                        "signed operator trust is enrolled; a signed profile rotation "
                        "is required"
                    )
                try:
                    operator_trust.require_authority_profile_transition(
                        attestation,
                        from_generation=state.generation,
                        from_profile_hash=state.profile_hash,
                        to_profile_hash=target,
                        operator=operator,
                        note=note,
                    )
                except OperatorIdentityError as exc:
                    raise AuthorityProfileError(str(exc)) from exc
                requested_at = attestation["signed_at"]
            transition = _transition(
                {
                    "from_generation": state.generation,
                    "to_generation": state.generation + 1,
                    "from_profile_hash": state.profile_hash,
                    "to_profile_hash": target,
                    "operator": operator,
                    "note": note,
                    "requested_at": requested_at,
                    "attestation": attestation,
                },
                "pending rotation",
            )
            pending = state.pending_rotation
            if pending is not None:
                same_request = all(
                    pending[field] == transition[field]
                    for field in (
                        "from_generation",
                        "to_generation",
                        "from_profile_hash",
                        "to_profile_hash",
                        "operator",
                        "note",
                    )
                )
                if same_request:
                    return state
                raise AuthorityProfileError(
                    "a different authority profile rotation is already pending"
                )
            updated = AuthorityProfileState.from_dict(
                {**state.to_dict(), "pending_rotation": transition}
            )
            updated.verify(operator_trust)
            atomic_write_json(self.path, updated.to_dict())
            return updated

    def _require_enrolled_trust(
        self, operator_trust: OperatorTrustPolicy | None
    ) -> None:
        trust_path = self.path.with_name("operator_trust.json")
        if not trust_path.exists():
            return
        if operator_trust is None:
            raise AuthorityProfileError(
                "signed operator trust is durably enrolled; trusted operator keys "
                "are required for authority profile resolution or rotation"
            )
        from .operator_trust_state import OperatorTrustStateStore

        try:
            state = OperatorTrustStateStore(trust_path).get()
            if state is None:
                raise AuthorityProfileError("durable operator trust state is missing")
            state.verify(operator_trust)
        except RuntimeError as exc:
            raise AuthorityProfileError(str(exc)) from exc


def _transition(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _TRANSITION_FIELDS:
        raise AuthorityProfileError(f"{field} fields do not match the schema")
    from_generation = value.get("from_generation")
    to_generation = value.get("to_generation")
    if type(from_generation) is not int or from_generation < 1:
        raise AuthorityProfileError(f"{field} from_generation is invalid")
    if type(to_generation) is not int or to_generation != from_generation + 1:
        raise AuthorityProfileError(f"{field} generation is not contiguous")
    from_hash = _hash(value.get("from_profile_hash"), f"{field} from_profile_hash")
    to_hash = _hash(value.get("to_profile_hash"), f"{field} to_profile_hash")
    if hmac.compare_digest(from_hash, to_hash):
        raise AuthorityProfileError(f"{field} must change the profile hash")
    operator = _text(value.get("operator"), f"{field} operator", _MAX_OPERATOR_CHARS)
    note = _text(value.get("note"), f"{field} note", _MAX_NOTE_CHARS)
    requested_at = value.get("requested_at")
    _timestamp(requested_at, f"{field} requested_at")
    attestation = value.get("attestation")
    if attestation is not None and not isinstance(attestation, dict):
        raise AuthorityProfileError(f"{field} attestation must be an object or null")
    if attestation is not None:
        expected = {
            "from_generation": from_generation,
            "to_generation": to_generation,
            "from_profile_hash": from_hash,
            "to_profile_hash": to_hash,
            "operator": operator,
            "note": note,
            "signed_at": requested_at,
        }
        if any(
            attestation.get(key) != expected_value
            for key, expected_value in expected.items()
        ):
            raise AuthorityProfileError(f"{field} attestation does not bind its fields")
    return {
        "from_generation": from_generation,
        "to_generation": to_generation,
        "from_profile_hash": from_hash,
        "to_profile_hash": to_hash,
        "operator": operator,
        "note": note,
        "requested_at": requested_at,
        "attestation": dict(attestation) if attestation is not None else None,
    }


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise AuthorityProfileError(f"{field} is not a sha256 identifier")
    digest = value.removeprefix("sha256:")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise AuthorityProfileError(f"{field} is not a sha256 identifier")
    return value


def _text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise AuthorityProfileError(f"{field} must be non-empty trimmed text")
    if len(value) > maximum:
        raise AuthorityProfileError(f"{field} exceeds {maximum} characters")
    return value


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise AuthorityProfileError(f"{field} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorityProfileError(f"{field} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorityProfileError(f"{field} must include a timezone")
    if parsed > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise AuthorityProfileError(f"{field} is too far in the future")
    return parsed
