"""Durable fail-closed enrollment for signed operator authority."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from .contracts import sha256_of, utc_now
from .operator_identity import (
    OperatorIdentityError,
    OperatorTrustPolicy,
)
from .persistence import atomic_write_json, exclusive_file_lock, read_json

TRUST_STATE_SCHEMA = "defiant.operator.trust_state"
TRUST_STATE_VERSION = "0.1.0"
SIGNED_REQUIRED = "signed_required"

_STATE_FIELDS = {
    "schema_name",
    "schema_version",
    "mode",
    "generation",
    "enrolled_at",
    "updated_at",
    "initial_bindings",
    "initial_bindings_hash",
    "bindings",
    "bindings_hash",
    "transitions",
}
_TRANSITION_FIELDS = {"attestation", "bindings"}
_MAX_STATE_BYTES = 1024 * 1024
_MAX_OPERATORS = 256
_MAX_KEYS = 1024
_MAX_TRANSITIONS = 1024


class OperatorTrustStateError(OperatorIdentityError):
    """Durable operator trust could not be established safely."""


@dataclass(frozen=True)
class OperatorTrustState:
    generation: int
    enrolled_at: str
    updated_at: str
    initial_bindings: dict[str, list[str]]
    initial_bindings_hash: str
    bindings: dict[str, list[str]]
    bindings_hash: str
    transitions: list[dict[str, Any]]

    @classmethod
    def enrolled(cls, policy: OperatorTrustPolicy) -> "OperatorTrustState":
        now = utc_now()
        return cls(
            generation=1,
            enrolled_at=now,
            updated_at=now,
            initial_bindings=policy.bindings,
            initial_bindings_hash=policy.bindings_hash,
            bindings=policy.bindings,
            bindings_hash=policy.bindings_hash,
            transitions=[],
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "OperatorTrustState":
        if set(raw) != _STATE_FIELDS:
            raise OperatorTrustStateError(
                "operator trust state fields do not match the schema"
            )
        if raw.get("schema_name") != TRUST_STATE_SCHEMA:
            raise OperatorTrustStateError("unsupported operator trust state schema")
        if raw.get("schema_version") != TRUST_STATE_VERSION:
            raise OperatorTrustStateError("unsupported operator trust state version")
        if raw.get("mode") != SIGNED_REQUIRED:
            raise OperatorTrustStateError("operator trust mode must be signed_required")

        generation = raw.get("generation")
        if type(generation) is not int or generation < 1:
            raise OperatorTrustStateError(
                "operator trust generation must be a positive integer"
            )
        enrolled_at = _timestamp(raw.get("enrolled_at"), "enrolled_at")
        updated_at = _timestamp(raw.get("updated_at"), "updated_at")
        if updated_at < enrolled_at:
            raise OperatorTrustStateError(
                "operator trust updated_at precedes enrollment"
            )

        initial = _bindings(raw.get("initial_bindings"), "initial_bindings")
        current = _bindings(raw.get("bindings"), "bindings")
        initial_hash = _hash(raw.get("initial_bindings_hash"), "initial_bindings_hash")
        current_hash = _hash(raw.get("bindings_hash"), "bindings_hash")
        if not hmac.compare_digest(initial_hash, sha256_of(initial)):
            raise OperatorTrustStateError("initial operator bindings hash is invalid")
        if not hmac.compare_digest(current_hash, sha256_of(current)):
            raise OperatorTrustStateError("current operator bindings hash is invalid")

        transitions = raw.get("transitions")
        if not isinstance(transitions, list):
            raise OperatorTrustStateError("operator trust transitions must be a list")
        if len(transitions) > _MAX_TRANSITIONS:
            raise OperatorTrustStateError("operator trust transition limit exceeded")
        if len(transitions) != generation - 1:
            raise OperatorTrustStateError(
                "operator trust transition count does not match its generation"
            )

        previous_bindings = initial
        previous_hash = initial_hash
        previous_time = enrolled_at
        normalized_transitions: list[dict[str, Any]] = []
        for index, transition in enumerate(transitions, start=1):
            if (
                not isinstance(transition, dict)
                or set(transition) != _TRANSITION_FIELDS
            ):
                raise OperatorTrustStateError(
                    f"operator trust transition {index} has invalid fields"
                )
            attestation = transition.get("attestation")
            if not isinstance(attestation, dict):
                raise OperatorTrustStateError(
                    f"operator trust transition {index} has no attestation"
                )
            candidate = _bindings(
                transition.get("bindings"), f"transition {index} bindings"
            )
            if not _is_additive(previous_bindings, candidate):
                raise OperatorTrustStateError(
                    f"operator trust transition {index} is not strictly additive"
                )
            expected_generation = index
            if (
                attestation.get("from_generation") != expected_generation
                or attestation.get("to_generation") != expected_generation + 1
            ):
                raise OperatorTrustStateError(
                    f"operator trust transition {index} generation is not contiguous"
                )
            candidate_hash = sha256_of(candidate)
            if (
                attestation.get("from_bindings_hash") != previous_hash
                or attestation.get("to_bindings_hash") != candidate_hash
            ):
                raise OperatorTrustStateError(
                    f"operator trust transition {index} does not bind its mappings"
                )
            signed_at = _timestamp(
                attestation.get("signed_at"), f"transition {index} signed_at"
            )
            if signed_at < previous_time:
                raise OperatorTrustStateError(
                    f"operator trust transition {index} predates its predecessor"
                )
            normalized_transitions.append(
                {"attestation": dict(attestation), "bindings": candidate}
            )
            previous_bindings = candidate
            previous_hash = candidate_hash
            previous_time = signed_at

        if previous_bindings != current or previous_hash != current_hash:
            raise OperatorTrustStateError(
                "operator trust transition chain does not reach current bindings"
            )
        if transitions and updated_at != previous_time:
            raise OperatorTrustStateError(
                "operator trust updated_at does not match its latest transition"
            )
        if not transitions and updated_at != enrolled_at:
            raise OperatorTrustStateError(
                "initial operator trust timestamps do not match"
            )

        return cls(
            generation=generation,
            enrolled_at=raw["enrolled_at"],
            updated_at=raw["updated_at"],
            initial_bindings=initial,
            initial_bindings_hash=initial_hash,
            bindings=current,
            bindings_hash=current_hash,
            transitions=normalized_transitions,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": TRUST_STATE_SCHEMA,
            "schema_version": TRUST_STATE_VERSION,
            "mode": SIGNED_REQUIRED,
            "generation": self.generation,
            "enrolled_at": self.enrolled_at,
            "updated_at": self.updated_at,
            "initial_bindings": self.initial_bindings,
            "initial_bindings_hash": self.initial_bindings_hash,
            "bindings": self.bindings,
            "bindings_hash": self.bindings_hash,
            "transitions": self.transitions,
        }

    def verify(self, policy: OperatorTrustPolicy) -> None:
        if policy.bindings != self.bindings:
            raise OperatorTrustStateError(
                "configured operator trust does not match durable enrollment; "
                "use an explicit signed additive rotation"
            )
        previous = self.initial_bindings
        previous_hash = self.initial_bindings_hash
        for index, transition in enumerate(self.transitions, start=1):
            attestation = transition["attestation"]
            operator = attestation.get("operator")
            key_id = attestation.get("key_id")
            if not isinstance(operator, str) or key_id not in previous.get(
                operator, []
            ):
                raise OperatorTrustStateError(
                    f"operator trust transition {index} was not signed by a prior key"
                )
            candidate = transition["bindings"]
            candidate_hash = sha256_of(candidate)
            try:
                policy.require_trust_transition(
                    attestation,
                    from_generation=index,
                    from_bindings_hash=previous_hash,
                    to_bindings_hash=candidate_hash,
                    operator=operator,
                    note=str(attestation.get("note", "")),
                )
            except OperatorIdentityError as exc:
                raise OperatorTrustStateError(str(exc)) from exc
            previous = candidate
            previous_hash = candidate_hash

    def projection(self, *, verification: str) -> dict[str, Any]:
        return {
            "state": "ready",
            "mode": SIGNED_REQUIRED,
            "generation": self.generation,
            "bindings_hash": self.bindings_hash,
            "operator_count": len(self.bindings),
            "key_count": sum(len(keys) for keys in self.bindings.values()),
            "verification": verification,
        }


class OperatorTrustStateStore:
    """Enroll and rotate signed operator trust without silent downgrade."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self) -> OperatorTrustState | None:
        if not self.path.exists():
            return None
        try:
            if self.path.stat().st_size > _MAX_STATE_BYTES:
                raise OperatorTrustStateError("operator trust state is too large")
            return OperatorTrustState.from_dict(read_json(self.path))
        except OperatorTrustStateError:
            raise
        except (OSError, RuntimeError) as exc:
            raise OperatorTrustStateError(str(exc)) from exc

    def resolve_for_authority(
        self, specs: Iterable[str | Path]
    ) -> OperatorTrustPolicy | None:
        supplied = list(specs)
        candidate = OperatorTrustPolicy.from_specs(supplied) if supplied else None
        state = self.get()
        if state is None and candidate is None:
            if self._legacy_signed_authority_present():
                raise OperatorTrustStateError(
                    "signed operator attestations predate durable enrollment; "
                    "trusted operator keys are required to migrate this workdir"
                )
            return None
        if state is None:
            assert candidate is not None
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with exclusive_file_lock(self.path):
                state = self.get()
                if state is None:
                    state = OperatorTrustState.enrolled(candidate)
                    atomic_write_json(self.path, state.to_dict())
            state.verify(candidate)
            return candidate
        if candidate is None:
            raise OperatorTrustStateError(
                "signed operator trust is durably enrolled; trusted operator keys "
                "are required for authority-bearing startup"
            )
        state.verify(candidate)
        return candidate

    def _legacy_signed_authority_present(self) -> bool:
        approvals_path = self.path.with_name("approvals.json")
        if not approvals_path.exists():
            return False
        try:
            approvals = read_json(approvals_path)
        except RuntimeError as exc:
            raise OperatorTrustStateError(str(exc)) from exc
        return any(
            isinstance(approval, dict)
            and (
                approval.get("decision_attestation") is not None
                or approval.get("reconciliation_attestation") is not None
            )
            for approval in approvals.values()
        )

    def rotate(
        self,
        current: OperatorTrustPolicy,
        candidate: OperatorTrustPolicy,
        attestation: dict[str, Any],
    ) -> OperatorTrustState:
        with exclusive_file_lock(self.path):
            state = self.get()
            if state is None:
                raise OperatorTrustStateError(
                    "operator trust is not enrolled; start once with trusted keys"
                )
            if (
                state.bindings == candidate.bindings
                and state.transitions
                and state.transitions[-1]["attestation"] == attestation
            ):
                state.verify(candidate)
                return state
            state.verify(current)
            if not current.is_additive_successor(candidate):
                raise OperatorTrustStateError(
                    "online operator trust rotation must be strictly additive; "
                    "key removal or reassignment requires offline compromise recovery"
                )
            operator = attestation.get("operator")
            key_id = attestation.get("key_id")
            note = attestation.get("note")
            if (
                not isinstance(operator, str)
                or not isinstance(note, str)
                or not note.strip()
                or key_id not in state.bindings.get(operator, [])
            ):
                raise OperatorTrustStateError(
                    "trust rotation requires a note and a signer from the current generation"
                )
            try:
                current.require_trust_transition(
                    attestation,
                    from_generation=state.generation,
                    from_bindings_hash=state.bindings_hash,
                    to_bindings_hash=candidate.bindings_hash,
                    operator=operator,
                    note=note,
                )
            except OperatorIdentityError as exc:
                raise OperatorTrustStateError(str(exc)) from exc
            updated = OperatorTrustState.from_dict(
                {
                    **state.to_dict(),
                    "generation": state.generation + 1,
                    "updated_at": attestation["signed_at"],
                    "bindings": candidate.bindings,
                    "bindings_hash": candidate.bindings_hash,
                    "transitions": [
                        *state.transitions,
                        {
                            "attestation": dict(attestation),
                            "bindings": candidate.bindings,
                        },
                    ],
                }
            )
            updated.verify(candidate)
            atomic_write_json(self.path, updated.to_dict())
            return updated


def _bindings(value: Any, field: str) -> dict[str, list[str]]:
    if not isinstance(value, dict) or not value:
        raise OperatorTrustStateError(f"{field} must be a non-empty object")
    if len(value) > _MAX_OPERATORS:
        raise OperatorTrustStateError(f"{field} operator limit exceeded")
    normalized: dict[str, list[str]] = {}
    key_count = 0
    for operator, key_ids in value.items():
        if (
            not isinstance(operator, str)
            or not operator.strip()
            or operator != operator.strip()
            or len(operator) > 256
        ):
            raise OperatorTrustStateError(f"{field} contains an invalid operator")
        if not isinstance(key_ids, list) or not key_ids:
            raise OperatorTrustStateError(f"{field} contains an empty key set")
        if any(not _is_hash(key_id) for key_id in key_ids):
            raise OperatorTrustStateError(f"{field} contains an invalid key id")
        unique = sorted(set(key_ids))
        if unique != key_ids:
            raise OperatorTrustStateError(f"{field} key ids must be sorted and unique")
        normalized[operator] = unique
        key_count += len(unique)
        if key_count > _MAX_KEYS:
            raise OperatorTrustStateError(f"{field} key limit exceeded")
    if list(normalized) != sorted(normalized):
        raise OperatorTrustStateError(f"{field} operators must be sorted")
    return normalized


def _is_additive(
    current: dict[str, list[str]], candidate: dict[str, list[str]]
) -> bool:
    return current != candidate and all(
        operator in candidate and set(keys).issubset(candidate[operator])
        for operator, keys in current.items()
    )


def _hash(value: Any, field: str) -> str:
    if not _is_hash(value):
        raise OperatorTrustStateError(f"{field} is not a sha256 identifier")
    return value


def _is_hash(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise OperatorTrustStateError(f"{field} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OperatorTrustStateError(f"{field} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OperatorTrustStateError(f"{field} must include a timezone")
    if parsed > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise OperatorTrustStateError(f"{field} is too far in the future")
    return parsed
