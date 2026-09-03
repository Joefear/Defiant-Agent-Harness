"""Compact durable continuity anchor for authority publication checkpoints."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .contracts import authority_snapshot_and_sha256_of, sha256_of, utc_now
from .limits import MAX_AUTHORITY_PUBLICATION_CONTINUITY_STATE_BYTES
from .persistence import (
    PersistenceError,
    atomic_write_json,
    exclusive_file_lock,
    prepare_storage_root,
    read_json,
)

AUTHORITY_PUBLICATION_CONTINUITY_SCHEMA = "defiant.authority_publication_continuity"
AUTHORITY_PUBLICATION_CONTINUITY_VERSION = "0.1.0"
_STATE_FIELDS = {
    "schema_name",
    "schema_version",
    "sequence",
    "checkpoint_hash",
    "prior_checkpoint_hash",
    "anchored_at",
    "record_hash",
}
_RECORD_TYPE = "authority_publication_continuity"
_MAX_STATE_BYTES = MAX_AUTHORITY_PUBLICATION_CONTINUITY_STATE_BYTES


class AuthorityPublicationContinuityError(RuntimeError):
    """The publication continuity ratchet cannot be trusted or advanced."""


@dataclass(frozen=True)
class AuthorityPublicationContinuityState:
    sequence: int
    checkpoint_hash: str
    prior_checkpoint_hash: str
    anchored_at: str
    record_hash: str

    @classmethod
    def from_dict(cls, raw: Any) -> "AuthorityPublicationContinuityState":
        snapshot = _snapshot(raw)
        if set(snapshot) != _STATE_FIELDS:
            raise AuthorityPublicationContinuityError(
                "authority publication continuity fields do not match schema"
            )
        if snapshot.get("schema_name") != AUTHORITY_PUBLICATION_CONTINUITY_SCHEMA:
            raise AuthorityPublicationContinuityError(
                "unsupported authority publication continuity schema"
            )
        if snapshot.get("schema_version") != AUTHORITY_PUBLICATION_CONTINUITY_VERSION:
            raise AuthorityPublicationContinuityError(
                "unsupported authority publication continuity version"
            )
        state = cls(
            sequence=_sequence(snapshot.get("sequence")),
            checkpoint_hash=_hash(snapshot.get("checkpoint_hash"), "checkpoint_hash"),
            prior_checkpoint_hash=_checkpoint_link(
                snapshot.get("prior_checkpoint_hash")
            ),
            anchored_at=_timestamp(snapshot.get("anchored_at")),
            record_hash=_hash(snapshot.get("record_hash"), "record_hash"),
        )
        if state.record_hash != state.expected_record_hash():
            raise AuthorityPublicationContinuityError(
                "authority publication continuity record hash does not match"
            )
        return state

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        checkpoint_hash: str,
        prior_checkpoint_hash: str,
    ) -> "AuthorityPublicationContinuityState":
        state = cls(
            sequence=_sequence(sequence),
            checkpoint_hash=_hash(checkpoint_hash, "checkpoint_hash"),
            prior_checkpoint_hash=_checkpoint_link(prior_checkpoint_hash),
            anchored_at=utc_now(),
            record_hash="sha256:" + "0" * 64,
        )
        return cls(
            sequence=state.sequence,
            checkpoint_hash=state.checkpoint_hash,
            prior_checkpoint_hash=state.prior_checkpoint_hash,
            anchored_at=state.anchored_at,
            record_hash=state.expected_record_hash(),
        )

    def expected_record_hash(self) -> str:
        return sha256_of(
            {
                "record_type": _RECORD_TYPE,
                "sequence": self.sequence,
                "checkpoint_hash": self.checkpoint_hash,
                "prior_checkpoint_hash": self.prior_checkpoint_hash,
                "anchored_at": self.anchored_at,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": AUTHORITY_PUBLICATION_CONTINUITY_SCHEMA,
            "schema_version": AUTHORITY_PUBLICATION_CONTINUITY_VERSION,
            "sequence": self.sequence,
            "checkpoint_hash": self.checkpoint_hash,
            "prior_checkpoint_hash": self.prior_checkpoint_hash,
            "anchored_at": self.anchored_at,
            "record_hash": self.record_hash,
        }


class AuthorityPublicationContinuityStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self) -> AuthorityPublicationContinuityState | None:
        if not self.path.exists():
            return None
        try:
            return AuthorityPublicationContinuityState.from_dict(
                read_json(self.path, max_bytes=_MAX_STATE_BYTES)
            )
        except AuthorityPublicationContinuityError:
            raise
        except (OSError, PersistenceError, RuntimeError) as exc:
            raise AuthorityPublicationContinuityError(_error_detail(exc)) from exc

    def advance(
        self,
        *,
        sequence: int,
        checkpoint_hash: str,
        prior_checkpoint_hash: str,
    ) -> AuthorityPublicationContinuityState:
        candidate = AuthorityPublicationContinuityState.create(
            sequence=sequence,
            checkpoint_hash=checkpoint_hash,
            prior_checkpoint_hash=prior_checkpoint_hash,
        )
        prepare_storage_root(self.path.parent)
        try:
            with exclusive_file_lock(self.path):
                current = self.get()
                if current is not None:
                    if (
                        current.sequence == candidate.sequence
                        and current.checkpoint_hash == candidate.checkpoint_hash
                        and current.prior_checkpoint_hash
                        == candidate.prior_checkpoint_hash
                    ):
                        return current
                    if candidate.sequence != current.sequence + 1:
                        raise AuthorityPublicationContinuityError(
                            "authority publication continuity sequence did not advance"
                        )
                    if candidate.prior_checkpoint_hash != current.checkpoint_hash:
                        raise AuthorityPublicationContinuityError(
                            "authority publication continuity predecessor does not match"
                        )
                elif candidate.sequence != 1:
                    raise AuthorityPublicationContinuityError(
                        "authority publication continuity cannot initialize after sequence one"
                    )
                atomic_write_json(
                    self.path,
                    candidate.to_dict(),
                    max_bytes=_MAX_STATE_BYTES,
                )
                return candidate
        except AuthorityPublicationContinuityError:
            raise
        except (OSError, PersistenceError) as exc:
            raise AuthorityPublicationContinuityError(_error_detail(exc)) from exc


def _snapshot(value: Any) -> dict[str, Any]:
    try:
        snapshot, _ = authority_snapshot_and_sha256_of(
            value,
            maximum_canonical_bytes=_MAX_STATE_BYTES,
        )
    except ValueError as exc:
        raise AuthorityPublicationContinuityError(
            "authority publication continuity exceeds bounded canonical state"
        ) from exc
    if type(snapshot) is not dict:
        raise AuthorityPublicationContinuityError(
            "authority publication continuity state must be an object"
        )
    return snapshot


def _sequence(value: Any) -> int:
    if type(value) is not int or value < 1:
        raise AuthorityPublicationContinuityError(
            "authority publication continuity sequence is invalid"
        )
    return value


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AuthorityPublicationContinuityError(f"{field} is not a sha256 identifier")
    normalized = str.__str__(value)
    if not str.startswith(normalized, "sha256:"):
        raise AuthorityPublicationContinuityError(f"{field} is not a sha256 identifier")
    digest = str.removeprefix(normalized, "sha256:")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise AuthorityPublicationContinuityError(f"{field} is not a sha256 identifier")
    return normalized


def _checkpoint_link(value: Any) -> str:
    if isinstance(value, str) and str.__str__(value) == "GENESIS":
        return "GENESIS"
    return _hash(value, "prior_checkpoint_hash")


def _timestamp(value: Any) -> str:
    if not isinstance(value, str):
        raise AuthorityPublicationContinuityError("anchored_at must be a timestamp")
    normalized = str.__str__(value)
    try:
        parsed = datetime.fromisoformat(str.replace(normalized, "Z", "+00:00"))
    except ValueError as exc:
        raise AuthorityPublicationContinuityError(
            "anchored_at must be a timestamp"
        ) from exc
    if not normalized or parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorityPublicationContinuityError("anchored_at must include a timezone")
    return normalized


def _error_detail(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        return exc.strerror or exc.__class__.__name__
    return str(exc)
