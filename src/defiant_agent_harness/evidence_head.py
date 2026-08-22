"""Profile-bound durable checkpoints for the append-only evidence head."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .contracts import utc_now
from .persistence import (
    PersistenceError,
    atomic_write_json,
    exclusive_file_lock,
    inspect_state_file,
    inspect_storage_root,
    read_json,
)

EVIDENCE_HEAD_SCHEMA = "defiant.evidence_head"
EVIDENCE_HEAD_VERSION = "0.1.0"
EVIDENCE_HEAD_MODE = "durable_checkpoint"
GENESIS_HEAD = "sha256:" + "0" * 64
_STATE_FIELDS = {
    "schema_name",
    "schema_version",
    "profile_hash",
    "mode",
    "record_count",
    "head_hash",
    "checkpointed_at",
}
_MAX_STATE_BYTES = 64 * 1024


class EvidenceHeadError(RuntimeError):
    """The durable evidence checkpoint could not be trusted or advanced."""


@dataclass(frozen=True)
class EvidenceHeadState:
    profile_hash: str
    mode: str
    record_count: int
    head_hash: str
    checkpointed_at: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EvidenceHeadState":
        if not isinstance(raw, dict) or set(raw) != _STATE_FIELDS:
            raise EvidenceHeadError("evidence head fields do not match schema")
        if raw.get("schema_name") != EVIDENCE_HEAD_SCHEMA:
            raise EvidenceHeadError("unsupported evidence head schema")
        if raw.get("schema_version") != EVIDENCE_HEAD_VERSION:
            raise EvidenceHeadError("unsupported evidence head version")
        profile_hash = _hash(raw.get("profile_hash"), "profile_hash")
        mode = raw.get("mode")
        if mode != EVIDENCE_HEAD_MODE:
            raise EvidenceHeadError("unsupported evidence head mode")
        record_count = raw.get("record_count")
        if type(record_count) is not int or record_count < 0:
            raise EvidenceHeadError("record_count must be a non-negative integer")
        head_hash = _hash(raw.get("head_hash"), "head_hash")
        if record_count == 0 and head_hash != GENESIS_HEAD:
            raise EvidenceHeadError("empty evidence checkpoint must use genesis")
        checkpointed_at = raw.get("checkpointed_at")
        if not isinstance(checkpointed_at, str) or not checkpointed_at:
            raise EvidenceHeadError("checkpointed_at must be a timestamp")
        try:
            parsed = datetime.fromisoformat(checkpointed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EvidenceHeadError("checkpointed_at must be a timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise EvidenceHeadError("checkpointed_at must include a timezone")
        return cls(profile_hash, mode, record_count, head_hash, checkpointed_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": EVIDENCE_HEAD_SCHEMA,
            "schema_version": EVIDENCE_HEAD_VERSION,
            "profile_hash": self.profile_hash,
            "mode": self.mode,
            "record_count": self.record_count,
            "head_hash": self.head_hash,
            "checkpointed_at": self.checkpointed_at,
        }

    def projection(self, *, verification: str) -> dict[str, Any]:
        return {
            "state": self.mode,
            "verification": verification,
            "profile_hash": self.profile_hash,
            "record_count": self.record_count,
            "head_hash": self.head_hash,
            "last_checkpointed_at": self.checkpointed_at,
        }


class EvidenceHeadStateStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self) -> EvidenceHeadState | None:
        try:
            if inspect_storage_root(self.path.parent) is None:
                return None
            current = inspect_state_file(self.path)
            if current is None:
                return None
            if current.st_size > _MAX_STATE_BYTES:
                raise EvidenceHeadError("evidence head state is too large")
            return EvidenceHeadState.from_dict(read_json(self.path))
        except EvidenceHeadError:
            raise
        except (OSError, PersistenceError, RuntimeError) as exc:
            raise EvidenceHeadError(_error_detail(exc)) from exc

    def reconcile_for_authority(
        self,
        profile_hash: str,
        records: Iterable[dict[str, Any]],
        *,
        allow_profile_rebind: bool = False,
    ) -> EvidenceHeadState:
        profile_hash = _hash(profile_hash, "profile_hash")
        materialized = list(records)
        count, head = evidence_position(materialized)
        try:
            with exclusive_file_lock(self.path):
                state = self.get()
                if state is None:
                    return self._write(profile_hash, count, head)
                if state.profile_hash != profile_hash:
                    if not allow_profile_rebind:
                        raise EvidenceHeadError(
                            "evidence head is not bound to the active authority profile"
                        )
                    prior_verification = assess_evidence_head(state, materialized)
                    if prior_verification in {"verified", "forward_recovery"}:
                        return self._write(profile_hash, count, head)
                    if prior_verification == "rollback":
                        raise EvidenceHeadError(
                            "evidence chain is behind its durable checkpoint"
                        )
                    raise EvidenceHeadError(
                        "evidence chain diverges from its durable checkpoint"
                    )
                verification = assess_evidence_head(state, materialized)
                if verification == "verified":
                    return state
                if verification == "forward_recovery":
                    return self._write(profile_hash, count, head)
                if verification == "rollback":
                    raise EvidenceHeadError(
                        "evidence chain is behind its durable checkpoint"
                    )
                raise EvidenceHeadError(
                    "evidence chain diverges from its durable checkpoint"
                )
        except EvidenceHeadError:
            raise
        except (OSError, PersistenceError) as exc:
            raise EvidenceHeadError(_error_detail(exc)) from exc

    def advance(
        self,
        profile_hash: str,
        *,
        previous_count: int,
        previous_head: str,
        record_count: int,
        head_hash: str,
    ) -> EvidenceHeadState:
        profile_hash = _hash(profile_hash, "profile_hash")
        previous_head = _hash(previous_head, "previous_head")
        head_hash = _hash(head_hash, "head_hash")
        if type(previous_count) is not int or previous_count < 0:
            raise EvidenceHeadError("previous_count is invalid")
        if type(record_count) is not int or record_count <= previous_count:
            raise EvidenceHeadError("evidence checkpoint must advance")
        try:
            with exclusive_file_lock(self.path):
                state = self.get()
                if state is None:
                    raise EvidenceHeadError("evidence head is not initialized")
                if state.profile_hash != profile_hash:
                    raise EvidenceHeadError(
                        "evidence head is not bound to the active authority profile"
                    )
                if state.record_count == record_count and state.head_hash == head_hash:
                    return state
                if (
                    state.record_count != previous_count
                    or state.head_hash != previous_head
                ):
                    raise EvidenceHeadError(
                        "evidence head changed before checkpoint advance"
                    )
                return self._write(profile_hash, record_count, head_hash)
        except EvidenceHeadError:
            raise
        except (OSError, PersistenceError) as exc:
            raise EvidenceHeadError(_error_detail(exc)) from exc

    def _write(
        self,
        profile_hash: str,
        record_count: int,
        head_hash: str,
    ) -> EvidenceHeadState:
        state = EvidenceHeadState(
            profile_hash=profile_hash,
            mode=EVIDENCE_HEAD_MODE,
            record_count=record_count,
            head_hash=head_hash,
            checkpointed_at=utc_now(),
        )
        atomic_write_json(self.path, state.to_dict())
        return state


def evidence_head_authority() -> dict[str, str]:
    return {"mode": EVIDENCE_HEAD_MODE, "schema_version": EVIDENCE_HEAD_VERSION}


def evidence_position(records: list[dict[str, Any]]) -> tuple[int, str]:
    return len(records), records[-1]["record_hash"] if records else GENESIS_HEAD


def assess_evidence_head(
    state: EvidenceHeadState,
    records: list[dict[str, Any]],
) -> str:
    count, head = evidence_position(records)
    if count == state.record_count:
        return "verified" if head == state.head_hash else "diverged"
    if count < state.record_count:
        return "rollback"
    if state.record_count == 0:
        return "forward_recovery" if state.head_hash == GENESIS_HEAD else "diverged"
    prefix = records[state.record_count - 1].get("record_hash")
    return "forward_recovery" if prefix == state.head_hash else "diverged"


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise EvidenceHeadError(f"{field} is not a sha256 identifier")
    digest = value.removeprefix("sha256:")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise EvidenceHeadError(f"{field} is not a sha256 identifier")
    return value


def _error_detail(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        return exc.strerror or exc.__class__.__name__
    return str(exc)
