"""Profile-bound identity assurance for the governed workspace root."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .contracts import sha256_of, utc_now
from .persistence import (
    PersistenceError,
    atomic_write_json,
    exclusive_file_lock,
    inspect_state_file,
    inspect_storage_root,
    read_json,
)

WORKSPACE_INTEGRITY_SCHEMA = "defiant.workspace_integrity"
WORKSPACE_INTEGRITY_VERSION = "0.1.0"
_MODE = "identity_bound"
_STATE_FIELDS = {
    "schema_name",
    "schema_version",
    "profile_hash",
    "mode",
    "root_hash",
    "verified_at",
}
_MAX_STATE_BYTES = 64 * 1024
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class WorkspaceIntegrityError(RuntimeError):
    """The governed workspace root could not be trusted."""


@dataclass(frozen=True)
class WorkspaceRootAssurance:
    mode: str
    root_hash: str
    root: Path
    identity: tuple[int, int]

    def __post_init__(self) -> None:
        if self.mode != _MODE:
            raise WorkspaceIntegrityError("unsupported workspace integrity mode")
        _hash(self.root_hash, "root_hash")
        if not self.root.is_absolute():
            raise WorkspaceIntegrityError("workspace root must be absolute")
        if (
            type(self.identity) is not tuple
            or len(self.identity) != 2
            or any(type(value) is not int for value in self.identity)
        ):
            raise WorkspaceIntegrityError(
                "workspace identity must contain two integers"
            )

    def authority_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "root_hash": self.root_hash}


def prepare_workspace_root(path: str | Path) -> WorkspaceRootAssurance:
    candidate = Path(path)
    if not os.path.lexists(candidate):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise WorkspaceIntegrityError(_error_detail(exc)) from exc
    return _observe_workspace_root(candidate)


def inspect_workspace_root(path: str | Path) -> WorkspaceRootAssurance | None:
    candidate = Path(path)
    if not os.path.lexists(candidate):
        return None
    return _observe_workspace_root(candidate)


def require_workspace_root_unchanged(assurance: WorkspaceRootAssurance) -> None:
    current = _observe_workspace_root(assurance.root)
    if current.root != assurance.root or current.identity != assurance.identity:
        raise WorkspaceIntegrityError("workspace root identity changed")


@dataclass(frozen=True)
class WorkspaceIntegrityState:
    profile_hash: str
    mode: str
    root_hash: str
    verified_at: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "WorkspaceIntegrityState":
        if not isinstance(raw, dict) or set(raw) != _STATE_FIELDS:
            raise WorkspaceIntegrityError(
                "workspace integrity fields do not match schema"
            )
        if raw.get("schema_name") != WORKSPACE_INTEGRITY_SCHEMA:
            raise WorkspaceIntegrityError("unsupported workspace integrity schema")
        if raw.get("schema_version") != WORKSPACE_INTEGRITY_VERSION:
            raise WorkspaceIntegrityError("unsupported workspace integrity version")
        profile_hash = _hash(raw.get("profile_hash"), "profile_hash")
        root_hash = _hash(raw.get("root_hash"), "root_hash")
        mode = raw.get("mode")
        if mode != _MODE:
            raise WorkspaceIntegrityError("unsupported workspace integrity mode")
        verified_at = raw.get("verified_at")
        if not isinstance(verified_at, str) or not verified_at:
            raise WorkspaceIntegrityError("verified_at must be a timestamp")
        try:
            parsed = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise WorkspaceIntegrityError("verified_at must be a timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise WorkspaceIntegrityError("verified_at must include a timezone")
        return cls(profile_hash, mode, root_hash, verified_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": WORKSPACE_INTEGRITY_SCHEMA,
            "schema_version": WORKSPACE_INTEGRITY_VERSION,
            "profile_hash": self.profile_hash,
            "mode": self.mode,
            "root_hash": self.root_hash,
            "verified_at": self.verified_at,
        }

    def authority_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "root_hash": self.root_hash}

    def projection(self, *, verification: str) -> dict[str, Any]:
        return {
            "state": self.mode,
            "verification": verification,
            "profile_hash": self.profile_hash,
            "root_hash": self.root_hash,
            "last_verified_at": self.verified_at,
        }


class WorkspaceIntegrityStateStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self) -> WorkspaceIntegrityState | None:
        try:
            if inspect_storage_root(self.path.parent) is None:
                return None
            current = inspect_state_file(self.path)
            if current is None:
                return None
            if current.st_size > _MAX_STATE_BYTES:
                raise WorkspaceIntegrityError("workspace integrity state is too large")
            return WorkspaceIntegrityState.from_dict(read_json(self.path))
        except WorkspaceIntegrityError:
            raise
        except (OSError, PersistenceError, RuntimeError) as exc:
            raise WorkspaceIntegrityError(_error_detail(exc)) from exc

    def record(
        self,
        profile_hash: str,
        assurance: WorkspaceRootAssurance,
    ) -> WorkspaceIntegrityState:
        profile_hash = _hash(profile_hash, "profile_hash")
        stable = assurance.authority_dict()
        try:
            with exclusive_file_lock(self.path):
                previous = self.get()
                if previous is not None and previous.profile_hash == profile_hash:
                    if previous.authority_dict() != stable:
                        raise WorkspaceIntegrityError(
                            "workspace integrity conflicts with the active authority "
                            "profile"
                        )
                state = WorkspaceIntegrityState(
                    profile_hash=profile_hash,
                    **stable,
                    verified_at=utc_now(),
                )
                atomic_write_json(self.path, state.to_dict())
                return state
        except WorkspaceIntegrityError:
            raise
        except (OSError, PersistenceError) as exc:
            raise WorkspaceIntegrityError(_error_detail(exc)) from exc


def _observe_workspace_root(path: Path) -> WorkspaceRootAssurance:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise WorkspaceIntegrityError(_error_detail(exc)) from exc
    if stat.S_ISLNK(before.st_mode) or _is_reparse(before):
        raise WorkspaceIntegrityError(
            "workspace root must not be a symlink or reparse point"
        )
    if not stat.S_ISDIR(before.st_mode):
        raise WorkspaceIntegrityError("workspace root must be a directory")
    try:
        resolved = path.resolve(strict=True)
        after = os.lstat(resolved)
    except OSError as exc:
        raise WorkspaceIntegrityError(_error_detail(exc)) from exc
    before_identity = (before.st_dev, before.st_ino)
    after_identity = (after.st_dev, after.st_ino)
    if before_identity != after_identity or not stat.S_ISDIR(after.st_mode):
        raise WorkspaceIntegrityError(
            "workspace root identity changed during inspection"
        )
    root_hash = sha256_of(
        {
            "canonical_path": os.path.normcase(str(resolved)),
            "device": after_identity[0],
            "inode": after_identity[1],
        }
    )
    return WorkspaceRootAssurance(_MODE, root_hash, resolved, after_identity)


def _is_reparse(observation: os.stat_result) -> bool:
    return bool(getattr(observation, "st_file_attributes", 0) & _REPARSE_POINT)


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise WorkspaceIntegrityError(f"{field} is not a sha256 identifier")
    digest = value.removeprefix("sha256:")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise WorkspaceIntegrityError(f"{field} is not a sha256 identifier")
    return value


def _error_detail(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        return exc.strerror or exc.__class__.__name__
    return str(exc)
