"""Authority-bound assurance for the local state filesystem boundary."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .contracts import authority_snapshot_and_sha256_of, sha256_of, utc_now
from .limits import MAX_STATE_STORAGE_STATE_BYTES
from .persistence import (
    PersistenceError,
    StorageRootObservation,
    atomic_write_json,
    exclusive_file_lock,
    inspect_state_file,
    inspect_storage_root,
    prepare_storage_root,
    read_json,
    require_storage_root_unchanged,
)
from .windows_acl import (
    WindowsAclError,
    inspect_windows_private_acl,
)

STATE_STORAGE_SCHEMA = "defiant.state_storage"
STATE_STORAGE_VERSION = "0.2.0"
WINDOWS_ACL_POLICY = "current_user_system_administrators"
_STATE_FIELDS_V1 = {
    "schema_name",
    "schema_version",
    "profile_hash",
    "mode",
    "root_hash",
    "private_permissions",
    "directory_sync",
    "verified_at",
}
_STATE_FIELDS = _STATE_FIELDS_V1 | {
    "acl_policy",
    "acl_protected",
    "acl_principal_count",
}
_MODES = {"posix_private", "structural_only", "windows_private_acl"}
_DIRECTORY_SYNC = {"required", "best_effort"}
_MAX_STATE_BYTES = MAX_STATE_STORAGE_STATE_BYTES
KNOWN_STATE_FILENAMES = (
    "approvals.json",
    "authority.lock",
    "authority_profile.json",
    "budget.json",
    "control_plane_isolation.json",
    "evidence.jsonl",
    "evidence_head.json",
    "evidence_witness_policy.json",
    "hook_executions.json",
    "launch_envelope.json",
    "operation_journal.json",
    "operator_trust.json",
    "runtime_artifacts.json",
    "state_storage.json",
    "workspace_integrity.json",
)


class StateStorageError(RuntimeError):
    """The local state filesystem boundary could not be trusted."""


@dataclass(frozen=True)
class StateStorageAssurance:
    mode: str
    root_hash: str
    private_permissions: bool | None
    directory_sync: str
    acl_policy: str | None
    acl_protected: bool | None
    acl_principal_count: int
    root: Path
    identity: tuple[int, int]

    def __post_init__(self) -> None:
        if self.mode not in _MODES:
            raise StateStorageError("unsupported state storage mode")
        _hash(self.root_hash, "root_hash")
        if self.mode == "posix_private" and self.private_permissions is not True:
            raise StateStorageError("POSIX state storage is not private")
        if self.mode == "structural_only" and self.private_permissions is not None:
            raise StateStorageError("structural state storage posture is inconsistent")
        if self.mode == "windows_private_acl":
            if self.private_permissions is not True:
                raise StateStorageError("Windows state storage ACL is not private")
            if self.acl_policy != WINDOWS_ACL_POLICY:
                raise StateStorageError("unsupported Windows state ACL policy")
            if self.acl_protected is not True:
                raise StateStorageError("Windows state root DACL is not protected")
            if (
                type(self.acl_principal_count) is not int
                or not 1 <= self.acl_principal_count <= 3
            ):
                raise StateStorageError(
                    "Windows state ACL principal count is inconsistent"
                )
        elif (
            self.acl_policy is not None
            or self.acl_protected is not None
            or self.acl_principal_count != 0
        ):
            raise StateStorageError("state ACL posture is inconsistent")
        if self.directory_sync not in _DIRECTORY_SYNC:
            raise StateStorageError("unsupported state directory sync posture")
        if not isinstance(self.root, Path) or not self.root.is_absolute():
            raise StateStorageError("state storage root must be absolute")
        if (
            type(self.identity) is not tuple
            or len(self.identity) != 2
            or any(type(value) is not int for value in self.identity)
        ):
            raise StateStorageError("state storage identity must contain two integers")

    def authority_dict(self) -> dict[str, Any]:
        result = {
            "mode": self.mode,
            "root_hash": self.root_hash,
            "private_permissions": self.private_permissions,
            "directory_sync": self.directory_sync,
        }
        if self.mode == "windows_private_acl":
            result["acl_policy"] = self.acl_policy
            result["acl_protected"] = self.acl_protected
        return result


def prepare_state_storage(
    path: str | Path,
    *,
    require_windows_private_acl: bool = False,
) -> StateStorageAssurance:
    try:
        return _assurance(
            prepare_storage_root(path),
            require_windows_private_acl=require_windows_private_acl,
        )
    except (PersistenceError, WindowsAclError) as exc:
        raise StateStorageError(str(exc)) from exc


def inspect_state_storage(
    path: str | Path,
    *,
    require_windows_private_acl: bool = False,
) -> StateStorageAssurance | None:
    try:
        observation = inspect_storage_root(path)
        return (
            None
            if observation is None
            else _assurance(
                observation,
                require_windows_private_acl=require_windows_private_acl,
            )
        )
    except (PersistenceError, WindowsAclError) as exc:
        raise StateStorageError(str(exc)) from exc


def require_state_storage_unchanged(assurance: StateStorageAssurance) -> None:
    try:
        require_storage_root_unchanged(_observation(assurance))
        if assurance.mode == "windows_private_acl":
            current = inspect_windows_private_acl(assurance.root, directory=True)
            if (
                current.dacl_protected is not True
                or current.principal_count != assurance.acl_principal_count
            ):
                raise StateStorageError(
                    "Windows state ACL posture changed after verification"
                )
    except (PersistenceError, WindowsAclError) as exc:
        raise StateStorageError(str(exc)) from exc


def inspect_state_storage_files(
    assurance: StateStorageAssurance,
    filenames: Iterable[str],
) -> tuple[int, int]:
    """Validate known files and return checked-file and orphan-temp counts."""
    checked = 0
    try:
        require_storage_root_unchanged(_observation(assurance))
        if assurance.mode == "windows_private_acl":
            inspect_windows_private_acl(assurance.root, directory=True)
        for filename in filenames:
            path = assurance.root / filename
            if inspect_state_file(path) is not None:
                if assurance.mode == "windows_private_acl":
                    inspect_windows_private_acl(path, directory=False)
                checked += 1
        temporary = 0
        with os.scandir(assurance.root) as entries:
            for entry in entries:
                if entry.name.startswith(".") and entry.name.endswith(".tmp"):
                    inspect_state_file(assurance.root / entry.name)
                    if assurance.mode == "windows_private_acl":
                        inspect_windows_private_acl(
                            assurance.root / entry.name,
                            directory=False,
                        )
                    temporary += 1
        require_storage_root_unchanged(_observation(assurance))
        return checked, temporary
    except (OSError, PersistenceError, WindowsAclError) as exc:
        raise StateStorageError(_error_detail(exc)) from exc


@dataclass(frozen=True, init=False)
class StateStorageState:
    profile_hash: str
    mode: str
    root_hash: str
    private_permissions: bool | None
    directory_sync: str
    acl_policy: str | None
    acl_protected: bool | None
    acl_principal_count: int
    verified_at: str

    def __init__(
        self,
        profile_hash: str,
        mode: str,
        root_hash: str,
        private_permissions: bool | None,
        directory_sync: str,
        acl_policy: str | None,
        acl_protected: bool | None,
        acl_principal_count: int,
        verified_at: str,
    ):
        state = self._from_snapshot(
            _state_storage_state_snapshot(
                {
                    "schema_name": STATE_STORAGE_SCHEMA,
                    "schema_version": STATE_STORAGE_VERSION,
                    "profile_hash": profile_hash,
                    "mode": mode,
                    "root_hash": root_hash,
                    "private_permissions": private_permissions,
                    "directory_sync": directory_sync,
                    "acl_policy": acl_policy,
                    "acl_protected": acl_protected,
                    "acl_principal_count": acl_principal_count,
                    "verified_at": verified_at,
                }
            )
        )
        self._install(
            profile_hash=state.profile_hash,
            mode=state.mode,
            root_hash=state.root_hash,
            private_permissions=state.private_permissions,
            directory_sync=state.directory_sync,
            acl_policy=state.acl_policy,
            acl_protected=state.acl_protected,
            acl_principal_count=state.acl_principal_count,
            verified_at=state.verified_at,
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "StateStorageState":
        return cls._from_snapshot(_state_storage_state_snapshot(raw))

    @classmethod
    def _from_snapshot(cls, raw: dict[str, Any]) -> "StateStorageState":
        if raw.get("schema_name") != STATE_STORAGE_SCHEMA:
            raise StateStorageError("unsupported state storage schema")
        version = raw.get("schema_version")
        if version not in {"0.1.0", STATE_STORAGE_VERSION}:
            raise StateStorageError("unsupported state storage version")
        expected_fields = _STATE_FIELDS_V1 if version == "0.1.0" else _STATE_FIELDS
        if set(raw) != expected_fields:
            raise StateStorageError("state storage fields do not match schema")
        profile_hash = _hash(raw.get("profile_hash"), "profile_hash")
        root_hash = _hash(raw.get("root_hash"), "root_hash")
        mode = raw.get("mode")
        private = raw.get("private_permissions")
        directory_sync = raw.get("directory_sync")
        if mode not in _MODES:
            raise StateStorageError("unsupported state storage mode")
        if mode == "posix_private" and private is not True:
            raise StateStorageError("POSIX state storage is not private")
        if mode == "structural_only" and private is not None:
            raise StateStorageError("structural state storage posture is inconsistent")
        acl_policy = raw.get("acl_policy")
        acl_protected = raw.get("acl_protected")
        acl_principal_count = raw.get("acl_principal_count", 0)
        if mode == "windows_private_acl":
            if private is not True:
                raise StateStorageError("Windows state storage ACL is not private")
            if acl_policy != WINDOWS_ACL_POLICY:
                raise StateStorageError("unsupported Windows state ACL policy")
            if acl_protected is not True:
                raise StateStorageError("Windows state root DACL is not protected")
            if (
                type(acl_principal_count) is not int
                or not 1 <= acl_principal_count <= 3
            ):
                raise StateStorageError(
                    "Windows state ACL principal count is inconsistent"
                )
        elif (
            acl_policy is not None
            or acl_protected is not None
            or acl_principal_count != 0
        ):
            raise StateStorageError("state ACL posture is inconsistent")
        if directory_sync not in _DIRECTORY_SYNC:
            raise StateStorageError("unsupported state directory sync posture")
        verified_at = raw.get("verified_at")
        if not isinstance(verified_at, str) or not verified_at:
            raise StateStorageError("verified_at must be a timestamp")
        try:
            parsed = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise StateStorageError("verified_at must be a timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise StateStorageError("verified_at must include a timezone")
        state = object.__new__(cls)
        state._install(
            profile_hash=profile_hash,
            mode=mode,
            root_hash=root_hash,
            private_permissions=private,
            directory_sync=directory_sync,
            acl_policy=acl_policy,
            acl_protected=acl_protected,
            acl_principal_count=acl_principal_count,
            verified_at=verified_at,
        )
        return state

    def _install(
        self,
        *,
        profile_hash: str,
        mode: str,
        root_hash: str,
        private_permissions: bool | None,
        directory_sync: str,
        acl_policy: str | None,
        acl_protected: bool | None,
        acl_principal_count: int,
        verified_at: str,
    ) -> None:
        object.__setattr__(self, "profile_hash", profile_hash)
        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "root_hash", root_hash)
        object.__setattr__(self, "private_permissions", private_permissions)
        object.__setattr__(self, "directory_sync", directory_sync)
        object.__setattr__(self, "acl_policy", acl_policy)
        object.__setattr__(self, "acl_protected", acl_protected)
        object.__setattr__(self, "acl_principal_count", acl_principal_count)
        object.__setattr__(self, "verified_at", verified_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": STATE_STORAGE_SCHEMA,
            "schema_version": STATE_STORAGE_VERSION,
            "profile_hash": self.profile_hash,
            "mode": self.mode,
            "root_hash": self.root_hash,
            "private_permissions": self.private_permissions,
            "directory_sync": self.directory_sync,
            "acl_policy": self.acl_policy,
            "acl_protected": self.acl_protected,
            "acl_principal_count": self.acl_principal_count,
            "verified_at": self.verified_at,
        }

    def authority_dict(self) -> dict[str, Any]:
        result = {
            "mode": self.mode,
            "root_hash": self.root_hash,
            "private_permissions": self.private_permissions,
            "directory_sync": self.directory_sync,
        }
        if self.mode == "windows_private_acl":
            result["acl_policy"] = self.acl_policy
            result["acl_protected"] = self.acl_protected
        return result

    def projection(
        self,
        *,
        verification: str,
        files_checked: int,
        temporary_files: int,
    ) -> dict[str, Any]:
        return {
            "state": self.mode,
            "verification": verification,
            "profile_hash": self.profile_hash,
            "root_hash": self.root_hash,
            "private_permissions": self.private_permissions,
            "directory_sync": self.directory_sync,
            "acl_policy": self.acl_policy,
            "acl_protected": self.acl_protected,
            "acl_principal_count": self.acl_principal_count,
            "files_checked": files_checked,
            "temporary_files": temporary_files,
            "last_verified_at": self.verified_at,
        }


class StateStorageStateStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self) -> StateStorageState | None:
        try:
            if inspect_storage_root(self.path.parent) is None:
                return None
            current = inspect_state_file(self.path)
            if current is None:
                return None
            return StateStorageState.from_dict(
                read_json(self.path, max_bytes=_MAX_STATE_BYTES)
            )
        except StateStorageError:
            raise
        except (OSError, PersistenceError, RuntimeError) as exc:
            raise StateStorageError(_error_detail(exc)) from exc

    def record(
        self, profile_hash: str, assurance: StateStorageAssurance
    ) -> StateStorageState:
        profile_hash = _hash(profile_hash, "profile_hash")
        candidate = StateStorageState(
            profile_hash=profile_hash,
            mode=assurance.mode,
            root_hash=assurance.root_hash,
            private_permissions=assurance.private_permissions,
            directory_sync=assurance.directory_sync,
            acl_policy=assurance.acl_policy,
            acl_protected=assurance.acl_protected,
            acl_principal_count=assurance.acl_principal_count,
            verified_at=utc_now(),
        )
        try:
            with exclusive_file_lock(self.path):
                previous = self.get()
                if previous is not None and previous.profile_hash == profile_hash:
                    if previous.authority_dict() != candidate.authority_dict():
                        raise StateStorageError(
                            "state storage conflicts with the active authority profile"
                        )
                _write_state(self.path, candidate)
                return candidate
        except StateStorageError:
            raise
        except (OSError, PersistenceError) as exc:
            raise StateStorageError(_error_detail(exc)) from exc


def _state_storage_state_snapshot(value: Any) -> dict[str, Any]:
    try:
        snapshot, _ = authority_snapshot_and_sha256_of(
            value,
            maximum_canonical_bytes=_MAX_STATE_BYTES,
        )
    except ValueError as exc:
        raise StateStorageError(
            "state storage observation exceeds bounded canonical state"
        ) from exc
    if type(snapshot) is not dict:
        raise StateStorageError("state storage observation must be an object")
    return snapshot


def _write_state(path: Path, state: StateStorageState) -> None:
    candidate = StateStorageState.from_dict(state.to_dict()).to_dict()
    atomic_write_json(path, candidate, max_bytes=_MAX_STATE_BYTES)


def _assurance(
    observation: StorageRootObservation,
    *,
    require_windows_private_acl: bool = False,
) -> StateStorageAssurance:
    windows_acl = (
        inspect_windows_private_acl(observation.path, directory=True)
        if require_windows_private_acl
        else None
    )
    mode = (
        "windows_private_acl"
        if windows_acl is not None
        else (
            "posix_private"
            if observation.private_permissions is True
            else "structural_only"
        )
    )
    root_hash = sha256_of(
        {
            "canonical_path": os.path.normcase(str(observation.path)),
            "device": observation.identity[0],
            "inode": observation.identity[1],
        }
    )
    return StateStorageAssurance(
        mode=mode,
        root_hash=root_hash,
        private_permissions=(
            True if windows_acl is not None else observation.private_permissions
        ),
        directory_sync=observation.directory_sync,
        acl_policy=WINDOWS_ACL_POLICY if windows_acl is not None else None,
        acl_protected=(windows_acl.dacl_protected if windows_acl is not None else None),
        acl_principal_count=(
            windows_acl.principal_count if windows_acl is not None else 0
        ),
        root=observation.path,
        identity=observation.identity,
    )


def _observation(assurance: StateStorageAssurance) -> StorageRootObservation:
    return StorageRootObservation(
        assurance.root,
        assurance.identity,
        assurance.private_permissions,
        assurance.directory_sync,
    )


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise StateStorageError(f"{field} is not a sha256 identifier")
    normalized = str.__str__(value)
    if not str.startswith(normalized, "sha256:"):
        raise StateStorageError(f"{field} is not a sha256 identifier")
    digest = str.removeprefix(normalized, "sha256:")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise StateStorageError(f"{field} is not a sha256 identifier")
    return normalized


def _error_detail(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        return exc.strerror or exc.__class__.__name__
    return str(exc)
