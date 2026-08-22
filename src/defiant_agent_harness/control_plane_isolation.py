"""Profile-bound isolation between governed tools and Defiant control state."""

from __future__ import annotations

import os
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

CONTROL_PLANE_ISOLATION_SCHEMA = "defiant.control_plane_isolation"
CONTROL_PLANE_ISOLATION_VERSION = "0.1.0"
_MODE = "protected_state_root"
_RELATIONSHIPS = {
    "separate",
    "state_within_workspace",
    "workspace_within_state",
    "same_root",
}
_STATE_FIELDS = {
    "schema_name",
    "schema_version",
    "profile_hash",
    "mode",
    "contract_hash",
    "workspace_hash",
    "protected_root_count",
    "relationship",
    "verified_at",
}
_MAX_STATE_BYTES = 64 * 1024


class ControlPlaneIsolationError(RuntimeError):
    """The tool/control-plane isolation contract could not be trusted."""


@dataclass(frozen=True)
class ControlPlaneIsolationAssurance:
    mode: str
    contract_hash: str
    workspace_hash: str
    protected_root_count: int
    relationship: str
    workspace_root: Path
    protected_roots: tuple[Path, ...]

    def __post_init__(self) -> None:
        if self.mode != _MODE:
            raise ControlPlaneIsolationError("unsupported control-plane isolation mode")
        _hash(self.contract_hash, "contract_hash")
        _hash(self.workspace_hash, "workspace_hash")
        if type(self.protected_root_count) is not int or self.protected_root_count < 1:
            raise ControlPlaneIsolationError("protected_root_count must be positive")
        if self.relationship not in _RELATIONSHIPS:
            raise ControlPlaneIsolationError("unsupported control-plane relationship")
        if not self.workspace_root.is_absolute():
            raise ControlPlaneIsolationError("workspace root must be absolute")
        if len(self.protected_roots) != self.protected_root_count or any(
            not path.is_absolute() for path in self.protected_roots
        ):
            raise ControlPlaneIsolationError("protected roots are inconsistent")

    def authority_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "contract_hash": self.contract_hash,
            "workspace_hash": self.workspace_hash,
            "protected_root_count": self.protected_root_count,
            "relationship": self.relationship,
        }


def build_control_plane_isolation(
    workspace_root: str | Path,
    state_root: str | Path,
) -> ControlPlaneIsolationAssurance:
    workspace = Path(workspace_root).resolve(strict=False)
    state = Path(state_root).resolve(strict=True)
    relationship = _relationship(workspace, state)
    workspace_hash = sha256_of(_canonical_path(workspace))
    stable = {
        "mode": _MODE,
        "workspace_hash": workspace_hash,
        "protected_root_count": 1,
        "relationship": relationship,
        "protected_root_hashes": [sha256_of(_canonical_path(state))],
    }
    return ControlPlaneIsolationAssurance(
        mode=_MODE,
        contract_hash=sha256_of(stable),
        workspace_hash=workspace_hash,
        protected_root_count=1,
        relationship=relationship,
        workspace_root=workspace,
        protected_roots=(state,),
    )


@dataclass(frozen=True)
class ControlPlaneIsolationState:
    profile_hash: str
    mode: str
    contract_hash: str
    workspace_hash: str
    protected_root_count: int
    relationship: str
    verified_at: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ControlPlaneIsolationState":
        if not isinstance(raw, dict) or set(raw) != _STATE_FIELDS:
            raise ControlPlaneIsolationError(
                "control-plane isolation fields do not match schema"
            )
        if raw.get("schema_name") != CONTROL_PLANE_ISOLATION_SCHEMA:
            raise ControlPlaneIsolationError(
                "unsupported control-plane isolation schema"
            )
        if raw.get("schema_version") != CONTROL_PLANE_ISOLATION_VERSION:
            raise ControlPlaneIsolationError(
                "unsupported control-plane isolation version"
            )
        profile_hash = _hash(raw.get("profile_hash"), "profile_hash")
        contract_hash = _hash(raw.get("contract_hash"), "contract_hash")
        workspace_hash = _hash(raw.get("workspace_hash"), "workspace_hash")
        mode = raw.get("mode")
        count = raw.get("protected_root_count")
        relationship = raw.get("relationship")
        if mode != _MODE:
            raise ControlPlaneIsolationError("unsupported control-plane isolation mode")
        if type(count) is not int or count < 1:
            raise ControlPlaneIsolationError("protected_root_count must be positive")
        if relationship not in _RELATIONSHIPS:
            raise ControlPlaneIsolationError("unsupported control-plane relationship")
        verified_at = raw.get("verified_at")
        if not isinstance(verified_at, str) or not verified_at:
            raise ControlPlaneIsolationError("verified_at must be a timestamp")
        try:
            parsed = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ControlPlaneIsolationError("verified_at must be a timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ControlPlaneIsolationError("verified_at must include a timezone")
        return cls(
            profile_hash,
            mode,
            contract_hash,
            workspace_hash,
            count,
            relationship,
            verified_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": CONTROL_PLANE_ISOLATION_SCHEMA,
            "schema_version": CONTROL_PLANE_ISOLATION_VERSION,
            "profile_hash": self.profile_hash,
            "mode": self.mode,
            "contract_hash": self.contract_hash,
            "workspace_hash": self.workspace_hash,
            "protected_root_count": self.protected_root_count,
            "relationship": self.relationship,
            "verified_at": self.verified_at,
        }

    def authority_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "contract_hash": self.contract_hash,
            "workspace_hash": self.workspace_hash,
            "protected_root_count": self.protected_root_count,
            "relationship": self.relationship,
        }

    def projection(self, *, verification: str) -> dict[str, Any]:
        return {
            "state": self.mode,
            "verification": verification,
            "profile_hash": self.profile_hash,
            "contract_hash": self.contract_hash,
            "workspace_hash": self.workspace_hash,
            "protected_root_count": self.protected_root_count,
            "relationship": self.relationship,
            "last_verified_at": self.verified_at,
        }


class ControlPlaneIsolationStateStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self) -> ControlPlaneIsolationState | None:
        try:
            if inspect_storage_root(self.path.parent) is None:
                return None
            current = inspect_state_file(self.path)
            if current is None:
                return None
            if current.st_size > _MAX_STATE_BYTES:
                raise ControlPlaneIsolationError(
                    "control-plane isolation state is too large"
                )
            return ControlPlaneIsolationState.from_dict(read_json(self.path))
        except ControlPlaneIsolationError:
            raise
        except (OSError, PersistenceError, RuntimeError) as exc:
            raise ControlPlaneIsolationError(_error_detail(exc)) from exc

    def record(
        self,
        profile_hash: str,
        assurance: ControlPlaneIsolationAssurance,
    ) -> ControlPlaneIsolationState:
        profile_hash = _hash(profile_hash, "profile_hash")
        stable = assurance.authority_dict()
        try:
            with exclusive_file_lock(self.path):
                previous = self.get()
                if previous is not None and previous.profile_hash == profile_hash:
                    if previous.authority_dict() != stable:
                        raise ControlPlaneIsolationError(
                            "control-plane isolation conflicts with the active "
                            "authority profile"
                        )
                state = ControlPlaneIsolationState(
                    profile_hash=profile_hash,
                    **stable,
                    verified_at=utc_now(),
                )
                atomic_write_json(self.path, state.to_dict())
                return state
        except ControlPlaneIsolationError:
            raise
        except (OSError, PersistenceError) as exc:
            raise ControlPlaneIsolationError(_error_detail(exc)) from exc


def _relationship(workspace: Path, state: Path) -> str:
    if workspace == state:
        return "same_root"
    if state.is_relative_to(workspace):
        return "state_within_workspace"
    if workspace.is_relative_to(state):
        return "workspace_within_state"
    return "separate"


def _canonical_path(path: Path) -> str:
    return os.path.normcase(str(path))


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ControlPlaneIsolationError(f"{field} is not a sha256 identifier")
    digest = value.removeprefix("sha256:")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ControlPlaneIsolationError(f"{field} is not a sha256 identifier")
    return value


def _error_detail(exc: BaseException) -> str:
    if isinstance(exc, OSError):
        return exc.strerror or exc.__class__.__name__
    return str(exc)
