"""Content-addressed assurance for local runtime artifacts."""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .contracts import sha256_of, utc_now
from .persistence import (
    PersistenceError,
    atomic_write_json,
    exclusive_file_lock,
    prepare_storage_root,
    read_json,
)

RUNTIME_ARTIFACT_SCHEMA = "defiant.runtime_artifacts"
RUNTIME_ARTIFACT_VERSION = "0.1.0"
_STATE_FIELDS = {
    "schema_name",
    "schema_version",
    "profile_hash",
    "mode",
    "bundle_hash",
    "artifact_count",
    "executable_pinned",
    "verified_at",
}
_MODES = {"required", "unverified", "remote_not_applicable"}
_MAX_STATE_BYTES = 64 * 1024
_CHUNK_SIZE = 1024 * 1024


class RuntimeArtifactError(RuntimeError):
    """Runtime artifact assurance could not be established safely."""


@dataclass(frozen=True)
class RuntimeArtifactPin:
    """One operator-authored content pin in a local runtime bundle."""

    role: str
    path: Path
    sha256: str

    def __post_init__(self) -> None:
        role = self.role
        if (
            not isinstance(role, str)
            or not role
            or role != role.strip()
            or any(
                char not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for char in role
            )
        ):
            raise RuntimeArtifactError(
                "artifact role must use lowercase letters, digits, '_' or '-'"
            )
        object.__setattr__(self, "sha256", _hash(self.sha256, "artifact sha256"))


@dataclass(frozen=True)
class RuntimeArtifactAssurance:
    """Sanitized result of verifying a runtime artifact bundle."""

    mode: str
    bundle_hash: str | None
    artifact_count: int
    executable_pinned: bool
    command: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.mode not in _MODES:
            raise RuntimeArtifactError("unsupported runtime artifact mode")
        if self.bundle_hash is not None:
            _hash(self.bundle_hash, "bundle_hash")
        if type(self.artifact_count) is not int or self.artifact_count < 0:
            raise RuntimeArtifactError("artifact_count must be a non-negative integer")
        if type(self.executable_pinned) is not bool:
            raise RuntimeArtifactError("executable_pinned must be boolean")
        if self.mode == "required" and (
            self.bundle_hash is None
            or self.artifact_count < 1
            or not self.executable_pinned
        ):
            raise RuntimeArtifactError("required artifact assurance is incomplete")

    def authority_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "bundle_hash": self.bundle_hash,
            "artifact_count": self.artifact_count,
            "executable_pinned": self.executable_pinned,
        }


def unverified_artifacts(command: tuple[str, ...]) -> RuntimeArtifactAssurance:
    return RuntimeArtifactAssurance("unverified", None, 0, False, command)


def remote_artifacts() -> RuntimeArtifactAssurance:
    return RuntimeArtifactAssurance("remote_not_applicable", None, 0, False, ())


def verify_runtime_artifacts(
    command: tuple[str, ...],
    pins: Iterable[RuntimeArtifactPin],
    *,
    workdir: str | Path,
    cwd: str | Path | None = None,
) -> RuntimeArtifactAssurance:
    """Verify every pin and return an absolute executable command."""
    pins = tuple(pins)
    if not pins:
        return unverified_artifacts(command)
    if not command:
        raise RuntimeArtifactError("artifact pins require a local command")

    roles = [pin.role for pin in pins]
    if len(set(roles)) != len(roles):
        raise RuntimeArtifactError("artifact roles must be unique")
    executable = next((pin for pin in pins if pin.role == "executable"), None)
    if executable is None:
        raise RuntimeArtifactError("artifact pins require exactly one executable role")

    state_root = Path(workdir).resolve(strict=False)
    observations: list[dict[str, Any]] = []
    resolved_by_role: dict[str, Path] = {}
    resolved_paths: set[Path] = set()
    for pin in pins:
        source = pin.path
        if _path_has_symlink(source):
            raise RuntimeArtifactError(f"artifact '{pin.role}' must not be a symlink")
        try:
            resolved = source.resolve(strict=True)
        except OSError as exc:
            raise RuntimeArtifactError(
                f"artifact '{pin.role}' is missing or inaccessible"
            ) from exc
        if not resolved.is_file():
            raise RuntimeArtifactError(f"artifact '{pin.role}' must be a regular file")
        if resolved in resolved_paths:
            raise RuntimeArtifactError(
                "artifact paths must be unique after canonical resolution"
            )
        resolved_paths.add(resolved)
        if _is_within(resolved, state_root):
            raise RuntimeArtifactError(
                f"artifact '{pin.role}' must be outside mutable harness state"
            )
        observed = _file_hash(resolved)
        if not hmac.compare_digest(observed, pin.sha256):
            raise RuntimeArtifactError(f"artifact '{pin.role}' digest mismatch")
        resolved_by_role[pin.role] = resolved
        observations.append(
            {
                "role": pin.role,
                "path_hash": sha256_of(os.path.normcase(str(resolved))),
                "content_hash": observed,
                "size_bytes": resolved.stat().st_size,
            }
        )

    executable_path = resolved_by_role["executable"]
    configured = _resolve_command_executable(command[0], cwd)
    if configured != executable_path:
        raise RuntimeArtifactError(
            "server.command executable does not resolve to the pinned executable"
        )
    observations.sort(key=lambda item: item["role"])
    return RuntimeArtifactAssurance(
        mode="required",
        bundle_hash=sha256_of(observations),
        artifact_count=len(observations),
        executable_pinned=True,
        command=(str(executable_path), *command[1:]),
    )


def require_same_artifact_bundle(
    expected: RuntimeArtifactAssurance,
    observed: RuntimeArtifactAssurance,
) -> None:
    """Reject a verification-to-spawn race detected before process creation."""
    if expected.authority_dict() != observed.authority_dict():
        raise RuntimeArtifactError(
            "runtime artifact bundle changed after authority-profile verification"
        )


@dataclass(frozen=True)
class RuntimeArtifactState:
    profile_hash: str
    mode: str
    bundle_hash: str | None
    artifact_count: int
    executable_pinned: bool
    verified_at: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RuntimeArtifactState":
        if not isinstance(raw, dict) or set(raw) != _STATE_FIELDS:
            raise RuntimeArtifactError(
                "runtime artifact state fields do not match schema"
            )
        if raw.get("schema_name") != RUNTIME_ARTIFACT_SCHEMA:
            raise RuntimeArtifactError("unsupported runtime artifact schema")
        if raw.get("schema_version") != RUNTIME_ARTIFACT_VERSION:
            raise RuntimeArtifactError("unsupported runtime artifact version")
        profile_hash = _hash(raw.get("profile_hash"), "profile_hash")
        assurance = RuntimeArtifactAssurance(
            raw.get("mode"),
            raw.get("bundle_hash"),
            raw.get("artifact_count"),
            raw.get("executable_pinned"),
            (),
        )
        verified_at = raw.get("verified_at")
        if not isinstance(verified_at, str) or not verified_at:
            raise RuntimeArtifactError("verified_at must be a timestamp")
        try:
            parsed = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RuntimeArtifactError("verified_at must be a timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise RuntimeArtifactError("verified_at must include a timezone")
        return cls(profile_hash, **assurance.authority_dict(), verified_at=verified_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": RUNTIME_ARTIFACT_SCHEMA,
            "schema_version": RUNTIME_ARTIFACT_VERSION,
            "profile_hash": self.profile_hash,
            "mode": self.mode,
            "bundle_hash": self.bundle_hash,
            "artifact_count": self.artifact_count,
            "executable_pinned": self.executable_pinned,
            "verified_at": self.verified_at,
        }

    def projection(self, *, verification: str) -> dict[str, Any]:
        return {
            "state": "pinned" if self.mode == "required" else self.mode,
            "verification": verification,
            "profile_hash": self.profile_hash,
            "bundle_hash": self.bundle_hash,
            "artifact_count": self.artifact_count,
            "executable_pinned": self.executable_pinned,
            "last_verified_at": self.verified_at,
        }


class RuntimeArtifactStateStore:
    """Persist only a sanitized verification result, never artifact paths."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self) -> RuntimeArtifactState | None:
        if not self.path.exists():
            return None
        try:
            if self.path.stat().st_size > _MAX_STATE_BYTES:
                raise RuntimeArtifactError("runtime artifact state is too large")
            return RuntimeArtifactState.from_dict(read_json(self.path))
        except RuntimeArtifactError:
            raise
        except (OSError, RuntimeError) as exc:
            raise RuntimeArtifactError(str(exc)) from exc

    def record(
        self,
        profile_hash: str,
        assurance: RuntimeArtifactAssurance,
    ) -> RuntimeArtifactState:
        profile_hash = _hash(profile_hash, "profile_hash")
        prepare_storage_root(self.path.parent)
        try:
            with exclusive_file_lock(self.path):
                previous = self.get()
                stable = assurance.authority_dict()
                if previous is not None and previous.profile_hash == profile_hash:
                    previous_stable = {
                        "mode": previous.mode,
                        "bundle_hash": previous.bundle_hash,
                        "artifact_count": previous.artifact_count,
                        "executable_pinned": previous.executable_pinned,
                    }
                    if previous_stable != stable:
                        raise RuntimeArtifactError(
                            "runtime artifact state conflicts with the active authority profile"
                        )
                state = RuntimeArtifactState(
                    profile_hash=profile_hash,
                    **stable,
                    verified_at=utc_now(),
                )
                atomic_write_json(self.path, state.to_dict())
                return state
        except RuntimeArtifactError:
            raise
        except (OSError, PersistenceError) as exc:
            raise RuntimeArtifactError(str(exc)) from exc


def _resolve_command_executable(value: str, cwd: str | Path | None) -> Path:
    candidate = Path(value)
    if candidate.is_absolute() or candidate.parent != Path("."):
        if not candidate.is_absolute():
            candidate = Path(cwd) / candidate if cwd is not None else candidate
        try:
            return candidate.resolve(strict=True)
        except OSError as exc:
            raise RuntimeArtifactError("server.command executable is missing") from exc
    found = shutil.which(value)
    if not found:
        raise RuntimeArtifactError("server.command executable cannot be resolved")
    return Path(found).resolve(strict=True)


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError as exc:
        raise RuntimeArtifactError(f"cannot hash artifact '{path.name}'") from exc
    return f"sha256:{digest.hexdigest()}"


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise RuntimeArtifactError(f"{field} is not a sha256 identifier")
    digest = value.removeprefix("sha256:")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise RuntimeArtifactError(f"{field} is not a sha256 identifier")
    return value


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _path_has_symlink(path: Path) -> bool:
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parts[1:] if absolute.anchor else absolute.parts:
        current /= part
        if current.is_symlink():
            return True
    return False
