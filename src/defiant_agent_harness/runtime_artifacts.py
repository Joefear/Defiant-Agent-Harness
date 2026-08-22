"""Content-addressed assurance for local runtime artifacts."""

from __future__ import annotations

import hashlib
import hmac
import os
import shutil
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
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
RUNTIME_ARTIFACT_VERSION = "0.2.0"
_STATE_FIELDS_V1 = {
    "schema_name",
    "schema_version",
    "profile_hash",
    "mode",
    "bundle_hash",
    "artifact_count",
    "executable_pinned",
    "verified_at",
}
_STATE_FIELDS = _STATE_FIELDS_V1 | {
    "dependency_root_count",
    "dependency_file_count",
}
_MODES = {"required", "closed", "unverified", "remote_not_applicable"}
_MAX_STATE_BYTES = 64 * 1024
_MAX_DEPENDENCY_FILES = 100_000
_MAX_DEPENDENCY_ENTRIES = 200_000
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
class RuntimeDependencyFilePin:
    """One operator-authored file pin relative to a closed dependency root."""

    path: str
    sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _relative_manifest_path(self.path))
        object.__setattr__(self, "sha256", _hash(self.sha256, "dependency file sha256"))


@dataclass(frozen=True)
class RuntimeDependencyRoot:
    """A directory whose complete regular-file inventory is operator pinned."""

    path: Path
    files: tuple[RuntimeDependencyFilePin, ...]

    def __post_init__(self) -> None:
        if not self.files:
            raise RuntimeArtifactError("dependency root needs at least one file")
        if len(self.files) > _MAX_DEPENDENCY_FILES:
            raise RuntimeArtifactError("dependency root manifest has too many files")
        paths = [item.path for item in self.files]
        if len(set(paths)) != len(paths):
            raise RuntimeArtifactError("dependency root file paths must be unique")


@dataclass(frozen=True)
class RuntimeArtifactAssurance:
    """Sanitized result of verifying a runtime artifact bundle."""

    mode: str
    bundle_hash: str | None
    artifact_count: int
    executable_pinned: bool
    command: tuple[str, ...]
    dependency_root_count: int = 0
    dependency_file_count: int = 0

    def __post_init__(self) -> None:
        if self.mode not in _MODES:
            raise RuntimeArtifactError("unsupported runtime artifact mode")
        if self.bundle_hash is not None:
            _hash(self.bundle_hash, "bundle_hash")
        if type(self.artifact_count) is not int or self.artifact_count < 0:
            raise RuntimeArtifactError("artifact_count must be a non-negative integer")
        if type(self.executable_pinned) is not bool:
            raise RuntimeArtifactError("executable_pinned must be boolean")
        if (
            type(self.dependency_root_count) is not int
            or self.dependency_root_count < 0
        ):
            raise RuntimeArtifactError(
                "dependency_root_count must be a non-negative integer"
            )
        if (
            type(self.dependency_file_count) is not int
            or self.dependency_file_count < 0
        ):
            raise RuntimeArtifactError(
                "dependency_file_count must be a non-negative integer"
            )
        if self.mode == "required" and (
            self.bundle_hash is None
            or self.artifact_count < 1
            or not self.executable_pinned
        ):
            raise RuntimeArtifactError("required artifact assurance is incomplete")
        if self.mode == "closed" and (
            self.bundle_hash is None
            or self.artifact_count < 1
            or not self.executable_pinned
            or self.dependency_root_count < 1
            or self.dependency_file_count < 1
        ):
            raise RuntimeArtifactError("closed artifact assurance is incomplete")
        if self.mode != "closed" and (
            self.dependency_root_count or self.dependency_file_count
        ):
            raise RuntimeArtifactError(
                "dependency counts are only valid in closed artifact mode"
            )

    def authority_dict(self) -> dict[str, Any]:
        result = {
            "mode": self.mode,
            "bundle_hash": self.bundle_hash,
            "artifact_count": self.artifact_count,
            "executable_pinned": self.executable_pinned,
        }
        if self.mode == "closed":
            result.update(
                dependency_root_count=self.dependency_root_count,
                dependency_file_count=self.dependency_file_count,
            )
        return result


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
    dependency_roots: Iterable[RuntimeDependencyRoot] = (),
) -> RuntimeArtifactAssurance:
    """Verify every pin and return an absolute executable command."""
    pins = tuple(pins)
    dependency_roots = tuple(dependency_roots)
    if not pins and dependency_roots:
        raise RuntimeArtifactError("dependency roots require artifact pins")
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
    dependency_observations = _verify_dependency_roots(
        dependency_roots,
        state_root=state_root,
    )
    if dependency_observations:
        observations = [
            {"kind": "artifact", **item} for item in observations
        ] + dependency_observations
    return RuntimeArtifactAssurance(
        mode="closed" if dependency_roots else "required",
        bundle_hash=sha256_of(observations),
        artifact_count=len(observations),
        executable_pinned=True,
        command=(str(executable_path), *command[1:]),
        dependency_root_count=len(dependency_roots),
        dependency_file_count=len(dependency_observations),
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
    dependency_root_count: int
    dependency_file_count: int
    verified_at: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RuntimeArtifactState":
        if not isinstance(raw, dict):
            raise RuntimeArtifactError(
                "runtime artifact state fields do not match schema"
            )
        if raw.get("schema_name") != RUNTIME_ARTIFACT_SCHEMA:
            raise RuntimeArtifactError("unsupported runtime artifact schema")
        version = raw.get("schema_version")
        expected_fields = _STATE_FIELDS_V1 if version == "0.1.0" else _STATE_FIELDS
        if set(raw) != expected_fields:
            raise RuntimeArtifactError(
                "runtime artifact state fields do not match schema"
            )
        if version not in {"0.1.0", RUNTIME_ARTIFACT_VERSION}:
            raise RuntimeArtifactError("unsupported runtime artifact version")
        profile_hash = _hash(raw.get("profile_hash"), "profile_hash")
        assurance = RuntimeArtifactAssurance(
            raw.get("mode"),
            raw.get("bundle_hash"),
            raw.get("artifact_count"),
            raw.get("executable_pinned"),
            (),
            raw.get("dependency_root_count", 0),
            raw.get("dependency_file_count", 0),
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
        return cls(
            profile_hash=profile_hash,
            mode=assurance.mode,
            bundle_hash=assurance.bundle_hash,
            artifact_count=assurance.artifact_count,
            executable_pinned=assurance.executable_pinned,
            dependency_root_count=assurance.dependency_root_count,
            dependency_file_count=assurance.dependency_file_count,
            verified_at=verified_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": RUNTIME_ARTIFACT_SCHEMA,
            "schema_version": RUNTIME_ARTIFACT_VERSION,
            "profile_hash": self.profile_hash,
            "mode": self.mode,
            "bundle_hash": self.bundle_hash,
            "artifact_count": self.artifact_count,
            "executable_pinned": self.executable_pinned,
            "dependency_root_count": self.dependency_root_count,
            "dependency_file_count": self.dependency_file_count,
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
            "dependency_root_count": self.dependency_root_count,
            "dependency_file_count": self.dependency_file_count,
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
                    previous_stable: dict[str, Any] = {
                        "mode": previous.mode,
                        "bundle_hash": previous.bundle_hash,
                        "artifact_count": previous.artifact_count,
                        "executable_pinned": previous.executable_pinned,
                    }
                    if previous.mode == "closed":
                        previous_stable.update(
                            dependency_root_count=previous.dependency_root_count,
                            dependency_file_count=previous.dependency_file_count,
                        )
                    if previous_stable != stable:
                        raise RuntimeArtifactError(
                            "runtime artifact state conflicts with the active authority profile"
                        )
                state = RuntimeArtifactState(
                    profile_hash=profile_hash,
                    mode=assurance.mode,
                    bundle_hash=assurance.bundle_hash,
                    artifact_count=assurance.artifact_count,
                    executable_pinned=assurance.executable_pinned,
                    dependency_root_count=assurance.dependency_root_count,
                    dependency_file_count=assurance.dependency_file_count,
                    verified_at=utc_now(),
                )
                atomic_write_json(self.path, state.to_dict())
                return state
        except RuntimeArtifactError:
            raise
        except (OSError, PersistenceError) as exc:
            raise RuntimeArtifactError(str(exc)) from exc


def _verify_dependency_roots(
    roots: tuple[RuntimeDependencyRoot, ...],
    *,
    state_root: Path,
) -> list[dict[str, Any]]:
    if not roots:
        return []

    resolved_roots: list[tuple[Path, RuntimeDependencyRoot]] = []
    for root in roots:
        if _path_has_link_or_reparse(root.path):
            raise RuntimeArtifactError("dependency root must not contain links")
        try:
            resolved = root.path.resolve(strict=True)
        except OSError as exc:
            raise RuntimeArtifactError(
                "dependency root is missing or inaccessible"
            ) from exc
        if not resolved.is_dir():
            raise RuntimeArtifactError("dependency root must be a directory")
        if _is_within(resolved, state_root) or _is_within(state_root, resolved):
            raise RuntimeArtifactError(
                "dependency roots and mutable harness state must not overlap"
            )
        resolved_roots.append((resolved, root))

    canonical = [item[0] for item in resolved_roots]
    if len(set(canonical)) != len(canonical):
        raise RuntimeArtifactError("dependency root paths must be unique")
    for index, left in enumerate(canonical):
        for right in canonical[index + 1 :]:
            if _is_within(left, right) or _is_within(right, left):
                raise RuntimeArtifactError("dependency roots must not overlap")

    observations: list[dict[str, Any]] = []
    for resolved, root in sorted(
        resolved_roots, key=lambda item: os.path.normcase(str(item[0]))
    ):
        expected = {item.path: item for item in root.files}
        observed_paths = _inventory_dependency_root(resolved)
        expected_paths = set(expected)
        if observed_paths != expected_paths:
            added = len(observed_paths - expected_paths)
            missing = len(expected_paths - observed_paths)
            raise RuntimeArtifactError(
                f"dependency root inventory mismatch ({added} added, {missing} missing)"
            )
        root_hash = sha256_of(os.path.normcase(str(resolved)))
        for relative in sorted(expected):
            candidate = resolved.joinpath(*PurePosixPath(relative).parts)
            if _path_has_link_or_reparse(candidate):
                raise RuntimeArtifactError("dependency files must not contain links")
            try:
                canonical_file = candidate.resolve(strict=True)
            except OSError as exc:
                raise RuntimeArtifactError(
                    "dependency file disappeared during verification"
                ) from exc
            if not _is_within(canonical_file, resolved):
                raise RuntimeArtifactError("dependency file escapes its root")
            try:
                metadata = candidate.stat(follow_symlinks=False)
            except OSError as exc:
                raise RuntimeArtifactError(
                    "dependency file is inaccessible during verification"
                ) from exc
            if (
                not stat.S_ISREG(metadata.st_mode)
                or _is_reparse(metadata)
                or metadata.st_nlink != 1
            ):
                raise RuntimeArtifactError("dependency file must be a regular file")
            observed = _file_hash(candidate)
            if not hmac.compare_digest(observed, expected[relative].sha256):
                raise RuntimeArtifactError("dependency file digest mismatch")
            observations.append(
                {
                    "kind": "dependency",
                    "root_hash": root_hash,
                    "relative_path": relative,
                    "content_hash": observed,
                    "size_bytes": metadata.st_size,
                }
            )
    return observations


def _inventory_dependency_root(root: Path) -> set[str]:
    files: set[str] = set()
    entry_count = 0
    stack: list[tuple[Path, PurePosixPath]] = [(root, PurePosixPath())]
    while stack:
        directory, relative_dir = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise RuntimeArtifactError("cannot inventory dependency root") from exc
        for entry in entries:
            entry_count += 1
            if entry_count > _MAX_DEPENDENCY_ENTRIES:
                raise RuntimeArtifactError("dependency root has too many entries")
            relative = relative_dir / entry.name
            try:
                # pathlib uses the full Windows stat path and reports link
                # counts accurately; DirEntry.stat may return st_nlink == 0.
                metadata = Path(entry.path).lstat()
            except OSError as exc:
                raise RuntimeArtifactError(
                    "dependency entry is inaccessible during inventory"
                ) from exc
            if entry.is_symlink() or _is_reparse(metadata):
                raise RuntimeArtifactError("dependency root must not contain links")
            if stat.S_ISDIR(metadata.st_mode):
                stack.append((Path(entry.path), relative))
            elif stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise RuntimeArtifactError(
                        "dependency root must not contain hard links"
                    )
                normalized = relative.as_posix()
                if normalized in files:
                    raise RuntimeArtifactError(
                        "dependency root contains duplicate canonical paths"
                    )
                files.add(normalized)
                if len(files) > _MAX_DEPENDENCY_FILES:
                    raise RuntimeArtifactError("dependency root has too many files")
            else:
                raise RuntimeArtifactError(
                    "dependency root contains a non-regular entry"
                )
    return files


def _relative_manifest_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\x00" in value
    ):
        raise RuntimeArtifactError("dependency file path must be non-empty")
    if "\\" in value:
        raise RuntimeArtifactError("dependency file path must use '/' separators")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise RuntimeArtifactError(
            "dependency file path must be canonical and relative"
        )
    return value


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


def _path_has_link_or_reparse(path: Path) -> bool:
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parts[1:] if absolute.anchor else absolute.parts:
        current /= part
        try:
            metadata = current.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            return True
    return False


def _is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)
