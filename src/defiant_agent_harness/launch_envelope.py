"""Deterministic, sanitized assurance for local subprocess launch context."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .contracts import sha256_of, utc_now
from .persistence import (
    PersistenceError,
    atomic_write_json,
    exclusive_file_lock,
    read_json,
)

LAUNCH_ENVELOPE_SCHEMA = "defiant.launch_envelope"
LAUNCH_ENVELOPE_VERSION = "0.1.0"
_STATE_FIELDS = {
    "schema_name",
    "schema_version",
    "profile_hash",
    "mode",
    "environment_hash",
    "variable_count",
    "secret_count",
    "unsafe_count",
    "cwd_hash",
    "verified_at",
}
_MODES = {"restricted", "inherited_unrestricted", "remote_not_applicable"}
_MAX_STATE_BYTES = 64 * 1024

# Variables able to redirect code loading, shell initialization, dependency
# resolution, or runtime-wide behavior. Strict mode needs an explicit per-name
# acknowledgement before any of them cross the process boundary.
UNSAFE_ENVIRONMENT_VARIABLES = frozenset(
    {
        "BASH_ENV",
        "CDPATH",
        "CLASSPATH",
        "COMSPEC",
        "CURL_CA_BUNDLE",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "ENV",
        "GCONV_PATH",
        "GLIBC_TUNABLES",
        "GEM_HOME",
        "GEM_PATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "IFS",
        "JAVA_TOOL_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PATH",
        "PERL5LIB",
        "PERL5OPT",
        "PSMODULEPATH",
        "PROMPT_COMMAND",
        "PYTHONBREAKPOINT",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "REQUESTS_CA_BUNDLE",
        "RUBYLIB",
        "RUBYOPT",
        "SHELLOPTS",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "ZDOTDIR",
        "_JAVA_OPTIONS",
    }
)


class LaunchEnvelopeError(RuntimeError):
    """A local launch envelope could not be established safely."""


@dataclass(frozen=True)
class LaunchEnvironmentConfig:
    """Operator-authored restricted child-environment contract."""

    inherit: tuple[str, ...] = ()
    secret_env: tuple[str, ...] = ()
    values: tuple[tuple[str, str], ...] = ()
    allow_unsafe: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        inherited = tuple(_name(value, "inherit") for value in self.inherit)
        secrets = tuple(_name(value, "secret_env") for value in self.secret_env)
        values_list: list[tuple[str, str]] = []
        for entry in self.values:
            if not isinstance(entry, (tuple, list)) or len(entry) != 2:
                raise LaunchEnvelopeError(
                    "launch environment set entries must be name/value pairs"
                )
            name, value = entry
            checked_name = _name(name, "set")
            values_list.append((checked_name, _value(value, f"set.{checked_name}")))
        values = tuple(values_list)
        allowed = tuple(_name(value, "allow_unsafe") for value in self.allow_unsafe)
        names = [*inherited, *secrets, *(name for name, _ in values)]
        folded = [name.casefold() for name in names]
        if len(folded) != len(set(folded)):
            raise LaunchEnvelopeError(
                "launch environment variable sources must not overlap"
            )
        if len(allowed) != len({name.casefold() for name in allowed}):
            raise LaunchEnvelopeError("allow_unsafe entries must be unique")
        configured = {name.casefold() for name in names}
        for name in allowed:
            if name.casefold() not in configured:
                raise LaunchEnvelopeError(
                    "allow_unsafe may name only a configured environment variable"
                )
            if name.upper() not in UNSAFE_ENVIRONMENT_VARIABLES:
                raise LaunchEnvelopeError(
                    f"allow_unsafe contains non-sensitive variable {name!r}"
                )
        object.__setattr__(self, "inherit", tuple(sorted(inherited, key=str.casefold)))
        object.__setattr__(self, "secret_env", tuple(sorted(secrets, key=str.casefold)))
        object.__setattr__(
            self, "values", tuple(sorted(values, key=lambda x: x[0].casefold()))
        )
        object.__setattr__(
            self, "allow_unsafe", tuple(sorted(allowed, key=str.casefold))
        )


@dataclass(frozen=True)
class LaunchEnvelopeAssurance:
    """Sanitized launch result plus private effective process inputs."""

    mode: str
    environment_hash: str | None
    variable_count: int
    secret_count: int
    unsafe_count: int
    cwd_hash: str | None
    environment: Mapping[str, str] | None
    cwd: Path | None
    cwd_identity: tuple[int, int] | None

    def __post_init__(self) -> None:
        if self.mode not in _MODES:
            raise LaunchEnvelopeError("unsupported launch envelope mode")
        if self.environment_hash is not None:
            _hash(self.environment_hash, "environment_hash")
        if self.cwd_hash is not None:
            _hash(self.cwd_hash, "cwd_hash")
        counts = (self.variable_count, self.secret_count, self.unsafe_count)
        if any(type(value) is not int or value < 0 for value in counts):
            raise LaunchEnvelopeError(
                "launch envelope counts must be non-negative integers"
            )
        if (
            self.secret_count > self.variable_count
            or self.unsafe_count > self.variable_count
        ):
            raise LaunchEnvelopeError("launch envelope counts are inconsistent")

        if self.mode == "remote_not_applicable":
            if any(counts) or any(
                value is not None
                for value in (
                    self.environment_hash,
                    self.cwd_hash,
                    self.environment,
                    self.cwd,
                    self.cwd_identity,
                )
            ):
                raise LaunchEnvelopeError("remote launch envelope must be empty")
            return

        if self.environment is None or self.cwd is None or self.cwd_identity is None:
            raise LaunchEnvelopeError("local launch envelope is incomplete")
        if self.cwd_hash is None:
            raise LaunchEnvelopeError("local launch envelope requires a cwd hash")
        if (
            type(self.cwd_identity) is not tuple
            or len(self.cwd_identity) != 2
            or any(type(value) is not int for value in self.cwd_identity)
        ):
            raise LaunchEnvelopeError(
                "cwd identity must contain device and inode integers"
            )
        normalized: dict[str, str] = {}
        folded: set[str] = set()
        for name, value in self.environment.items():
            checked_name = _name(name, "effective")
            checked_value = _value(value, f"effective.{checked_name}")
            if checked_name.casefold() in folded:
                raise LaunchEnvelopeError(
                    "effective environment variable names must be unique"
                )
            folded.add(checked_name.casefold())
            normalized[checked_name] = checked_value
        if len(normalized) != self.variable_count:
            raise LaunchEnvelopeError("launch envelope variable count is inconsistent")
        unsafe_count = sum(
            name.upper() in UNSAFE_ENVIRONMENT_VARIABLES for name in normalized
        )
        if unsafe_count != self.unsafe_count:
            raise LaunchEnvelopeError("launch envelope unsafe count is inconsistent")
        if self.mode == "restricted" and self.environment_hash is None:
            raise LaunchEnvelopeError("restricted launch envelope is incomplete")
        if self.mode == "inherited_unrestricted" and (
            self.environment_hash is not None or self.secret_count != 0
        ):
            raise LaunchEnvelopeError("unrestricted launch envelope is inconsistent")
        object.__setattr__(self, "environment", MappingProxyType(normalized))

    def authority_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "environment_hash": self.environment_hash,
            "variable_count": self.variable_count,
            "secret_count": self.secret_count,
            "unsafe_count": self.unsafe_count,
            "cwd_hash": self.cwd_hash,
        }


def build_launch_envelope(
    config: LaunchEnvironmentConfig | None,
    *,
    cwd: str | Path | None,
    workdir: str | Path,
    parent_environment: Mapping[str, str] | None = None,
) -> LaunchEnvelopeAssurance:
    """Resolve one exact cwd and snapshot the effective child environment."""
    resolved_cwd, identity = _resolve_cwd(cwd, workdir, restricted=config is not None)
    cwd_hash = sha256_of(os.path.normcase(str(resolved_cwd)))
    source = dict(os.environ if parent_environment is None else parent_environment)
    if config is None:
        return LaunchEnvelopeAssurance(
            "inherited_unrestricted",
            None,
            len(source),
            0,
            sum(name.upper() in UNSAFE_ENVIRONMENT_VARIABLES for name in source),
            cwd_hash,
            source,
            resolved_cwd,
            identity,
        )

    by_folded = {name.casefold(): (name, value) for name, value in source.items()}
    effective: dict[str, str] = {}
    observations: list[dict[str, Any]] = []
    allowed = {name.casefold() for name in config.allow_unsafe}
    secret_names = {name.casefold() for name in config.secret_env}

    for configured_name in (*config.inherit, *config.secret_env):
        found = by_folded.get(configured_name.casefold())
        if found is None:
            raise LaunchEnvelopeError(
                f"required parent environment variable {configured_name!r} is not set"
            )
        _, value = found
        value = _value(value, configured_name)
        secret = configured_name.casefold() in secret_names
        if secret and not value:
            raise LaunchEnvelopeError(
                f"required secret environment variable {configured_name!r} is empty"
            )
        effective[configured_name] = value
        observations.append(
            {
                "name": configured_name,
                "source": "secret_env" if secret else "inherit",
                "value_hash": None if secret else sha256_of(value),
            }
        )

    for name, value in config.values:
        effective[name] = value
        observations.append(
            {"name": name, "source": "set", "value_hash": sha256_of(value)}
        )

    unsafe = sorted(
        name for name in effective if name.upper() in UNSAFE_ENVIRONMENT_VARIABLES
    )
    unapproved = [name for name in unsafe if name.casefold() not in allowed]
    if unapproved:
        raise LaunchEnvelopeError(
            "unsafe launch environment variables require explicit allow_unsafe: "
            + ", ".join(unapproved)
        )
    observations.sort(key=lambda item: item["name"].casefold())
    return LaunchEnvelopeAssurance(
        "restricted",
        sha256_of(observations),
        len(effective),
        len(config.secret_env),
        len(unsafe),
        cwd_hash,
        effective,
        resolved_cwd,
        identity,
    )


def remote_launch_envelope() -> LaunchEnvelopeAssurance:
    return LaunchEnvelopeAssurance(
        "remote_not_applicable", None, 0, 0, 0, None, None, None, None
    )


def require_launch_target_unchanged(assurance: LaunchEnvelopeAssurance) -> None:
    """Detect a cwd replacement between profile resolution and process spawn."""
    if assurance.cwd is None or assurance.cwd_identity is None:
        return
    try:
        stat = assurance.cwd.stat()
    except OSError as exc:
        raise LaunchEnvelopeError(
            "launch working directory changed or disappeared"
        ) from exc
    if (
        not assurance.cwd.is_dir()
        or (stat.st_dev, stat.st_ino) != assurance.cwd_identity
    ):
        raise LaunchEnvelopeError("launch working directory changed after verification")


@dataclass(frozen=True)
class LaunchEnvelopeState:
    profile_hash: str
    mode: str
    environment_hash: str | None
    variable_count: int
    secret_count: int
    unsafe_count: int
    cwd_hash: str | None
    verified_at: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "LaunchEnvelopeState":
        if not isinstance(raw, dict) or set(raw) != _STATE_FIELDS:
            raise LaunchEnvelopeError(
                "launch envelope state fields do not match schema"
            )
        if raw.get("schema_name") != LAUNCH_ENVELOPE_SCHEMA:
            raise LaunchEnvelopeError("unsupported launch envelope schema")
        if raw.get("schema_version") != LAUNCH_ENVELOPE_VERSION:
            raise LaunchEnvelopeError("unsupported launch envelope version")
        profile_hash = _hash(raw.get("profile_hash"), "profile_hash")
        mode = raw.get("mode")
        if mode not in _MODES:
            raise LaunchEnvelopeError("unsupported launch envelope mode")
        environment_hash = raw.get("environment_hash")
        cwd_hash = raw.get("cwd_hash")
        if environment_hash is not None:
            _hash(environment_hash, "environment_hash")
        if cwd_hash is not None:
            _hash(cwd_hash, "cwd_hash")
        counts = []
        for field in ("variable_count", "secret_count", "unsafe_count"):
            value = raw.get(field)
            if type(value) is not int or value < 0:
                raise LaunchEnvelopeError(f"{field} must be a non-negative integer")
            counts.append(value)
        if counts[1] > counts[0] or counts[2] > counts[0]:
            raise LaunchEnvelopeError("launch envelope counts are inconsistent")
        if mode == "restricted" and (environment_hash is None or cwd_hash is None):
            raise LaunchEnvelopeError("restricted launch envelope is incomplete")
        if mode == "inherited_unrestricted" and (
            environment_hash is not None or counts[1] != 0 or cwd_hash is None
        ):
            raise LaunchEnvelopeError("unrestricted launch envelope is inconsistent")
        if mode == "remote_not_applicable" and (
            environment_hash is not None or cwd_hash is not None or any(counts)
        ):
            raise LaunchEnvelopeError("remote launch envelope must be empty")
        verified_at = raw.get("verified_at")
        if not isinstance(verified_at, str) or not verified_at:
            raise LaunchEnvelopeError("verified_at must be a timestamp")
        try:
            parsed = datetime.fromisoformat(verified_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise LaunchEnvelopeError("verified_at must be a timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise LaunchEnvelopeError("verified_at must include a timezone")
        return cls(
            profile_hash,
            mode,
            environment_hash,
            counts[0],
            counts[1],
            counts[2],
            cwd_hash,
            verified_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": LAUNCH_ENVELOPE_SCHEMA,
            "schema_version": LAUNCH_ENVELOPE_VERSION,
            "profile_hash": self.profile_hash,
            "mode": self.mode,
            "environment_hash": self.environment_hash,
            "variable_count": self.variable_count,
            "secret_count": self.secret_count,
            "unsafe_count": self.unsafe_count,
            "cwd_hash": self.cwd_hash,
            "verified_at": self.verified_at,
        }

    def projection(self, *, verification: str) -> dict[str, Any]:
        return {
            "state": self.mode,
            "verification": verification,
            "profile_hash": self.profile_hash,
            "environment_hash": self.environment_hash,
            "variable_count": self.variable_count,
            "secret_count": self.secret_count,
            "unsafe_count": self.unsafe_count,
            "cwd_hash": self.cwd_hash,
            "last_verified_at": self.verified_at,
        }


class LaunchEnvelopeStateStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self) -> LaunchEnvelopeState | None:
        if not self.path.exists():
            return None
        try:
            if self.path.stat().st_size > _MAX_STATE_BYTES:
                raise LaunchEnvelopeError("launch envelope state is too large")
            return LaunchEnvelopeState.from_dict(read_json(self.path))
        except LaunchEnvelopeError:
            raise
        except (OSError, RuntimeError) as exc:
            raise LaunchEnvelopeError(str(exc)) from exc

    def record(
        self, profile_hash: str, assurance: LaunchEnvelopeAssurance
    ) -> LaunchEnvelopeState:
        profile_hash = _hash(profile_hash, "profile_hash")
        stable = assurance.authority_dict()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with exclusive_file_lock(self.path):
                previous = self.get()
                if previous is not None and previous.profile_hash == profile_hash:
                    previous_stable = {key: getattr(previous, key) for key in stable}
                    if previous_stable != stable:
                        raise LaunchEnvelopeError(
                            "launch envelope state conflicts with the active authority profile"
                        )
                state = LaunchEnvelopeState(
                    profile_hash=profile_hash, **stable, verified_at=utc_now()
                )
                atomic_write_json(self.path, state.to_dict())
                return state
        except LaunchEnvelopeError:
            raise
        except (OSError, PersistenceError) as exc:
            raise LaunchEnvelopeError(str(exc)) from exc


def _resolve_cwd(
    cwd: str | Path | None, workdir: str | Path, *, restricted: bool
) -> tuple[Path, tuple[int, int]]:
    if restricted and cwd is None:
        raise LaunchEnvelopeError(
            "restricted launch environment requires an explicit server.cwd"
        )
    candidate = Path.cwd() if cwd is None else Path(cwd)
    if _path_has_symlink(candidate):
        raise LaunchEnvelopeError("launch working directory must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
        stat = resolved.stat()
    except OSError as exc:
        raise LaunchEnvelopeError(
            "launch working directory is missing or inaccessible"
        ) from exc
    if not resolved.is_dir():
        raise LaunchEnvelopeError("launch working directory must be a directory")
    state_root = Path(workdir).resolve(strict=False)
    try:
        resolved.relative_to(state_root)
    except ValueError:
        pass
    else:
        raise LaunchEnvelopeError(
            "launch working directory must be outside mutable harness state"
        )
    return resolved, (stat.st_dev, stat.st_ino)


def _path_has_symlink(path: Path) -> bool:
    absolute = path if path.is_absolute() else Path.cwd() / path
    current = Path(absolute.anchor)
    for part in absolute.parts[1:] if absolute.anchor else absolute.parts:
        current /= part
        if current.is_symlink():
            return True
    return False


def _name(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "=" in value
        or "\x00" in value
    ):
        raise LaunchEnvelopeError(
            f"launch environment {field} names must be non-empty trimmed text"
        )
    return value


def _value(value: Any, field: str) -> str:
    if not isinstance(value, str) or "\x00" in value:
        raise LaunchEnvelopeError(f"launch environment {field} must be a string")
    return value


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise LaunchEnvelopeError(f"{field} is not a sha256 identifier")
    digest = value.removeprefix("sha256:")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise LaunchEnvelopeError(f"{field} is not a sha256 identifier")
    return value
