"""Crash-safe publication checkpoint for profile-bound authority observations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .contracts import authority_snapshot_and_sha256_of, sha256_of, utc_now
from .limits import (
    MAX_AUTHORITY_PUBLICATION_MANIFEST_BYTES,
    MAX_AUTHORITY_PUBLICATION_STATE_BYTES,
)
from .persistence import (
    PersistenceError,
    atomic_write_json,
    exclusive_file_lock,
    prepare_storage_root,
    read_json,
)

AUTHORITY_PUBLICATION_SCHEMA = "defiant.authority_publication"
AUTHORITY_PUBLICATION_VERSION = "0.3.0"
LEGACY_AUTHORITY_PUBLICATION_VERSION = "0.1.0"
TARGET_COMMITMENT_AUTHORITY_PUBLICATION_VERSION = "0.2.0"
_SUPPORTED_AUTHORITY_PUBLICATION_VERSIONS = {
    LEGACY_AUTHORITY_PUBLICATION_VERSION,
    TARGET_COMMITMENT_AUTHORITY_PUBLICATION_VERSION,
    AUTHORITY_PUBLICATION_VERSION,
}
_STATE_FIELDS = {"schema_name", "schema_version", "active", "completed"}
_LEGACY_INTENT_FIELDS = {
    "profile_hash",
    "generation",
    "manifest_hash",
    "prepared_at",
}
_INTENT_FIELDS = {*_LEGACY_INTENT_FIELDS, "store_hashes"}
AUTHORITY_PUBLICATION_STORE_NAMES = (
    "state_storage",
    "control_plane_isolation",
    "workspace_integrity",
    "evidence_witness_policy",
    "runtime_artifacts",
    "launch_envelope",
    "evidence_head",
)
_OPTIONAL_AUTHORITY_PUBLICATION_STORES = {
    "runtime_artifacts",
    "launch_envelope",
}
_LEGACY_CHECKPOINT_FIELDS = {
    "profile_hash",
    "generation",
    "manifest_hash",
    "completed_at",
}
_CHECKPOINT_FIELDS = {*_LEGACY_CHECKPOINT_FIELDS, "store_hashes"}


class AuthorityPublicationError(RuntimeError):
    """A coordinated authority publication cannot be proven or recovered."""


@dataclass(frozen=True)
class AuthorityPublicationIntent:
    profile_hash: str
    generation: int
    manifest_hash: str
    prepared_at: str
    store_hashes: tuple[tuple[str, str | None], ...] | None = None

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        schema_version: str = AUTHORITY_PUBLICATION_VERSION,
    ) -> "AuthorityPublicationIntent":
        snapshot = _snapshot(raw, "authority publication intent")
        expected_fields = (
            _LEGACY_INTENT_FIELDS
            if schema_version == LEGACY_AUTHORITY_PUBLICATION_VERSION
            else _INTENT_FIELDS
        )
        if set(snapshot) != expected_fields:
            raise AuthorityPublicationError(
                "authority publication intent fields do not match schema"
            )
        return cls(
            _hash(snapshot.get("profile_hash"), "profile_hash"),
            _generation(snapshot.get("generation")),
            _hash(snapshot.get("manifest_hash"), "manifest_hash"),
            _timestamp(snapshot.get("prepared_at"), "prepared_at"),
            (
                None
                if schema_version == LEGACY_AUTHORITY_PUBLICATION_VERSION
                else _store_hashes(snapshot.get("store_hashes"))
            ),
        )

    def matches(
        self,
        profile_hash: str,
        generation: int,
        manifest_hash: str,
        store_hashes: Any | None = None,
    ) -> bool:
        basic_match = (
            self.profile_hash == profile_hash
            and self.generation == generation
            and self.manifest_hash == manifest_hash
        )
        if not basic_match or store_hashes is None or self.store_hashes is None:
            return basic_match
        if type(store_hashes) is tuple:
            store_hashes = dict(store_hashes)
        return self.store_hashes == _store_hashes(store_hashes)

    def to_dict(self) -> dict[str, Any]:
        result = {
            "profile_hash": self.profile_hash,
            "generation": self.generation,
            "manifest_hash": self.manifest_hash,
            "prepared_at": self.prepared_at,
        }
        if self.store_hashes is not None:
            result["store_hashes"] = dict(self.store_hashes)
        return result

    def with_store_hashes(self, store_hashes: Any) -> "AuthorityPublicationIntent":
        """Upgrade a matching legacy replay intent for its completed checkpoint."""
        return AuthorityPublicationIntent(
            self.profile_hash,
            self.generation,
            self.manifest_hash,
            self.prepared_at,
            _store_hashes(store_hashes),
        )


@dataclass(frozen=True)
class AuthorityPublicationCheckpoint:
    profile_hash: str
    generation: int
    manifest_hash: str
    completed_at: str
    store_hashes: tuple[tuple[str, str | None], ...] | None = None

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        *,
        schema_version: str = AUTHORITY_PUBLICATION_VERSION,
    ) -> "AuthorityPublicationCheckpoint":
        snapshot = _snapshot(raw, "authority publication checkpoint")
        expected_fields = (
            _CHECKPOINT_FIELDS
            if schema_version == AUTHORITY_PUBLICATION_VERSION
            else _LEGACY_CHECKPOINT_FIELDS
        )
        if set(snapshot) != expected_fields:
            raise AuthorityPublicationError(
                "authority publication checkpoint fields do not match schema"
            )
        return cls(
            _hash(snapshot.get("profile_hash"), "profile_hash"),
            _generation(snapshot.get("generation")),
            _hash(snapshot.get("manifest_hash"), "manifest_hash"),
            _timestamp(snapshot.get("completed_at"), "completed_at"),
            (
                _checkpoint_store_hashes(snapshot.get("store_hashes"))
                if schema_version == AUTHORITY_PUBLICATION_VERSION
                else None
            ),
        )

    def matches(self, profile_hash: str, generation: int, manifest_hash: str) -> bool:
        return (
            self.profile_hash == profile_hash
            and self.generation == generation
            and self.manifest_hash == manifest_hash
        )

    def to_dict(
        self,
        *,
        schema_version: str = AUTHORITY_PUBLICATION_VERSION,
    ) -> dict[str, Any]:
        result = {
            "profile_hash": self.profile_hash,
            "generation": self.generation,
            "manifest_hash": self.manifest_hash,
            "completed_at": self.completed_at,
        }
        if schema_version == AUTHORITY_PUBLICATION_VERSION:
            result["store_hashes"] = (
                None if self.store_hashes is None else dict(self.store_hashes)
            )
        return result


@dataclass(frozen=True)
class AuthorityPublicationState:
    active: AuthorityPublicationIntent | None
    completed: AuthorityPublicationCheckpoint | None
    schema_version: str = AUTHORITY_PUBLICATION_VERSION

    @classmethod
    def from_dict(cls, raw: Any) -> "AuthorityPublicationState":
        snapshot = _snapshot(raw, "authority publication state")
        if set(snapshot) != _STATE_FIELDS:
            raise AuthorityPublicationError(
                "authority publication state fields do not match schema"
            )
        if snapshot.get("schema_name") != AUTHORITY_PUBLICATION_SCHEMA:
            raise AuthorityPublicationError("unsupported authority publication schema")
        schema_version = snapshot.get("schema_version")
        if schema_version not in _SUPPORTED_AUTHORITY_PUBLICATION_VERSIONS:
            raise AuthorityPublicationError("unsupported authority publication version")
        active_raw = snapshot.get("active")
        completed_raw = snapshot.get("completed")
        active = (
            None
            if active_raw is None
            else AuthorityPublicationIntent.from_dict(
                active_raw,
                schema_version=schema_version,
            )
        )
        completed = (
            None
            if completed_raw is None
            else AuthorityPublicationCheckpoint.from_dict(
                completed_raw,
                schema_version=schema_version,
            )
        )
        if active is None and completed is None:
            raise AuthorityPublicationError(
                "authority publication state requires an active or completed record"
            )
        if (
            schema_version == AUTHORITY_PUBLICATION_VERSION
            and active is None
            and completed is not None
            and completed.store_hashes is None
        ):
            raise AuthorityPublicationError(
                "completed authority publication requires store commitments"
            )
        if active is not None and completed is not None:
            if active.generation not in {
                completed.generation,
                completed.generation + 1,
            }:
                raise AuthorityPublicationError(
                    "authority publication generations are not contiguous"
                )
            if active.generation == completed.generation and not active.matches(
                completed.profile_hash,
                completed.generation,
                completed.manifest_hash,
                completed.store_hashes,
            ):
                raise AuthorityPublicationError(
                    "same-generation authority publication records disagree"
                )
        return cls(active, completed, schema_version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": AUTHORITY_PUBLICATION_SCHEMA,
            "schema_version": self.schema_version,
            "active": self.active.to_dict() if self.active is not None else None,
            "completed": (
                self.completed.to_dict(schema_version=self.schema_version)
                if self.completed is not None
                else None
            ),
        }

    def projection(self) -> dict[str, Any]:
        current = self.active or self.completed
        return {
            "state": "recovery_required" if self.active is not None else "complete",
            "verification": "prepared" if self.active is not None else "verified",
            "profile_hash": current.profile_hash if current is not None else None,
            "generation": current.generation if current is not None else 0,
            "manifest_hash": current.manifest_hash if current is not None else None,
            "store_commitments": (
                "recorded"
                if self.active is not None and self.active.store_hashes is not None
                else (
                    "legacy_unavailable"
                    if self.active is not None
                    else "not_applicable"
                )
            ),
            "checkpoint_store_commitments": (
                "not_applicable"
                if self.completed is None
                else (
                    "recorded"
                    if self.completed.store_hashes is not None
                    else "legacy_unavailable"
                )
            ),
            "prepared_at": (
                self.active.prepared_at if self.active is not None else None
            ),
            "completed_at": (
                self.completed.completed_at if self.completed is not None else None
            ),
        }


class AuthorityPublicationStore:
    """Persist one exact replay intent and the last completed publication."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def get(self) -> AuthorityPublicationState | None:
        if not self.path.exists():
            return None
        try:
            return AuthorityPublicationState.from_dict(
                read_json(
                    self.path,
                    max_bytes=MAX_AUTHORITY_PUBLICATION_STATE_BYTES,
                )
            )
        except AuthorityPublicationError:
            raise
        except (OSError, RuntimeError) as exc:
            raise AuthorityPublicationError(str(exc)) from exc

    def prepare(
        self,
        profile_hash: str,
        generation: int,
        manifest_hash: str,
        store_hashes: Any,
    ) -> AuthorityPublicationIntent:
        profile_hash = _hash(profile_hash, "profile_hash")
        generation = _generation(generation)
        manifest_hash = _hash(manifest_hash, "manifest_hash")
        store_hashes = _store_hashes(store_hashes)
        prepare_storage_root(self.path.parent)
        try:
            with exclusive_file_lock(self.path):
                state = self.get() or AuthorityPublicationState(None, None)
                if state.active is not None:
                    if state.active.matches(
                        profile_hash,
                        generation,
                        manifest_hash,
                        store_hashes,
                    ):
                        return state.active
                    raise AuthorityPublicationError(
                        "a different authority publication requires recovery"
                    )
                intent = AuthorityPublicationIntent(
                    profile_hash,
                    generation,
                    manifest_hash,
                    utc_now(),
                    store_hashes,
                )
                self._write(
                    AuthorityPublicationState(
                        intent,
                        state.completed,
                        AUTHORITY_PUBLICATION_VERSION,
                    )
                )
                return intent
        except AuthorityPublicationError:
            raise
        except (OSError, PersistenceError) as exc:
            raise AuthorityPublicationError(str(exc)) from exc

    def complete(self, intent: AuthorityPublicationIntent) -> AuthorityPublicationState:
        expected = AuthorityPublicationIntent.from_dict(
            intent.to_dict(),
            schema_version=(
                AUTHORITY_PUBLICATION_VERSION
                if intent.store_hashes is not None
                else LEGACY_AUTHORITY_PUBLICATION_VERSION
            ),
        )
        try:
            with exclusive_file_lock(self.path):
                state = self.get()
                if state is None or state.active is None:
                    raise AuthorityPublicationError(
                        "no active authority publication to complete"
                    )
                if (
                    state.active.profile_hash != expected.profile_hash
                    or state.active.generation != expected.generation
                    or state.active.manifest_hash != expected.manifest_hash
                    or state.active.prepared_at != expected.prepared_at
                    or (
                        state.active.store_hashes is not None
                        and state.active.store_hashes != expected.store_hashes
                    )
                ):
                    raise AuthorityPublicationError(
                        "authority publication completion does not match intent"
                    )
                if expected.store_hashes is None:
                    raise AuthorityPublicationError(
                        "authority publication completion requires store commitments"
                    )
                checkpoint = AuthorityPublicationCheckpoint(
                    expected.profile_hash,
                    expected.generation,
                    expected.manifest_hash,
                    utc_now(),
                    expected.store_hashes,
                )
                completed = AuthorityPublicationState(
                    None,
                    checkpoint,
                    AUTHORITY_PUBLICATION_VERSION,
                )
                self._write(completed)
                return completed
        except AuthorityPublicationError:
            raise
        except (OSError, PersistenceError) as exc:
            raise AuthorityPublicationError(str(exc)) from exc

    def _write(self, state: AuthorityPublicationState) -> None:
        candidate = AuthorityPublicationState.from_dict(state.to_dict()).to_dict()
        atomic_write_json(
            self.path,
            candidate,
            max_bytes=MAX_AUTHORITY_PUBLICATION_STATE_BYTES,
        )


def authority_manifest_hash(manifest: Any) -> str:
    try:
        snapshot, digest = authority_snapshot_and_sha256_of(
            manifest,
            maximum_canonical_bytes=MAX_AUTHORITY_PUBLICATION_MANIFEST_BYTES,
        )
    except ValueError as exc:
        raise AuthorityPublicationError(
            "authority publication manifest exceeds bounded canonical state"
        ) from exc
    if type(snapshot) is not dict or not snapshot:
        raise AuthorityPublicationError(
            "authority publication manifest must be a non-empty object"
        )
    return digest


def authority_manifest_hash_for(
    *,
    profile_hash: str,
    generation: int,
    state_storage: Any,
    control_plane_isolation: Any,
    workspace_integrity: Any,
    evidence_witness_policy: Any,
    runtime_artifacts: Any | None,
    launch_envelope: Any | None,
    evidence_head: Any,
) -> str:
    """Hash one complete set of sanitized profile-bound observations."""
    manifest_hash, _ = authority_manifest_commitments_for(
        profile_hash=profile_hash,
        generation=generation,
        state_storage=state_storage,
        control_plane_isolation=control_plane_isolation,
        workspace_integrity=workspace_integrity,
        evidence_witness_policy=evidence_witness_policy,
        runtime_artifacts=runtime_artifacts,
        launch_envelope=launch_envelope,
        evidence_head=evidence_head,
    )
    return manifest_hash


def authority_manifest_commitments_for(
    *,
    profile_hash: str,
    generation: int,
    state_storage: Any,
    control_plane_isolation: Any,
    workspace_integrity: Any,
    evidence_witness_policy: Any,
    runtime_artifacts: Any | None,
    launch_envelope: Any | None,
    evidence_head: Any,
) -> tuple[str, dict[str, str | None]]:
    """Commit one manifest and each exact target-store authority projection."""
    manifest = {
        "profile_hash": _hash(profile_hash, "profile_hash"),
        "generation": _generation(generation),
        "stores": {
            "state_storage": state_storage,
            "control_plane_isolation": control_plane_isolation,
            "workspace_integrity": workspace_integrity,
            "evidence_witness_policy": evidence_witness_policy,
            "runtime_artifacts": runtime_artifacts,
            "launch_envelope": launch_envelope,
            "evidence_head": evidence_head,
        },
    }
    try:
        snapshot, manifest_hash = authority_snapshot_and_sha256_of(
            manifest,
            maximum_canonical_bytes=MAX_AUTHORITY_PUBLICATION_MANIFEST_BYTES,
        )
    except ValueError as exc:
        raise AuthorityPublicationError(
            "authority publication manifest exceeds bounded canonical state"
        ) from exc
    stores = snapshot.get("stores")
    if type(stores) is not dict or set(stores) != set(
        AUTHORITY_PUBLICATION_STORE_NAMES
    ):
        raise AuthorityPublicationError(
            "authority publication manifest stores do not match schema"
        )
    store_hashes = {
        name: None if stores[name] is None else sha256_of(stores[name])
        for name in AUTHORITY_PUBLICATION_STORE_NAMES
    }
    return manifest_hash, dict(_store_hashes(store_hashes))


def authority_manifest_commitments_from_state(
    state_root: str | Path,
    *,
    profile_hash: str,
    generation: int,
) -> tuple[str, dict[str, str | None]]:
    """Reconstruct exact publication commitments from durable dependencies."""
    from .control_plane_isolation import ControlPlaneIsolationStateStore
    from .evidence_head import (
        EvidenceHeadStateStore,
        evidence_head_authority,
    )
    from .evidence_witness import EvidenceWitnessPolicyStore, WITNESS_VERSION
    from .launch_envelope import LaunchEnvelopeStateStore
    from .runtime_artifacts import RuntimeArtifactStateStore
    from .state_storage import StateStorageStateStore
    from .workspace_integrity import WorkspaceIntegrityStateStore

    root = Path(state_root)
    try:
        storage = StateStorageStateStore(root / "state_storage.json").get()
        isolation = ControlPlaneIsolationStateStore(
            root / "control_plane_isolation.json"
        ).get()
        workspace = WorkspaceIntegrityStateStore(
            root / "workspace_integrity.json"
        ).get()
        witness = EvidenceWitnessPolicyStore(
            root / "evidence_witness_policy.json"
        ).get()
        runtime = RuntimeArtifactStateStore(root / "runtime_artifacts.json").get()
        launch = LaunchEnvelopeStateStore(root / "launch_envelope.json").get()
        evidence_head = EvidenceHeadStateStore(root / "evidence_head.json").get()
    except RuntimeError as exc:
        raise AuthorityPublicationError(
            "a completed authority publication dependency is invalid"
        ) from exc

    required = {
        "state_storage": storage,
        "control_plane_isolation": isolation,
        "workspace_integrity": workspace,
        "evidence_witness_policy": witness,
        "evidence_head": evidence_head,
    }
    missing = next(
        (name for name, value in required.items() if value is None),
        None,
    )
    if missing is not None:
        raise AuthorityPublicationError(
            f"completed authority publication dependency '{missing}' is missing"
        )
    bound = {
        **required,
        "runtime_artifacts": runtime,
        "launch_envelope": launch,
    }
    mismatched = next(
        (
            name
            for name, value in bound.items()
            if value is not None and value.profile_hash != profile_hash
        ),
        None,
    )
    if mismatched is not None:
        raise AuthorityPublicationError(
            f"completed authority publication dependency '{mismatched}' has a profile mismatch"
        )

    witness_authority = {
        "mode": witness.mode,
        "schema_version": WITNESS_VERSION,
        "trusted_key_ids": list(witness.trusted_key_ids),
    }
    if witness.max_unwitnessed_records is not None:
        witness_authority["max_unwitnessed_records"] = witness.max_unwitnessed_records
    return authority_manifest_commitments_for(
        profile_hash=profile_hash,
        generation=generation,
        state_storage=storage.authority_dict(),
        control_plane_isolation=isolation.authority_dict(),
        workspace_integrity=workspace.authority_dict(),
        evidence_witness_policy=witness_authority,
        runtime_artifacts=(runtime.authority_dict() if runtime is not None else None),
        launch_envelope=(launch.authority_dict() if launch is not None else None),
        evidence_head=evidence_head_authority(),
    )


def _snapshot(value: Any, field: str) -> dict[str, Any]:
    try:
        snapshot, _ = authority_snapshot_and_sha256_of(
            value,
            maximum_canonical_bytes=MAX_AUTHORITY_PUBLICATION_STATE_BYTES,
        )
    except ValueError as exc:
        raise AuthorityPublicationError(
            f"{field} exceeds bounded canonical state"
        ) from exc
    if type(snapshot) is not dict:
        raise AuthorityPublicationError(f"{field} must be an object")
    return snapshot


def _hash(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AuthorityPublicationError(f"{field} is not a sha256 identifier")
    normalized = str.__str__(value)
    if not str.startswith(normalized, "sha256:"):
        raise AuthorityPublicationError(f"{field} is not a sha256 identifier")
    digest = str.removeprefix(normalized, "sha256:")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise AuthorityPublicationError(f"{field} is not a sha256 identifier")
    return normalized


def _store_hashes(value: Any) -> tuple[tuple[str, str | None], ...]:
    snapshot = _snapshot(value, "authority publication store hashes")
    if set(snapshot) != set(AUTHORITY_PUBLICATION_STORE_NAMES):
        raise AuthorityPublicationError(
            "authority publication store hash fields do not match schema"
        )
    result = []
    for name in AUTHORITY_PUBLICATION_STORE_NAMES:
        store_hash = snapshot.get(name)
        if store_hash is None:
            if name not in _OPTIONAL_AUTHORITY_PUBLICATION_STORES:
                raise AuthorityPublicationError(
                    f"authority publication store hash '{name}' is required"
                )
            result.append((name, None))
        else:
            result.append((name, _hash(store_hash, f"store_hashes.{name}")))
    return tuple(result)


def _checkpoint_store_hashes(
    value: Any,
) -> tuple[tuple[str, str | None], ...] | None:
    if value is None:
        return None
    return _store_hashes(value)


def _generation(value: Any) -> int:
    if type(value) is not int or value < 1:
        raise AuthorityPublicationError("authority publication generation is invalid")
    return value


def _timestamp(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise AuthorityPublicationError(f"{field} must be a timestamp")
    normalized = str.__str__(value)
    try:
        parsed = datetime.fromisoformat(str.replace(normalized, "Z", "+00:00"))
    except ValueError as exc:
        raise AuthorityPublicationError(f"{field} must be a timestamp") from exc
    if not normalized or parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorityPublicationError(f"{field} must include a timezone")
    return normalized
