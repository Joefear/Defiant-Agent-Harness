"""Capability-gated tool registry.

The registry owns authoritative tool metadata and a process-local signing key.
Adapters may describe an action, but they cannot downgrade the registered side
effect or forge a grant that this registry will accept.

This protects the harness against accidental bypasses and untrusted adapter
claims. Code already executing inside the harness process is part of the
trusted computing base; Python is not an OS sandbox.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from copy import deepcopy
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Callable, Iterable

from ..contracts import (
    ActionHashLimitError,
    CapabilityGrant,
    Decision,
    EvidenceRecord,
    GrantError,
    ProposedAction,
    ResultStatus,
    SideEffect,
    action_sha256_of,
    canonical_json,
    sha256_of,
)
from ..limits import MAX_TOOL_RESULT_SUMMARY_CHARACTERS
from ..money import ZERO, money
from ..workspace_integrity import (
    WorkspaceIntegrityError,
    WorkspaceRootAssurance,
    require_workspace_root_unchanged,
)


class ToolContractError(RuntimeError):
    """An action disagrees with the registry's authoritative contract."""


class ToolResultContractError(ValueError):
    """A post-execution result cannot be accepted as canonical evidence."""

    def __init__(self, message: str, *, limit_enforced: str):
        super().__init__(message)
        self.limit_enforced = limit_enforced


class ToolResultLimitError(ToolResultContractError):
    """A post-execution result exceeded a fixed resource ceiling."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    side_effect_level: SideEffect
    description: str
    cost_estimate_usd: Decimal = ZERO
    supports_dry_run: bool = True
    target_scope: str = "any"  # any | workspace | workspace_path

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("tool name must be non-empty")
        if not isinstance(self.side_effect_level, SideEffect):
            object.__setattr__(
                self, "side_effect_level", SideEffect(self.side_effect_level)
            )
        object.__setattr__(
            self,
            "cost_estimate_usd",
            money(self.cost_estimate_usd, field_name=f"{self.name}.cost_estimate_usd"),
        )
        if self.target_scope not in {"any", "workspace", "workspace_path"}:
            raise ValueError(
                f"invalid target_scope for {self.name}: {self.target_scope}"
            )

    def authority_dict(self) -> dict[str, Any]:
        """Security-relevant contract fields included in the ruleset hash."""
        return {
            "name": self.name,
            "side_effect_level": self.side_effect_level.value,
            "cost_estimate_usd": str(self.cost_estimate_usd),
            "supports_dry_run": self.supports_dry_run,
            "target_scope": self.target_scope,
        }


@dataclass
class ToolResult:
    status: str  # succeeded | failed
    summary: str
    output: Any = None
    cost_usd: Decimal = ZERO
    dry_run: bool = False
    _sealed_output_hash: str = field(default="", init=False, repr=False)
    _contract_sealed: bool = field(default=False, init=False, repr=False)

    _CONTRACT_FIELDS = frozenset({"status", "summary", "output", "cost_usd", "dry_run"})

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_contract_sealed", False) and (
            name in self._CONTRACT_FIELDS
            or name in {"_sealed_output_hash", "_contract_sealed"}
        ):
            raise ValueError("sealed tool result contract fields cannot be changed")
        object.__setattr__(self, name, value)

    def __post_init__(self) -> None:
        self._validate_contract()

    def validate_fields(self) -> None:
        """Normalize scalar fields before completion cost is selected."""
        self._validate_fields()

    def seal_contract(self) -> None:
        """Revalidate, detach, hash, and freeze one returned tool result."""
        if self._contract_sealed:
            return
        self._validate_contract()
        output = deepcopy(self.output)
        output_hash = _tool_result_output_hash(output)
        object.__setattr__(self, "output", output)
        object.__setattr__(self, "_sealed_output_hash", output_hash)
        object.__setattr__(self, "_contract_sealed", True)

    def _validate_fields(self) -> None:
        if not isinstance(self.status, str) or self.status not in {
            "succeeded",
            "failed",
        }:
            raise ToolResultContractError(
                "tool result status is invalid",
                limit_enforced="tool_result_status",
            )
        if not isinstance(self.summary, str):
            raise ToolResultContractError(
                "tool result summary must be a string",
                limit_enforced="tool_result_summary_contract",
            )
        if len(self.summary) > MAX_TOOL_RESULT_SUMMARY_CHARACTERS:
            raise ToolResultLimitError(
                "tool result summary exceeds maximum of "
                f"{MAX_TOOL_RESULT_SUMMARY_CHARACTERS} characters",
                limit_enforced="tool_result_summary_characters",
            )
        if not isinstance(self.dry_run, bool):
            raise ToolResultContractError(
                "tool result dry_run must be a boolean",
                limit_enforced="tool_result_dry_run",
            )
        try:
            self.cost_usd = money(self.cost_usd, field_name="tool result cost_usd")
        except ValueError as exc:
            raise ToolResultContractError(
                "tool result cost is invalid",
                limit_enforced="tool_result_cost",
            ) from exc

    def _validate_contract(self) -> None:
        self._validate_fields()
        _tool_result_output_hash(self.output)

    @property
    def output_hash(self) -> str:
        if self._contract_sealed:
            return self._sealed_output_hash
        return _tool_result_output_hash(self.output)


def _tool_result_output_hash(output: Any) -> str:
    try:
        return action_sha256_of(output)
    except ActionHashLimitError as exc:
        suffix = exc.limit_enforced.removeprefix("action_hash_")
        raise ToolResultLimitError(
            "tool result output exceeds a fixed canonical-value ceiling",
            limit_enforced=f"tool_result_output_{suffix}",
        ) from exc
    except (TypeError, ValueError) as exc:
        raise ToolResultContractError(
            "tool result output is not canonical JSON data",
            limit_enforced="tool_result_output_contract",
        ) from exc


class ToolRegistry:
    def __init__(
        self,
        dry_run: bool = False,
        workspace_root: str | Path = "workspace",
    ):
        self._tools: dict[str, tuple[ToolSpec, Callable[..., ToolResult]]] = {}
        self.dry_run = dry_run
        # Preserve the configured final path component until authority startup
        # has rejected symlink/reparse indirection. Binding canonicalizes it.
        self.workspace_root = Path(workspace_root).absolute()
        self._workspace_assurance: WorkspaceRootAssurance | None = None
        self._protected_roots: tuple[Path, ...] = ()
        self._grant_key = secrets.token_bytes(32)

    # -- registration -------------------------------------------------

    def register(self, spec: ToolSpec, fn: Callable[..., ToolResult]) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool '{spec.name}' already registered")
        self._tools[spec.name] = (spec, fn)

    def spec(self, name: str) -> ToolSpec | None:
        entry = self._tools.get(name)
        return entry[0] if entry else None

    def names(self) -> list[str]:
        return sorted(self._tools)

    def specs(self) -> list[ToolSpec]:
        return [spec for spec, _ in self._tools.values()]

    def _protect_roots(self, roots: Iterable[str | Path]) -> None:
        """Bind control-plane roots that workspace tools must never overlap."""
        resolved = tuple(
            sorted(
                {Path(root).resolve(strict=True) for root in roots},
                key=lambda path: str(path).casefold(),
            )
        )
        if not resolved:
            raise ToolContractError(
                "at least one protected control-plane root is required"
            )
        if self._protected_roots and self._protected_roots != resolved:
            raise ToolContractError(
                "tool registry is already bound to different protected roots"
            )
        self._protected_roots = resolved

    def _bind_workspace_root(self, assurance: WorkspaceRootAssurance) -> None:
        if assurance.root != self.workspace_root.resolve(strict=True):
            raise ToolContractError(
                "workspace assurance does not match the tool registry root"
            )
        if (
            self._workspace_assurance is not None
            and self._workspace_assurance != assurance
        ):
            raise ToolContractError(
                "tool registry is already bound to a different workspace root"
            )
        self._workspace_assurance = assurance
        self.workspace_root = assurance.root

    # -- authoritative contract --------------------------------------

    def validate_action(self, action: ProposedAction) -> None:
        entry = self._tools.get(action.tool_name)
        if entry is None:
            raise ToolContractError(f"tool '{action.tool_name}' is not registered")
        spec, _ = entry
        if action.side_effect_level is not spec.side_effect_level:
            raise ToolContractError(
                f"adapter classified '{action.tool_name}' as "
                f"'{action.side_effect_level.value}', but the registry declares "
                f"'{spec.side_effect_level.value}'"
            )
        if spec.target_scope == "workspace":
            self._require_workspace_unchanged()
            target = resolve_workspace_target(action.target, self.workspace_root)
            self._require_unprotected(target)
        elif spec.target_scope == "workspace_path":
            self._require_workspace_unchanged()
            target = resolve_workspace_target(
                action.target,
                self.workspace_root,
                allow_root=True,
            )
            self._require_unprotected(target)

    def _require_unprotected(self, target: Path) -> None:
        for protected in self._protected_roots:
            if (
                target == protected
                or target.is_relative_to(protected)
                or protected.is_relative_to(target)
            ):
                raise ToolContractError(
                    "workspace target overlaps a protected control-plane path"
                )

    def _require_workspace_unchanged(self) -> None:
        if self._workspace_assurance is None:
            return
        try:
            require_workspace_root_unchanged(self._workspace_assurance)
        except WorkspaceIntegrityError as exc:
            raise ToolContractError(str(exc)) from exc

    # -- signed authority --------------------------------------------

    def authorize(
        self,
        action: ProposedAction,
        evidence_record: EvidenceRecord,
    ) -> CapabilityGrant:
        """Sign one grant after a sealed authorization record exists."""
        self.validate_action(action)
        if not evidence_record.record_hash:
            raise GrantError("authorization evidence must be sealed before grant issue")
        if sha256_of(evidence_record.body()) != evidence_record.record_hash:
            raise GrantError("authorization evidence content does not match its seal")
        if evidence_record.action_id != action.action_id:
            raise GrantError("authorization evidence/action id mismatch")
        if evidence_record.tool_name != action.tool_name:
            raise GrantError("authorization evidence/tool mismatch")
        if evidence_record.authorization_hash != action.authorization_hash:
            raise GrantError("authorization evidence/action hash mismatch")
        if evidence_record.result_status is not ResultStatus.SKIPPED:
            raise GrantError("authorization evidence is not execution-pending")
        if evidence_record.decision not in {
            Decision.ALLOW,
            Decision.APPROVAL_REQUIRED,
        }:
            raise GrantError("blocked evidence cannot authorize execution")

        grant = CapabilityGrant(
            action_id=action.action_id,
            tool_name=action.tool_name,
            authorization_hash=action.authorization_hash,
            evidence_record_id=evidence_record.record_id,
            evidence_record_hash=evidence_record.record_hash,
        )
        grant.signature = self._sign(grant)
        return grant

    def _sign(self, grant: CapabilityGrant) -> str:
        return hmac.new(
            self._grant_key,
            canonical_json(grant.claims()).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _verify(self, grant: CapabilityGrant) -> None:
        expected = self._sign(grant)
        if not grant.signature or not hmac.compare_digest(grant.signature, expected):
            raise GrantError(
                "capability grant signature is invalid; forged or cross-registry "
                "grants cannot execute tools"
            )

    # -- the only execution path -------------------------------------

    def execute(
        self,
        action: ProposedAction,
        grant: CapabilityGrant | None,
        dry_run: bool | None = None,
    ) -> ToolResult:
        if grant is None:
            raise GrantError(
                f"refusing to execute '{action.tool_name}': no capability grant "
                "presented"
            )

        self._verify(grant)
        self.validate_action(action)
        grant.spend(action)

        spec, fn = self._tools[action.tool_name]
        effective_dry_run = self.dry_run if dry_run is None else dry_run
        if effective_dry_run:
            if not spec.supports_dry_run:
                return ToolResult(
                    status="failed",
                    summary=f"tool '{spec.name}' does not support dry run",
                    dry_run=True,
                )
            return ToolResult(
                status="succeeded",
                summary=f"DRY RUN: would execute {spec.name} on {action.target}",
                output={
                    "dry_run": True,
                    "target": action.target,
                    "payload": action.payload,
                },
                cost_usd=ZERO,
                dry_run=True,
            )

        try:
            result = fn(action)
        except ToolResultContractError:
            # The grant is already spent. Leave the sealed authorization open
            # for approval-backed or approval-free reconciliation rather than
            # pretending the post-execution outcome is known.
            raise
        except Exception as exc:  # tool failure is data, not a harness crash
            return ToolResult(
                status="failed",
                summary=f"{type(exc).__name__}: {exc}",
                output=None,
                cost_usd=spec.cost_estimate_usd,
            )
        if not isinstance(result, ToolResult):
            raise ToolResultContractError(
                "tool returned an invalid result contract after execution",
                limit_enforced="tool_result_contract",
            )
        result.dry_run = False
        return result


def resolve_workspace_target(
    target: str,
    workspace_root: str | Path,
    *,
    allow_root: bool = False,
) -> Path:
    """Resolve a user-supplied file target inside one configured workspace."""
    if not isinstance(target, str) or not target.strip():
        raise ToolContractError("workspace file target must be non-empty")

    # Reject absolute syntax for both path families regardless of the host OS.
    # ``Path`` alone is host-dependent: on Linux it treats ``C:\...`` and UNC
    # paths as ordinary relative filenames.
    windows_path = PureWindowsPath(target)
    posix_path = PurePosixPath(target)
    if (
        windows_path.is_absolute()
        or windows_path.drive
        or windows_path.anchor
        or posix_path.is_absolute()
    ):
        raise ToolContractError(f"path is outside the approved workspace: {target}")

    # Treat both slash styles as separators so a path cannot change meaning
    # when a policy decision and execution happen on different platforms.
    parts = [
        part for part in target.replace("\\", "/").split("/") if part not in {"", "."}
    ]
    while parts and parts[0] in {".", "workspace"}:
        parts.pop(0)
    if ".." in parts:
        raise ToolContractError("workspace file target must name a file")

    root = Path(workspace_root).resolve(strict=False)
    if not parts:
        if allow_root:
            return root
        raise ToolContractError("workspace file target must name a file")
    candidate = root.joinpath(*parts).resolve(strict=False)
    if not candidate.is_relative_to(root) or (candidate == root and not allow_root):
        raise ToolContractError(f"path is outside the approved workspace: {target}")
    return candidate


def canonical_workspace_target(
    target: str,
    workspace_root: str | Path,
    *,
    allow_root: bool = False,
) -> str:
    """Normalize a same-host workspace path for policy and evidence.

    MCP servers commonly advertise or return absolute paths. The original
    transport payload remains unchanged and authorization-bound, while this
    canonical target prevents an in-workspace absolute path from looking like
    an escape to policy.
    """
    if not isinstance(target, str) or not target.strip():
        raise ToolContractError("workspace file target must be non-empty")

    root = Path(workspace_root).resolve(strict=False)
    supplied = Path(target)
    if supplied.is_absolute():
        candidate = supplied.resolve(strict=False)
        if not candidate.is_relative_to(root):
            raise ToolContractError(f"path is outside the approved workspace: {target}")
        if candidate == root and not allow_root:
            raise ToolContractError("workspace file target must name a file")
    else:
        candidate = resolve_workspace_target(
            target,
            root,
            allow_root=allow_root,
        )

    relative = candidate.relative_to(root)
    if not relative.parts:
        return "workspace"
    return "workspace/" + relative.as_posix()
