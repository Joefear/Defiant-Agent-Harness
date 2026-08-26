"""Canonical data contracts for the Defiant Agent Harness.

These are the only structures that cross layer boundaries. Every field that
participates in a security decision is hashed, and every hash is computed from
a canonical JSON encoding so that records are reproducible across machines.

Design rule: contracts are inert. They carry no authority and perform no I/O.
Authority is carried by a registry-signed CapabilityGrant issued only against
sealed authorization evidence in the normal control path.
"""

from __future__ import annotations

import enum
import hashlib
import json
import math
import uuid
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from functools import lru_cache
from typing import Any, Iterable

from .limits import (
    MAX_ACTION_HASH_CANONICAL_BYTES,
    MAX_ACTION_HASH_MAPPING_ENTRIES,
    MAX_ACTION_HASH_NESTING_DEPTH,
    MAX_ACTION_HASH_NODES,
    MAX_ACTION_HASH_NUMBER_CHARACTERS,
    MAX_ACTION_HASH_SCALAR_CHARACTERS,
    MAX_ACTION_HASH_STRING_TOKEN_BYTES,
    MAX_PROVENANCE_REFS,
    MAX_PROVENANCE_TEXT_CHARACTERS,
    MAX_PROVENANCE_TEXT_ITEM_CHARACTERS,
    MAX_REQUEST_ALLOWED_TOOL_CHARACTERS,
    MAX_REQUEST_ALLOWED_TOOLS,
    MAX_REQUEST_IDENTIFIER_CHARACTERS,
    MAX_REQUEST_TEXT_CHARACTERS,
    MAX_REQUEST_TEXT_ITEM_CHARACTERS,
)
from .money import ZERO, money, money_text


# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------


def utc_now() -> str:
    """RFC3339 UTC timestamp. Single source of time for the whole harness."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def canonical_json(obj: Any) -> str:
    """Deterministic JSON encoding used for every hash in the system."""
    return json.dumps(
        _enum_safe(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def sha256_of(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


class ActionHashLimitError(ValueError):
    """Action-controlled canonical hashing exceeded a fixed resource ceiling."""

    def __init__(self, message: str, *, limit_enforced: str):
        super().__init__(message)
        self.limit_enforced = limit_enforced


class RequestLimitError(ValueError):
    """Governed request or provenance metadata exceeded a fixed ceiling."""

    def __init__(self, message: str, *, limit_enforced: str):
        super().__init__(message)
        self.limit_enforced = limit_enforced


def action_sha256_of(obj: Any) -> str:
    """Hash action material without constructing an unbounded JSON string.

    This preserves the byte-for-byte canonical encoding used by ``sha256_of``
    while validating action-controlled structure first and feeding encoder
    chunks directly into SHA-256 under a fixed byte ceiling.
    """

    _validate_action_hash_structure(obj)
    encoder = json.JSONEncoder(
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=_action_hash_default,
    )
    digest = hashlib.sha256()
    encoded_bytes = 0
    try:
        for chunk in encoder.iterencode(obj):
            raw = chunk.encode("utf-8")
            if len(raw) > MAX_ACTION_HASH_CANONICAL_BYTES - encoded_bytes:
                _raise_action_hash_canonical_limit()
            digest.update(raw)
            encoded_bytes += len(raw)
    except ActionHashLimitError:
        raise
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError("action hash input is not canonical JSON data") from exc
    return "sha256:" + digest.hexdigest()


# ---------------------------------------------------------------------------
# enums
# ---------------------------------------------------------------------------


class Sensitivity(str, enum.Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CLIENT = "client"
    LEGAL = "legal"
    FINANCIAL = "financial"
    REGULATED = "regulated"
    UNKNOWN = "unknown"


class SideEffect(str, enum.Enum):
    """Ordered by blast radius. Policy thresholds compare against this order."""

    NONE = "none"
    LOCAL_WRITE = "local_write"
    EXTERNAL_SEND = "external_send"
    EXTERNAL_PUBLISH = "external_publish"
    SPEND = "spend"
    DESTRUCTIVE = "destructive"


SIDE_EFFECT_ORDER = [
    SideEffect.NONE,
    SideEffect.LOCAL_WRITE,
    SideEffect.EXTERNAL_SEND,
    SideEffect.EXTERNAL_PUBLISH,
    SideEffect.SPEND,
    SideEffect.DESTRUCTIVE,
]


def side_effect_rank(level: SideEffect) -> int:
    return SIDE_EFFECT_ORDER.index(level)


class Trust(str, enum.Enum):
    """Provenance of content flowing through the harness.

    This is the mechanical form of the invariant:
    knowledge can inform execution, knowledge cannot authorize execution.

    TRUSTED    - operator-authored, or approved knowledge under operator control.
    UNTRUSTED  - anything the agent read from the outside world: web pages, email
                 bodies, inbound documents, tool output, third-party MCP results.
    DERIVED    - produced by the agent from a mix; carries the worst trust level
                 of its inputs.
    """

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    DERIVED = "derived"


class Decision(str, enum.Enum):
    ALLOW = "allow"
    BLOCK = "block"
    APPROVAL_REQUIRED = "approval_required"


class ResultStatus(str, enum.Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    PENDING_APPROVAL = "pending_approval"
    EXPIRED = "expired"
    REJECTED = "rejected"
    NOT_EXECUTED = "not_executed"


# ---------------------------------------------------------------------------
# provenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContentRef:
    """A piece of content the agent consumed, with its provenance recorded.

    The harness never stores raw content in evidence -- only a hash and its
    trust level. That keeps evidence small, shareable, and free of client data.
    """

    ref_id: str
    origin: str  # "operator", "workspace_file", "web", "email", "mcp:<server>", ...
    trust: Trust
    content_hash: str
    label: str = ""

    def __post_init__(self) -> None:
        _require_text(self.ref_id, "ref_id")
        _require_text(self.origin, "origin")
        _require_text(self.content_hash, "content_hash")
        for field_name in ("ref_id", "origin", "content_hash", "label"):
            _require_provenance_text(getattr(self, field_name), field_name)
        if not isinstance(self.trust, Trust):
            object.__setattr__(self, "trust", Trust(self.trust))

    @staticmethod
    def of(origin: str, trust: Trust, content: Any, label: str = "") -> "ContentRef":
        return ContentRef(
            ref_id=new_id("ref"),
            origin=origin,
            trust=trust,
            content_hash=action_sha256_of(content),
            label=label,
        )


def worst_trust(refs: list[ContentRef]) -> Trust:
    """Trust is contagious downward. Any untrusted input taints the result."""
    if not refs:
        # Missing provenance is never equivalent to operator-authored content.
        return Trust.DERIVED
    if any(r.trust is Trust.UNTRUSTED for r in refs):
        return Trust.UNTRUSTED
    if any(r.trust is Trust.DERIVED for r in refs):
        return Trust.DERIVED
    return Trust.TRUSTED


# ---------------------------------------------------------------------------
# request / action / decision
# ---------------------------------------------------------------------------


@dataclass
class HarnessRequest:
    task: str
    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: new_id("req"))
    task_type: str = "general"
    sensitivity: Sensitivity = Sensitivity.INTERNAL
    allowed_tools: list[str] = field(default_factory=list)
    budget_limit_usd: Decimal | None = None
    inputs: list[ContentRef] = field(default_factory=list)
    created_at: str = field(default_factory=utc_now)
    _contract_sealed: bool = field(default=False, init=False, repr=False)

    _CONTRACT_FIELDS = frozenset(
        {
            "task",
            "user_id",
            "workspace_id",
            "request_id",
            "task_type",
            "sensitivity",
            "allowed_tools",
            "budget_limit_usd",
            "inputs",
            "created_at",
        }
    )

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_contract_sealed", False) and (
            name in self._CONTRACT_FIELDS or name == "_contract_sealed"
        ):
            raise ValueError("sealed request contract fields cannot be changed")
        object.__setattr__(self, name, value)

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_tools, list):
            raise ValueError("allowed_tools must be a list")
        if not isinstance(self.inputs, list):
            raise ValueError("inputs must be a list")
        self._validate_contract()

    def _validate_contract(self) -> None:
        if not isinstance(self.sensitivity, Sensitivity):
            self.sensitivity = Sensitivity(self.sensitivity)
        if self.budget_limit_usd is not None:
            self.budget_limit_usd = money(
                self.budget_limit_usd, field_name="budget_limit_usd"
            )
        self.created_at = _utc_timestamp(self.created_at, "created_at")
        _require_text(self.task, "task")
        _require_text(self.user_id, "user_id")
        _require_text(self.workspace_id, "workspace_id")
        _require_text(self.request_id, "request_id")
        _require_text(self.task_type, "task_type")
        _require_request_text(self.task, "task", MAX_REQUEST_TEXT_ITEM_CHARACTERS)
        for field_name in ("user_id", "workspace_id", "request_id", "task_type"):
            _require_request_text(
                getattr(self, field_name),
                field_name,
                MAX_REQUEST_IDENTIFIER_CHARACTERS,
            )
        if not isinstance(self.allowed_tools, (list, tuple)):
            raise ValueError("allowed_tools must be a list")
        if len(self.allowed_tools) > MAX_REQUEST_ALLOWED_TOOLS:
            raise RequestLimitError(
                "request allowed tool count exceeds maximum of "
                f"{MAX_REQUEST_ALLOWED_TOOLS}",
                limit_enforced="request_allowed_tools",
            )
        if any(
            not isinstance(name, str) or not name.strip() for name in self.allowed_tools
        ):
            raise ValueError("allowed_tools must contain non-empty strings")
        for name in self.allowed_tools:
            _require_request_text(
                name,
                "allowed tool",
                MAX_REQUEST_ALLOWED_TOOL_CHARACTERS,
            )
        if not isinstance(self.inputs, (list, tuple)):
            raise ValueError("inputs must be a list")
        if len(self.inputs) > MAX_PROVENANCE_REFS:
            raise RequestLimitError(
                "request input provenance count exceeds maximum of "
                f"{MAX_PROVENANCE_REFS}",
                limit_enforced="request_provenance_refs",
            )
        if any(not isinstance(ref, ContentRef) for ref in self.inputs):
            raise ValueError("inputs must contain ContentRef objects")
        _validate_request_text_volume(self)

    def seal_contract(self) -> None:
        """Validate, detach, and freeze the request used by the control path."""
        if self._contract_sealed:
            return
        self._validate_contract()
        object.__setattr__(self, "allowed_tools", tuple(self.allowed_tools))
        object.__setattr__(self, "inputs", tuple(self.inputs))
        object.__setattr__(self, "_contract_sealed", True)

    def to_dict(self) -> dict:
        data = _enum_safe(asdict(self))
        data.pop("_contract_sealed", None)
        return data

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "HarnessRequest":
        data = dict(raw)
        data.pop("_contract_sealed", None)
        data["sensitivity"] = Sensitivity(data.get("sensitivity", "internal"))
        data["inputs"] = [
            ContentRef(
                ref_id=ref["ref_id"],
                origin=ref["origin"],
                trust=Trust(ref["trust"]),
                content_hash=ref["content_hash"],
                label=ref.get("label", ""),
            )
            for ref in data.get("inputs", [])
        ]
        return cls(**data)


@dataclass
class ProposedAction:
    """What the agent wants to do. Produced by an adapter, never trusted."""

    tool_name: str
    target: str
    payload: dict
    side_effect_level: SideEffect
    agent_reason: str = ""
    action_id: str = field(default_factory=lambda: new_id("act"))
    request_id: str = ""
    # Provenance of the material this action's payload was built from.
    payload_sources: list[ContentRef] = field(default_factory=list)
    estimated_cost_usd: Decimal = ZERO
    created_at: str = field(default_factory=utc_now)
    _sealed_payload_hash: str = field(default="", init=False, repr=False)
    _sealed_authorization_hash: str = field(default="", init=False, repr=False)
    _fingerprints_sealed: bool = field(default=False, init=False, repr=False)

    _AUTHORIZATION_FIELDS = frozenset(
        {
            "action_id",
            "request_id",
            "tool_name",
            "target",
            "payload",
            "side_effect_level",
            "payload_sources",
            "estimated_cost_usd",
        }
    )

    def __setattr__(self, name: str, value: Any) -> None:
        if name in self._AUTHORIZATION_FIELDS and getattr(
            self, "_fingerprints_sealed", False
        ):
            raise ValueError("sealed action authorization fields cannot be changed")
        object.__setattr__(self, name, value)

    def __post_init__(self) -> None:
        _require_text(self.tool_name, "tool_name")
        _require_text(self.target, "target")
        _require_text(self.action_id, "action_id")
        if not isinstance(self.payload, dict):
            raise ValueError("payload must be a dictionary")
        if not isinstance(self.side_effect_level, SideEffect):
            self.side_effect_level = SideEffect(self.side_effect_level)
        if not isinstance(self.payload_sources, list):
            raise ValueError("payload_sources must be a list")
        if len(self.payload_sources) > MAX_PROVENANCE_REFS:
            raise RequestLimitError(
                "action payload provenance count exceeds maximum of "
                f"{MAX_PROVENANCE_REFS}",
                limit_enforced="action_provenance_refs",
            )
        if any(not isinstance(ref, ContentRef) for ref in self.payload_sources):
            raise ValueError("payload_sources must contain ContentRef objects")
        _validate_provenance_text_volume(self.payload_sources)
        self.estimated_cost_usd = money(
            self.estimated_cost_usd, field_name="estimated_cost_usd"
        )
        self.created_at = _utc_timestamp(self.created_at, "created_at")

    @property
    def payload_hash(self) -> str:
        """Binds approvals and capability grants to exact content.

        If the payload changes by one byte, every approval and grant issued
        against the old payload becomes invalid.
        """
        if self._fingerprints_sealed:
            return self._sealed_payload_hash
        return action_sha256_of(self.payload)

    @property
    def payload_trust(self) -> Trust:
        return worst_trust(self.payload_sources)

    @property
    def authorization_hash(self) -> str:
        """Bind authority to the complete policy-relevant action surface."""
        if self._fingerprints_sealed:
            return self._sealed_authorization_hash
        return action_sha256_of(self._authorization_surface())

    def seal_fingerprints(self) -> tuple[str, str]:
        """Detach, hash once, and seal the action used by the control path."""
        if self._fingerprints_sealed:
            return self._sealed_payload_hash, self._sealed_authorization_hash

        # Validate before copying so cycles or attacker-defined objects cannot
        # amplify deepcopy work. Then detach caller-owned containers before
        # establishing the authority snapshot.
        _validate_action_hash_structure(self.payload)
        _validate_action_hash_structure(self._authorization_surface())
        payload = deepcopy(self.payload)
        sources = deepcopy(self.payload_sources)
        payload_hash = action_sha256_of(payload)
        authorization_hash = action_sha256_of(
            self._authorization_surface(payload=payload, payload_sources=sources)
        )
        object.__setattr__(self, "payload", payload)
        object.__setattr__(self, "payload_sources", sources)
        object.__setattr__(self, "_sealed_payload_hash", payload_hash)
        object.__setattr__(self, "_sealed_authorization_hash", authorization_hash)
        object.__setattr__(self, "_fingerprints_sealed", True)
        return payload_hash, authorization_hash

    def current_authorization_hash(self) -> str:
        """Re-hash live fields for the final capability boundary check."""
        return action_sha256_of(self._authorization_surface())

    def _authorization_surface(
        self,
        *,
        payload: dict | None = None,
        payload_sources: list[ContentRef] | None = None,
    ) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "target": self.target,
            "payload": self.payload if payload is None else payload,
            "side_effect_level": self.side_effect_level,
            "payload_sources": [
                asdict(ref)
                for ref in (
                    self.payload_sources if payload_sources is None else payload_sources
                )
            ],
            "estimated_cost_usd": self.estimated_cost_usd,
        }

    def to_dict(self) -> dict:
        d = _enum_safe(asdict(self))
        d.pop("_sealed_payload_hash", None)
        d.pop("_sealed_authorization_hash", None)
        d.pop("_fingerprints_sealed", None)
        d["payload_hash"] = self.payload_hash
        d["payload_trust"] = self.payload_trust.value
        d["authorization_hash"] = self.authorization_hash
        return d

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ProposedAction":
        data = dict(raw)
        data.pop("payload_hash", None)
        data.pop("payload_trust", None)
        data.pop("authorization_hash", None)
        data["side_effect_level"] = SideEffect(data["side_effect_level"])
        data["payload_sources"] = [
            ContentRef(
                ref_id=ref["ref_id"],
                origin=ref["origin"],
                trust=Trust(ref["trust"]),
                content_hash=ref["content_hash"],
                label=ref.get("label", ""),
            )
            for ref in data.get("payload_sources", [])
        ]
        return cls(**data)


@dataclass
class GuardrailDecision:
    decision: Decision
    reason: str
    policy_ids: list[str] = field(default_factory=list)
    policy_version: str = ""
    ruleset_hash: str = ""
    approval_scope: str = ""
    expires_at: str | None = None
    redactions: list[str] = field(default_factory=list)
    # Exactly what the engine saw when it decided. Without this, "replayable"
    # is a marketing word: you cannot re-run a decision you cannot reconstruct.
    decision_inputs: dict = field(default_factory=dict)
    decided_at: str = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not isinstance(self.decision, Decision):
            self.decision = Decision(self.decision)
        _require_text(self.reason, "decision reason")
        if not self.policy_ids or any(
            not isinstance(policy_id, str) or not policy_id
            for policy_id in self.policy_ids
        ):
            raise ValueError("policy_ids must contain at least one non-empty id")
        self.decided_at = _utc_timestamp(self.decided_at, "decided_at")
        if self.expires_at is not None:
            self.expires_at = _utc_timestamp(self.expires_at, "expires_at")

    def to_dict(self) -> dict:
        return _enum_safe(asdict(self))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "GuardrailDecision":
        data = dict(raw)
        data["decision"] = Decision(data["decision"])
        return cls(**data)


# ---------------------------------------------------------------------------
# capability grant -- the only key that opens the tool layer
# ---------------------------------------------------------------------------


class GrantError(RuntimeError):
    """Raised when the tool layer is reached without valid authority."""


@dataclass
class CapabilityGrant:
    """Single-use authority to execute exactly one action with exactly one payload.

    The tool registry signs a grant only after receiving a sealed authorization
    record. Unsigned construction remains possible as a Python object, but the
    registry refuses to execute it.
    """

    action_id: str
    tool_name: str
    authorization_hash: str
    evidence_record_id: str
    evidence_record_hash: str
    issued_at: str = field(default_factory=utc_now)
    grant_id: str = field(default_factory=lambda: new_id("grant"))
    signature: str = field(default="", repr=False)
    _spent: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        for name in (
            "action_id",
            "tool_name",
            "authorization_hash",
            "evidence_record_id",
            "evidence_record_hash",
            "grant_id",
        ):
            _require_text(getattr(self, name), name)
        self.issued_at = _utc_timestamp(self.issued_at, "issued_at")

    def claims(self) -> dict[str, str]:
        return {
            "action_id": self.action_id,
            "tool_name": self.tool_name,
            "authorization_hash": self.authorization_hash,
            "evidence_record_id": self.evidence_record_id,
            "evidence_record_hash": self.evidence_record_hash,
            "issued_at": self.issued_at,
            "grant_id": self.grant_id,
        }

    def spend(self, action: ProposedAction) -> None:
        """Consume the grant. Raises if it does not match, or is already used."""
        if self._spent:
            raise GrantError(f"capability grant {self.grant_id} already spent")
        if action.action_id != self.action_id:
            raise GrantError("grant/action id mismatch")
        if action.tool_name != self.tool_name:
            raise GrantError("grant/tool mismatch")
        presented_hash = action.current_authorization_hash()
        if presented_hash != self.authorization_hash:
            raise GrantError(
                "action changed after authorization -- grant is void "
                f"(authorized {self.authorization_hash}, "
                f"presented {presented_hash})"
            )
        object.__setattr__(self, "_spent", True)


# ---------------------------------------------------------------------------
# evidence
# ---------------------------------------------------------------------------


@dataclass
class EvidenceRecord:
    request_id: str
    action_id: str
    decision: Decision
    result_status: ResultStatus
    schema_name: str = "defiant.agent_harness.evidence_record"
    schema_version: str = "0.1.0"
    record_id: str = field(default_factory=lambda: new_id("evd"))
    timestamp: str = field(default_factory=utc_now)
    agent_runner: str = "mock"
    model_id: str = ""
    user_id: str = ""
    workspace_id: str = ""
    tool_name: str = ""
    target: str = ""
    side_effect_level: str = SideEffect.NONE.value
    policy_ids: list[str] = field(default_factory=list)
    policy_version: str = ""
    ruleset_hash: str = ""
    decision_reason: str = ""
    decision_inputs: dict = field(default_factory=dict)
    approved_by: str | None = None
    approved_at: str | None = None
    payload_hash: str = ""
    authorization_hash: str = ""
    payload_trust: str = Trust.TRUSTED.value
    input_refs: list[dict] = field(default_factory=list)
    output_hash: str = ""
    result_summary: str = ""
    cost_usd: Decimal = ZERO
    budget_remaining_usd: Decimal | None = None
    dry_run: bool = False
    reconciliation_outcome: str = ""
    reconciled_by: str = ""
    reconciled_at: str | None = None
    reconciliation_note: str = ""
    # chain
    previous_record_hash: str = ""
    record_hash: str = ""

    def __post_init__(self) -> None:
        _require_text(self.request_id, "request_id")
        _require_text(self.action_id, "action_id")
        if not isinstance(self.decision, Decision):
            self.decision = Decision(self.decision)
        if not isinstance(self.result_status, ResultStatus):
            self.result_status = ResultStatus(self.result_status)
        self.cost_usd = money(self.cost_usd, field_name="cost_usd")
        if self.budget_remaining_usd is not None:
            # An actual model call may overrun its reservation, so a remaining
            # balance can be negative. Preserve it honestly in evidence.
            value = Decimal(str(self.budget_remaining_usd))
            if not value.is_finite():
                raise ValueError("budget_remaining_usd must be finite")
            self.budget_remaining_usd = value
        self.timestamp = _utc_timestamp(self.timestamp, "timestamp")
        if self.approved_at is not None:
            self.approved_at = _utc_timestamp(self.approved_at, "approved_at")
        if self.reconciled_at is not None:
            self.reconciled_at = _utc_timestamp(self.reconciled_at, "reconciled_at")

    def body(self) -> dict:
        """Everything except the record's own hash -- the hashed surface."""
        d = _enum_safe(asdict(self))
        d.pop("record_hash", None)
        return d

    def seal(self, previous_record_hash: str) -> "EvidenceRecord":
        if self.record_hash:
            raise ValueError("evidence record is already sealed")
        self.previous_record_hash = previous_record_hash
        self.record_hash = sha256_of(self.body())
        return self

    def to_dict(self) -> dict:
        d = _enum_safe(asdict(self))
        return d


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _enum_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _enum_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_enum_safe(v) for v in obj]
    if isinstance(obj, tuple):
        return [_enum_safe(v) for v in obj]
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, Decimal):
        return money_text(obj)
    return obj


def _action_hash_default(obj: Any) -> Any:
    """JSONEncoder fallback matching the existing canonical conversion."""
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, Decimal):
        return _bounded_money_text(obj)
    raise TypeError(f"unsupported action hash value type: {type(obj).__name__}")


def _validate_action_hash_structure(obj: Any) -> None:
    """Preflight action data and its exact canonical size without encoding."""

    nodes = 0
    canonical_bytes = 0
    active_containers: set[int] = set()

    def claim_node(depth: int) -> None:
        nonlocal nodes
        if depth > MAX_ACTION_HASH_NESTING_DEPTH:
            raise ActionHashLimitError(
                "action hash input exceeds maximum nesting depth of "
                f"{MAX_ACTION_HASH_NESTING_DEPTH}",
                limit_enforced="action_hash_nesting_depth",
            )
        nodes += 1
        if nodes > MAX_ACTION_HASH_NODES:
            raise ActionHashLimitError(
                "action hash input exceeds maximum node count of "
                f"{MAX_ACTION_HASH_NODES}",
                limit_enforced="action_hash_nodes",
            )

    def consume(width: int) -> None:
        nonlocal canonical_bytes
        if width > MAX_ACTION_HASH_CANONICAL_BYTES - canonical_bytes:
            _raise_action_hash_canonical_limit()
        canonical_bytes += width

    def visit_key(value: Any, depth: int) -> None:
        claim_node(depth)
        if isinstance(value, enum.Enum):
            visit_key(value.value, depth)
            return
        if isinstance(value, Decimal):
            consume(_validate_action_hash_string_token(_bounded_money_text(value)))
            return
        if isinstance(value, str):
            consume(_validate_action_hash_scalar(value))
            return
        if isinstance(value, bool):
            consume(6 if value else 7)
            return
        if value is None:
            consume(6)
            return
        if isinstance(value, int):
            consume(_validate_action_hash_integer(value) + 2)
            return
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("action hash input contains a non-finite number")
            text = float.__repr__(value)
            _validate_action_hash_number_text(text)
            consume(len(text) + 2)
            return
        _action_hash_default(value)

    def visit(value: Any, depth: int) -> None:
        claim_node(depth)
        if isinstance(value, enum.Enum):
            visit(value.value, depth)
            return
        if isinstance(value, Decimal):
            consume(_validate_action_hash_string_token(_bounded_money_text(value)))
            return
        if isinstance(value, str):
            consume(_validate_action_hash_scalar(value))
            return
        if isinstance(value, bool):
            consume(4 if value else 5)
            return
        if value is None:
            consume(4)
            return
        if isinstance(value, int):
            consume(_validate_action_hash_integer(value))
            return
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("action hash input contains a non-finite number")
            text = float.__repr__(value)
            _validate_action_hash_number_text(text)
            consume(len(text))
            return
        if isinstance(value, dict):
            if dict.__len__(value) > MAX_ACTION_HASH_MAPPING_ENTRIES:
                raise ActionHashLimitError(
                    "action hash mapping exceeds maximum entry count of "
                    f"{MAX_ACTION_HASH_MAPPING_ENTRIES}",
                    limit_enforced="action_hash_mapping_entries",
                )
            marker = id(value)
            if marker in active_containers:
                raise ValueError("action hash input contains a cyclic container")
            active_containers.add(marker)
            try:
                consume(2)
                for index, (key, child) in enumerate(value.items()):
                    if index:
                        consume(1)
                    # Keys are part of the canonical surface even though JSON's
                    # encoder visits them differently from mapping values.
                    visit_key(key, depth + 1)
                    consume(1)
                    visit(child, depth + 1)
            finally:
                active_containers.remove(marker)
            return
        if isinstance(value, (list, tuple)):
            marker = id(value)
            if marker in active_containers:
                raise ValueError("action hash input contains a cyclic container")
            active_containers.add(marker)
            try:
                consume(2)
                for index, child in enumerate(value):
                    if index:
                        consume(1)
                    visit(child, depth + 1)
            finally:
                active_containers.remove(marker)
            return
        # Preserve the old canonical encoder's rejection behavior, but do so
        # before it can recurse through an attacker-defined object.
        _action_hash_default(value)

    visit(obj, 0)


def _validate_action_hash_scalar(value: str) -> int:
    if len(value) > MAX_ACTION_HASH_SCALAR_CHARACTERS:
        raise ActionHashLimitError(
            "action hash scalar exceeds maximum of "
            f"{MAX_ACTION_HASH_SCALAR_CHARACTERS} characters",
            limit_enforced="action_hash_scalar_characters",
        )
    return _validate_action_hash_string_token(value)


def _validate_action_hash_string_token(value: str) -> int:
    # ``JSONEncoder(ensure_ascii=True)`` emits the opening and closing quotes,
    # printable ASCII verbatim, short escapes for five controls plus quote and
    # backslash, six-byte ``\uXXXX`` escapes for other BMP code points, and
    # two such escapes for non-BMP code points. Count that exact ASCII byte
    # length without constructing the escaped token.
    used = 2
    if used > MAX_ACTION_HASH_STRING_TOKEN_BYTES:
        _raise_action_hash_string_token_limit()
    if (
        value.isascii()
        and value.isprintable()
        and '"' not in value
        and "\\" not in value
    ):
        used += len(value)
        if used > MAX_ACTION_HASH_STRING_TOKEN_BYTES:
            _raise_action_hash_string_token_limit()
        return used

    for character in value:
        codepoint = ord(character)
        if character in {'"', "\\", "\b", "\f", "\n", "\r", "\t"}:
            width = 2
        elif 0x20 <= codepoint <= 0x7E:
            width = 1
        elif codepoint <= 0xFFFF:
            width = 6
        else:
            width = 12
        if width > MAX_ACTION_HASH_STRING_TOKEN_BYTES - used:
            _raise_action_hash_string_token_limit()
        used += width
    return used


def _raise_action_hash_string_token_limit() -> None:
    raise ActionHashLimitError(
        "action hash canonical string token exceeds maximum of "
        f"{MAX_ACTION_HASH_STRING_TOKEN_BYTES} bytes",
        limit_enforced="action_hash_string_token_bytes",
    )


def _validate_action_hash_integer(value: int) -> int:
    sign_characters = 1 if value < 0 else 0
    allowed_digits = MAX_ACTION_HASH_NUMBER_CHARACTERS - sign_characters
    if allowed_digits <= 0:
        _raise_action_hash_number_limit()
    boundary = _action_hash_integer_boundary(allowed_digits)
    if value >= boundary or value <= -boundary:
        _raise_action_hash_number_limit()
    return len(int.__repr__(value))


def _bounded_money_text(value: Decimal) -> str:
    result = money(value)
    if result == ZERO:
        return "0"
    digits, retained_digits, exponent = _canonical_money_components(result)
    if (
        _canonical_money_text_length(retained_digits, exponent)
        > MAX_ACTION_HASH_NUMBER_CHARACTERS
    ):
        _raise_action_hash_number_limit()
    coefficient = "".join(str(digit) for digit in digits[:retained_digits])
    if exponent >= 0:
        return coefficient + ("0" * exponent)
    fractional_digits = -exponent
    if fractional_digits >= retained_digits:
        return "0." + ("0" * (fractional_digits - retained_digits)) + coefficient
    split_at = retained_digits - fractional_digits
    return coefficient[:split_at] + "." + coefficient[split_at:]


@lru_cache(maxsize=16)
def _action_hash_integer_boundary(digits: int) -> int:
    return 10**digits


def _canonical_money_components(value: Decimal) -> tuple[tuple[int, ...], int, int]:
    parts = value.as_tuple()
    digits = parts.digits
    if len(digits) > MAX_ACTION_HASH_NUMBER_CHARACTERS:
        _raise_action_hash_number_limit()
    exponent = int(parts.exponent)
    if exponent >= 0:
        return digits, len(digits), exponent

    fractional_digits = -exponent
    trailing_zeros = 0
    for digit in reversed(digits):
        if digit != 0:
            break
        trailing_zeros += 1
    removed_zeros = min(fractional_digits, trailing_zeros)
    return digits, len(digits) - removed_zeros, exponent + removed_zeros


def _canonical_money_text_length(retained_digits: int, exponent: int) -> int:
    if exponent >= 0:
        return retained_digits + exponent
    fractional_digits = -exponent
    if fractional_digits >= retained_digits:
        return 2 + fractional_digits
    return retained_digits + 1


def _validate_action_hash_number_text(value: str) -> None:
    if len(value) > MAX_ACTION_HASH_NUMBER_CHARACTERS:
        _raise_action_hash_number_limit()


def _raise_action_hash_number_limit() -> None:
    raise ActionHashLimitError(
        "action hash canonical number exceeds maximum of "
        f"{MAX_ACTION_HASH_NUMBER_CHARACTERS} characters",
        limit_enforced="action_hash_number_characters",
    )


def _raise_action_hash_canonical_limit() -> None:
    raise ActionHashLimitError(
        "action canonical hash input exceeds maximum of "
        f"{MAX_ACTION_HASH_CANONICAL_BYTES} bytes",
        limit_enforced="action_hash_canonical_bytes",
    )


def _require_request_text(value: str, field_name: str, maximum: int) -> None:
    if len(value) > maximum:
        raise RequestLimitError(
            f"request {field_name} exceeds maximum of {maximum} characters",
            limit_enforced="request_text_item",
        )


def _require_provenance_text(value: Any, field_name: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if len(value) > MAX_PROVENANCE_TEXT_ITEM_CHARACTERS:
        raise RequestLimitError(
            "provenance metadata item exceeds maximum of "
            f"{MAX_PROVENANCE_TEXT_ITEM_CHARACTERS} characters",
            limit_enforced="provenance_text_item",
        )


def _validate_request_text_volume(request: HarnessRequest) -> None:
    def values() -> Iterable[str]:
        yield request.task
        yield request.user_id
        yield request.workspace_id
        yield request.request_id
        yield request.task_type
        yield from request.allowed_tools
        for ref in request.inputs:
            yield ref.ref_id
            yield ref.origin
            yield ref.content_hash
            yield ref.label

    _require_aggregate_text(
        values(),
        maximum=MAX_REQUEST_TEXT_CHARACTERS,
        label="request text",
        limit_enforced="request_text_characters",
    )


def _validate_provenance_text_volume(refs: list[ContentRef]) -> None:
    values = (
        value
        for ref in refs
        for value in (ref.ref_id, ref.origin, ref.content_hash, ref.label)
    )
    _require_aggregate_text(
        values,
        maximum=MAX_PROVENANCE_TEXT_CHARACTERS,
        label="action provenance text",
        limit_enforced="action_provenance_text_characters",
    )


def _require_aggregate_text(
    values: Iterable[str],
    *,
    maximum: int,
    label: str,
    limit_enforced: str,
) -> None:
    used = 0
    for value in values:
        if len(value) > maximum - used:
            raise RequestLimitError(
                f"{label} exceeds maximum of {maximum} characters",
                limit_enforced=limit_enforced,
            )
        used += len(value)


def _require_text(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _utc_timestamp(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be an RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
