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
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

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
        allow_nan=False,
    )


def sha256_of(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


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
        if not isinstance(self.trust, Trust):
            object.__setattr__(self, "trust", Trust(self.trust))

    @staticmethod
    def of(origin: str, trust: Trust, content: Any, label: str = "") -> "ContentRef":
        return ContentRef(
            ref_id=new_id("ref"),
            origin=origin,
            trust=trust,
            content_hash=sha256_of(content),
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

    def __post_init__(self) -> None:
        _require_text(self.task, "task")
        _require_text(self.user_id, "user_id")
        _require_text(self.workspace_id, "workspace_id")
        _require_text(self.request_id, "request_id")
        if not isinstance(self.sensitivity, Sensitivity):
            self.sensitivity = Sensitivity(self.sensitivity)
        if self.budget_limit_usd is not None:
            self.budget_limit_usd = money(
                self.budget_limit_usd, field_name="budget_limit_usd"
            )
        if any(not isinstance(ref, ContentRef) for ref in self.inputs):
            raise ValueError("inputs must contain ContentRef objects")
        self.created_at = _utc_timestamp(self.created_at, "created_at")

    def to_dict(self) -> dict:
        return _enum_safe(asdict(self))

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "HarnessRequest":
        data = dict(raw)
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

    def __post_init__(self) -> None:
        _require_text(self.tool_name, "tool_name")
        _require_text(self.target, "target")
        _require_text(self.action_id, "action_id")
        if not isinstance(self.payload, dict):
            raise ValueError("payload must be a dictionary")
        if not isinstance(self.side_effect_level, SideEffect):
            self.side_effect_level = SideEffect(self.side_effect_level)
        if any(not isinstance(ref, ContentRef) for ref in self.payload_sources):
            raise ValueError("payload_sources must contain ContentRef objects")
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
        return sha256_of(self.payload)

    @property
    def payload_trust(self) -> Trust:
        return worst_trust(self.payload_sources)

    @property
    def authorization_hash(self) -> str:
        """Bind authority to the complete policy-relevant action surface."""
        return sha256_of(
            {
                "action_id": self.action_id,
                "request_id": self.request_id,
                "tool_name": self.tool_name,
                "target": self.target,
                "payload": self.payload,
                "side_effect_level": self.side_effect_level,
                "payload_sources": [asdict(ref) for ref in self.payload_sources],
                "estimated_cost_usd": self.estimated_cost_usd,
            }
        )

    def to_dict(self) -> dict:
        d = _enum_safe(asdict(self))
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
        if action.authorization_hash != self.authorization_hash:
            raise GrantError(
                "action changed after authorization -- grant is void "
                f"(authorized {self.authorization_hash}, "
                f"presented {action.authorization_hash})"
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
